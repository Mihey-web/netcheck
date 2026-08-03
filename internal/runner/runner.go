// Package runner оркеструет прогон: слои по порядку, пробы внутри слоя
// параллельно, сбор улик и вердикта.
package runner

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"sync"
	"time"

	"github.com/mihey/netcheck/internal/analyze"
	"github.com/mihey/netcheck/internal/config"
	"github.com/mihey/netcheck/internal/env"
	"github.com/mihey/netcheck/internal/geo"
	"github.com/mihey/netcheck/internal/geo/data"
	"github.com/mihey/netcheck/internal/i18n"
	"github.com/mihey/netcheck/internal/probe"
	"github.com/mihey/netcheck/internal/verdict"
)

// DoH-эндпоинты: сначала Cloudflare, при неудаче Google
// (из РФ cloudflare-dns.com бывает придушен).
var dohEndpoints = []string{
	"https://cloudflare-dns.com/dns-query",
	"https://dns.google/dns-query",
}

// Лестница нейтральных имён для контрольного рукопожатия: ими проверяем,
// рвёт ли DPI именно по имени. Одного example.com мало — CloudFront и Google
// Cloud LB не знают этого имени и отвергают его сами, поэтому за ним идут
// имена, которые эти площадки обслуживают штатно.
var neutralSNIs = []string{"example.com", "d1.awsstatic.com", "www.google.com"}

// maxIPsPerHost — сколько адресов пробовать, прежде чем говорить «блок по IP».
// У notion.so один из двух адресов мёртв целиком, и DNS отдаёт их в случайном
// порядке: по одному адресу вердикт был подбрасыванием монеты.
const maxIPsPerHost = 3

// Prober — сетевые операции, вынесенные за интерфейс ради тестов.
type Prober interface {
	Ping(ctx context.Context, ip string) probe.Result
	ResolveSystem(ctx context.Context, host string) probe.Result
	ResolveUDP(ctx context.Context, host, server string) probe.Result
	ResolveDoH(ctx context.Context, host, doh string) probe.Result
	TCPConnect(ctx context.Context, ipPort string) probe.Result
	TLSHandshake(ctx context.Context, ipPort, sni string) probe.Result
	HTTPGet(ctx context.Context, rawURL string, proxy *url.URL) probe.Result
	Trace(ctx context.Context, ip string) ([]probe.Hop, error)
}

// Live — боевая реализация Prober поверх пакета probe.
type Live struct{}

func (Live) Ping(ctx context.Context, ip string) probe.Result { return probe.Ping(ctx, ip) }
func (Live) ResolveSystem(ctx context.Context, host string) probe.Result {
	return probe.ResolveSystem(ctx, host)
}
func (Live) ResolveUDP(ctx context.Context, host, server string) probe.Result {
	return probe.ResolveUDP(ctx, host, server)
}
func (Live) ResolveDoH(ctx context.Context, host, doh string) probe.Result {
	return probe.ResolveDoH(ctx, host, doh)
}
func (Live) TCPConnect(ctx context.Context, ipPort string) probe.Result {
	return probe.TCPConnect(ctx, ipPort)
}
func (Live) TLSHandshake(ctx context.Context, ipPort, sni string) probe.Result {
	return probe.TLSHandshake(ctx, ipPort, sni)
}
func (Live) HTTPGet(ctx context.Context, rawURL string, proxy *url.URL) probe.Result {
	return probe.HTTPGet(ctx, rawURL, proxy)
}
func (Live) Trace(ctx context.Context, ip string) ([]probe.Hop, error) {
	return probe.Trace(ctx, ip)
}

type Progress struct {
	Layer string `json:"layer"`
	Done  bool   `json:"done"`
}

type Report struct {
	StartedAt time.Time                `json:"startedAt"`
	Duration  time.Duration            `json:"duration"`
	Env       env.Snapshot             `json:"env"`
	Results   []probe.Result           `json:"results"`
	Layers    []verdict.LayerStatus    `json:"layers"`
	Services  []verdict.ServiceVerdict `json:"services"`
	Verdict   verdict.Verdict          `json:"verdict"`
	// Aborted — прогон оборван на нижнем слое: дальше проверять было нечего.
	Aborted bool `json:"aborted,omitempty"`
	// Routes — лучи от пользователя до места, где путь кончился (вкладка «Карта»).
	//
	// Пришли на смену пингу облачных якорей. Пинг до чужого дата-центра
	// отвечал на вопрос, которого никто не задавал: он не говорил ни где
	// стоит сервер нужного сервиса, ни почему до него не доходит.
	Routes []geo.Route `json:"routes,omitempty"`
	// GeoDirect/GeoProxy — откуда нас видит интернет напрямую и через VPN.
	// Заполняются только при включённой настройке map.geo_lookup.
	GeoDirect *geo.Info `json:"geoDirect,omitempty"`
	GeoProxy  *geo.Info `json:"geoProxy,omitempty"`
}

// Relocalize пересобирает вердикт сохранённого отчёта на другом языке.
// Факты (окружение, слои, диагнозы) языка не знают — переводится только текст.
func Relocalize(rep Report, l i18n.Lang) Report {
	rep.Verdict = verdict.Build(l, verdict.Input{Env: rep.Env, Layers: rep.Layers, Services: rep.Services})
	return rep
}

type collector struct {
	mu      sync.Mutex
	results []probe.Result
}

func (c *collector) add(rs ...probe.Result) {
	c.mu.Lock()
	c.results = append(c.results, rs...)
	c.mu.Unlock()
}

type blockedOutcome struct {
	sv  verdict.ServiceVerdict
	res []probe.Result
	// traceIP — адрес, до которого имеет смысл трассировать маршрут:
	// живой, если такой нашёлся, иначе первый из ответа DNS.
	traceIP string
}

// Run гоняет батарею проверок. snap — уже собранный снимок окружения
// (его делает вызывающий, чтобы UI показал окружение раньше результатов).
func Run(ctx context.Context, cfg config.Config, lang i18n.Lang, p Prober, snap env.Snapshot, onProgress func(Progress)) Report {
	started := time.Now()
	runCtx, cancel := context.WithTimeout(ctx, time.Duration(cfg.Timeouts.RunMs)*time.Millisecond)
	defer cancel()

	probeTimeout := time.Duration(cfg.Timeouts.ProbeMs) * time.Millisecond
	withTimeout := func() (context.Context, context.CancelFunc) {
		return context.WithTimeout(runCtx, probeTimeout)
	}
	report := func(layer string) {
		if onProgress != nil {
			onProgress(Progress{Layer: layer, Done: true})
		}
	}

	col := &collector{}
	rep := Report{StartedAt: started, Env: snap}
	proxyURL := firstProxyURL(snap)

	// ── слой 1: шлюз ─────────────────────────────────────────────
	gwStatus := probe.StatusOK
	if cfg.Ping.Gateway && snap.Gateway != "" && net.ParseIP(snap.Gateway) != nil {
		c, cancelProbe := withTimeout()
		res := p.Ping(c, snap.Gateway)
		cancelProbe()
		col.add(res)
		gwStatus = res.Status

		if gwStatus == probe.StatusFail && cfg.Ping.GlobalIP != "" {
			// Роутер молчит на ICMP — это ещё не приговор: домашние роутеры
			// и корпоративные сети сплошь и рядом просто не отвечают на ping.
			// Один дешёвый вопрос наружу отличает «фильтруется ICMP»
			// от «связи нет вообще», и только во втором случае рвём прогон.
			c, cancelProbe := withTimeout()
			ctrl := p.TCPConnect(c, net.JoinHostPort(cfg.Ping.GlobalIP, "443"))
			cancelProbe()
			col.add(ctrl)
			if ctrl.Status == probe.StatusOK {
				gwStatus = probe.StatusWarn
			}
		}
	}
	rep.Layers = append(rep.Layers, verdict.LayerStatus{Layer: "gateway", Status: gwStatus})
	report("gateway")

	// Связи нет от слова совсем: всё, что выше, показало бы одинаковый «fail»
	// и только сбивало бы с толку. Помечаем остальные слои непроверенными.
	if gwStatus == probe.StatusFail {
		for _, l := range []string{"dns", "runet", "global", "blocked"} {
			rep.Layers = append(rep.Layers, verdict.LayerStatus{Layer: l, Status: probe.StatusSkip})
			report(l)
		}
		rep.Aborted = true
		rep.Results = col.results
		rep.Verdict = verdict.Build(lang, verdict.Input{Env: snap, Layers: rep.Layers})
		rep.Duration = time.Since(started)
		if rep.Duration <= 0 {
			rep.Duration = time.Nanosecond
		}
		return rep
	}

	// ── слой 2: DNS тремя путями ─────────────────────────────────
	dnsProbe := firstOr(cfg.Targets.Blocked, "youtube.com")
	var sysIPs []string
	dnsStatus := probe.StatusOK
	{
		var wg sync.WaitGroup
		var sysRes, udpRes, dohRes probe.Result
		wg.Add(3)
		go func() {
			defer wg.Done()
			c, cancelProbe := withTimeout()
			defer cancelProbe()
			sysRes = p.ResolveSystem(c, dnsProbe)
		}()
		go func() {
			defer wg.Done()
			c, cancelProbe := withTimeout()
			defer cancelProbe()
			udpRes = p.ResolveUDP(c, dnsProbe, "8.8.8.8:53")
		}()
		go func() {
			defer wg.Done()
			for _, ep := range dohEndpoints {
				c, cancelProbe := withTimeout()
				dohRes = p.ResolveDoH(c, dnsProbe, ep)
				cancelProbe()
				if dohRes.Status == probe.StatusOK {
					return
				}
			}
		}()
		wg.Wait()
		col.add(sysRes, udpRes, dohRes)
		sysIPs = sysRes.IPs
		// Расхождение системного ответа с DoH подменой НЕ является: у любого
		// CDN это обычный GeoDNS, и раньше именно оно вешало на каждый прогон
		// строку «провайдер подменяет DNS-ответы». Подмена — это адрес,
		// которого в интернете быть не может.
		switch {
		case sysRes.Status == probe.StatusFail:
			dnsStatus = probe.StatusFail
		case analyze.PrivateAnswer(sysIPs):
			dnsStatus = probe.StatusWarn
		}
	}
	rep.Layers = append(rep.Layers, verdict.LayerStatus{Layer: "dns", Status: dnsStatus})
	report("dns")

	// ── слои 3–4: рунет и заграница ──────────────────────────────
	runetStatus := checkZone(p, col, withTimeout, cfg.Targets.Runet)
	rep.Layers = append(rep.Layers, verdict.LayerStatus{Layer: "runet", Status: runetStatus})
	report("runet")

	if cfg.Ping.GlobalIP != "" {
		c, cancelProbe := withTimeout()
		col.add(p.Ping(c, cfg.Ping.GlobalIP))
		cancelProbe()
	}
	globalStatus := checkZone(p, col, withTimeout, cfg.Targets.Global)
	rep.Layers = append(rep.Layers, verdict.LayerStatus{Layer: "global", Status: globalStatus})
	report("global")

	// ── карта: «откуда нас видно» ────────────────────────────────
	// Идёт параллельно слою сервисов — на общее время прогона не влияет.
	// Сами лучи строятся после слоя сервисов: до трассировки надо знать,
	// какой адрес у цели живой.
	var mapWG sync.WaitGroup
	if cfg.Map.Enabled {
		if cfg.Map.GeoLookup {
			mapWG.Add(1)
			go func() {
				defer mapWG.Done()
				if info, err := geo.Lookup(runCtx, nil); err == nil {
					rep.GeoDirect = info
				}
				if proxyURL != nil {
					if info, err := geo.Lookup(runCtx, proxyURL); err == nil {
						rep.GeoProxy = info
					}
				}
			}()
		}
	}

	// ── слой 5: блокируемые сервисы ──────────────────────────────
	// геоблокируемые проверяются тем же способом: разницу ставит analyze
	blockedHosts := append(append([]string{}, cfg.Targets.Blocked...), cfg.Targets.GeoBlocked...)
	outs := make([]blockedOutcome, len(blockedHosts))
	var wg sync.WaitGroup
	for i, host := range blockedHosts {
		wg.Add(1)
		go func(i int, host string) {
			defer wg.Done()
			outs[i] = checkBlocked(p, withTimeout, host, proxyURL)
		}(i, host)
	}
	wg.Wait()

	blockedStatus := probe.StatusOK
	for _, o := range outs {
		col.add(o.res...)
		rep.Services = append(rep.Services, o.sv)
		if !o.sv.DirectOK {
			blockedStatus = probe.StatusFail
		}
	}
	rep.Layers = append(rep.Layers, verdict.LayerStatus{Layer: "blocked", Status: blockedStatus})
	report("blocked")

	if cfg.Map.Enabled {
		// Трассировкам нужен свой бюджет, а не остаток общего: они идут
		// последними, и если проверки съели всё время, карта оказалась бы
		// пустой — причём без объяснения, что времени просто не хватило.
		traceCtx, cancelTrace := context.WithTimeout(ctx, traceBudget)
		rep.Routes = traceRoutes(traceCtx, p, outs)
		cancelTrace()
	}
	mapWG.Wait()
	rep.Results = col.results
	rep.Verdict = verdict.Build(lang, verdict.Input{Env: snap, Layers: rep.Layers, Services: rep.Services})
	rep.Duration = time.Since(started)
	if rep.Duration <= 0 {
		rep.Duration = time.Nanosecond
	}
	return rep
}

// maxParallelTraces — сколько маршрутов трассировать одновременно.
// Каждая трассировка держит два десятка ICMP-дескрипторов, и без предела
// полсотни целей открыли бы их тысячу разом. Двенадцать — компромисс:
// стандартный набор целей проходит за две волны.
const maxParallelTraces = 12

// traceBudget — сколько времени отводится на всю карту.
const traceBudget = 6 * time.Second

// traceRoutes строит лучи до проверенных целей.
//
// Трассируются все цели, а не только упавшие: работающий сервис на карте
// нужен не меньше — по нему видно, докуда путь проходит нормально, и с чем
// сравнивать оборвавшийся.
func traceRoutes(ctx context.Context, p Prober, outs []blockedOutcome) []geo.Route {
	db, err := data.Load()
	if err != nil {
		// Без базы луч всё равно рисуется — просто без подписей,
		// чей это роутер. Это хуже, но честнее, чем пустая карта.
		db = nil
	}

	routes := make([]geo.Route, len(outs))
	sem := make(chan struct{}, maxParallelTraces)
	var wg sync.WaitGroup

	for i, o := range outs {
		if o.traceIP == "" {
			continue
		}
		wg.Add(1)
		go func(i int, host, ip string, serviceOK bool) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			hops, err := p.Trace(ctx, ip)
			if err != nil {
				routes[i] = geo.Route{
					Host: host, TargetIP: ip, ServiceOK: serviceOK,
					Note: "трассировка не отработала: " + err.Error(),
				}
				return
			}
			routes[i] = geo.BuildRoute(host, ip, hops, db, serviceOK)
		}(i, o.sv.Host, o.traceIP, o.sv.DirectOK)
	}
	wg.Wait()

	out := routes[:0]
	for _, r := range routes {
		if r.Host != "" {
			out = append(out, r)
		}
	}
	return out
}

// checkZone — HTTPS до каждой цели зоны; зона жива, если жива хотя бы одна.
func checkZone(p Prober, col *collector, withTimeout func() (context.Context, context.CancelFunc), hosts []string) probe.Status {
	if len(hosts) == 0 {
		return probe.StatusOK
	}
	results := make([]probe.Result, len(hosts))
	var wg sync.WaitGroup
	for i, h := range hosts {
		wg.Add(1)
		go func(i int, h string) {
			defer wg.Done()
			c, cancel := withTimeout()
			defer cancel()
			results[i] = p.HTTPGet(c, "https://"+h, nil)
		}(i, h)
	}
	wg.Wait()
	col.add(results...)
	for _, r := range results {
		if r.Status == probe.StatusOK {
			return probe.StatusOK
		}
	}
	return probe.StatusFail
}

// checkBlocked собирает улики по одной блокируемой цели и ставит диагноз.
func checkBlocked(p Prober, withTimeout func() (context.Context, context.CancelFunc), host string, proxyURL *url.URL) blockedOutcome {
	var out blockedOutcome
	ev := analyze.Evidence{Host: host}

	c, cancel := withTimeout()
	sysRes := p.ResolveSystem(c, host)
	cancel()
	out.res = append(out.res, sysRes)
	ev.SysIPs = sysRes.IPs

	for _, ep := range dohEndpoints {
		c, cancel := withTimeout()
		dohRes := p.ResolveDoH(c, host, ep)
		cancel()
		out.res = append(out.res, dohRes)
		if dohRes.Status == probe.StatusOK {
			ev.DoHIPs = dohRes.IPs
			break
		}
	}

	// Перебираем адреса, а не берём первый: один мёртвый адрес в ответе DNS
	// не делает сервис заблокированным.
	var liveIP string
	for _, ip := range dedupIPs(ev.DoHIPs, ev.SysIPs) {
		if out.traceIP == "" {
			// Трассировать есть смысл и до мёртвого адреса: именно так
			// и видно, на каком шаге путь до него обрывается.
			out.traceIP = ip
		}
		c, cancel := withTimeout()
		r := p.TCPConnect(c, net.JoinHostPort(ip, "443"))
		cancel()
		out.res = append(out.res, r)
		ev.TCP = append(ev.TCP, r)
		if r.Status == probe.StatusOK {
			liveIP = ip
			out.traceIP = ip
			break
		}
	}

	// Ни один адрес не отвечает — дальше мерить нечего, и четыре лишних
	// таймаута ничего не добавят к уже доказанному.
	if liveIP == "" {
		out.sv = verdict.ServiceVerdict{Host: host, Cause: analyze.Diagnose(ev)}
		return out
	}

	ipPort := net.JoinHostPort(liveIP, "443")
	c, cancel = withTimeout()
	ev.TLSReal = p.TLSHandshake(c, ipPort, host)
	cancel()
	out.res = append(out.res, ev.TLSReal)

	if ev.TLSReal.Status == probe.StatusFail {
		for _, sni := range neutralSNIs {
			c, cancel := withTimeout()
			r := p.TLSHandshake(c, ipPort, sni)
			cancel()
			out.res = append(out.res, r)
			ev.TLSNeutral = append(ev.TLSNeutral, r)
			if r.Status == probe.StatusOK {
				break // сервер отозвался, лестницу дальше крутить незачем
			}
		}
		// Рукопожатие с настоящим именем не проходит — HTTP по нему тем более
		// не пройдёт. Не тратим на него бюджет.
		out.sv = verdict.ServiceVerdict{Host: host, Cause: analyze.Diagnose(ev)}
		if proxyURL != nil {
			ev.ProxyTried = true
			c, cancel := withTimeout()
			pr := p.HTTPGet(c, "https://"+host, proxyURL)
			cancel()
			out.res = append(out.res, pr)
			ev.ProxyOK = pr.Status == probe.StatusOK
			out.sv.ProxyOK = ev.ProxyOK
			out.sv.Cause = analyze.Diagnose(ev)
		}
		return out
	}

	c, cancel = withTimeout()
	ev.HTTP = p.HTTPGet(c, "https://"+host, nil)
	cancel()
	out.res = append(out.res, ev.HTTP)

	directOK := ev.HTTP.Status == probe.StatusOK && !isRefusal(ev.HTTP)
	proxyOK := false
	// Контрольный замер через прокси — не роскошь, а единственный способ
	// отличить геоблок от антибота: тот же 403 из другой страны означает
	// защиту от роботов, другой ответ — что нас не пускают по стране.
	if proxyURL != nil {
		ev.ProxyTried = true
		c, cancel := withTimeout()
		pr := p.HTTPGet(c, "https://"+host, proxyURL)
		cancel()
		out.res = append(out.res, pr)
		ev.Control = &pr
		proxyOK = pr.Status == probe.StatusOK
		ev.ProxyOK = proxyOK
	}

	out.sv = verdict.ServiceVerdict{Host: host, DirectOK: directOK, ProxyOK: proxyOK}
	if !directOK {
		out.sv.Cause = analyze.Diagnose(ev)
	}
	return out
}

// isRefusal — сервер ответил, но отказом (403/429/451). Формально HTTP-проба
// удалась, для пользователя сервис не работает.
func isRefusal(r probe.Result) bool {
	return r.Code == 403 || r.Code == 429 || r.Code == 451
}

// dedupIPs — до maxIPsPerHost адресов, сначала DoH: он снят мимо провайдера.
func dedupIPs(lists ...[]string) []string {
	seen := map[string]bool{}
	var out []string
	for _, l := range lists {
		for _, ip := range l {
			if ip == "" || seen[ip] {
				continue
			}
			seen[ip] = true
			out = append(out, ip)
			if len(out) == maxIPsPerHost {
				return out
			}
		}
	}
	return out
}

// firstProxyURL — первый активный прокси-листенер как URL для http.Transport.
func firstProxyURL(s env.Snapshot) *url.URL {
	for _, p := range s.Proxies {
		if p.Kind != "listener" || !p.Active {
			continue
		}
		scheme := "http"
		if p.Proto == "socks5" {
			scheme = "socks5"
		}
		if u, err := url.Parse(fmt.Sprintf("%s://%s", scheme, p.Addr)); err == nil {
			return u
		}
	}
	return nil
}

func firstOr[T any](s []T, def T) T {
	if len(s) > 0 {
		return s[0]
	}
	return def
}
