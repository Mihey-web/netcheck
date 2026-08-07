// Package runner оркеструет прогон: слои по порядку, пробы внутри слоя
// параллельно, сбор улик и вердикта.
package runner

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/url"
	"strings"
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
// Адреса, а не имена: чтобы сходить в cloudflare-dns.com, пришлось бы
// сначала отрезолвить его — системным резолвером, ровно тем, который DoH
// и должен обойти. Независимый путь падал вместе с зависимым, и мёртвый
// DNS выглядел как мёртвая сеть. У обоих адресов есть IP в сертификате.
var dohEndpoints = []string{
	"https://1.1.1.1/dns-query",
	"https://8.8.8.8/dns-query",
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
	HTTPGet(ctx context.Context, rawURL string, proxy *url.URL, pinIP string) probe.Result
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
func (Live) HTTPGet(ctx context.Context, rawURL string, proxy *url.URL, pinIP string) probe.Result {
	return probe.HTTPGet(ctx, rawURL, proxy, pinIP)
}
func (Live) Trace(ctx context.Context, ip string) ([]probe.Hop, error) {
	return probe.Trace(ctx, ip)
}

// Progress — событие хода прогона. Либо «слой закончен» (Done), либо
// очередной готовый результат (Result): таблица заполняется по ходу дела,
// а не одним куском в конце, и видно, на чём именно прогон сейчас стоит.
type Progress struct {
	Layer  string        `json:"layer"`
	Done   bool          `json:"done,omitempty"`
	Result *probe.Result `json:"result,omitempty"`
	// Checked/Total — счётчик «N из M» целей для кнопки: сколько целей
	// уже получили итог и сколько их всего в этом прогоне. Событие с этими
	// полями (и без Result/Done) — просто тик счётчика.
	Checked int `json:"checked,omitempty"`
	Total   int `json:"total,omitempty"`
}

// captiveURL — контрольный запрос по обычному HTTP. Ровно им пользуется сам
// Windows, чтобы понять, есть ли интернет: ответ должен быть 200 с телом
// captiveBody. Всё остальное означает, что вместо адресата ответил кто-то
// по пути — обычно окно входа в публичный Wi-Fi.
const (
	captiveURL  = "http://www.msftconnecttest.com/connecttest.txt"
	captiveBody = "Microsoft Connect Test"
)

// значения Report.Captive живут в пакете verdict — он же их и толкует
const (
	captivePortal = verdict.CaptivePortal
	captiveOpen   = verdict.CaptiveOpen
	captiveDead   = verdict.CaptiveDead
)

// maxParallelChecks — сколько блокируемых целей проверять одновременно.
// Без предела полный набор запускал полсотни цепочек DNS+TCP+TLS разом,
// и сеть отвечала таймаутами просто от собственной перегрузки.
const maxParallelChecks = 12

// captiveKind разбирает ответ на контрольный запрос.
func captiveKind(r probe.Result) string {
	switch {
	case r.Code == 0:
		return "" // никто не ответил — связи нет вовсе
	case r.Code == 200 && strings.Contains(r.Body, captiveBody):
		return captiveOpen
	case r.Code >= 400:
		// Ошибка от самого адресата (или от корпоративного прокси) — это
		// не страница входа. Советовать «откройте браузер и авторизуйтесь»
		// там, где авторизовываться негде, хуже, чем промолчать.
		return ""
	case r.Code >= 300 && probe.SameSite("www.msftconnecttest.com", r.Location):
		return captiveOpen // штатный редирект внутри того же сайта
	default:
		return captivePortal
	}
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
	// Canceled — прогон прерван снаружи (кнопка «Отменить», закрытие окна
	// или общий таймаут): замеры неполные, вердикт по ним не строится
	// и в историю такой прогон не пишется.
	Canceled bool `json:"canceled,omitempty"`
	// Captive — что показал контрольный HTTP-запрос, когда не открылся
	// ни один сайт: "portal" (ответ подменён страницей входа), "open"
	// (наружу ходим, а сайты не открываются) или "" (не ответил никто).
	Captive string `json:"captive,omitempty"`
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
	// GeoDataDate — дата выпуска вшитой геобазы (YYYY-MM-DD): по ней UI
	// сможет предупредить, что подписи карты собраны по устаревшим данным.
	GeoDataDate string `json:"geoDataDate,omitempty"`
}

// Relocalize пересобирает вердикт сохранённого отчёта на другом языке.
// Факты (окружение, слои, диагнозы) языка не знают — переводится только текст.
func Relocalize(rep Report, l i18n.Lang) Report {
	rep.Verdict = verdict.Build(l, verdict.Input{
		Env: rep.Env, Layers: rep.Layers, Services: rep.Services, Captive: rep.Captive,
	})
	// Лучи копируем перед локализацией: Report пришёл по значению, но срез
	// внутри общий, и запись Note в него портила бы отчёт вызывающего.
	rep.Routes = append([]geo.Route(nil), rep.Routes...)
	localizeRoutes(rep.Routes, l)
	return rep
}

// localizeRoutes собирает подписи карты из кодов причин — тем же манером,
// каким verdict собирает текст из message-id. Старые отчёты в истории несут
// готовый Note без кода: их не трогаем, честнее оставить строку языка прогона,
// чем стереть объяснение.
func localizeRoutes(routes []geo.Route, l i18n.Lang) {
	for i := range routes {
		r := &routes[i]
		if r.NoteID == "" {
			continue
		}
		args := make([]any, len(r.NoteArgs))
		for j, a := range r.NoteArgs {
			args[j] = a
		}
		r.Note = i18n.T(l, r.NoteID, args...)
	}
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
	// События уходят из нескольких горутин разом — сериализуем, чтобы
	// подписчик (UI) получал их по одному и в целости.
	var emitMu sync.Mutex
	emit := func(pr Progress) {
		if onProgress == nil {
			return
		}
		emitMu.Lock()
		onProgress(pr)
		emitMu.Unlock()
	}
	report := func(layer string) { emit(Progress{Layer: layer, Done: true}) }
	// live — результат сразу на экран, не дожидаясь конца слоя.
	live := func(layer string, rs ...probe.Result) {
		for i := range rs {
			r := rs[i]
			emit(Progress{Layer: layer, Result: &r})
		}
	}

	col := &collector{}
	rep := Report{StartedAt: started, Env: snap}
	proxyURL := firstProxyURL(snap)
	// add — и в отчёт, и на экран. Порядок в отчёте остаётся детерминированным
	// (его задают вызовы add), а на экран строки идут по мере готовности.
	add := func(layer string, rs ...probe.Result) {
		col.add(rs...)
		live(layer, rs...)
	}

	// Счётчик «N из M» для кнопки: цель — это шлюз, DNS и каждый проверяемый
	// хост. Тик уходит, когда по цели готов итог, а не когда её начали.
	totalTargets := 2 + len(cfg.Targets.Runet) + len(cfg.Targets.Global) +
		len(cfg.Targets.Blocked) + len(cfg.Targets.GeoBlocked)
	var tickMu sync.Mutex
	ticked := 0
	tick := func(layer string) {
		tickMu.Lock()
		ticked++
		n := ticked
		tickMu.Unlock()
		emit(Progress{Layer: layer, Checked: n, Total: totalTargets})
	}

	// canceled — отмена между слоями. Каждый замер после отмены лишь
	// пересказывал бы умерший контекст таймаутами, а вердикт из таких
	// «замеров» («Интернета нет» из-за нажатой кнопки) — выдумка.
	canceled := func(next string) (Report, bool) {
		if runCtx.Err() == nil {
			return Report{}, false
		}
		rep.Canceled = true
		var skipped []verdict.LayerStatus
		if next != "" {
			skipped = skipFrom(next, report)
		}
		return finish(&rep, col, started, lang, skipped), true
	}

	// ── слой 1: шлюз ─────────────────────────────────────────────
	gwStatus := probe.StatusOK
	if cfg.Ping.Gateway {
		if snap.Gateway == "" || net.ParseIP(snap.Gateway) == nil {
			// Адаптер подключён, а маршрута по умолчанию нет: сеть не настроена.
			// Раньше этот случай молча считался «шлюз в порядке», и прогон
			// уходил проверять интернет, которого взяться неоткуда.
			gwStatus = probe.StatusFail
		} else {
			c, cancelProbe := withTimeout()
			res := p.Ping(c, snap.Gateway)
			cancelProbe()
			add("gateway", res)
			gwStatus = res.Status

			if gwStatus == probe.StatusFail && cfg.Ping.GlobalIP != "" {
				// Роутер молчит на ICMP — это ещё не приговор: домашние роутеры
				// и корпоративные сети сплошь и рядом просто не отвечают на ping.
				// Один дешёвый вопрос наружу отличает «фильтруется ICMP»
				// от «связи нет вообще», и только во втором случае рвём прогон.
				c, cancelProbe := withTimeout()
				ctrl := p.TCPConnect(c, net.JoinHostPort(cfg.Ping.GlobalIP, "443"))
				cancelProbe()
				add("gateway", ctrl)
				if ctrl.Status == probe.StatusOK {
					gwStatus = probe.StatusWarn
				}
			}
		}
	}
	rep.Layers = append(rep.Layers, verdict.LayerStatus{Layer: "gateway", Status: gwStatus})
	tick("gateway")
	report("gateway")

	// Связи нет от слова совсем: всё, что выше, показало бы одинаковый «fail»
	// и только сбивало бы с толку. Помечаем остальные слои непроверенными.
	if gwStatus == probe.StatusFail {
		return finish(&rep, col, started, lang, skipFrom("dns", report))
	}
	if r, ok := canceled("dns"); ok {
		return r
	}

	// ── слой 2: DNS тремя путями ─────────────────────────────────
	// Контрольное имя фиксированное, а не первое из пользовательского списка.
	// Опечатка в своей цели или домен, которого больше нет, честно давали
	// отказ по всем трём путям — и прогон обрывался с диагнозом «интернета
	// нет» на совершенно здоровой сети.
	dnsProbe := "cloudflare.com"
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
			live("dns", sysRes)
		}()
		go func() {
			defer wg.Done()
			c, cancelProbe := withTimeout()
			defer cancelProbe()
			udpRes = p.ResolveUDP(c, dnsProbe, "8.8.8.8:53")
			live("dns", udpRes)
		}()
		// Каждая попытка DoH — в отчёт и на экран, как в checkBlocked.
		// Раньше запоминалась только последняя, и неудача Cloudflare
		// молча исчезала под удачей Google.
		var dohAll []probe.Result
		go func() {
			defer wg.Done()
			for _, ep := range dohEndpoints {
				c, cancelProbe := withTimeout()
				dohRes = p.ResolveDoH(c, dnsProbe, ep)
				cancelProbe()
				dohAll = append(dohAll, dohRes)
				live("dns", dohRes)
				if dohRes.Status == probe.StatusOK {
					break
				}
			}
		}()
		wg.Wait()
		col.add(sysRes, udpRes)
		col.add(dohAll...)
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
		// Молчат все три пути сразу — системный резолвер, UDP мимо провайдера
		// и DoH. Это уже не «сломан DNS»: так выглядит сеть, из которой наружу
		// не уходит ничего. Один SYN отвечает на вопрос дешевле, чем два
		// следующих слоя, которым всё равно нечем резолвить имена.
		if sysRes.Status != probe.StatusOK && udpRes.Status != probe.StatusOK &&
			dohRes.Status != probe.StatusOK && cfg.Ping.GlobalIP != "" {
			c, cancelProbe := withTimeout()
			ctrl := p.TCPConnect(c, net.JoinHostPort(cfg.Ping.GlobalIP, "443"))
			cancelProbe()
			add("dns", ctrl)
			// Одного якоря мало: 1.1.1.1 режут и провайдеры, и корпоративные
			// сети, а прямой 443 наружу в корпоративке закрыт по определению.
			// Обрываем прогон, только если молчит ещё и обычный HTTP.
			if ctrl.Status != probe.StatusOK {
				c, cancelProbe := withTimeout()
				alt := p.HTTPGet(c, captiveURL, nil, "")
				cancelProbe()
				add("dns", alt)
				rep.Captive = captiveKind(alt)
				if alt.Code == 0 {
					rep.Captive = captiveDead
					rep.Layers = append(rep.Layers, verdict.LayerStatus{Layer: "dns", Status: dnsStatus})
					report("dns")
					return finish(&rep, col, started, lang, skipFrom("runet", report))
				}
			}
		}
	}
	rep.Layers = append(rep.Layers, verdict.LayerStatus{Layer: "dns", Status: dnsStatus})
	tick("dns")
	report("dns")
	if r, ok := canceled("runet"); ok {
		return r
	}

	// ── слои 3–4: рунет и заграница ──────────────────────────────
	runetStatus := checkZone(p, col, withTimeout, cfg.Targets.Runet, "runet", live, tick)
	rep.Layers = append(rep.Layers, verdict.LayerStatus{Layer: "runet", Status: runetStatus})
	report("runet")
	if r, ok := canceled("global"); ok {
		return r
	}

	if cfg.Ping.GlobalIP != "" {
		c, cancelProbe := withTimeout()
		add("global", p.Ping(c, cfg.Ping.GlobalIP))
		cancelProbe()
	}
	globalStatus := checkZone(p, col, withTimeout, cfg.Targets.Global, "global", live, tick)

	// Не открылось ничего — ни здесь, ни за границей. Прежде чем говорить
	// «интернета нет», один контрольный запрос по обычному HTTP: он отличает
	// оборванную связь от публичного Wi-Fi, который держит нас на странице
	// входа, и от сети, где режут именно HTTPS.
	deadEnd := runetStatus == probe.StatusFail && globalStatus == probe.StatusFail
	// Спрашиваем шире, чем обрываем: контрольный запрос нужен всякий раз,
	// когда ни одна зона не открылась по-настоящему, — в том числе когда
	// сайты отвечают отказом. Именно так выглядит страница входа в публичный
	// Wi-Fi: она отвечает на всё, но ни один сайт не открывается.
	zonesChecked := runetStatus != probe.StatusSkip || globalStatus != probe.StatusSkip
	if zonesChecked && runetStatus != probe.StatusOK && globalStatus != probe.StatusOK {
		c, cancelProbe := withTimeout()
		ctrl := p.HTTPGet(c, captiveURL, nil, "")
		cancelProbe()
		add("global", ctrl)
		rep.Captive = captiveKind(ctrl)
	}
	rep.Layers = append(rep.Layers, verdict.LayerStatus{Layer: "global", Status: globalStatus})
	report("global")
	if r, ok := canceled("blocked"); ok {
		return r
	}

	// Сеть мертва до самого верха: проверять по отдельности два десятка
	// сервисов бессмысленно. Каждый дал бы тот же таймаут, прогон растянулся
	// бы на лишние полминуты, а вердикт получился бы враньём — «домен больше
	// не существует» про YouTube, который просто некуда спросить.
	if deadEnd {
		return finish(&rep, col, started, lang, skipFrom("blocked", report))
	}

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
				// Ошибка — в лог, а не в никуда: молча проглоченная, она
				// выглядела как «гео просто не определилось», и отличить
				// сбой сервиса от выключенной настройки было нечем.
				if info, err := geo.Lookup(runCtx, nil); err == nil {
					rep.GeoDirect = info
				} else {
					log.Printf("geo.Lookup напрямую: %v", err)
				}
				if proxyURL != nil {
					if info, err := geo.Lookup(runCtx, proxyURL); err == nil {
						rep.GeoProxy = info
					} else {
						log.Printf("geo.Lookup через прокси: %v", err)
					}
				}
			}()
		}
	}

	// ── слой 5: блокируемые сервисы ──────────────────────────────
	// геоблокируемые проверяются тем же способом: разницу ставит analyze
	blockedHosts := append(append([]string{}, cfg.Targets.Blocked...), cfg.Targets.GeoBlocked...)
	outs := make([]blockedOutcome, len(blockedHosts))
	sem := make(chan struct{}, maxParallelChecks)
	var wg sync.WaitGroup
	for i, host := range blockedHosts {
		wg.Add(1)
		go func(i int, host string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			outs[i] = checkBlocked(p, withTimeout, host, proxyURL, func(r probe.Result) {
				live("blocked", r)
			})
			tick("blocked")
		}(i, host)
	}
	wg.Wait()

	// Пустой список — «не проверяли», а не «всё в порядке»: зелёная галочка
	// на непроведённой проверке ничем не лучше выдуманного диагноза.
	blockedStatus := probe.StatusSkip
	if len(outs) > 0 {
		blockedStatus = probe.StatusOK
	}
	for _, o := range outs {
		col.add(o.res...)
		rep.Services = append(rep.Services, o.sv)
		if !o.sv.DirectOK {
			blockedStatus = probe.StatusFail
		}
	}
	rep.Layers = append(rep.Layers, verdict.LayerStatus{Layer: "blocked", Status: blockedStatus})
	report("blocked")
	if r, ok := canceled(""); ok {
		return r
	}

	// Ждём геолокацию до трассировок: её координаты — точка отсчёта, от которой
	// считается, успел бы свет до очередного шага или база опять соврала.
	mapWG.Wait()
	if cfg.Map.Enabled {
		// Трассировкам нужен свой бюджет, а не остаток общего: они идут
		// последними, и если проверки съели всё время, карта оказалась бы
		// пустой — причём без объяснения, что времени просто не хватило.
		traceCtx, cancelTrace := context.WithTimeout(ctx, traceBudget)
		rep.Routes = traceRoutes(traceCtx, p, outs, rep.GeoDirect)
		cancelTrace()
		localizeRoutes(rep.Routes, lang)
		// Дата выпуска геобазы — в отчёт: без неё устаревшая на годы база
		// неотличима от свежей, и UI нечем предупредить пользователя.
		rep.GeoDataDate = data.ReleaseDate()
	}
	// Отмена в самом хвосте (во время трассировок): пользователь попросил
	// остановиться — прогон честно считается прерванным, даже если слои успели.
	// Смотрим на внешний ctx, а не на runCtx: трассировки живут на своём
	// бюджете дольше RunMs, и истёкший таймаут прогона здесь — норма,
	// а не отмена.
	rep.Canceled = ctx.Err() != nil
	return finish(&rep, col, started, lang, nil)
}

// layerOrder — порядок слоёв прогона снизу вверх.
var layerOrder = []string{"gateway", "dns", "runet", "global", "blocked"}

// skipFrom помечает непроверенными все слои начиная с указанного и объявляет
// их фронту, чтобы цепочка не осталась висеть на «идёт проверка».
func skipFrom(first string, report func(string)) []verdict.LayerStatus {
	var out []verdict.LayerStatus
	seen := false
	for _, l := range layerOrder {
		if l == first {
			seen = true
		}
		if !seen {
			continue
		}
		out = append(out, verdict.LayerStatus{Layer: l, Status: probe.StatusSkip})
		report(l)
	}
	return out
}

// finish — общий хвост прогона: непроверенные слои, вердикт, длительность.
// skipped непустой значит, что прогон оборван раньше времени.
func finish(rep *Report, col *collector, started time.Time, lang i18n.Lang, skipped []verdict.LayerStatus) Report {
	if len(skipped) > 0 {
		rep.Layers = append(rep.Layers, skipped...)
		rep.Aborted = true
	}
	rep.Results = col.results
	if rep.Canceled {
		// Отменённый прогон — не диагноз. Половина проверок не выполнялась,
		// а оставшиеся умерли вместе с контекстом; строить по ним вердикт
		// значило бы выдавать «Интернета нет» за итог нажатой «Отменить».
		rep.Verdict = verdict.Verdict{
			Lines: []string{i18n.T(lang, "verdict.canceled")},
			Chain: rep.Layers,
		}
	} else {
		rep.Verdict = verdict.Build(lang, verdict.Input{
			Env: rep.Env, Layers: rep.Layers, Services: rep.Services, Captive: rep.Captive,
		})
	}
	rep.Duration = time.Since(started)
	if rep.Duration <= 0 {
		rep.Duration = time.Nanosecond
	}
	return *rep
}

// maxParallelTraces — сколько маршрутов трассировать одновременно.
// Каждая трассировка держит два десятка ICMP-дескрипторов, и без предела
// полсотни целей открыли бы их тысячу разом. Двенадцать — компромисс:
// стандартный набор целей проходит за две волны.
const maxParallelTraces = 12

// traceBudget — сколько времени отводится на всю карту.
//
// Одна трассировка в худшем случае стоит таймаут шага (1.5 с) плюс паузы
// между волнами, плюс перепроверку развилок (0.7 с), плюс обратные запросы
// имён (0.9 с) — около трёх с половиной секунд. Стандартный набор целей идёт
// в две волны по двенадцать, отсюда девять: при шести секундах вторая волна
// обрывалась бы на полпути и половина карты оказывалась пустой без всякого
// объяснения.
const traceBudget = 9 * time.Second

// traceRoutes строит лучи до проверенных целей.
//
// Трассируются все цели, а не только упавшие: работающий сервис на карте
// нужен не меньше — по нему видно, докуда путь проходит нормально, и с чем
// сравнивать оборвавшийся.
func traceRoutes(ctx context.Context, p Prober, outs []blockedOutcome, direct *geo.Info) []geo.Route {
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
				// Код причины, а не готовая строка: подпись соберёт i18n
				// на языке пользователя — в том числе при смене языка
				// поверх сохранённой истории (Relocalize).
				routes[i] = geo.Route{
					Host: host, TargetIP: ip, ServiceOK: serviceOK,
					NoteID: "map.note.trace_failed", NoteArgs: []string{err.Error()},
				}
				return
			}
			routes[i] = geo.BuildRoute(host, ip, hops, db, serviceOK, direct)
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
// Пустой список целей — не «зона в порядке», а «нечего было спрашивать»:
// такую зону вердикт обязан считать непроверенной, а не работающей.
func checkZone(p Prober, col *collector, withTimeout func() (context.Context, context.CancelFunc),
	hosts []string, layer string, live func(string, ...probe.Result), tick func(string)) probe.Status {
	if len(hosts) == 0 {
		return probe.StatusSkip
	}
	results := make([]probe.Result, len(hosts))
	var wg sync.WaitGroup
	for i, h := range hosts {
		wg.Add(1)
		go func(i int, h string) {
			defer wg.Done()
			c, cancel := withTimeout()
			defer cancel()
			results[i] = p.HTTPGet(c, "https://"+h, nil, "")
			live(layer, results[i])
			tick(layer)
		}(i, h)
	}
	wg.Wait()
	col.add(results...)

	// Зона жива, если хоть один сайт по-настоящему открылся. Отказ по коду
	// (403 от Сбербанка под VPN, 429 от антибота) — это не «связи нет»:
	// сервер ответил, дошли. Такая зона получает warn, и прогон продолжается.
	// Прежде любой 403 делал зону мёртвой, а два таких — обрывали проверку
	// сервисов вердиктом «интернета нет» на рабочей сети.
	answered := false
	for i, r := range results {
		if r.Outcome == probe.OutOK {
			answered = true
		}
		if r.Status == probe.StatusOK &&
			(r.Code < 300 || probe.SameSite(hosts[i], r.Location)) {
			return probe.StatusOK
		}
	}
	if answered {
		return probe.StatusWarn
	}
	return probe.StatusFail
}

// checkBlocked собирает улики по одной блокируемой цели и ставит диагноз.
func checkBlocked(p Prober, withTimeout func() (context.Context, context.CancelFunc), host string,
	proxyURL *url.URL, live func(probe.Result)) blockedOutcome {
	var out blockedOutcome
	ev := analyze.Evidence{Host: host}
	// keep — улику в отчёт и сразу же на экран: цели проверяются параллельно,
	// и ждать конца всего слоя, чтобы показать первую строку, незачем.
	keep := func(r probe.Result) {
		out.res = append(out.res, r)
		live(r)
	}

	c, cancel := withTimeout()
	sysRes := p.ResolveSystem(c, host)
	cancel()
	keep(sysRes)
	ev.SysIPs, ev.SysOutcome = sysRes.IPs, sysRes.Outcome

	for _, ep := range dohEndpoints {
		c, cancel := withTimeout()
		dohRes := p.ResolveDoH(c, host, ep)
		cancel()
		keep(dohRes)
		ev.DoHOutcome = dohRes.Outcome
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
		keep(r)
		ev.TCP = append(ev.TCP, r)
		if r.Status == probe.StatusOK {
			liveIP = ip
			out.traceIP = ip
			break
		}
	}

	// Ни один адрес не отвечает — дальше мерить нечего, и четыре лишних
	// таймаута ничего не добавят к уже доказанному. Но замер через VPN
	// сделать обязаны: блокировка по IP — как раз тот случай, когда
	// человеку важнее всего знать, откроется ли сервис у него сейчас.
	// Без этого замера вердикт советовал «нужен VPN» тому, у кого VPN
	// давно включён и всё работает.
	if liveIP == "" {
		out.sv = verdict.ServiceVerdict{Host: host, Cause: analyze.Diagnose(ev), ProxyTried: ev.ProxyTried}
		if proxyURL != nil {
			ev.ProxyTried = true
			c, cancel := withTimeout()
			pr := p.HTTPGet(c, "https://"+host, proxyURL, "")
			cancel()
			keep(pr)
			ev.ProxyOK = pr.Status == probe.StatusOK
			out.sv.ProxyOK = ev.ProxyOK
			out.sv.ProxyTried = true
			out.sv.Cause = analyze.Diagnose(ev)
		}
		return out
	}

	ipPort := net.JoinHostPort(liveIP, "443")
	c, cancel = withTimeout()
	ev.TLSReal = p.TLSHandshake(c, ipPort, host)
	cancel()
	keep(ev.TLSReal)

	if ev.TLSReal.Status == probe.StatusFail {
		for _, sni := range neutralSNIs {
			c, cancel := withTimeout()
			r := p.TLSHandshake(c, ipPort, sni)
			cancel()
			keep(r)
			ev.TLSNeutral = append(ev.TLSNeutral, r)
			if r.Status == probe.StatusOK {
				break // сервер отозвался, лестницу дальше крутить незачем
			}
		}
		// Рукопожатие с настоящим именем не проходит — HTTP по нему тем более
		// не пройдёт. Не тратим на него бюджет.
		out.sv = verdict.ServiceVerdict{Host: host, Cause: analyze.Diagnose(ev), ProxyTried: ev.ProxyTried}
		if proxyURL != nil {
			ev.ProxyTried = true
			c, cancel := withTimeout()
			pr := p.HTTPGet(c, "https://"+host, proxyURL, "")
			cancel()
			keep(pr)
			ev.ProxyOK = pr.Status == probe.StatusOK
			out.sv.ProxyOK = ev.ProxyOK
			out.sv.ProxyTried = true
			out.sv.Cause = analyze.Diagnose(ev)
		}
		return out
	}

	c, cancel = withTimeout()
	ev.HTTP = p.HTTPGet(c, "https://"+host, nil, liveIP)
	cancel()
	keep(ev.HTTP)

	// Редирект на чужой домен здесь успехом считается, и это принципиально.
	//
	// Сюда мы попадаем только после успешного рукопожатия с настоящим именем
	// (ev.TLSReal выше), то есть сертификат проверен и выписан на этот самый
	// хост. Заглушка провайдера такого предъявить не может — для этого ей
	// нужен доверенный сертификат на чужое имя, а это уже не заглушка,
	// а подмена, и её ловит отдельная проверка (CauseMITM).
	//
	// Значит, 302 с проверенного сертификата — ответ настоящего сервера,
	// какой бы домен в нём ни стоял. Прежнее правило «чужой домен — заглушка»
	// объявляло сломанным claude.ai, который отвечает штатным редиректом
	// на www.anthropic.com, — и пользователь читал «claude.ai не работает»,
	// разговаривая через него же.
	//
	// Настоящие заглушки провайдеры ставят на голом HTTP, порт 80. Мы туда
	// не ходим вовсе, так что разбор заглушек в analyze до этого замера
	// не достаёт — честнее признать это, чем ловить их правилом,
	// которое врёт на живых сервисах.
	// Проверка «я не робот» — не поломка: сервер ответил, путь чист,
	// в браузере сайт откроется. Записывать его в недоступные нельзя,
	// но и молча объявлять рабочим тоже: мы его не проверили.
	directOK := (ev.HTTP.Status == probe.StatusOK || ev.HTTP.Challenge) && !isRefusal(ev.HTTP)
	proxyOK := false
	// Контрольный замер через прокси — не роскошь, а единственный способ
	// отличить геоблок от антибота: тот же 403 из другой страны означает
	// защиту от роботов, другой ответ — что нас не пускают по стране.
	if proxyURL != nil {
		ev.ProxyTried = true
		c, cancel := withTimeout()
		pr := p.HTTPGet(c, "https://"+host, proxyURL, "")
		cancel()
		keep(pr)
		ev.Control = &pr
		proxyOK = pr.Status == probe.StatusOK
		ev.ProxyOK = proxyOK
	}

	out.sv = verdict.ServiceVerdict{
		Host: host, DirectOK: directOK, ProxyOK: proxyOK, ProxyTried: ev.ProxyTried,
		Challenged: ev.HTTP.Challenge,
	}
	if !directOK {
		out.sv.Cause = analyze.Diagnose(ev)
	}
	return out
}

// isRefusal — сервер ответил, но отказом (403/429/451). Формально HTTP-проба
// удалась, для пользователя сервис не работает.
// isRefusal — сервер ответил отказом. Проверка «я не робот» приходит с тем же
// кодом 403, но отказом не является: сервер как раз готов пустить, просто
// требует доказать, что ты браузер. Считать её отказом значило записывать
// в недоступные сайты, которые у пользователя открываются.
func isRefusal(r probe.Result) bool {
	if r.Challenge {
		return false
	}
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

// FirstProxyURL — то же самое для внешних вызовов: биндинг замера скорости
// меряет и через VPN, и прокси ему нужен тот же, каким пользуется прогон.
func FirstProxyURL(s env.Snapshot) *url.URL { return firstProxyURL(s) }

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

