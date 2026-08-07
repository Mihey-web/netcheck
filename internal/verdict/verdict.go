// Package verdict собирает человекочитаемый вердикт из фактов прогона.
// Чистая функция: (язык, факты) → строки; сетью не пользуется.
package verdict

import (
	"net"
	"strings"

	"github.com/mihey/netcheck/internal/analyze"
	"github.com/mihey/netcheck/internal/env"
	"github.com/mihey/netcheck/internal/i18n"
	"github.com/mihey/netcheck/internal/probe"
)

type LayerStatus struct {
	Layer  string       `json:"layer"` // gateway|dns|runet|global|blocked
	Status probe.Status `json:"status"`
}

type ServiceVerdict struct {
	Host     string `json:"host"`
	DirectOK bool   `json:"directOk"`
	ProxyOK  bool   `json:"proxyOk"`
	// ProxyTried — замер через VPN вообще делался. Без этого флага
	// «не работает даже через VPN» говорилось и о тех сервисах,
	// которые через VPN ни разу не спрашивали.
	ProxyTried bool `json:"proxyTried,omitempty"`
	// Challenged — вместо страницы пришла проверка «я не робот». Сервер
	// ответил, путь чист, в браузере сайт откроется — но программой он
	// не проверен, и выдавать это за «работает» так же нечестно,
	// как за «не работает».
	Challenged bool          `json:"challenged,omitempty"`
	Cause      analyze.Cause `json:"cause"`
	// Status/Advice/Reason — коды статуса и совета плюс локализованная
	// причина для выдачи на главном экране. Вычисляются в Build, чтобы
	// фронт не дублировал логику; заполнены только в Verdict.Services —
	// в Report.Services эти поля пустые.
	Status string `json:"status,omitempty"`
	Advice string `json:"advice,omitempty"`
	Reason string `json:"reason,omitempty"`
}

// Коды статуса сервиса для главного экрана (ServiceVerdict.Status).
// Статус отвечает на практический вопрос «откроется ли сайт у меня в браузере
// прямо сейчас», а не на абстрактный «блокируют ли его»: владелец с включённым
// VPN читал «только через VPN» как «не работает», хотя сайт у него открывался.
const (
	SvcOK = "ok" // работает напрямую
	// напрямую заблокирован, но через VPN открылся, и браузер сейчас
	// ходит через VPN — то есть для человека сайт работает
	SvcOKViaVPN = "ok_via_vpn"
	// заблокирован, через VPN открывается, но VPN сейчас браузер не покрывает
	SvcNeedVPN   = "need_vpn"
	SvcGeo       = "geo"       // сам сайт не пускает по стране
	SvcChallenge = "challenge" // антибот/капча: в браузере скорее всего откроется
	SvcDown      = "down"      // не работает нигде
	SvcUnknown   = "unknown"   // не удалось определить
)

// Коды совета «что делать» (ServiceVerdict.Advice); текст — в i18n по этим же ключам.
const (
	AdviceVPN     = "advice.vpn"      // заблокировано провайдером — поможет VPN/обход DPI
	AdviceVPNKeep = "advice.vpn_keep" // работает через ваш VPN — не выключайте его
	AdviceVPNFail = "advice.vpn_fail" // не открылось ни напрямую, ни через VPN — дело в VPN-сервере
	AdviceGeo     = "advice.geo"      // нужен VPN с выходом НЕ в РФ
	AdviceBrowser = "advice.browser"  // капча: просто откройте в браузере
	AdviceDNS     = "advice.dns"      // DNS-подмена: включите DoH / смените DNS
	AdviceWait    = "advice.wait"     // сервис лежит сам — остаётся ждать
	AdviceNone    = "advice.none"     // работает / сказать нечего
)

// causeOutcome — таблица Cause→(Status, Advice): единственное место истины
// для кодов главного экрана. Уточнения по фактам замера (DirectOK, Challenged,
// «через VPN пробовали и не вышло») живут в ServiceOutcome, но раскладка
// по причинам — только здесь. Рядом с таблицей — табличный тест на каждый Cause.
var causeOutcome = map[analyze.Cause]struct{ Status, Advice string }{
	// режет провайдер — лечится VPN или обходом DPI
	analyze.CauseDPI:      {SvcNeedVPN, AdviceVPN},
	analyze.CauseIPBlock:  {SvcNeedVPN, AdviceVPN},
	analyze.CauseStateful: {SvcNeedVPN, AdviceVPN},
	analyze.CauseHTTPDrop: {SvcNeedVPN, AdviceVPN},
	analyze.CauseStub:     {SvcNeedVPN, AdviceVPN},
	analyze.CauseMITM:     {SvcNeedVPN, AdviceVPN},
	// подмена DNS обходится и без VPN — сменой резолвера
	analyze.CauseDNSSpoof: {SvcNeedVPN, AdviceDNS},
	analyze.CauseGeoBlock: {SvcGeo, AdviceGeo},
	analyze.CauseAntibot:  {SvcChallenge, AdviceBrowser},
	analyze.CauseDown:     {SvcDown, AdviceWait},
	// не открылось ни напрямую, ни через VPN: совет — про VPN-сервер,
	// потому что именно он не справился (причина уже в Reason)
	analyze.CauseProxyToo: {SvcDown, AdviceVPNFail},
	// про имя ничего не доказано — честное «не удалось определить»
	analyze.CauseNXDomain:  {SvcUnknown, AdviceNone},
	analyze.CauseDNSSilent: {SvcUnknown, AdviceNone},
	analyze.CauseUnknown:   {SvcUnknown, AdviceNone},
}

// ServiceOutcome — статус и совет по одному сервису. Экспортирована ради
// табличного теста: он обязан покрыть каждый Cause из causeOutcome.
// vpnCoversBrowser — «трафик браузера сейчас идёт через VPN» (см. одноимённую
// функцию): без него нельзя ответить на практический вопрос статуса —
// «откроется ли сайт у меня в браузере прямо сейчас».
func ServiceOutcome(s ServiceVerdict, vpnCoversBrowser bool) (status, advice string) {
	// Капча важнее причин: сервер ответил и в браузере сайт откроется,
	// каким бы ни был диагноз по остальным уликам.
	if s.Challenged {
		return SvcChallenge, AdviceBrowser
	}
	if s.DirectOK {
		return SvcOK, AdviceNone
	}
	o, ok := causeOutcome[s.Cause]
	if !ok {
		return SvcUnknown, AdviceNone // пустой Cause при провале
	}
	// «Через VPN да» — это замер, а не надежда: если через VPN пробовали
	// и не вышло, сервис не работает нигде. Совет «поможет VPN» при этом
	// врал бы — этот VPN как раз не помог, — поэтому совет меняется на
	// «дело в VPN-сервере». Исключение — подмена DNS: она обходится сменой
	// резолвера и без VPN, неудача VPN этот совет не отменяет.
	if o.Status == SvcNeedVPN && s.ProxyTried && !s.ProxyOK {
		if o.Advice == AdviceDNS {
			return SvcDown, AdviceDNS
		}
		return SvcDown, AdviceVPNFail
	}
	// Через VPN открылся, и браузер сейчас ходит через VPN — значит, для
	// человека сайт РАБОТАЕТ, и говорить «нужен VPN» ему нельзя: владелец
	// с включённым VPN читал это как «не работает». Геоблок сюда тоже
	// попадает: раз контрольный замер через VPN прошёл, выход оказался
	// в подходящей стране.
	if (o.Status == SvcNeedVPN || o.Status == SvcGeo) && s.ProxyOK && vpnCoversBrowser {
		return SvcOKViaVPN, AdviceVPNKeep
	}
	return o.Status, o.Advice
}

// reasonID — ключ i18n с причиной по одному сервису; пусто — причины нет.
func reasonID(s ServiceVerdict) string {
	switch {
	case s.Challenged:
		return "svc.challenge"
	case s.DirectOK || s.Cause == "":
		return ""
	case s.Cause == analyze.CauseProxyToo:
		return "svc.proxy_fails"
	default:
		return "svc.blocked." + string(s.Cause)
	}
}

// Итог контрольного HTTP-запроса, когда не открылся ни один сайт.
const (
	CaptivePortal = "portal" // ответ подменён — впереди страница входа
	CaptiveOpen   = "open"   // ответ настоящий: наружу ходим, а сайты не открываются
	CaptiveDead   = "dead"   // наружу не уходит ни один пакет
)

type Input struct {
	Env      env.Snapshot
	Layers   []LayerStatus
	Services []ServiceVerdict
	// Captive — одно из Captive* выше либо пусто, если не проверяли.
	Captive string
}

type Verdict struct {
	Lines    []string      `json:"lines"`
	Warnings []string      `json:"warnings"`
	Chain    []LayerStatus `json:"chain"`
	// Services — те же сервисы, что пришли в Input, но с кодами Status/Advice
	// и локализованной причиной: готовая выдача для главного экрана.
	// Успешные здесь тоже есть — список обязан быть полным ответом
	// «что работает, а что нет», а не перечнем жалоб.
	Services []ServiceVerdict `json:"services,omitempty"`
	// VPNCoversBrowser — трафик браузера сейчас идёт через VPN. Фронт
	// показывает по нему строку контекста («VPN применяется к браузеру» /
	// «браузер идёт мимо VPN»); противоположный случай с текстом-предупреждением
	// уже есть в Lines (warn.proxy_bypass) — флаг его не дублирует, а даёт
	// машиночитаемый признак.
	VPNCoversBrowser bool `json:"vpnCoversBrowser"`
}

// proxyIsInnocent — диагноз, который сам объясняет неудачу через VPN,
// и валить её на VPN-сервер после этого нельзя. Геоблок здесь тоже:
// «сайт отказал по стране» уже говорит, что выход VPN оказался
// в неподходящей стране, — дописывать «проблема на стороне VPN-сервера»
// значит спорить с соседней строкой.
func proxyIsInnocent(c analyze.Cause) bool {
	return c == analyze.CauseAntibot || c == analyze.CauseDown ||
		c == analyze.CauseGeoBlock
}

// prettyNames — человеко-имена известных сервисов; остальные — как есть.
var prettyNames = map[string]string{
	"youtube.com":   "YouTube",
	"discord.com":   "Discord",
	"instagram.com": "Instagram",
	"x.com":         "X",
	"facebook.com":  "Facebook",
	"twitter.com":   "Twitter",
}

func pretty(host string) string {
	if p, ok := prettyNames[host]; ok {
		return p
	}
	return host
}

// layerStatus — статус слоя. Отсутствующий слой — StatusSkip, а не StatusOK:
// «данных нет» не должно молча превращаться в «всё хорошо».
func layerStatus(layers []LayerStatus, name string) probe.Status {
	for _, l := range layers {
		if l.Layer == name {
			return l.Status
		}
	}
	return probe.StatusSkip
}

// isAPIPA — адрес из 169.254.0.0/16, который Windows назначает себе сама,
// когда роутер не выдал адрес по DHCP. Железный признак «Wi-Fi подключён,
// а сети нет»: ни один пакет из такой сети никуда не уйдёт.
func isAPIPA(s string) bool {
	ip := net.ParseIP(s)
	return ip != nil && ip.IsLinkLocalUnicast()
}

// viaVPN — трафик действительно идёт через туннель или прокси. Без этой
// проверки вердикт объяснял недоступность рунета «VPN заворачивает трафик»
// человеку, у которого никакого VPN не запущено.
func viaVPN(s env.Snapshot) bool {
	return s.DefaultViaTunnel || len(s.Tunnels) > 0 || s.Tailscale != "" || hasActiveProxy(s)
}

// vpnCoversBrowser — VPN применяется к трафику БРАУЗЕРА прямо сейчас.
// Это не то же, что viaVPN («VPN вообще запущен»): прокси-листенер может
// работать, пока браузер ходит мимо него. Браузер накрыт в двух случаях:
// TUN-режим (дефолтный маршрут в туннеле — в нём весь трафик) или включённый
// системный прокси Windows (WinINET, им пользуются браузеры), за адресом
// которого действительно слушает прокси.
func vpnCoversBrowser(s env.Snapshot) bool {
	if s.DefaultViaTunnel {
		return true
	}
	if !s.SystemProxyOn {
		return false
	}
	// Сверяем порт системного прокси с найденными листенерами: включённый
	// прокси с мёртвым адресом браузер не накрывает, а ломает. Если же ни
	// одного листенера не нащупали (порт не из списка проверяемых), верим
	// самому факту включённого прокси: доказать обратное нечем, а пугать
	// «нужен VPN» человека с работающим браузером — исходная ошибка,
	// которую эта функция и чинит.
	sawListener := false
	for _, p := range s.Proxies {
		if p.Kind != "listener" || !p.Active {
			continue
		}
		sawListener = true
		// ProxyServer из реестра бывает и «127.0.0.1:10808», и со схемой,
		// и в форме «http=127.0.0.1:10809;socks=127.0.0.1:10808» —
		// поэтому ищем «:порт» листенера как подстроку, а не сравниваем целиком.
		if i := strings.LastIndex(p.Addr, ":"); i >= 0 &&
			strings.Contains(s.SystemProxyAddr, p.Addr[i:]) {
			return true
		}
	}
	return !sawListener
}

// Build — вердикт словами: первый сломанный слой, блокировки по механизмам,
// работоспособность через VPN, предупреждения об окружении.
func Build(l i18n.Lang, in Input) Verdict {
	// Считается один раз на прогон: от этого флага зависят и статусы
	// сервисов (ok_via_vpn против need_vpn), и строка контекста на фронте.
	covers := vpnCoversBrowser(in.Env)
	v := Verdict{Chain: in.Layers, VPNCoversBrowser: covers}

	gw := layerStatus(in.Layers, "gateway")
	dns := layerStatus(in.Layers, "dns")
	runet := layerStatus(in.Layers, "runet")
	global := layerStatus(in.Layers, "global")

	if gw == probe.StatusFail {
		switch {
		case isAPIPA(in.Env.IP):
			v.Lines = append(v.Lines, i18n.T(l, "verdict.apipa"))
		case in.Env.Gateway == "":
			v.Lines = append(v.Lines, i18n.T(l, "verdict.no_route"))
		default:
			v.Lines = append(v.Lines, i18n.T(l, "verdict.gateway_down"))
		}
		v.Lines = append(v.Lines, i18n.T(l, "verdict.aborted"))
		v.Warnings = append(v.Warnings, envWarnings(l, in.Env)...)
		return v // дальше диагностировать нечего
	}

	// Сеть кончается сразу за роутером. Разбирается это одним контрольным
	// запросом ещё в прогоне, и от его исхода зависит, что вообще делать
	// человеку: жать «войти» в браузере, звонить провайдеру или чинить DNS.
	dead := in.Captive == CaptiveDead || (runet == probe.StatusFail && global == probe.StatusFail)
	switch {
	case in.Captive == CaptivePortal:
		v.Lines = append(v.Lines, i18n.T(l, "verdict.captive"))
	case in.Captive == CaptiveOpen:
		v.Lines = append(v.Lines, i18n.T(l, "verdict.http_only"))
	case dead:
		v.Lines = append(v.Lines, i18n.T(l, "verdict.no_internet"))
	// Skip рядом с Fail означает «второй зоны не выбрано», а не «всё хорошо»:
	// раньше такая пара проваливалась в default и выдавала «проверять было
	// нечего» человеку, у которого цели выбраны и как раз не открылись.
	case global == probe.StatusFail && runet != probe.StatusFail:
		v.Lines = append(v.Lines, i18n.T(l, "verdict.global_down"))
	case runet == probe.StatusFail && global != probe.StatusFail:
		if viaVPN(in.Env) {
			v.Lines = append(v.Lines, i18n.T(l, "verdict.runet_down_vpn"))
		} else {
			v.Lines = append(v.Lines, i18n.T(l, "verdict.runet_down"))
		}
	case runet == probe.StatusOK || global == probe.StatusOK:
		v.Lines = append(v.Lines, i18n.T(l, "verdict.internet_ok"))
	default:
		// обе зоны непроверены: целей не выбрано
		v.Lines = append(v.Lines, i18n.T(l, "verdict.nothing_checked"))
	}
	// «Роутер режет ICMP, это нормально» уместно, только когда всё остальное
	// работает. Рядом с «интернета нет» это предупреждение говорило ровно
	// противоположное соседней строке.
	if gw == probe.StatusWarn && !dead {
		v.Warnings = append(v.Warnings, i18n.T(l, "warn.gateway_icmp"))
	}
	// Молчащий резолвер — не подмена. Подмена доказывается адресом, которого
	// в интернете быть не может, и только это теперь называется подменой.
	switch {
	case dns == probe.StatusWarn:
		v.Lines = append(v.Lines, i18n.T(l, "dns.spoof"))
	case dns == probe.StatusFail && !dead:
		v.Lines = append(v.Lines, i18n.T(l, "dns.down"))
	}
	// Слой сервисов не запускали: сказать об этом честнее, чем молчать —
	// иначе пустая таблица выглядит как «всё проверили и всё хорошо».
	if layerStatus(in.Layers, "blocked") == probe.StatusSkip && len(in.Services) == 0 && dead {
		v.Lines = append(v.Lines, i18n.T(l, "verdict.services_skipped"))
	}

	// блокируемые сервисы: группировка по причине
	groups := map[analyze.Cause][]string{}
	var proxyFails, challenged []string
	// Сколько из недоступных напрямую открывается через VPN. Раньше здесь
	// стоял один флаг «через VPN доступно всё», и трёх сервисов, которые
	// не открываются нигде, хватало, чтобы промолчать про остальные двадцать.
	// Человек читал список блокировок без единого слова о том, что через
	// его же VPN почти всё это работает.
	var blockedTotal, blockedViaProxy int
	viaProxyAllOK := true
	for _, s := range in.Services {
		// Проверка «я не робот» — единственный исход, о котором честный ответ
		// звучит «не знаю». Сервер ответил, путь до него чист, в браузере сайт
		// откроется, а наш клиент капчу не решает по устройству. Молчать про
		// это нельзя: пользователь увидел бы сервис в рабочих и не понял бы,
		// почему он там, а объявить его сломанным — прямое враньё.
		if s.Challenged {
			challenged = append(challenged, pretty(s.Host))
			continue
		}
		if s.DirectOK {
			continue
		}
		if s.Cause == analyze.CauseProxyToo {
			proxyFails = append(proxyFails, pretty(s.Host))
			continue
		}
		groups[s.Cause] = append(groups[s.Cause], pretty(s.Host))
		blockedTotal++
		if s.ProxyOK {
			blockedViaProxy++
		}
		// механизм блокировки — это про сервис, а «VPN не помог» — про VPN;
		// одно не должно вытеснять другое из вердикта
		if !s.ProxyOK {
			viaProxyAllOK = false
			// Обвинять VPN-сервер можно только по итогу замера через него.
			// Раньше сюда попадали и сервисы, которые через VPN не спрашивали.
			//
			// И только если диагноз сам уже не объяснил, почему через VPN тоже
			// не вышло. Антибот ставится ровно по признаку «через другую страну
			// ответ тот же», а «сервис лежит» — по его собственной пятисотке;
			// добавлять к ним «похоже, проблема на стороне VPN-сервера» значит
			// спорить с собой же двумя строками ниже.
			if s.ProxyTried && !proxyIsInnocent(s.Cause) {
				proxyFails = append(proxyFails, pretty(s.Host))
			}
		}
	}
	// «Не находится ни одним резолвером» про десяток доменов разом — это
	// не диагноз, а самоопровержение: столько доменов одновременно не исчезает.
	// Значит, спрашивать было нечем, и честно сказать именно это.
	if len(groups[analyze.CauseNXDomain])+len(groups[analyze.CauseDNSSilent]) > 2 {
		delete(groups, analyze.CauseNXDomain)
		delete(groups, analyze.CauseDNSSilent)
		v.Lines = append(v.Lines, i18n.T(l, "svc.dns_unreachable"))
	}
	// порядок — от самого конкретного диагноза к самому расплывчатому
	order := []analyze.Cause{analyze.CauseDPI, analyze.CauseIPBlock, analyze.CauseDNSSpoof,
		analyze.CauseMITM, analyze.CauseStub, analyze.CauseGeoBlock, analyze.CauseAntibot,
		analyze.CauseDown, analyze.CauseHTTPDrop, analyze.CauseNXDomain,
		analyze.CauseDNSSilent, analyze.CauseStateful, analyze.CauseUnknown}
	var parts []string
	for _, c := range order {
		if hosts := groups[c]; len(hosts) > 0 {
			parts = append(parts, i18n.T(l, "svc.blocked."+string(c), strings.Join(hosts, ", ")))
		}
	}
	if len(parts) > 0 {
		line := strings.Join(parts, "; ")
		switch {
		case !hasActiveProxy(in.Env) || blockedViaProxy == 0:
			line += "."
		case viaProxyAllOK:
			line += " " + i18n.T(l, "svc.via_proxy_ok")
		default:
			// Часть открывается, часть нет. Голое «не всё» здесь бесполезно:
			// счёт говорит человеку ровно то, что он хочет знать.
			line += " " + i18n.T(l, "svc.via_proxy_some", blockedViaProxy, blockedTotal)
		}
		v.Lines = append(v.Lines, line)
	}
	if len(proxyFails) > 0 {
		v.Lines = append(v.Lines, i18n.T(l, "svc.proxy_fails", strings.Join(proxyFails, ", ")))
	}
	if len(challenged) > 0 {
		v.Lines = append(v.Lines, i18n.T(l, "svc.challenge", strings.Join(challenged, ", ")))
	}

	// Выдача для главного экрана: каждый сервис получает код статуса, код
	// совета и локализованную причину. Порядок — как в Input (порядок
	// справочника); сортировку «сломанные сверху» делает интерфейс.
	for _, s := range in.Services {
		s.Status, s.Advice = ServiceOutcome(s, covers)
		if id := reasonID(s); id != "" {
			s.Reason = i18n.T(l, id, pretty(s.Host))
		}
		v.Services = append(v.Services, s)
	}

	v.Warnings = append(v.Warnings, envWarnings(l, in.Env)...)
	return v
}

// envWarnings — предупреждения об окружении. От результатов сети не зависят,
// поэтому выдаются в том числе на оборванном прогоне.
func envWarnings(l i18n.Lang, s env.Snapshot) []string {
	// В режиме TUN системный прокси и должен быть выключен: трафик уходит
	// в адаптер. Пугать «браузер идёт МИМО VPN» в этом случае — врать.
	if hasListenerProxy(s) && !s.SystemProxyOn && !s.DefaultViaTunnel && len(s.Tunnels) == 0 {
		return []string{i18n.T(l, "warn.proxy_bypass")}
	}
	return nil
}

func hasActiveProxy(s env.Snapshot) bool {
	for _, p := range s.Proxies {
		if p.Active {
			return true
		}
	}
	return false
}

func hasListenerProxy(s env.Snapshot) bool {
	for _, p := range s.Proxies {
		if p.Kind == "listener" && p.Active {
			return true
		}
	}
	return false
}
