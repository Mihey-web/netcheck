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
	ProxyTried bool          `json:"proxyTried,omitempty"`
	Cause      analyze.Cause `json:"cause"`
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

// Build — вердикт словами: первый сломанный слой, блокировки по механизмам,
// работоспособность через VPN, предупреждения об окружении.
func Build(l i18n.Lang, in Input) Verdict {
	v := Verdict{Chain: in.Layers}

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
	var proxyFails []string
	viaProxyAllOK := true
	for _, s := range in.Services {
		if s.DirectOK {
			continue
		}
		if s.Cause == analyze.CauseProxyToo {
			proxyFails = append(proxyFails, pretty(s.Host))
			continue
		}
		groups[s.Cause] = append(groups[s.Cause], pretty(s.Host))
		// механизм блокировки — это про сервис, а «VPN не помог» — про VPN;
		// одно не должно вытеснять другое из вердикта
		if !s.ProxyOK {
			viaProxyAllOK = false
			// Обвинять VPN-сервер можно только по итогу замера через него.
			// Раньше сюда попадали и сервисы, которые через VPN не спрашивали.
			if s.ProxyTried {
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
		if viaProxyAllOK && hasActiveProxy(in.Env) {
			line += " " + i18n.T(l, "svc.via_proxy_ok")
		} else {
			line += "."
		}
		v.Lines = append(v.Lines, line)
	}
	if len(proxyFails) > 0 {
		v.Lines = append(v.Lines, i18n.T(l, "svc.proxy_fails", strings.Join(proxyFails, ", ")))
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
