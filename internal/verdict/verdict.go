// Package verdict собирает человекочитаемый вердикт из фактов прогона.
// Чистая функция: (язык, факты) → строки; сетью не пользуется.
package verdict

import (
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
	Host     string        `json:"host"`
	DirectOK bool          `json:"directOk"`
	ProxyOK  bool          `json:"proxyOk"`
	Cause    analyze.Cause `json:"cause"`
}

type Input struct {
	Env      env.Snapshot
	Layers   []LayerStatus
	Services []ServiceVerdict
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

func layerStatus(layers []LayerStatus, name string) probe.Status {
	for _, l := range layers {
		if l.Layer == name {
			return l.Status
		}
	}
	return probe.StatusOK
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
		v.Lines = append(v.Lines, i18n.T(l, "verdict.gateway_down"))
		v.Lines = append(v.Lines, i18n.T(l, "verdict.aborted"))
		return v // дальше диагностировать нечего
	}
	if gw == probe.StatusWarn {
		// шлюз не ответил на ping, но наружу мы вышли — ICMP просто режут
		v.Warnings = append(v.Warnings, i18n.T(l, "warn.gateway_icmp"))
	}
	switch {
	case runet == probe.StatusFail && global == probe.StatusFail:
		v.Lines = append(v.Lines, i18n.T(l, "verdict.no_internet"))
	case global == probe.StatusFail:
		v.Lines = append(v.Lines, i18n.T(l, "verdict.global_down"))
	case runet == probe.StatusFail:
		v.Lines = append(v.Lines, i18n.T(l, "verdict.runet_down"))
	default:
		v.Lines = append(v.Lines, i18n.T(l, "verdict.internet_ok"))
	}
	if dns == probe.StatusWarn || dns == probe.StatusFail {
		v.Lines = append(v.Lines, i18n.T(l, "dns.spoof"))
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
			if hasActiveProxy(in.Env) {
				proxyFails = append(proxyFails, pretty(s.Host))
			}
		}
	}
	// порядок — от самого конкретного диагноза к самому расплывчатому
	order := []analyze.Cause{analyze.CauseDPI, analyze.CauseIPBlock, analyze.CauseDNSSpoof,
		analyze.CauseMITM, analyze.CauseStub, analyze.CauseGeoBlock, analyze.CauseAntibot,
		analyze.CauseDown, analyze.CauseHTTPDrop, analyze.CauseNXDomain,
		analyze.CauseStateful, analyze.CauseUnknown}
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

	if hasListenerProxy(in.Env) && !in.Env.SystemProxyOn {
		v.Warnings = append(v.Warnings, i18n.T(l, "warn.proxy_bypass"))
	}
	return v
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
