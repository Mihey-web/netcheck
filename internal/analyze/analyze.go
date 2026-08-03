// Package analyze — разбор причины недоступности цели.
// Чистая логика без сети: на вход собранные улики, на выход диагноз.
//
// Главное правило пакета: диагноз ставится по КЛАССУ отказа, а не по факту
// «не получилось». Молчание до конца бюджета означает вмешательство по пути,
// быстрый RST или TLS-alert — что ответил сам сервер. Без этого различия
// DPI неотличим от честного отказа.
package analyze

import (
	"net"
	"strings"

	"github.com/mihey/netcheck/internal/probe"
)

type Cause string

const (
	CauseDNSSpoof Cause = "dns_spoof"    // системный DNS вернул подставной адрес
	CauseNXDomain Cause = "dns_nxdomain" // имя не резолвится нигде
	CauseIPBlock  Cause = "ip_block"     // TCP не проходит ни к одному адресу
	CauseDPI      Cause = "dpi_sni"      // TCP ок, рвётся именно на имени в ClientHello
	CauseStateful Cause = "ip_block_stateful"
	CauseMITM     Cause = "tls_mitm"     // предъявлен сертификат от неизвестного CA
	CauseStub     Cause = "isp_stub"     // редирект на заглушку провайдера
	CauseGeoBlock Cause = "geo_block"    // сервер ответил и отказал по стране
	CauseAntibot  Cause = "antibot"      // защита от роботов, а не блокировка
	CauseDown     Cause = "service_down" // 5xx: сервис лежит сам
	CauseHTTPDrop Cause = "http_drop"    // TLS живой, а HTTP-ответа нет
	CauseProxyToo Cause = "proxy_fails_too"
	CauseUnknown  Cause = "unknown"
)

// Confidence — насколько диагнозу можно верить. Показывается пользователю:
// «похоже на» и «доказано» — разные вещи.
type Confidence string

const (
	ConfHigh   Confidence = "high"
	ConfMedium Confidence = "medium"
	ConfLow    Confidence = "low"
)

// fastEnough — порог «сервер ответил сам». CloudFront отвергает чужой SNI
// за 162 мс, Google Cloud LB закрывает соединение за 111 мс, а вмешательство
// по пути выражается в молчании на секунды.
const fastEnough = 1000 // мс

// Evidence — улики по одной цели.
type Evidence struct {
	Host           string
	SysIPs, DoHIPs []string       // A-записи: системный резолвер vs DoH
	TCP            []probe.Result // TCP:443 по каждому пробованному адресу
	TLSReal        probe.Result   // TLS с настоящим SNI
	TLSNeutral     []probe.Result // лестница нейтральных имён к тому же адресу
	HTTP           probe.Result   // HTTP без следования редиректам
	// Control — тот же HTTP-запрос через прокси. nil, если прокси нет.
	Control    *probe.Result
	ProxyTried bool
	ProxyOK    bool
}

// Verdict — диагноз с уверенностью.
type Verdict struct {
	Cause      Cause
	Confidence Confidence
}

// Diagnose — первый сработавший признак даёт диагноз.
func Diagnose(ev Evidence) Cause { return Explain(ev).Cause }

// Explain — то же самое, но с оценкой уверенности. Порядок правил идёт
// от доказанного к предположительному.
func Explain(ev Evidence) Verdict {
	// ── 1. DNS ───────────────────────────────────────────────────
	if hasPrivate(ev.SysIPs) {
		return Verdict{CauseDNSSpoof, ConfHigh}
	}
	if len(ev.SysIPs) == 0 && len(ev.DoHIPs) == 0 {
		return Verdict{CauseNXDomain, ConfHigh}
	}

	// ── 2. IP ────────────────────────────────────────────────────
	if len(ev.TCP) > 0 && !anyOK(ev.TCP) {
		return Verdict{CauseIPBlock, ConfHigh}
	}

	// ── 3. DPI по имени ──────────────────────────────────────────
	// Одно и то же соединение: с настоящим именем молчит, с нейтральным
	// отвечает. Ответом считается любой быстрый исход — сервер имеет полное
	// право отвергнуть чужое имя, важно что он вообще ответил.
	if ev.TLSReal.Status == probe.StatusFail && interfered(ev.TLSReal) {
		if serverAnswered(ev.TLSNeutral) {
			return Verdict{CauseDPI, ConfHigh}
		}
		if len(ev.TLSNeutral) > 0 {
			return Verdict{CauseStateful, ConfLow}
		}
	}

	// ── 4. подмена сертификата ───────────────────────────────────
	if c := ev.TLSReal.Cert; c != nil && !c.ChainValid {
		return Verdict{CauseMITM, ConfHigh}
	}

	// ── 5–8. что сказал сам сервер ───────────────────────────────
	switch {
	case ev.HTTP.Code == 451:
		return Verdict{CauseGeoBlock, ConfHigh}
	case isAntibot(ev.HTTP):
		return Verdict{CauseAntibot, ConfHigh}
	case ev.HTTP.Code >= 500:
		return Verdict{CauseDown, ConfHigh}
	}

	// ── 9. TLS живой, HTTP молчит ────────────────────────────────
	if ev.TLSReal.Status == probe.StatusOK && ev.HTTP.Outcome == probe.OutTimeout {
		if ev.Control != nil && ev.Control.Status == probe.StatusOK {
			return Verdict{CauseHTTPDrop, ConfMedium}
		}
		return Verdict{CauseHTTPDrop, ConfLow}
	}

	// ── 7/11. 403 разбирается только контрольным замером ─────────
	// Тот же 403 через другую страну — это антибот; другой ответ — геоблок.
	if ev.HTTP.Code == 403 || ev.HTTP.Code == 429 {
		if ev.Control != nil {
			if ev.Control.Code == ev.HTTP.Code {
				return Verdict{CauseAntibot, ConfMedium}
			}
			return Verdict{CauseGeoBlock, ConfHigh}
		}
		return Verdict{CauseUnknown, ConfLow}
	}

	// ── 10. заглушка провайдера ──────────────────────────────────
	// Редирект на чужой домен сам по себе нормален (SSO, единый вход, смена
	// бренда: dzen.ru→sso.passport.yandex.ru, mail.ru→login.vk.ru,
	// twitter.com→x.com). Заглушка — когда через контрольный выход того же
	// редиректа нет.
	if ev.HTTP.Location != "" && !probe.SameSite(ev.Host, ev.HTTP.Location) {
		if ev.Control != nil && ev.Control.Location != ev.HTTP.Location {
			return Verdict{CauseGeoBlock, ConfMedium}
		}
		if ev.Control == nil {
			return Verdict{CauseStub, ConfLow}
		}
	}

	// ── 12. не работает и через прокси ───────────────────────────
	if ev.ProxyTried && !ev.ProxyOK && ev.HTTP.Status != probe.StatusOK {
		return Verdict{CauseProxyToo, ConfMedium}
	}
	return Verdict{CauseUnknown, ConfLow}
}

// interfered — отказ выглядит как вмешательство по пути, а не как ответ
// сервера: молчание до конца бюджета либо оборванное соединение.
func interfered(r probe.Result) bool {
	return r.Outcome == probe.OutTimeout || r.Outcome == probe.OutReset
}

// serverAnswered — хоть одно нейтральное имя получило быстрый ответ.
// TLS-alert и EOF считаются ответом: сервер жив, просто не знает это имя.
func serverAnswered(rs []probe.Result) bool {
	for _, r := range rs {
		if r.Latency.Milliseconds() > fastEnough {
			continue
		}
		switch r.Outcome {
		case probe.OutOK, probe.OutTLSAlert, probe.OutEOF, probe.OutRefused:
			return true
		}
	}
	return false
}

// isAntibot — 403/429 с подписью защиты от роботов. Через VPN такой ответ
// не меняется, и лечится он не сменой страны, а браузером.
func isAntibot(r probe.Result) bool {
	if r.Code != 403 && r.Code != 429 {
		return false
	}
	if r.CFMitigated != "" {
		return true
	}
	b := strings.ToLower(r.Body)
	return strings.Contains(b, "just a moment") ||
		strings.Contains(b, "cf-challenge") ||
		strings.Contains(b, "captcha")
}

func anyOK(rs []probe.Result) bool {
	for _, r := range rs {
		if r.Status == probe.StatusOK {
			return true
		}
	}
	return false
}

// hasPrivate — системный резолвер вернул адрес из приватного диапазона.
// Это единственная доказанная подмена DNS. Расхождение системного ответа
// с DoH подменой НЕ является: у любого CDN это обычный GeoDNS, и раньше
// именно оно записывало YouTube в «подмену DNS» вместо DPI.
func hasPrivate(ips []string) bool {
	for _, s := range ips {
		if ip := net.ParseIP(s); ip != nil &&
			(ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsUnspecified()) {
			return true
		}
	}
	return false
}

// PrivateAnswer — вернул ли резолвер адрес, которого в интернете быть не может.
// Единственный признак подмены, которому можно верить.
func PrivateAnswer(ips []string) bool { return hasPrivate(ips) }

// GeoDNS — расходятся ли ответы резолверов. Диагностическая пометка,
// не причина.
func GeoDNS(sys, doh []string) bool {
	if len(sys) == 0 || len(doh) == 0 {
		return false
	}
	return !probe.SameIPSet(sys, doh)
}
