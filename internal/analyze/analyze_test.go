package analyze

import (
	"testing"
	"time"

	"github.com/mihey/netcheck/internal/probe"
)

var (
	tcpOK   = []probe.Result{{Status: probe.StatusOK, Outcome: probe.OutOK}}
	tcpDead = []probe.Result{{Status: probe.StatusFail, Outcome: probe.OutTimeout}}
	tlsOK   = probe.Result{Status: probe.StatusOK, Outcome: probe.OutOK,
		Cert: &probe.CertInfo{ChainValid: true, NameMatch: true}}
	// молчит до конца бюджета — так выглядит вмешательство по пути
	tlsSilent = probe.Result{Status: probe.StatusFail, Outcome: probe.OutTimeout,
		Latency: 3 * time.Second}
	httpOK = probe.Result{Status: probe.StatusOK, Outcome: probe.OutOK, Code: 200}
)

// fast — нейтральное имя, на которое сервер ответил быстро (неважно чем).
func fast(o probe.Outcome) []probe.Result {
	st := probe.StatusFail
	if o == probe.OutOK {
		st = probe.StatusOK
	}
	return []probe.Result{{Outcome: o, Latency: 120 * time.Millisecond, Status: st}}
}

func TestDiagnose(t *testing.T) {
	cases := []struct {
		name string
		ev   Evidence
		want Cause
	}{
		{
			// единственная доказанная подмена: провайдер увёл имя в свою сеть
			name: "dns spoof — приватный адрес от системного резолвера",
			ev: Evidence{Host: "youtube.com", SysIPs: []string{"10.0.0.1"},
				DoHIPs: []string{"142.250.1.1"}, TCP: tcpOK, TLSReal: tlsOK, HTTP: httpOK},
			want: CauseDNSSpoof,
		},
		{
			// ГЛАВНЫЙ РЕГРЕСС: раньше это давало dns_spoof и прятало DPI.
			// Разные адреса одной сети Google — обычный GeoDNS.
			name: "geodns не подмена — диагноз ставит DPI",
			ev: Evidence{Host: "youtube.com",
				SysIPs: []string{"209.85.233.190"}, DoHIPs: []string{"216.58.207.110"},
				TCP: tcpOK, TLSReal: tlsSilent, TLSNeutral: fast(probe.OutOK)},
			want: CauseDPI,
		},
		{
			name: "ip block — не отвечает ни один адрес",
			ev: Evidence{Host: "instagram.com", SysIPs: []string{"31.13.72.174"},
				DoHIPs: []string{"31.13.72.174"}, TCP: tcpDead},
			want: CauseIPBlock,
		},
		{
			// CloudFront и Google LB отвергают чужое имя сами, но БЫСТРО —
			// это ответ сервера, значит рвут нас на настоящем имени
			name: "dpi при быстром tls-alert на нейтральном имени",
			ev: Evidence{Host: "soundcloud.com", SysIPs: []string{"52.84.150.52"},
				TCP: tcpOK, TLSReal: tlsSilent, TLSNeutral: fast(probe.OutTLSAlert)},
			want: CauseDPI,
		},
		{
			name: "dpi при быстром eof на нейтральном имени",
			ev: Evidence{Host: "linkedin.com", SysIPs: []string{"130.211.32.14"},
				TCP: tcpOK, TLSReal: tlsSilent, TLSNeutral: fast(probe.OutEOF)},
			want: CauseDPI,
		},
		{
			name: "молчит на любое имя — это уже не про имя",
			ev: Evidence{Host: "x.example", SysIPs: []string{"1.2.3.4"},
				TCP: tcpOK, TLSReal: tlsSilent,
				TLSNeutral: []probe.Result{{Outcome: probe.OutTimeout, Latency: 3 * time.Second}}},
			want: CauseStateful,
		},
		{
			name: "451 — геоблок без всяких контрольных замеров",
			ev: Evidence{Host: "figma.com", SysIPs: []string{"1.2.3.4"},
				TCP: tcpOK, TLSReal: tlsOK,
				HTTP: probe.Result{Status: probe.StatusFail, Code: 451,
					Body: "Figma is not available in your location"}},
			want: CauseGeoBlock,
		},
		{
			name: "403 с подписью cloudflare — антибот, а не блокировка",
			ev: Evidence{Host: "stackoverflow.com", SysIPs: []string{"1.2.3.4"},
				TCP: tcpOK, TLSReal: tlsOK,
				HTTP: probe.Result{Status: probe.StatusFail, Code: 403, CFMitigated: "challenge"}},
			want: CauseAntibot,
		},
		{
			name: "403 прямо и 200 через VPN — геоблок",
			ev: Evidence{Host: "gemini.google.com", SysIPs: []string{"1.2.3.4"},
				TCP: tcpOK, TLSReal: tlsOK,
				HTTP:    probe.Result{Status: probe.StatusFail, Code: 403},
				Control: &probe.Result{Status: probe.StatusOK, Code: 200}},
			want: CauseGeoBlock,
		},
		{
			name: "403 одинаково и там и там — антибот",
			ev: Evidence{Host: "chatgpt.com", SysIPs: []string{"1.2.3.4"},
				TCP: tcpOK, TLSReal: tlsOK,
				HTTP:    probe.Result{Status: probe.StatusFail, Code: 403},
				Control: &probe.Result{Status: probe.StatusFail, Code: 403}},
			want: CauseAntibot,
		},
		{
			// dzen.ru → sso.passport.yandex.ru: живой сайт, а не заглушка
			name: "штатный редирект на чужой домен не заглушка",
			ev: Evidence{Host: "dzen.ru", SysIPs: []string{"1.2.3.4"},
				TCP: tcpOK, TLSReal: tlsOK,
				HTTP:    probe.Result{Status: probe.StatusOK, Code: 302, Location: "sso.passport.yandex.ru"},
				Control: &probe.Result{Status: probe.StatusOK, Code: 302, Location: "sso.passport.yandex.ru"}},
			want: CauseUnknown,
		},
		{
			name: "5xx — сервис лежит сам",
			ev: Evidence{Host: "example.com", SysIPs: []string{"1.2.3.4"},
				TCP: tcpOK, TLSReal: tlsOK,
				HTTP: probe.Result{Status: probe.StatusFail, Code: 503}},
			want: CauseDown,
		},
		{
			// сертификат предъявлен, но цепочка не строится до системного корня
			name: "подмена сертификата",
			ev: Evidence{Host: "example.com", SysIPs: []string{"1.2.3.4"}, TCP: tcpOK,
				TLSReal: probe.Result{Status: probe.StatusOK, Outcome: probe.OutOK,
					Cert: &probe.CertInfo{Subject: "block.isp.ru", Issuer: "ISP CA", ChainValid: false}}},
			want: CauseMITM,
		},
		{
			// kaspi.kz: рукопожатие проходит с валидным сертификатом,
			// а ответа на запрос нет
			name: "tls живой, http молчит",
			ev: Evidence{Host: "kaspi.kz", SysIPs: []string{"1.2.3.4"},
				TCP: tcpOK, TLSReal: tlsOK,
				HTTP:    probe.Result{Status: probe.StatusFail, Outcome: probe.OutTimeout},
				Control: &probe.Result{Status: probe.StatusOK, Code: 200}},
			want: CauseHTTPDrop,
		},
		{
			name: "резолверы ответили, что имени нет",
			ev: Evidence{Host: "nope.invalid",
				SysOutcome: probe.OutNXDomain, DoHOutcome: probe.OutNXDomain},
			want: CauseNXDomain,
		},
		{
			// Молчание резолвера — не доказательство, что домена нет.
			// Ровно на этом месте программа хоронила два десятка живых
			// сервисов, стоило пропасть интернету.
			name: "резолверы промолчали",
			ev: Evidence{Host: "youtube.com",
				SysOutcome: probe.OutTimeout, DoHOutcome: probe.OutTimeout},
			want: CauseDNSSilent,
		},
	}
	for _, c := range cases {
		if got := Diagnose(c.ev); got != c.want {
			t.Errorf("%s: got %s, want %s", c.name, got, c.want)
		}
	}
}

// Расхождение резолверов — пометка, а не приговор.
func TestGeoDNSIsNotSpoof(t *testing.T) {
	sys := []string{"209.85.233.190"}
	doh := []string{"216.58.207.110"}
	if !GeoDNS(sys, doh) {
		t.Error("расхождение ответов должно помечаться как geodns")
	}
	if hasPrivate(sys) || hasPrivate(doh) {
		t.Error("публичные адреса подменой не считаются")
	}
}
