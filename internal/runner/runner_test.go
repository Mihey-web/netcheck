package runner

import (
	"context"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/mihey/netcheck/internal/analyze"
	"github.com/mihey/netcheck/internal/config"
	"github.com/mihey/netcheck/internal/env"
	"github.com/mihey/netcheck/internal/i18n"
	"github.com/mihey/netcheck/internal/probe"
	"github.com/mihey/netcheck/internal/verdict"
)

// fakeProber воспроизводит сценарий мокапа: рунет и заграница живы,
// youtube режется DPI (TLS с реальным SNI падает), x.com мёртв и через прокси.
type fakeProber struct{}

func (fakeProber) Ping(ctx context.Context, ip string) probe.Result {
	return probe.Result{Target: ip, Method: "ping", Status: probe.StatusOK}
}

func (fakeProber) ResolveSystem(ctx context.Context, host string) probe.Result {
	return probe.Result{Target: host, Method: "DNS", Status: probe.StatusOK, IPs: []string{"1.2.3.4"}}
}

func (fakeProber) ResolveUDP(ctx context.Context, host, server string) probe.Result {
	return probe.Result{Target: host, Method: "DNS·UDP", Status: probe.StatusOK, IPs: []string{"1.2.3.4"}}
}

func (fakeProber) ResolveDoH(ctx context.Context, host, doh string) probe.Result {
	return probe.Result{Target: host, Method: "DNS·DoH", Status: probe.StatusOK, IPs: []string{"1.2.3.4"}}
}

func (fakeProber) TCPConnect(ctx context.Context, ipPort string) probe.Result {
	return probe.Result{Target: ipPort, Method: "TCP:443", Status: probe.StatusOK, Outcome: probe.OutOK}
}

func (fakeProber) TLSHandshake(ctx context.Context, ipPort, sni string) probe.Result {
	// DPI: настоящее имя молчит до конца бюджета, нейтральное отвечает сразу
	if sni == "youtube.com" || sni == "x.com" {
		return probe.Result{Target: sni, Method: "TLS-SNI", SNI: sni,
			Status: probe.StatusFail, Outcome: probe.OutTimeout, Latency: 3 * time.Second}
	}
	return probe.Result{Target: sni, Method: "TLS-SNI", SNI: sni,
		Status: probe.StatusOK, Outcome: probe.OutOK, Latency: 100 * time.Millisecond,
		Cert: &probe.CertInfo{ChainValid: true, NameMatch: true}}
}

func (fakeProber) HTTPGet(ctx context.Context, rawURL string, proxy *url.URL, pinIP string) probe.Result {
	r := probe.Result{Target: rawURL, Method: "HTTPS", Status: probe.StatusOK,
		Outcome: probe.OutOK, Code: 200, Path: probe.PathDirect}
	if proxy != nil {
		r.Path = probe.PathProxy
		// через прокси всё живо, кроме x.com
		if strings.Contains(rawURL, "x.com") {
			r.Status = probe.StatusFail
		}
		return r
	}
	if strings.Contains(rawURL, "youtube.com") || strings.Contains(rawURL, "x.com") {
		r.Status = probe.StatusFail
	}
	return r
}

func testConfig() config.Config {
	c := config.Default()
	c.Targets.Runet = []string{"ya.ru"}
	c.Targets.Global = []string{"wikipedia.org"}
	c.Targets.Blocked = []string{"youtube.com", "x.com"}
	return c
}

// deadProber — сеть мертва целиком: ни ping, ни TCP наружу.
// Trace отдаёт короткий правдоподобный маршрут: домашний роутер, роутер
// провайдера, цель. Этого хватает, чтобы прогон построил луч и проверил
// сборку карты, не выходя в сеть.
func (fakeProber) Trace(ctx context.Context, ip string) ([]probe.Hop, error) {
	return []probe.Hop{
		{N: 1, IP: "192.168.1.1", RTTms: 1, Status: probe.HopOK},
		{N: 2, IP: "198.51.100.1", RTTms: 5, Status: probe.HopOK},
		{N: 3, IP: ip, RTTms: 32, Status: probe.HopFinal},
	}, nil
}

type deadProber struct{ fakeProber }

func (deadProber) Ping(ctx context.Context, ip string) probe.Result {
	return probe.Result{Target: ip, Method: "ping", Status: probe.StatusFail}
}
func (deadProber) TCPConnect(ctx context.Context, ipPort string) probe.Result {
	return probe.Result{Target: ipPort, Method: "TCP:443", Status: probe.StatusFail}
}

// icmpFilteredProber — роутер не отвечает на ping, но наружу связь есть.
type icmpFilteredProber struct{ fakeProber }

func (icmpFilteredProber) Ping(ctx context.Context, ip string) probe.Result {
	return probe.Result{Target: ip, Method: "ping", Status: probe.StatusFail}
}

func TestRunAbortsWhenGatewayUnreachable(t *testing.T) {
	snap := env.Snapshot{Gateway: "192.168.0.1"}
	var seen []string
	rep := Run(context.Background(), testConfig(), i18n.RU, deadProber{}, snap, func(p Progress) {
		if p.Done {
			seen = append(seen, p.Layer)
		}
	})

	if !rep.Aborted {
		t.Fatal("прогон обязан оборваться на мёртвом шлюзе")
	}
	if rep.Layers[0].Status != probe.StatusFail {
		t.Errorf("gateway: got %s, want fail", rep.Layers[0].Status)
	}
	for _, l := range rep.Layers[1:] {
		if l.Status != probe.StatusSkip {
			t.Errorf("слой %s: got %s, want skip", l.Layer, l.Status)
		}
	}
	if len(rep.Services) != 0 {
		t.Errorf("сервисы не должны проверяться после обрыва, got %d", len(rep.Services))
	}
	// цепочка в UI не должна «терять» слои: прогресс приходит по всем
	if len(seen) != 5 {
		t.Errorf("progress по всем слоям, got %v", seen)
	}
}

func TestRunContinuesWhenGatewayOnlyFiltersICMP(t *testing.T) {
	snap := env.Snapshot{Gateway: "192.168.0.1"}
	rep := Run(context.Background(), testConfig(), i18n.RU, icmpFilteredProber{}, snap, nil)

	if rep.Aborted {
		t.Fatal("связь наружу есть — обрывать прогон нельзя")
	}
	if rep.Layers[0].Status != probe.StatusWarn {
		t.Errorf("gateway: got %s, want warn", rep.Layers[0].Status)
	}
	if len(rep.Services) == 0 {
		t.Error("сервисы обязаны проверяться дальше")
	}
}

func TestRunLayersAndProgress(t *testing.T) {
	snap := env.Snapshot{
		Gateway: "192.168.0.1",
		Proxies: []env.ProxyHint{{Kind: "listener", Proto: "socks5", Addr: "127.0.0.1:10808", Active: true}},
	}
	var seen []string
	rep := Run(context.Background(), testConfig(), i18n.RU, fakeProber{}, snap, func(p Progress) {
		if p.Done {
			seen = append(seen, p.Layer)
		}
	})

	wantOrder := []string{"gateway", "dns", "runet", "global", "blocked"}
	if len(rep.Layers) != len(wantOrder) {
		t.Fatalf("want %d layers, got %d", len(wantOrder), len(rep.Layers))
	}
	for i, w := range wantOrder {
		if rep.Layers[i].Layer != w {
			t.Errorf("layer %d: got %s, want %s", i, rep.Layers[i].Layer, w)
		}
	}
	if len(seen) != len(wantOrder) {
		t.Errorf("progress must fire once per layer, got %v", seen)
	}
	if rep.Duration <= 0 {
		t.Error("duration must be positive")
	}
	if len(rep.Results) == 0 {
		t.Error("results must not be empty")
	}

	byHost := map[string]analyze.Cause{}
	for _, s := range rep.Services {
		byHost[s.Host] = s.Cause
	}
	if byHost["youtube.com"] != analyze.CauseDPI {
		t.Errorf("youtube: got %s, want dpi_sni", byHost["youtube.com"])
	}
	// x.com режется так же, как youtube, и вдобавок не работает через прокси.
	// Диагноз — механизм блокировки: это про сервис. Что VPN не помог —
	// отдельный факт, он живёт в ProxyOK и попадает в вердикт своей строкой.
	if byHost["x.com"] != analyze.CauseDPI {
		t.Errorf("x.com: got %s, want dpi_sni", byHost["x.com"])
	}
	for _, s := range rep.Services {
		if s.Host == "x.com" && s.ProxyOK {
			t.Error("x.com не работает через прокси — это должно быть видно")
		}
	}
	if len(rep.Verdict.Lines) == 0 {
		t.Error("verdict lines must not be empty")
	}
}

// cancelingProber жмёт «Отменить» посреди слоя DNS: ровно так выглядят
// кнопка отмены и закрытие окна во время прогона.
type cancelingProber struct {
	fakeProber
	cancel context.CancelFunc
}

func (p cancelingProber) ResolveSystem(ctx context.Context, host string) probe.Result {
	p.cancel()
	return p.fakeProber.ResolveSystem(ctx, host)
}

func TestRunCanceledMidRun(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	rep := Run(ctx, testConfig(), i18n.RU, cancelingProber{cancel: cancel},
		env.Snapshot{Gateway: "192.168.0.1"}, nil)

	if !rep.Canceled {
		t.Fatal("отменённый прогон обязан быть помечен Canceled")
	}
	// слои после отмены — непроверенные, а не выдуманно-мёртвые
	for _, l := range rep.Layers {
		if l.Layer == "runet" || l.Layer == "global" || l.Layer == "blocked" {
			if l.Status != probe.StatusSkip {
				t.Errorf("слой %s: got %s, want skip", l.Layer, l.Status)
			}
		}
	}
	if len(rep.Services) != 0 {
		t.Errorf("после отмены сервисы не проверяются, got %d", len(rep.Services))
	}
	all := strings.Join(rep.Verdict.Lines, " ")
	if !strings.Contains(all, "прервана") {
		t.Errorf("вердикт обязан сказать, что прогон прерван: %q", all)
	}
	// главное: отмена не должна превращаться в диагноз о сети
	for _, lie := range []string{"Интернета нет", "недоступ", "заблокирован"} {
		if strings.Contains(all, lie) {
			t.Errorf("отмена выдана за диагноз (%q): %s", lie, all)
		}
	}
}

// captiveKind разбирает ответ контрольного HTTP-запроса; здесь — границы:
// каждая ошибка в них превращается в совет «авторизуйтесь в Wi-Fi» там,
// где авторизовываться негде.
func TestCaptiveKind(t *testing.T) {
	cases := []struct {
		name string
		r    probe.Result
		want string
	}{
		{"никто не ответил", probe.Result{Code: 0}, ""},
		{"настоящий ответ адресата", probe.Result{Code: 200, Body: captiveBody}, captiveOpen},
		{"200 с чужим телом — подмена", probe.Result{Code: 200, Body: "<html>login</html>"}, captivePortal},
		{"ошибка адресата — не портал", probe.Result{Code: 404}, ""},
		{"штатный редирект внутри сайта", probe.Result{Code: 302, Location: "www.msftconnecttest.com"}, captiveOpen},
		{"редирект на чужой хост — портал", probe.Result{Code: 302, Location: "portal.example.com"}, captivePortal},
	}
	for _, tc := range cases {
		if got := captiveKind(tc.r); got != tc.want {
			t.Errorf("%s: got %q, want %q", tc.name, got, tc.want)
		}
	}
}

// redirectProber — сервис отвечает штатным редиректом на другой домен,
// как claude.ai отвечает 302 на www.anthropic.com.
type redirectProber struct{ fakeProber }

func (redirectProber) HTTPGet(ctx context.Context, rawURL string, proxy *url.URL, pinIP string) probe.Result {
	r := probe.Result{Target: rawURL, Method: "HTTPS", Status: probe.StatusOK,
		Outcome: probe.OutOK, Code: 302, Location: "www.anthropic.com", Path: probe.PathDirect}
	if proxy != nil {
		// Через VPN тот же сервис отдаёт 403: выходной адрес в чёрном списке.
		// Это про VPN, а не про сервис, и вердикт не должен их путать.
		r = probe.Result{Target: rawURL, Method: "HTTPS", Status: probe.StatusFail,
			Outcome: probe.OutOK, Code: 403, Path: probe.PathProxy}
	}
	return r
}

// Редирект на чужой домен с проверенного сертификата — ответ настоящего
// сервера, а не заглушка провайдера: заглушке для этого нужен доверенный
// сертификат на чужое имя. Прежнее правило объявляло claude.ai сломанным,
// и пользователь читал «claude.ai не работает», разговаривая через него же.
func TestCrossDomainRedirectIsNotABlock(t *testing.T) {
	cfg := testConfig()
	cfg.Targets.Blocked = []string{"claude.ai"}
	cfg.Map.Enabled = false

	snap := env.Snapshot{Gateway: "192.168.0.1"}
	rep := Run(context.Background(), cfg, i18n.RU, redirectProber{}, snap, nil)

	var got *verdictService
	for i := range rep.Services {
		if rep.Services[i].Host == "claude.ai" {
			got = &verdictService{rep.Services[i].DirectOK, rep.Services[i].Cause}
		}
	}
	if got == nil {
		t.Fatal("claude.ai пропал из отчёта")
	}
	if !got.directOK {
		t.Errorf("штатный редирект на чужой домен принят за блокировку, cause=%q", got.cause)
	}
	if got.cause != "" {
		t.Errorf("работающему сервису приписана причина блокировки: %q", got.cause)
	}
	for _, line := range rep.Verdict.Lines {
		if strings.Contains(line, "claude.ai") {
			t.Errorf("работающий сервис попал в вердикт: %q", line)
		}
	}
}

type verdictService struct {
	directOK bool
	cause    analyze.Cause
}

// challengeProber — сервис отдаёт капчу Cloudflare, как claude.ai через VPN:
// 403 с заголовком Cf-Mitigated: challenge и страницей «Just a moment...».
type challengeProber struct{ fakeProber }

func (challengeProber) HTTPGet(ctx context.Context, rawURL string, proxy *url.URL, pinIP string) probe.Result {
	r := probe.Result{Target: rawURL, Method: "HTTPS", Status: probe.StatusWarn,
		Outcome: probe.OutOK, Code: 403, CFMitigated: "challenge",
		Body: "<title>Just a moment...</title>", Challenge: true, Path: probe.PathDirect}
	if proxy != nil {
		r.Path = probe.PathProxy
	}
	return r
}

// Капча — не блокировка: сервер ответил, путь до него чист, в браузере сайт
// откроется. Записывать его в недоступные значило объявлять сломанным сервис,
// через который пользователь в эту минуту работает.
func TestChallengeIsNotABlock(t *testing.T) {
	cfg := testConfig()
	cfg.Targets.Blocked = []string{"claude.ai"}
	cfg.Map.Enabled = false

	rep := Run(context.Background(), cfg, i18n.RU, challengeProber{},
		env.Snapshot{Gateway: "192.168.0.1"}, nil)

	var sv *verdict.ServiceVerdict
	for i := range rep.Services {
		if rep.Services[i].Host == "claude.ai" {
			sv = &rep.Services[i]
		}
	}
	if sv == nil {
		t.Fatal("claude.ai пропал из отчёта")
	}
	if !sv.Challenged {
		t.Error("капча не распознана")
	}
	if !sv.DirectOK {
		t.Errorf("сервис с капчей записан в недоступные, cause=%q", sv.Cause)
	}
	all := strings.Join(rep.Verdict.Lines, "\n")
	if !strings.Contains(all, "я не робот") {
		t.Errorf("про капчу не сказано ни слова:\n%s", all)
	}
	for _, bad := range []string{"блокирует", "режет", "не пускает", "даже через VPN"} {
		if strings.Contains(all, bad) {
			t.Errorf("капча подана как блокировка (%q):\n%s", bad, all)
		}
	}
}
