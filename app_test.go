package main

import (
	"context"
	"net/url"
	"testing"

	"github.com/mihey/netcheck/internal/probe"
	"github.com/mihey/netcheck/internal/runner"
)

func TestAppConfigRoundTrip(t *testing.T) {
	t.Setenv("APPDATA", t.TempDir())

	a := NewApp()
	c := a.GetConfig()
	if len(c.Targets.Blocked) == 0 {
		t.Fatal("default config must have blocked targets")
	}

	c.Lang = "en"
	if err := a.SaveConfig(c); err != nil {
		t.Fatal(err)
	}
	if a.GetConfig().Lang != "en" {
		t.Fatal("lang not persisted through SaveConfig")
	}
	if a.CurrentLang() != "en" {
		t.Fatalf("CurrentLang = %q, want en", a.CurrentLang())
	}

	if err := a.SetLang("ru"); err != nil {
		t.Fatal(err)
	}
	if a.CurrentLang() != "ru" {
		t.Fatalf("SetLang failed: CurrentLang = %q", a.CurrentLang())
	}
}

func TestGetHistoryEmpty(t *testing.T) {
	t.Setenv("APPDATA", t.TempDir())
	if got := NewApp().GetHistory(); len(got) != 0 {
		t.Fatalf("fresh install must have empty history, got %d", len(got))
	}
}

// Второй RunCheck поверх идущего раньше молча возвращал пустой Report,
// и во фронте это выглядело как «проверка мгновенно закончилась ничем».
func TestRunCheckBusyEmitsEvent(t *testing.T) {
	t.Setenv("APPDATA", t.TempDir())
	a := NewApp()
	var events []string
	a.emit = func(name string, data ...interface{}) { events = append(events, name) }

	a.busy.Store(true) // «прогон уже идёт»
	rep := a.RunCheck()

	if !rep.StartedAt.IsZero() {
		t.Error("занятый RunCheck не должен изображать настоящий отчёт")
	}
	if len(events) != 1 || events[0] != "run-busy" {
		t.Errorf("ожидалось единственное событие run-busy, got %v", events)
	}
	// отмена без прогона — безопасный no-op
	a.CancelCheck()
}

// okProber — все пробы удаются мгновенно: RunSingle гоняется без сети.
type okProber struct{}

func (okProber) Ping(ctx context.Context, ip string) probe.Result {
	return probe.Result{Target: ip, Method: "ping", Status: probe.StatusOK}
}
func (okProber) ResolveSystem(ctx context.Context, host string) probe.Result {
	return probe.Result{Target: host, Method: "DNS", Status: probe.StatusOK, IPs: []string{"1.2.3.4"}}
}
func (okProber) ResolveUDP(ctx context.Context, host, server string) probe.Result {
	return probe.Result{Target: host, Method: "DNS·UDP", Status: probe.StatusOK, IPs: []string{"1.2.3.4"}}
}
func (okProber) ResolveDoH(ctx context.Context, host, doh string) probe.Result {
	return probe.Result{Target: host, Method: "DNS·DoH", Status: probe.StatusOK, IPs: []string{"1.2.3.4"}}
}
func (okProber) TCPConnect(ctx context.Context, ipPort string) probe.Result {
	return probe.Result{Target: ipPort, Method: "TCP:443", Status: probe.StatusOK, Outcome: probe.OutOK}
}
func (okProber) TLSHandshake(ctx context.Context, ipPort, sni string) probe.Result {
	return probe.Result{Target: sni, Method: "TLS-SNI", SNI: sni, Status: probe.StatusOK,
		Outcome: probe.OutOK, Cert: &probe.CertInfo{ChainValid: true, NameMatch: true}}
}
func (okProber) HTTPGet(ctx context.Context, rawURL string, proxy *url.URL, pinIP string) probe.Result {
	return probe.Result{Target: rawURL, Method: "HTTPS", Status: probe.StatusOK,
		Outcome: probe.OutOK, Code: 200}
}
func (okProber) Trace(ctx context.Context, ip string) ([]probe.Hop, error) {
	return nil, nil
}

// RunSingle: ровно одна цель, история не пополняется, итог уходит событием
// single-done, а не done (точечный ответ не подменяет главный отчёт).
func TestRunSingle(t *testing.T) {
	t.Setenv("APPDATA", t.TempDir())
	a := NewApp()
	a.prober = okProber{}
	var events []string
	a.emit = func(name string, data ...interface{}) { events = append(events, name) }

	rep, err := a.RunSingle("Example.COM")
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Services) != 1 || rep.Services[0].Host != "example.com" {
		t.Fatalf("ждали одну цель example.com, got %+v", rep.Services)
	}
	if len(rep.Verdict.Services) != 1 || rep.Verdict.Services[0].Status != "ok" {
		t.Errorf("в выдаче вердикта должна быть цель со status ok, got %+v", rep.Verdict.Services)
	}
	if got := a.GetHistory(); len(got) != 0 {
		t.Errorf("точечный прогон не должен писаться в историю, got %d записей", len(got))
	}
	sawSingle := false
	for _, e := range events {
		if e == "single-done" {
			sawSingle = true
		}
		if e == "done" {
			t.Error("точечный прогон не должен слать done — он подменил бы главный отчёт")
		}
	}
	if !sawSingle {
		t.Errorf("нет события single-done: %v", events)
	}
	if a.busy.Load() {
		t.Error("busy обязан сброситься после прогона")
	}
}

// RunSingle делит busy с RunCheck: второй прогон параллельно не стартует.
func TestRunSingleBusy(t *testing.T) {
	t.Setenv("APPDATA", t.TempDir())
	a := NewApp()
	var events []string
	a.emit = func(name string, data ...interface{}) { events = append(events, name) }

	a.busy.Store(true) // «прогон уже идёт»
	rep, err := a.RunSingle("example.com")
	if err != nil {
		t.Fatal(err)
	}
	if !rep.StartedAt.IsZero() || len(rep.Services) != 0 {
		t.Error("занятый RunSingle не должен изображать настоящий отчёт")
	}
	if len(events) != 1 || events[0] != "run-busy" {
		t.Errorf("ожидалось единственное событие run-busy, got %v", events)
	}
}

// Мусор на входе RunSingle — ошибка до всякой сети и без захвата busy.
func TestRunSingleRejectsBadHost(t *testing.T) {
	a := NewApp()
	for _, bad := range []string{"", "бортжурнал.рф", "a b", "-x.com", "x-.com"} {
		if _, err := a.RunSingle(bad); err == nil {
			t.Errorf("хост %q обязан быть отвергнут", bad)
		}
	}
	if a.busy.Load() {
		t.Error("отвергнутый хост не должен оставлять busy взведённым")
	}
}

// normalizeHost чистит то же, что фронт: схему, путь, регистр, хвостовую точку.
func TestNormalizeHost(t *testing.T) {
	cases := []struct{ in, want string }{
		{"example.com", "example.com"},
		{"HTTPS://Example.com/path?q=1", "example.com"},
		{"example.com.", "example.com"},
		{" sub.ex-ample.org ", "sub.ex-ample.org"},
	}
	for _, c := range cases {
		got, err := normalizeHost(c.in)
		if err != nil || got != c.want {
			t.Errorf("normalizeHost(%q) = (%q, %v), want %q", c.in, got, err, c.want)
		}
	}
}

// Пороги §4 табличным тестом, включая границы и усиление через VPN.
func TestSpeedStatusTable(t *testing.T) {
	cases := []struct {
		name                string
		service, ref, proxy float64
		want                string
	}{
		{"душат: сильно ниже эталона и медленно само по себе", 0.4, 100, 0, "slow"},
		{"четверть эталона, но абсолютно быстро — не slow", 10, 100, 0, "maybe_slow"},
		{"треть эталона", 30, 100, 0, "maybe_slow"},
		{"выше половины эталона", 60, 100, 0, "normal"},
		{"граница 0.25: ровно четверть — уже не slow", 1, 4, 0, "maybe_slow"},
		{"граница 2 Мбит/с: ровно 2 — уже не slow", 2, 100, 0, "maybe_slow"},
		{"чуть ниже обеих границ — slow", 1.9, 100, 0, "slow"},
		{"VPN в 4 раза быстрее усиливает maybe_slow до slow", 30, 100, 120, "slow"},
		{"VPN быстрее, но меньше чем в 4 раза — остаётся maybe_slow", 30, 100, 100, "maybe_slow"},
		{"normal не портится быстрым VPN", 60, 100, 300, "normal"},
		{"нулевой эталон — ошибка, сравнивать не с чем", 10, 0, 0, "error"},
		// Ноль при живом эталоне — не сбой замера, а его итог: с серверов
		// сервиса не идёт ничего, хотя канал качает. Это самое сильное
		// удушение, и прятать его за «не удалось замерить» нельзя.
		{"с сервиса не идёт ничего при живом канале — удушение", 0, 100, 0, "slow"},
		{"то же, и через VPN файл качается — удушение подтверждено", 0, 100, 80, "slow"},
	}
	for _, c := range cases {
		if got := speedStatus(c.service, c.ref, c.proxy); got != c.want {
			t.Errorf("%s: speedStatus(%v, %v, %v) = %q, want %q",
				c.name, c.service, c.ref, c.proxy, got, c.want)
		}
	}
}

// Замер не стартует параллельно с прогоном и не пробует мерить сервисы,
// у которых нет URL для замера.
func TestMeasureSpeedGuards(t *testing.T) {
	t.Setenv("APPDATA", t.TempDir())
	a := NewApp()
	var events []string
	a.emit = func(name string, data ...interface{}) { events = append(events, name) }

	if res := a.MeasureSpeed("no-such-service"); res.Status != "error" || res.Err == "" {
		t.Errorf("неизвестный сервис обязан дать error, got %+v", res)
	}
	if res := a.MeasureSpeed("ya"); res.Status != "error" {
		t.Errorf("сервис без SpeedURL обязан дать error, got %+v", res)
	}

	a.busy.Store(true) // «прогон уже идёт»
	res := a.MeasureSpeed("youtube")
	if res.Status != "error" {
		t.Errorf("занятый замер обязан дать error, got %+v", res)
	}
	found := false
	for _, e := range events {
		if e == "run-busy" {
			found = true
		}
	}
	if !found {
		t.Errorf("занятый замер обязан сказать run-busy, got %v", events)
	}
}

// Отменённый прогон не должен попадать в историю: его замеры — таймауты
// умершего контекста, а не факты о сети.
func TestShouldRecordSkipsCanceled(t *testing.T) {
	ctx := context.Background()
	if !shouldRecord(ctx, runner.Report{}) {
		t.Error("обычный прогон обязан писаться в историю")
	}
	if shouldRecord(ctx, runner.Report{Canceled: true}) {
		t.Error("прогон с пометкой Canceled не должен писаться в историю")
	}
	cctx, cancel := context.WithCancel(ctx)
	cancel()
	if shouldRecord(cctx, runner.Report{}) {
		t.Error("отменённый контекст — тоже отмена, в историю нельзя")
	}
}
