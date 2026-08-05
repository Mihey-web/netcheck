package runner

import (
	"context"
	"net/url"
	"strings"
	"testing"

	"github.com/mihey/netcheck/internal/env"
	"github.com/mihey/netcheck/internal/i18n"
	"github.com/mihey/netcheck/internal/probe"
	"github.com/mihey/netcheck/internal/verdict"
)

// offlineProber — «Wi-Fi подключён, интернета нет»: роутер пингуется,
// дальше не проходит ничего. Ровно тот случай, на котором программа раньше
// сочиняла «домен больше не существует» про два десятка живых сервисов.
type offlineProber struct{ fakeProber }

func (offlineProber) ResolveSystem(ctx context.Context, host string) probe.Result {
	return probe.Result{Target: host, Method: "DNS", Status: probe.StatusFail, Outcome: probe.OutTimeout}
}
func (offlineProber) ResolveUDP(ctx context.Context, host, server string) probe.Result {
	return probe.Result{Target: host, Method: "DNS·UDP", Status: probe.StatusFail, Outcome: probe.OutTimeout}
}
func (offlineProber) ResolveDoH(ctx context.Context, host, doh string) probe.Result {
	return probe.Result{Target: host, Method: "DNS·DoH", Status: probe.StatusFail, Outcome: probe.OutTimeout}
}
func (offlineProber) TCPConnect(ctx context.Context, ipPort string) probe.Result {
	return probe.Result{Target: ipPort, Method: "TCP:443", Status: probe.StatusFail, Outcome: probe.OutTimeout}
}
func (offlineProber) HTTPGet(ctx context.Context, rawURL string, proxy *url.URL, pinIP string) probe.Result {
	return probe.Result{Target: rawURL, Method: "HTTPS", Status: probe.StatusFail, Outcome: probe.OutTimeout}
}

func TestRunStopsWhenNothingLeavesTheRouter(t *testing.T) {
	snap := env.Snapshot{Gateway: "192.168.3.1", IP: "192.168.3.48"}
	rep := Run(context.Background(), testConfig(), i18n.RU, offlineProber{}, snap, nil)

	if !rep.Aborted {
		t.Fatal("наружу не уходит ничего — прогон обязан оборваться")
	}
	if rep.Captive != verdict.CaptiveDead {
		t.Errorf("captive: got %q, want %q", rep.Captive, verdict.CaptiveDead)
	}
	if len(rep.Services) != 0 {
		t.Errorf("сервисы нечем проверять, got %d", len(rep.Services))
	}
	for _, l := range rep.Layers {
		if l.Layer == "blocked" && l.Status != probe.StatusSkip {
			t.Errorf("слой blocked: got %s, want skip", l.Status)
		}
	}

	all := strings.Join(rep.Verdict.Lines, " ")
	for _, lie := range []string{"домен больше не существует", "подменя"} {
		if strings.Contains(all, lie) {
			t.Errorf("вердикт врёт про %q: %s", lie, all)
		}
	}
	if !strings.Contains(all, "Интернета нет") {
		t.Errorf("вердикт обязан сказать главное: %s", all)
	}
}

// portalProber — публичный Wi-Fi с окном входа: имена резолвятся (портал
// отвечает на всё), TCP проходит, но сайты не открываются, а контрольный
// HTTP-запрос возвращает чужую страницу вместо ожидаемого ответа.
type portalProber struct{ fakeProber }

func (portalProber) HTTPGet(ctx context.Context, rawURL string, proxy *url.URL, pinIP string) probe.Result {
	if strings.HasPrefix(rawURL, "http://") {
		return probe.Result{Target: rawURL, Method: "HTTP", Status: probe.StatusOK,
			Outcome: probe.OutOK, Code: 200, Body: "<html>Wi-Fi login required</html>"}
	}
	return probe.Result{Target: rawURL, Method: "HTTPS", Status: probe.StatusFail, Outcome: probe.OutReset}
}

func TestRunNamesCaptivePortalInsteadOfBlamingISP(t *testing.T) {
	snap := env.Snapshot{Gateway: "10.0.0.1", IP: "10.0.0.55"}
	rep := Run(context.Background(), testConfig(), i18n.RU, portalProber{}, snap, nil)

	if rep.Captive != verdict.CaptivePortal {
		t.Fatalf("captive: got %q, want %q", rep.Captive, verdict.CaptivePortal)
	}
	if len(rep.Services) != 0 {
		t.Errorf("слой сервисов должен быть пропущен, got %d", len(rep.Services))
	}
	all := strings.Join(rep.Verdict.Lines, " ")
	if !strings.Contains(all, "авторизуйтесь") {
		t.Errorf("вердикт обязан назвать действие пользователя: %s", all)
	}
	if strings.Contains(all, "провайдер") {
		t.Errorf("провайдер тут ни при чём: %s", all)
	}
}

func TestRunStreamsEveryResultAsItArrives(t *testing.T) {
	snap := env.Snapshot{Gateway: "192.168.0.1"}
	var streamed int
	var layers []string
	rep := Run(context.Background(), testConfig(), i18n.RU, fakeProber{}, snap, func(p Progress) {
		if p.Result != nil {
			streamed++
			if p.Layer == "" {
				t.Error("у живого результата обязан быть слой")
			}
			layers = append(layers, p.Layer)
		}
	})

	if streamed != len(rep.Results) {
		t.Errorf("на экран ушло %d результатов из %d", streamed, len(rep.Results))
	}
	if len(layers) == 0 || layers[0] != "gateway" {
		t.Errorf("первым обязан прийти шлюз, got %v", layers)
	}
}

// Пустой список целей — не «зона в порядке». Раньше снятые галочки давали
// зелёную цепочку и «Интернет работает» без единой сетевой проверки.
func TestRunReportsNothingCheckedOnEmptySelection(t *testing.T) {
	cfg := testConfig()
	cfg.Targets.Runet = nil
	cfg.Targets.Global = nil
	cfg.Targets.Blocked = nil
	cfg.Targets.GeoBlocked = nil

	rep := Run(context.Background(), cfg, i18n.RU, fakeProber{}, env.Snapshot{Gateway: "192.168.0.1"}, nil)

	all := strings.Join(rep.Verdict.Lines, " ")
	if strings.Contains(all, "Интернет работает") {
		t.Errorf("ничего не проверяли — так и надо сказать: %s", all)
	}
	if !strings.Contains(all, "Проверять было нечего") {
		t.Errorf("вердикт: %s", all)
	}
}
