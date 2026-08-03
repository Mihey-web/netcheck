package history

import (
	"fmt"
	"testing"
	"time"

	"github.com/mihey/netcheck/internal/analyze"
	"github.com/mihey/netcheck/internal/i18n"
	"github.com/mihey/netcheck/internal/probe"
	"github.com/mihey/netcheck/internal/runner"
	"github.com/mihey/netcheck/internal/verdict"
)

func TestAppendTrimAndOrder(t *testing.T) {
	t.Setenv("APPDATA", t.TempDir())

	base := time.Date(2026, 8, 1, 21, 0, 0, 0, time.UTC)
	for i := 0; i < 5; i++ {
		e := Entry{
			At:      base.Add(time.Duration(i) * time.Minute),
			Status:  probe.StatusOK,
			Summary: fmt.Sprintf("run %d", i),
		}
		if err := Append(Record{Entry: e}, 3); err != nil {
			t.Fatal(err)
		}
	}
	got, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Fatalf("want 3 kept, got %d", len(got))
	}
	if got[0].Summary != "run 4" {
		t.Fatalf("newest must come first, got %q", got[0].Summary)
	}
	if got[2].Summary != "run 2" {
		t.Fatalf("oldest kept must be run 2, got %q", got[2].Summary)
	}
}

func TestLoadEmpty(t *testing.T) {
	t.Setenv("APPDATA", t.TempDir())
	got, err := Load()
	if err != nil {
		t.Fatalf("missing file must not error: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("want empty, got %d", len(got))
	}
}

// Прогон должен переживать перезапуск целиком: строка списка + полный отчёт,
// который можно открыть и перечитать на другом языке.
func TestReportSurvivesRestart(t *testing.T) {
	t.Setenv("APPDATA", t.TempDir())

	at := time.Date(2026, 8, 2, 1, 26, 0, 0, time.UTC)
	rep := runner.Report{
		StartedAt: at,
		Duration:  13 * time.Second,
		Layers: []verdict.LayerStatus{
			{Layer: "gateway", Status: probe.StatusOK},
			{Layer: "blocked", Status: probe.StatusFail},
		},
		Services: []verdict.ServiceVerdict{
			{Host: "youtube.com", DirectOK: false, ProxyOK: true, Cause: analyze.CauseDPI},
		},
		Results: []probe.Result{{Target: "youtube.com", Method: "TLS-SNI", Status: probe.StatusFail}},
		Verdict: verdict.Verdict{Lines: []string{"…"}},
	}
	e := Summarize(rep, i18n.RU)
	e.At = at
	if err := Append(Record{Entry: e, Report: &rep}, 10); err != nil {
		t.Fatal(err)
	}

	got := ReportAt(at.Format(time.RFC3339Nano))
	if got == nil {
		t.Fatal("отчёт не сохранился — после перезапуска смотреть будет нечего")
	}
	if len(got.Results) != 1 || got.Results[0].Target != "youtube.com" {
		t.Fatalf("детали прогона потеряны: %+v", got.Results)
	}
	if len(got.Services) != 1 || got.Services[0].Cause != analyze.CauseDPI {
		t.Fatalf("диагноз потерян: %+v", got.Services)
	}

	// тот же прогон, прочитанный по-английски
	en, err := LoadLocalized(i18n.EN)
	if err != nil {
		t.Fatal(err)
	}
	ru, err := LoadLocalized(i18n.RU)
	if err != nil {
		t.Fatal(err)
	}
	if len(en) != 1 || len(ru) != 1 {
		t.Fatalf("want 1 entry each, got en=%d ru=%d", len(en), len(ru))
	}
	if en[0].Summary == ru[0].Summary {
		t.Errorf("итог не переводится: обе версии %q", en[0].Summary)
	}
}

func TestReportAtMissing(t *testing.T) {
	t.Setenv("APPDATA", t.TempDir())
	if ReportAt("2026-08-02T01:26:00Z") != nil {
		t.Fatal("несуществующий прогон должен давать nil")
	}
	if ReportAt("не время") != nil {
		t.Fatal("кривое время должно давать nil, а не панику")
	}
}

func TestSummarize(t *testing.T) {
	rep := runner.Report{
		Duration: 12400 * time.Millisecond,
		Layers: []verdict.LayerStatus{
			{Layer: "gateway", Status: probe.StatusOK},
			{Layer: "dns", Status: probe.StatusWarn},
			{Layer: "blocked", Status: probe.StatusFail},
		},
		Services: []verdict.ServiceVerdict{
			{Host: "youtube.com", DirectOK: false, ProxyOK: true, Cause: analyze.CauseDPI},
			{Host: "vk.com", DirectOK: true},
		},
		Verdict: verdict.Verdict{Lines: []string{"Интернет работает."}},
	}
	e := Summarize(rep, i18n.RU)
	if e.Status != probe.StatusFail {
		t.Fatalf("worst layer status must win: got %s", e.Status)
	}
	if e.Summary == "" {
		t.Fatal("summary must not be empty")
	}
	if e.Duration != rep.Duration {
		t.Fatalf("duration mismatch: %v vs %v", e.Duration, rep.Duration)
	}
}
