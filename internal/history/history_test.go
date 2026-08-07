package history

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
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

// Delete убирает ровно запрошенную запись и не трогает соседние;
// незнакомое или кривое время — не ошибка (удалять удалённое — нормально).
func TestDeleteRemovesOnlyRequested(t *testing.T) {
	t.Setenv("APPDATA", t.TempDir())

	base := time.Date(2026, 8, 5, 12, 0, 0, 0, time.UTC)
	for i := 0; i < 3; i++ {
		e := Entry{
			At:      base.Add(time.Duration(i) * time.Minute),
			Status:  probe.StatusOK,
			Summary: fmt.Sprintf("run %d", i),
		}
		if err := Append(Record{Entry: e}, 0); err != nil {
			t.Fatal(err)
		}
	}

	victim := base.Add(1 * time.Minute)
	if err := Delete([]string{victim.Format(time.RFC3339Nano)}); err != nil {
		t.Fatal(err)
	}
	got, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("после удаления одной записи должно остаться 2, got %d", len(got))
	}
	for _, e := range got {
		if e.Summary == "run 1" {
			t.Errorf("удалённая запись осталась в истории: %+v", got)
		}
	}

	// незнакомое время и мусор молча игнорируются, остальное не трогается
	if err := Delete([]string{"2030-01-01T00:00:00Z", "не время"}); err != nil {
		t.Fatalf("удаление несуществующего не должно быть ошибкой: %v", err)
	}
	got, err = Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("удаление несуществующего съело записи: осталось %d", len(got))
	}
}

// Clear на отсутствующем файле — не ошибка: стирать пустую историю
// пользователю никто не запрещал. А на существующем — стирает целиком.
func TestClearMissingAndExisting(t *testing.T) {
	t.Setenv("APPDATA", t.TempDir())

	if err := Clear(); err != nil {
		t.Fatalf("Clear без файла не должен падать: %v", err)
	}

	e := Entry{At: time.Date(2026, 8, 5, 12, 0, 0, 0, time.UTC), Status: probe.StatusOK, Summary: "run"}
	if err := Append(Record{Entry: e}, 0); err != nil {
		t.Fatal(err)
	}
	if err := Clear(); err != nil {
		t.Fatal(err)
	}
	got, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("после Clear история должна быть пуста, got %d", len(got))
	}
}

// Повреждённая строка в runs.jsonl (обрыв записи, ручная правка) не должна
// ронять всю историю: битое пропускается, целое читается.
func TestLoadSkipsCorruptLine(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("APPDATA", dir)

	ncDir := filepath.Join(dir, "netcheck")
	if err := os.MkdirAll(ncDir, 0o755); err != nil {
		t.Fatal(err)
	}
	rec := func(min int, sum string) string {
		raw, err := json.Marshal(Record{Entry: Entry{
			At:      time.Date(2026, 8, 5, 12, min, 0, 0, time.UTC),
			Status:  probe.StatusOK,
			Summary: sum,
		}})
		if err != nil {
			t.Fatal(err)
		}
		return string(raw)
	}
	content := rec(0, "первый") + "\n" +
		"{битый json, оборванная запись\n" +
		rec(1, "второй") + "\n"
	if err := os.WriteFile(filepath.Join(ncDir, "runs.jsonl"), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	got, err := Load()
	if err != nil {
		t.Fatalf("битая строка не должна ронять чтение: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("want 2 целых записи, got %d", len(got))
	}
	if got[0].Summary != "второй" || got[1].Summary != "первый" {
		t.Errorf("целые записи потерялись или перепутались: %+v", got)
	}
}
