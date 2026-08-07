package main

import (
	"context"
	"testing"

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
