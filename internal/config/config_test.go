package config

import (
	"os"
	"path/filepath"
	"testing"
)

// Старый конфиг хранил цели списками хостов. Обновление программы не должно
// молча стирать выбор пользователя — ни знакомые хосты, ни свои собственные.
func TestMigrateLegacyTargets(t *testing.T) {
	t.Setenv("APPDATA", t.TempDir())
	d, err := Dir()
	if err != nil {
		t.Fatal(err)
	}
	legacy := "lang: ru\n" +
		"targets:\n" +
		"  runet: [ya.ru]\n" +
		"  global: [github.com]\n" +
		"  blocked: [youtube.com, mysite.example]\n" +
		"  geoblocked: [netflix.com]\n"
	if err := os.WriteFile(filepath.Join(d, "config.yaml"), []byte(legacy), 0o644); err != nil {
		t.Fatal(err)
	}

	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"ya", "github", "youtube", "netflix"}
	if len(c.Services.Enabled) != len(want) {
		t.Fatalf("enabled = %v, want %v", c.Services.Enabled, want)
	}
	for i, id := range want {
		if c.Services.Enabled[i] != id {
			t.Errorf("enabled[%d] = %q, want %q", i, c.Services.Enabled[i], id)
		}
	}
	if len(c.Services.Custom) != 1 || c.Services.Custom[0].Host != "mysite.example" {
		t.Fatalf("свою цель потеряли: %v", c.Services.Custom)
	}
	if len(c.Targets.Blocked) != 2 {
		t.Errorf("blocked = %v, want youtube.com + mysite.example", c.Targets.Blocked)
	}
}

// Пустой выбор — это выбор: после сохранения он не должен подменяться дефолтом.
func TestEmptySelectionSurvivesReload(t *testing.T) {
	t.Setenv("APPDATA", t.TempDir())
	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	c.Services.Enabled = []string{}
	if err := c.Save(); err != nil {
		t.Fatal(err)
	}
	again, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(again.Services.Enabled) != 0 {
		t.Fatalf("выбор не сохранился: %v", again.Services.Enabled)
	}
	if len(again.Targets.Blocked) != 0 {
		t.Fatalf("цели должны быть пусты: %v", again.Targets.Blocked)
	}
}

func TestDefaultRoundTrip(t *testing.T) {
	t.Setenv("APPDATA", t.TempDir())

	got, err := Load() // файла нет → создаст дефолт
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Targets.Blocked) == 0 {
		t.Fatal("blocked targets empty")
	}
	if got.Timeouts.ProbeMs != 3000 {
		t.Fatalf("probe_ms = %d, want 3000", got.Timeouts.ProbeMs)
	}
	if got.HistoryKeep != 100 {
		t.Fatalf("history_keep = %d, want 100", got.HistoryKeep)
	}

	dir, err := Dir()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "config.yaml")); err != nil {
		t.Fatalf("config.yaml not created: %v", err)
	}

	got.Lang = "en"
	if err := got.Save(); err != nil {
		t.Fatal(err)
	}
	again, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if again.Lang != "en" {
		t.Fatalf("lang not persisted: %q", again.Lang)
	}
}
