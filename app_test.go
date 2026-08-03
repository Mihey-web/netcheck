package main

import "testing"

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
