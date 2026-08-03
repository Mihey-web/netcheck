package i18n

import (
	"strings"
	"testing"
)

func TestTBothLanguages(t *testing.T) {
	ru := T(RU, "warn.proxy_bypass")
	en := T(EN, "warn.proxy_bypass")
	if ru == "" || en == "" || ru == en {
		t.Fatalf("both languages must exist and differ: ru=%q en=%q", ru, en)
	}
}

func TestTArgs(t *testing.T) {
	got := T(RU, "svc.blocked.dpi_sni", "YouTube")
	if !strings.Contains(got, "YouTube") {
		t.Fatalf("args not substituted: %q", got)
	}
}

func TestTMissingID(t *testing.T) {
	if got := T(RU, "no.such.id"); got != "no.such.id" {
		t.Fatalf("missing id must return the id itself, got %q", got)
	}
}

func TestResolve(t *testing.T) {
	if Resolve("ru") != RU || Resolve("en") != EN {
		t.Fatal("explicit lang must win")
	}
	if l := Resolve("auto"); l != RU && l != EN {
		t.Fatalf("auto must resolve to ru or en, got %q", l)
	}
}
