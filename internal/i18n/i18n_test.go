package i18n

import (
	"regexp"
	"strings"
	"testing"
)

// verbRe — format-verbs вида %s/%d/%v; %% — не verb.
var verbRe = regexp.MustCompile(`%[a-zA-Z]`)

func verbs(s string) []string {
	return verbRe.FindAllString(strings.ReplaceAll(s, "%%", ""), -1)
}

// TestMessagesComplete — полнота словаря: у каждого ключа есть непустые RU и EN,
// а format-verbs совпадают по числу и порядку. Конкретные тексты не проверяются:
// формулировки — не контракт, контракт — ключи и подстановки.
func TestMessagesComplete(t *testing.T) {
	for id, m := range messages {
		ru, okRU := m[RU]
		en, okEN := m[EN]
		if !okRU || ru == "" {
			t.Errorf("%s: нет русского текста", id)
		}
		if !okEN || en == "" {
			t.Errorf("%s: нет английского текста", id)
		}
		if !okRU || !okEN {
			continue
		}
		vr, ve := verbs(ru), verbs(en)
		if strings.Join(vr, ",") != strings.Join(ve, ",") {
			t.Errorf("%s: format-verbs расходятся: ru=%v en=%v", id, vr, ve)
		}
	}
}

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
