//go:build live

// Живой прогон по реальной сети: go test -tags live -run TestLiveRun -v .
// Обычные прогоны тестов его не трогают — здесь настоящие запросы наружу.
package main

import (
	"strconv"
	"strings"
	"testing"
)

var itoa = strconv.Itoa

func TestLiveRun(t *testing.T) {
	rep := NewApp().RunCheck()

	t.Logf("прогон занял %s", rep.Duration)
	for _, l := range rep.Layers {
		t.Logf("слой %-8s %s", l.Layer, l.Status)
	}
	for _, s := range rep.Services {
		t.Logf("сервис %-16s напрямую=%v прокси=%v причина=%s", s.Host, s.DirectOK, s.ProxyOK, s.Cause)
	}
	t.Log("── карта: докуда доходит трафик ──")
	for _, r := range rep.Routes {
		end := "никто не ответил"
		if r.Break != nil {
			end = r.Break.IP
			if r.Break.Org != "" {
				end += " · AS" + itoa(int(r.Break.ASN)) + " " + r.Break.Org
			}
			if r.Break.Country != "" {
				end += " · " + r.Break.Country
			}
		}
		t.Logf("  %-20s шагов=%2d дошли=%-5v конец: %s", r.Host, len(r.Nodes), r.Reached, end)
		if r.Note != "" {
			t.Logf("       %s", r.Note)
		}
	}

	t.Log("── вердикт ──")
	for _, line := range rep.Verdict.Lines {
		t.Log("  " + line)
	}
	for _, w := range rep.Verdict.Warnings {
		t.Log("  ⚠ " + w)
	}

	if len(rep.Layers) == 0 {
		t.Fatal("прогон не дал ни одного слоя")
	}
	// Тест запускается с живого интернета: «интернета нет» означало бы,
	// что диагностика снова врёт.
	if strings.Contains(strings.Join(rep.Verdict.Lines, " "), "Интернета нет") {
		t.Errorf("вердикт утверждает, что интернета нет, хотя прогон идёт с живой сети")
	}
}
