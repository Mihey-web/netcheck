//go:build windows

package probe

import (
	"context"
	"testing"
	"time"
)

func TestPingLoopback(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	res := Ping(ctx, "127.0.0.1")
	if res.Status != StatusOK {
		t.Fatalf("loopback ping should be ok, got %s (%s)", res.Status, res.Detail)
	}
	if res.Method != "ping" {
		t.Fatalf("method = %q", res.Method)
	}
	if res.Outcome != OutOK {
		t.Errorf("outcome = %q, want %q", res.Outcome, OutOK)
	}
}

// Timeout и unreachable — противоположные факты: молчание значит «пакет
// ушёл и не вернулся», unreachable — «сеть отказалась его нести».
// Коды из ipexport.h приходят и через GetLastError, и в reply.Status.
func TestPingOutcomeMapping(t *testing.T) {
	cases := []struct {
		code uint32
		want Outcome
	}{
		{ipReqTimedOut, OutTimeout},
		{ipDestNetUnreachable, OutUnreach},
		{ipDestHostUnreachable, OutUnreach},
		{ipDestPortUnreachable, OutUnreach},
		{ipDestNoRoute, OutUnreach},
		{12345, OutOther}, // незнакомый код — честное «другое», а не пустота
	}
	for _, c := range cases {
		if got := pingOutcome(c.code); got != c.want {
			t.Errorf("pingOutcome(%d) = %q, want %q", c.code, got, c.want)
		}
	}
}

func TestPingUnreachable(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 800*time.Millisecond)
	defer cancel()
	// 192.0.2.1 — TEST-NET-1, гарантированно не маршрутизируется
	res := Ping(ctx, "192.0.2.1")
	if res.Status != StatusFail {
		t.Fatalf("TEST-NET ping should fail, got %s", res.Status)
	}
	// Каким именно классом кончилось — зависит от сети машины (молчание
	// либо unreachable от роутера), но класс обязан быть проставлен.
	if res.Outcome != OutTimeout && res.Outcome != OutUnreach {
		t.Errorf("outcome = %q, want timeout or unreachable", res.Outcome)
	}
}
