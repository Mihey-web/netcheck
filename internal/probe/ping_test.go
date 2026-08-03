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
}

func TestPingUnreachable(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 800*time.Millisecond)
	defer cancel()
	// 192.0.2.1 — TEST-NET-1, гарантированно не маршрутизируется
	res := Ping(ctx, "192.0.2.1")
	if res.Status != StatusFail {
		t.Fatalf("TEST-NET ping should fail, got %s", res.Status)
	}
}
