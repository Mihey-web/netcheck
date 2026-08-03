package probe

import (
	"context"
	"net"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// mockDNS поднимает локальный UDP-DNS, отвечающий A-записью answerIP на любой запрос.
func mockDNS(t *testing.T, answerIP [4]byte) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close() })
	go func() {
		buf := make([]byte, 1500)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			var req dnsmessage.Message
			if err := req.Unpack(buf[:n]); err != nil || len(req.Questions) == 0 {
				continue
			}
			q := req.Questions[0]
			resp := dnsmessage.Message{
				Header:    dnsmessage.Header{ID: req.Header.ID, Response: true, RecursionAvailable: true},
				Questions: []dnsmessage.Question{q},
				Answers: []dnsmessage.Resource{{
					Header: dnsmessage.ResourceHeader{Name: q.Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 60},
					Body:   &dnsmessage.AResource{A: answerIP},
				}},
			}
			out, err := resp.Pack()
			if err != nil {
				continue
			}
			pc.WriteTo(out, addr)
		}
	}()
	return pc.LocalAddr().String()
}

func TestResolveUDPAgainstMock(t *testing.T) {
	srv := mockDNS(t, [4]byte{93, 184, 216, 34})
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	res := ResolveUDP(ctx, "example.com", srv)
	if res.Status != StatusOK {
		t.Fatalf("want ok, got %s (%s)", res.Status, res.Detail)
	}
	if len(res.IPs) != 1 || res.IPs[0] != "93.184.216.34" {
		t.Fatalf("unexpected IPs: %v", res.IPs)
	}
	if res.Method != "DNS·UDP" {
		t.Fatalf("method = %q", res.Method)
	}
}

func TestResolveUDPTimeout(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	// 192.0.2.1 — TEST-NET, никто не ответит
	res := ResolveUDP(ctx, "example.com", "192.0.2.1:53")
	if res.Status != StatusFail {
		t.Fatalf("want fail, got %s", res.Status)
	}
}
