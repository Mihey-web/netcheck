package probe

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
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
	// Молчание резолвера обязано классифицироваться: пустой Outcome
	// не даёт analyze отличить «сети нет» от «имени нет».
	if res.Outcome != OutTimeout {
		t.Errorf("outcome = %q, want %q", res.Outcome, OutTimeout)
	}
}

// Сетевая ошибка DoH тоже обязана получить класс: «DoH задушен» ставится
// именно по нему, а с пустым Outcome ветка не срабатывала никогда.
func TestResolveDoHNetworkErrorClassified(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 700*time.Millisecond)
	defer cancel()
	// порт 1 на loopback закрыт — быстрый отказ, а не молчание
	res := ResolveDoH(ctx, "example.com", "http://127.0.0.1:1/dns-query")
	if res.Status != StatusFail {
		t.Fatalf("want fail, got %s (%s)", res.Status, res.Detail)
	}
	if res.Outcome == "" || res.Outcome == OutOK {
		t.Errorf("outcome = %q, want classified failure", res.Outcome)
	}
}

// aRec — A-запись для сборки тестовых DNS-ответов.
func aRec(name dnsmessage.Name, ip [4]byte) dnsmessage.Resource {
	return dnsmessage.Resource{
		Header: dnsmessage.ResourceHeader{Name: name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 60},
		Body:   &dnsmessage.AResource{A: ip},
	}
}

func mustName(t *testing.T, s string) dnsmessage.Name {
	t.Helper()
	n, err := dnsmessage.NewName(s)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

// Классическая инжекция: подделка от имени резолвера приходит РАНЬШЕ
// настоящего ответа, но с чужим Transaction ID. Кто выходит по первому
// пакету — тот подделку и записывает как честный ответ; ResolveUDP обязан
// её отбросить и дождаться настоящего.
func TestResolveUDPDropsForgedReply(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close() })
	go func() {
		buf := make([]byte, 1500)
		n, addr, err := pc.ReadFrom(buf)
		if err != nil {
			return
		}
		var req dnsmessage.Message
		if err := req.Unpack(buf[:n]); err != nil || len(req.Questions) == 0 {
			return
		}
		q := req.Questions[0]
		// Сначала — подделка: тот же вопрос, чужой идентификатор.
		forged := dnsmessage.Message{
			Header:    dnsmessage.Header{ID: req.Header.ID + 1, Response: true, RecursionAvailable: true},
			Questions: []dnsmessage.Question{q},
			Answers:   []dnsmessage.Resource{aRec(q.Name, [4]byte{6, 6, 6, 6})},
		}
		if out, err := forged.Pack(); err == nil {
			pc.WriteTo(out, addr)
		}
		// Потом — настоящий ответ.
		real := dnsmessage.Message{
			Header:    dnsmessage.Header{ID: req.Header.ID, Response: true, RecursionAvailable: true},
			Questions: []dnsmessage.Question{q},
			Answers:   []dnsmessage.Resource{aRec(q.Name, [4]byte{93, 184, 216, 34})},
		}
		if out, err := real.Pack(); err == nil {
			pc.WriteTo(out, addr)
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	res := ResolveUDP(ctx, "example.com", pc.LocalAddr().String())
	if res.Status != StatusOK {
		t.Fatalf("want ok, got %s (%s)", res.Status, res.Detail)
	}
	if len(res.IPs) != 1 || res.IPs[0] != "93.184.216.34" {
		t.Fatalf("IPs = %v, want настоящий ответ без подделки", res.IPs)
	}
	for _, ip := range res.IPs {
		if ip == "6.6.6.6" {
			t.Fatalf("подделанный адрес записан как честный ответ: %v", res.IPs)
		}
	}
}

// parseAnswers — граница доверия ко всему DNS-слою: принимать можно только
// свой ответ и только адреса запрошенного имени (плюс его CNAME-цепочку).
func TestParseAnswers(t *testing.T) {
	q := dnsmessage.Question{
		Name:  mustName(t, "example.com."),
		Type:  dnsmessage.TypeA,
		Class: dnsmessage.ClassINET,
	}
	const id = uint16(0x1234)
	hdr := dnsmessage.Header{ID: id, Response: true}

	cases := []struct {
		name        string
		msg         dnsmessage.Message
		wantIPs     []string
		wantForeign bool
	}{
		{
			// Приклеенная запись для постороннего домена не должна
			// сойти за наш адрес.
			name: "приклеенная A-запись чужого имени отброшена",
			msg: dnsmessage.Message{
				Header:    hdr,
				Questions: []dnsmessage.Question{q},
				Answers: []dnsmessage.Resource{
					aRec(mustName(t, "example.com."), [4]byte{1, 2, 3, 4}),
					aRec(mustName(t, "evil.example."), [4]byte{6, 6, 6, 6}),
				},
			},
			wantIPs: []string{"1.2.3.4"},
		},
		{
			// Легитимное раскрытие через CNAME — обычное дело у CDN,
			// адрес конца цепочки принимается.
			name: "легитимная CNAME-цепочка принята",
			msg: dnsmessage.Message{
				Header:    hdr,
				Questions: []dnsmessage.Question{q},
				Answers: []dnsmessage.Resource{
					{
						Header: dnsmessage.ResourceHeader{Name: mustName(t, "example.com."), Type: dnsmessage.TypeCNAME, Class: dnsmessage.ClassINET, TTL: 60},
						Body:   &dnsmessage.CNAMEResource{CNAME: mustName(t, "cdn.example.net.")},
					},
					aRec(mustName(t, "cdn.example.net."), [4]byte{5, 6, 7, 8}),
				},
			},
			wantIPs: []string{"5.6.7.8"},
		},
		{
			name: "чужой Transaction ID — не наш ответ",
			msg: dnsmessage.Message{
				Header:    dnsmessage.Header{ID: id + 1, Response: true},
				Questions: []dnsmessage.Question{q},
				Answers:   []dnsmessage.Resource{aRec(mustName(t, "example.com."), [4]byte{1, 2, 3, 4})},
			},
			wantForeign: true,
		},
		{
			name: "чужой вопрос — не наш ответ",
			msg: dnsmessage.Message{
				Header: hdr,
				Questions: []dnsmessage.Question{{
					Name: mustName(t, "other.example."), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET,
				}},
				Answers: []dnsmessage.Resource{aRec(mustName(t, "other.example."), [4]byte{1, 2, 3, 4})},
			},
			wantForeign: true,
		},
		{
			name: "пакет-запрос (QR=0) — не ответ вовсе",
			msg: dnsmessage.Message{
				Header:    dnsmessage.Header{ID: id},
				Questions: []dnsmessage.Question{q},
			},
			wantForeign: true,
		},
	}
	for _, c := range cases {
		raw, err := c.msg.Pack()
		if err != nil {
			t.Fatalf("%s: pack: %v", c.name, err)
		}
		ips, _, err := parseAnswers(raw, id, "example.com")
		if c.wantForeign {
			if !errors.Is(err, errForeignReply) {
				t.Errorf("%s: err = %v, want errForeignReply", c.name, err)
			}
			continue
		}
		if err != nil {
			t.Errorf("%s: unexpected err: %v", c.name, err)
			continue
		}
		if len(ips) != len(c.wantIPs) {
			t.Errorf("%s: ips = %v, want %v", c.name, ips, c.wantIPs)
			continue
		}
		for i := range ips {
			if ips[i] != c.wantIPs[i] {
				t.Errorf("%s: ips = %v, want %v", c.name, ips, c.wantIPs)
			}
		}
	}
}

// ResolveDoH против локального сервера: честный dns-message принимается,
// HTML капитивного портала и ответ с чужим ID — улики подмены (OutInjected),
// а не невнятная ошибка разбора.
func TestResolveDoHAgainstLocalServer(t *testing.T) {
	// respond — общий кусок «прочитать запрос и ответить DNS-сообщением»,
	// idShift двигает Transaction ID (0 — честный ответ).
	respond := func(w http.ResponseWriter, r *http.Request, idShift uint16) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		var req dnsmessage.Message
		if err := req.Unpack(body); err != nil || len(req.Questions) == 0 {
			http.Error(w, "not dns", http.StatusBadRequest)
			return
		}
		q := req.Questions[0]
		resp := dnsmessage.Message{
			Header:    dnsmessage.Header{ID: req.Header.ID + idShift, Response: true, RecursionAvailable: true},
			Questions: []dnsmessage.Question{q},
			Answers:   []dnsmessage.Resource{aRec(q.Name, [4]byte{93, 184, 216, 34})},
		}
		out, err := resp.Pack()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/dns-message")
		w.Write(out)
	}

	cases := []struct {
		name        string
		handler     http.HandlerFunc
		wantStatus  Status
		wantOutcome Outcome
		wantIP      string
	}{
		{
			name:        "валидный dns-message — OK с адресами",
			handler:     func(w http.ResponseWriter, r *http.Request) { respond(w, r, 0) },
			wantStatus:  StatusOK,
			wantOutcome: OutOK,
			wantIP:      "93.184.216.34",
		},
		{
			// Капитивный портал охотно отдаёт 200 с HTML-страницей входа.
			name: "200 с text/html — ответил не тот",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "text/html; charset=utf-8")
				io.WriteString(w, "<html><title>Вход в сеть</title></html>")
			},
			wantStatus:  StatusFail,
			wantOutcome: OutInjected,
		},
		{
			name:        "dns-message с чужим ID — инжект",
			handler:     func(w http.ResponseWriter, r *http.Request) { respond(w, r, 1) },
			wantStatus:  StatusFail,
			wantOutcome: OutInjected,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			srv := httptest.NewServer(c.handler)
			defer srv.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			res := ResolveDoH(ctx, "example.com", srv.URL)
			if res.Status != c.wantStatus {
				t.Fatalf("status = %s (%s), want %s", res.Status, res.Detail, c.wantStatus)
			}
			if res.Outcome != c.wantOutcome {
				t.Errorf("outcome = %q, want %q", res.Outcome, c.wantOutcome)
			}
			if c.wantIP != "" && (len(res.IPs) != 1 || res.IPs[0] != c.wantIP) {
				t.Errorf("IPs = %v, want [%s]", res.IPs, c.wantIP)
			}
		})
	}
}
