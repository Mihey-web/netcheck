package probe

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// newTestTLSServer — TLS-листенер с самоподписанным сертом, принимающий рукопожатия.
func newTestTLSServer(t *testing.T) net.Listener {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "netcheck.test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				// дочитать рукопожатие и закрыть
				if tc, ok := c.(*tls.Conn); ok {
					tc.Handshake()
				}
				c.Close()
			}(conn)
		}
	}()
	return ln
}

func TestTLSHandshakeLocal(t *testing.T) {
	ln := newTestTLSServer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	res := TLSHandshake(ctx, ln.Addr().String(), "whatever.sni")
	if res.Status != StatusOK {
		t.Fatalf("want ok, got %s (%s)", res.Status, res.Detail)
	}
	if res.Method != "TLS-SNI" {
		t.Fatalf("method = %q", res.Method)
	}
}

func TestTLSHandshakeClosedPort(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 700*time.Millisecond)
	defer cancel()
	// порт 1 на loopback закрыт
	res := TLSHandshake(ctx, "127.0.0.1:1", "x.test")
	if res.Status != StatusFail {
		t.Fatalf("want fail, got %s", res.Status)
	}
}

func TestTCPConnect(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	ctx := context.Background()
	if res := TCPConnect(ctx, ln.Addr().String()); res.Status != StatusOK {
		t.Fatalf("open port: want ok, got %s (%s)", res.Status, res.Detail)
	}
	ctx2, cancel := context.WithTimeout(ctx, 700*time.Millisecond)
	defer cancel()
	if res := TCPConnect(ctx2, "127.0.0.1:1"); res.Status != StatusFail {
		t.Fatalf("closed port: want fail, got %s", res.Status)
	}
}

func TestSameSite(t *testing.T) {
	cases := []struct {
		req, loc string
		want     bool
	}{
		{"ya.ru", "ya.ru", true},
		{"vk.com", "m.vk.com", true},                 // мобильная версия
		{"wikipedia.org", "www.wikipedia.org", true}, // www
		{"www.youtube.com", "youtube.com", true},     // и обратно
		{"youtube.com", "block.isp.ru", false},       // заглушка провайдера
		{"discord.com", "discord.gg", false},         // другой домен
		{"ya.ru", "", true},                          // относительный Location
	}
	for _, c := range cases {
		if got := sameSite(c.req, c.loc); got != c.want {
			t.Errorf("sameSite(%q,%q) = %v, want %v", c.req, c.loc, got, c.want)
		}
	}
}

// Редирект внутри того же сайта — рабочий сайт, а не проблема: ya.ru отдаёт
// 301 на себя же, vk.com — на m.vk.com. Раньше это ломало вердикт целиком.
func TestHTTPGetSameSiteRedirectIsOK(t *testing.T) {
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, srv.URL+"/home", http.StatusMovedPermanently)
	}))
	defer srv.Close()

	res := HTTPGet(context.Background(), srv.URL, nil, "")
	if res.Status != StatusOK {
		t.Fatalf("same-site redirect must be ok, got %s (%s)", res.Status, res.Detail)
	}
}

func TestHTTPGetOKAndRedirect(t *testing.T) {
	okSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer okSrv.Close()
	redirSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://block.example.isp/stub", http.StatusFound)
	}))
	defer redirSrv.Close()

	ctx := context.Background()
	res := HTTPGet(ctx, okSrv.URL, nil, "")
	if res.Status != StatusOK {
		t.Fatalf("200: want ok, got %s (%s)", res.Status, res.Detail)
	}
	// HTTPGet диагнозов не ставит: редирект — это «сайт жив и куда-то ведёт».
	// Заглушка это провайдера или штатный SSO, решает analyze по Location.
	res = HTTPGet(ctx, redirSrv.URL, nil, "")
	if res.Status != StatusOK {
		t.Fatalf("302: want ok, got %s (%s)", res.Status, res.Detail)
	}
	if res.Code != 302 {
		t.Errorf("code = %d, want 302", res.Code)
	}
	if res.Location != "block.example.isp" {
		t.Errorf("location = %q, want host of redirect target", res.Location)
	}
}
