package probe

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
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
		// Суффиксы из двух меток: «две последние метки» считали
		// block.isp.co.uk тем же сайтом, что и site.co.uk.
		{"site.co.uk", "block.isp.co.uk", false},
		{"www.site.co.uk", "site.co.uk", true},
		{"site.com.tr", "block.isp.com.tr", false},
	}
	for _, c := range cases {
		if got := sameSite(c.req, c.loc); got != c.want {
			t.Errorf("sameSite(%q,%q) = %v, want %v", c.req, c.loc, got, c.want)
		}
	}
}

// Границы эвристики «я не робот»: Cf-Mitigated говорит о challenge только
// значением "challenge" ("block" — это блок), а голое слово «captcha»
// в тексте страницы ловило и формы обратной связи.
func TestIsChallenge(t *testing.T) {
	cases := []struct {
		name string
		r    Result
		want bool
	}{
		{"cloudflare challenge на 503", Result{Code: 503, CFMitigated: "challenge"}, true},
		{"cf-mitigated: block — это блок, а не challenge", Result{Code: 403, CFMitigated: "block"}, false},
		{"страница just a moment на 503", Result{Code: 503, Body: "<title>Just a moment...</title>"}, true},
		{"страница challenges.cloudflare.com", Result{Code: 403, Body: "src=\"https://challenges.cloudflare.com/x.js\""}, true},
		{"datadome captcha-delivery", Result{Code: 403, Body: "src=\"https://ct.captcha-delivery.com/c.js\""}, true},
		{"голое слово captcha — не challenge", Result{Code: 403, Body: "contact us if the captcha bothered you"}, false},
		{"код 200 — не challenge, что бы ни было в теле", Result{Code: 200, Body: "just a moment"}, false},
		{"обычный 403 без подписей", Result{Code: 403, Body: "Forbidden"}, false},
	}
	for _, c := range cases {
		if got := IsChallenge(c.r); got != c.want {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
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

// Обрыв тела RST'ом — почерк частичной фильтрации: заголовки пропустили,
// содержимое срезали. Такой ответ обязан давать предупреждение «тело
// оборвано», а не сходить за «сайт жив»: раньше ошибка чтения тела
// молча выбрасывалась.
func TestHTTPGetBodyCutByRST(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hj, ok := w.(http.Hijacker)
		if !ok {
			t.Error("httptest-сервер обязан уметь Hijack")
			return
		}
		conn, _, err := hj.Hijack()
		if err != nil {
			t.Error(err)
			return
		}
		// Заголовки обещают длинное тело, отдаём только начало…
		io.WriteString(conn, "HTTP/1.1 200 OK\r\n"+
			"Content-Type: text/html\r\n"+
			"Content-Length: 65536\r\n\r\n"+
			strings.Repeat("x", 512))
		// …даём клиенту прочитать заголовки и рвём сокет сбросом:
		// SetLinger(0) превращает Close в RST вместо честного FIN.
		time.Sleep(100 * time.Millisecond)
		if tc, ok := conn.(*net.TCPConn); ok {
			tc.SetLinger(0)
		}
		conn.Close()
	}))
	defer srv.Close()

	res := HTTPGet(context.Background(), srv.URL, nil, "")
	if res.Status != StatusWarn {
		t.Fatalf("оборванное тело должно давать warn, got %s (%s)", res.Status, res.Detail)
	}
	if !strings.Contains(res.Detail, "тело оборвано") {
		t.Errorf("detail = %q, ждали упоминание обрыва тела", res.Detail)
	}
	if res.Outcome == OutOK || res.Outcome == "" {
		t.Errorf("outcome = %q — обрыв тела сошёл за успех", res.Outcome)
	}
}

// fakeConnectProxy — локальный HTTP-прокси: на CONNECT отвечает статусом
// status; при echo=true дальше возвращает клиенту всё, что тот прислал.
func fakeConnectProxy(t *testing.T, status string, echo bool) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
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
				defer c.Close()
				br := bufio.NewReader(c)
				req, err := http.ReadRequest(br)
				if err != nil || req.Method != http.MethodConnect {
					return
				}
				io.WriteString(c, "HTTP/1.1 "+status+"\r\n\r\n")
				if echo {
					// эхо через br: часть данных клиента могла уже
					// осесть в буфере чтения
					io.Copy(c, br)
				}
			}(conn)
		}
	}()
	return ln.Addr().String()
}

// Ответ 200 на CONNECT — туннель установлен: соединение живо и данные
// ходят в обе стороны.
func TestDialViaProxyHTTPConnectOK(t *testing.T) {
	addr := fakeConnectProxy(t, "200 Connection established", true)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	u, err := url.Parse("http://" + addr)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := DialViaProxy(ctx, u, "target.test:443")
	if err != nil {
		t.Fatalf("CONNECT 200 должен давать живое соединение: %v", err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 4)
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("данные через туннель не вернулись: %v", err)
	}
	if string(buf) != "ping" {
		t.Errorf("эхо = %q, want %q", buf, "ping")
	}
}

// Отказ прокси на CONNECT — ошибка с внятным упоминанием прокси: именно
// по этому тексту человек отличает «VPN-клиент не смог» от «сайт лежит».
func TestDialViaProxyHTTPConnectRefused(t *testing.T) {
	addr := fakeConnectProxy(t, "502 Bad Gateway", false)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	u, err := url.Parse("http://" + addr)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := DialViaProxy(ctx, u, "target.test:443")
	if err == nil {
		conn.Close()
		t.Fatal("502 от прокси должен быть ошибкой, а не соединением")
	}
	if !strings.Contains(err.Error(), "proxy CONNECT") {
		t.Errorf("ошибка %q не упоминает proxy CONNECT", err)
	}
}
