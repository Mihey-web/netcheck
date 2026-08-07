package probe

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	xproxy "golang.org/x/net/proxy"
	"golang.org/x/net/publicsuffix"
)

// BrowserUA — представляемся браузером. С «netcheck/1.0» mail.ru отдаёт 302
// на login.vk.ru, и программа сама себе устраивает ложный диагноз «заглушка
// провайдера». Мерить надо то, что увидит человек в браузере.
const BrowserUA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 " +
	"(KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36"

// bodyPeek — сколько начала ответа сохраняем как улику. Подписи защиты
// от роботов у разных площадок стоят на разной глубине, и 256 байт хватало
// только Cloudflare.
const bodyPeek = 4 << 10

// OutCanceled — прогон отменили раньше, чем проба успела кончиться.
// Это не факт о сети, а факт о нас: analyze обязан игнорировать такой
// исход, иначе закрытие окна посреди прогона рисовало бы блокировки.
const OutCanceled Outcome = "canceled"

// classifyErr — КАК проба кончилась. Это ключ ко всей диагностике: молчание
// до конца бюджета означает вмешательство по пути, а быстрый отказ — что
// ответил сам сервер.
func classifyErr(err error) Outcome {
	if err == nil {
		return OutOK
	}
	// Сначала — числовой код ошибки сокета. Он не зависит ни от языка
	// системы, ни от формулировок Go, тогда как разбор текста ниже
	// на русской Windows не находит ничего.
	if out, ok := platformOutcome(err); ok {
		return out
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return OutTimeout
	}
	// Отмена — не исход пробы, а обрыв прогона. Свалить её в OutOther
	// значило бы строить вердикт на пробах, которым не дали закончиться.
	if errors.Is(err, context.Canceled) {
		return OutCanceled
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return OutTimeout
	}
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return OutEOF
	}
	var alert tls.AlertError
	if errors.As(err, &alert) {
		return OutTLSAlert
	}
	// «Первая запись не похожа на TLS» означает буквально: на 443 в ответ
	// пришло не рукопожатие. Это вброс постороннего ответа по пути, а не
	// отказ сервера, и считать его признаком «сервер жив» нельзя.
	var rec tls.RecordHeaderError
	if errors.As(err, &rec) {
		return OutInjected
	}
	s := strings.ToLower(err.Error())
	switch {
	case strings.Contains(s, "refused"):
		return OutRefused
	case strings.Contains(s, "reset by peer"),
		strings.Contains(s, "forcibly closed"),
		strings.Contains(s, "connection was aborted"):
		return OutReset
	case strings.Contains(s, "unreachable"):
		return OutUnreach
	// «eof» проверяется по концу строки: в сообщении есть адрес цели,
	// и подстрока нашлась бы в любом theoffice.com.
	case strings.HasSuffix(s, "eof"):
		return OutEOF
	case strings.Contains(s, "tls:"), strings.Contains(s, "handshake"):
		return OutTLSAlert
	case strings.Contains(s, "no such host"), strings.Contains(s, "server misbehaving"):
		return OutDNSFail
	}
	return OutOther
}

// TCPConnect — чистое TCP-соединение до ipPort ("1.2.3.4:443").
func TCPConnect(ctx context.Context, ipPort string) Result {
	start := time.Now()
	_, port, _ := net.SplitHostPort(ipPort)
	r := Result{Target: ipPort, Method: "TCP:" + port, Path: PathDirect}
	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", ipPort)
	r.Latency = time.Since(start)
	if err != nil {
		r.Status, r.Detail, r.Outcome = StatusFail, err.Error(), classifyErr(err)
		return r
	}
	conn.Close()
	r.Status, r.Outcome = StatusOK, OutOK
	return r
}

// TLSHandshake — TCP + TLS-рукопожатие с заданным SNI.
// Сертификат НЕ проверяется: важен сам факт, что рукопожатие дошло до конца
// (DPI рвёт его по SNI до завершения).
func TLSHandshake(ctx context.Context, ipPort, sni string) Result {
	start := time.Now()
	r := Result{Target: sni, Method: "TLS-SNI", Path: PathDirect, SNI: sni}
	var d net.Dialer
	raw, err := d.DialContext(ctx, "tcp", ipPort)
	if err != nil {
		r.Latency = time.Since(start)
		r.Status, r.Detail, r.Outcome = StatusFail, err.Error(), classifyErr(err)
		return r
	}
	defer raw.Close()
	if dl, ok := ctx.Deadline(); ok {
		raw.SetDeadline(dl)
	}
	// Тот же список протоколов, что предъявляет HTTP-проба. Иначе у двух
	// проб разный отпечаток рукопожатия, а DPI умеет резать по нему —
	// и «TLS прошёл, HTTP не прошёл» означало бы не то, что мы думаем.
	tc := tls.Client(raw, &tls.Config{
		ServerName:         sni,
		InsecureSkipVerify: true,
		NextProtos:         []string{"h2", "http/1.1"},
	})
	err = tc.HandshakeContext(ctx)
	r.Latency = time.Since(start)
	if err != nil {
		r.Status, r.Detail, r.Outcome = StatusFail, err.Error(), classifyErr(err)
		return r
	}
	r.Status, r.Outcome = StatusOK, OutOK
	r.Cert = inspectCert(tc.ConnectionState(), sni)
	return r
}

// inspectCert — сертификат как улика. Проверяем вручную, потому что само
// рукопожатие идёт с InsecureSkipVerify: иначе подмена оборвала бы соединение
// и мы бы её не увидели, а только потеряли бы факт.
//
// Несовпадение имени само по себе подменой НЕ является: www.msftconnecttest.com
// штатно предъявляет сертификат Akamai от DigiCert. Подмена — это когда цепочка
// не строится до корня из системного хранилища.
func inspectCert(cs tls.ConnectionState, sni string) *CertInfo {
	if len(cs.PeerCertificates) == 0 {
		return nil
	}
	leaf := cs.PeerCertificates[0]
	ci := &CertInfo{
		Subject:   leaf.Subject.CommonName,
		Issuer:    leaf.Issuer.CommonName,
		NameMatch: leaf.VerifyHostname(sni) == nil,
	}
	inter := x509.NewCertPool()
	for _, c := range cs.PeerCertificates[1:] {
		inter.AddCert(c)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{DNSName: sni, Intermediates: inter}); err != nil {
		ci.ChainErr = err.Error()
		// имя может не совпасть по вине CDN — пробуем цепочку саму по себе
		if _, err2 := leaf.Verify(x509.VerifyOptions{Intermediates: inter}); err2 == nil {
			ci.ChainValid = true
			ci.ChainErr = ""
		}
	} else {
		ci.ChainValid = true
	}
	return ci
}

// HTTPGet — GET без следования редиректам. proxy==nil — напрямую;
// иначе через прокси (socks5:// и http:// понимает сам http.Transport).
// pinIP, если задан, подставляется вместо результата резолва: улики должны
// собираться с ОДНОГО адреса. Прежде TCP и TLS проверялись по найденному
// живому адресу, а HTTP резолвил имя заново и у CDN уходил на другой —
// живое рукопожатие с мёртвым запросом складывались в диагноз «режут
// содержимое», хотя резали по IP.
func HTTPGet(ctx context.Context, rawURL string, proxy *url.URL, pinIP string) Result {
	start := time.Now()
	method := "HTTPS"
	if strings.HasPrefix(strings.ToLower(rawURL), "http://") {
		method = "HTTP" // подписывать открытый порт 80 как HTTPS — дезинформация
	}
	r := Result{Target: rawURL, Method: method, Path: PathDirect}
	if proxy != nil {
		r.Path = PathProxy
	}
	tr := &http.Transport{DisableKeepAlives: true, ForceAttemptHTTP2: true}
	// Transport создаётся на каждый вызов: без явного закрытия соединения
	// доживали бы до конца прогона, и полный прогон тёк сокетами.
	defer tr.CloseIdleConnections()
	if proxy != nil {
		tr.Proxy = http.ProxyURL(proxy)
	} else if pinIP != "" {
		tr.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			_, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			var d net.Dialer
			return d.DialContext(ctx, network, net.JoinHostPort(pinIP, port))
		}
	}
	client := &http.Client{
		Transport: tr,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		r.Status, r.Detail = StatusFail, err.Error()
		return r
	}
	req.Header.Set("User-Agent", BrowserUA)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Accept-Language", "ru-RU,ru;q=0.9,en;q=0.8")
	resp, err := client.Do(req)
	r.Latency = time.Since(start)
	if err != nil {
		r.Status, r.Detail, r.Outcome = StatusFail, err.Error(), classifyErr(err)
		return r
	}
	defer resp.Body.Close()

	r.Outcome = OutOK
	r.Code = resp.StatusCode
	r.Server = resp.Header.Get("Server")
	r.CFMitigated = resp.Header.Get("Cf-Mitigated")
	// Читаем 4 КБ, а не 256 байт: подпись защиты от роботов у не-Cloudflare
	// (DataDome, Qrator) стоит после длинной преамбулы, и в прежнее окно
	// не помещалась — антибот принимался за неизвестную причину.
	body, rerr := io.ReadAll(io.LimitReader(resp.Body, bodyPeek))
	r.Body = string(body)
	// Обрыв на теле — почерк частичной фильтрации: заголовки пропустили,
	// содержимое срезали. Прежде ошибка чтения молча выбрасывалась,
	// и такой ответ засчитывался как «сайт жив».
	if rerr != nil && !errors.Is(rerr, io.EOF) {
		r.Outcome = classifyErr(rerr)
		r.Status, r.Detail = StatusWarn, "тело оборвано: "+rerr.Error()
		return r
	}
	// Location хранится ХОСТОМ. Прежде при относительном редиректе («/ru/»)
	// в поле оставался путь, а analyze сравнивал его с именем сайта как
	// с чужим доменом — и любой сайт, отдающий на «/» редирект внутрь себя,
	// записывался в «заглушку провайдера».
	if loc := resp.Header.Get("Location"); loc != "" {
		if u, err := url.Parse(loc); err == nil {
			r.Location = u.Host // пусто для относительного — так и задумано
		}
	}

	// HTTPGet больше не ставит диагнозов: 3xx — это «сайт жив и куда-то ведёт»,
	// а заглушка это провайдера или штатный SSO, решает analyze по Location.
	// 31 цель из 52 отдаёт редирект на GET /, и разбирать их здесь по двум
	// последним меткам домена значило записывать в заглушки живые dzen.ru
	// и mail.ru.
	r.Challenge = IsChallenge(r)

	switch {
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		r.Status, r.Detail = StatusOK, fmt.Sprintf("%d", resp.StatusCode)
	case resp.StatusCode >= 300 && resp.StatusCode < 400:
		r.Status, r.Detail = StatusOK, fmt.Sprintf("%d -> %s", resp.StatusCode, r.Location)
	case r.Challenge:
		// Предупреждение, а не отказ: сервер ответил, путь до него чист,
		// а решить проверку «я не робот» наш клиент не может по устройству.
		r.Status, r.Detail = StatusWarn, fmt.Sprintf("проверка «я не робот» (http %d)", resp.StatusCode)
	default:
		r.Status, r.Detail = StatusFail, fmt.Sprintf("http %d", resp.StatusCode)
	}
	return r
}

// IsChallenge — ответ является проверкой «я не робот». Эвристика одна
// на probe и analyze: пока у каждого была своя копия, challenge на 403
// ловился, а тот же challenge на 503 записывался в «сервис лежит».
//
// Cloudflare помечает такой ответ заголовком Cf-Mitigated: challenge;
// у прочих (DataDome, Qrator) остаётся узнаваемая страница. Коды берём
// все три, какими эту проверку отдают: 403, 429 и 503.
func IsChallenge(r Result) bool {
	switch r.Code {
	case 403, 429, 503:
	default:
		return false
	}
	// Только значение "challenge": Cf-Mitigated: block — это блок,
	// и принимать его за проверку «я не робот» значило звать блокировку
	// «в браузере откроется».
	if r.CFMitigated == "challenge" {
		return true
	}
	b := strings.ToLower(r.Body)
	return strings.Contains(b, "just a moment") ||
		strings.Contains(b, "cf-challenge") ||
		strings.Contains(b, "challenges.cloudflare.com") ||
		// DataDome грузит капчу с captcha-delivery.com; голое слово
		// «captcha» ловило и формы обратной связи на обычных страницах.
		strings.Contains(b, "captcha-delivery.com")
}

// SameSite — ведёт ли редирект на тот же сайт. Нужен analyze при разборе
// заглушек.
func SameSite(reqHost, locHost string) bool { return sameSite(reqHost, locHost) }

// sameSite — сравниваем сайты по eTLD+1: ya.ru→ya.ru, vk.com→m.vk.com,
// wikipedia.org→www.wikipedia.org — свои; youtube.com→block.isp.ru — чужой.
// Пустой Location (относительный) — свой.
//
// Именно eTLD+1, а не «две последние метки»: на co.uk/com.tr/spb.ru сайт
// задаётся тремя метками, и block.isp.co.uk сходил за «тот же сайт»,
// что и site.co.uk.
func sameSite(reqHost, locHost string) bool {
	if locHost == "" {
		return true
	}
	base := func(h string) string {
		if i := strings.IndexByte(h, ':'); i >= 0 {
			h = h[:i] // отрезаем порт
		}
		h = strings.TrimSuffix(strings.ToLower(h), ".")
		if s, err := publicsuffix.EffectiveTLDPlusOne(h); err == nil {
			return s
		}
		return h // голый суффикс или мусор — сравниваем как есть
	}
	return base(reqHost) == base(locHost)
}

// DialViaProxy — TCP-соединение до targetHostPort через локальный прокси.
// Поддерживает socks5:// (x/net/proxy) и http:// (CONNECT).
func DialViaProxy(ctx context.Context, proxyURL *url.URL, targetHostPort string) (net.Conn, error) {
	switch proxyURL.Scheme {
	case "socks5", "socks5h":
		d, err := xproxy.SOCKS5("tcp", proxyURL.Host, nil, &net.Dialer{})
		if err != nil {
			return nil, err
		}
		if cd, ok := d.(xproxy.ContextDialer); ok {
			return cd.DialContext(ctx, "tcp", targetHostPort)
		}
		return d.Dial("tcp", targetHostPort)
	case "http":
		var nd net.Dialer
		conn, err := nd.DialContext(ctx, "tcp", proxyURL.Host)
		if err != nil {
			return nil, err
		}
		if dl, ok := ctx.Deadline(); ok {
			conn.SetDeadline(dl)
		}
		fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", targetHostPort, targetHostPort)
		br := bufio.NewReader(conn)
		resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
		if err != nil {
			conn.Close()
			return nil, err
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			conn.Close()
			return nil, fmt.Errorf("proxy CONNECT: %s", resp.Status)
		}
		conn.SetDeadline(time.Time{})
		return conn, nil
	default:
		return nil, fmt.Errorf("unsupported proxy scheme %q", proxyURL.Scheme)
	}
}
