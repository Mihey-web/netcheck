package probe

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// dohClient — отдельный клиент с Proxy: nil. http.DefaultTransport берёт
// HTTPS_PROXY из окружения, и на машине с запущенным VPN-клиентом DoH-резолв
// уходил бы в чужую страну, пока TCP/TLS-пробы идут напрямую. Тогда «честный
// IP» снимается не оттуда, где мы меряем, и расхождение с системным DNS
// программа устраивает себе сама.
var dohClient = &http.Client{Transport: &http.Transport{Proxy: nil, DisableKeepAlives: true}}

// ResolveSystem — резолв системным резолвером Windows.
func ResolveSystem(ctx context.Context, host string) Result {
	start := time.Now()
	r := Result{Target: host, Method: "DNS", Path: PathDirect}
	ips, err := net.DefaultResolver.LookupHost(ctx, host)
	r.Latency = time.Since(start)
	if err != nil {
		r.Status, r.Detail = StatusFail, err.Error()
		// «Имени нет» и «резолвер не ответил» — противоположные факты.
		// Пока они сваливались в один StatusFail, мёртвая сеть выглядела
		// как два десятка одновременно исчезнувших доменов.
		var de *net.DNSError
		switch {
		case errors.As(err, &de) && de.IsNotFound:
			r.Outcome = OutNXDomain
		case errors.As(err, &de) && de.IsTimeout:
			r.Outcome = OutTimeout
		default:
			r.Outcome = classifyErr(err)
		}
		return r
	}
	r.IPs, r.Status, r.Outcome = onlyIPv4(ips), StatusOK, OutOK
	if len(r.IPs) == 0 {
		// Имя есть, A-записей нет: сюда попадают и IPv6-only домены.
		// Это не «домена не существует».
		r.Status, r.Detail, r.Outcome = StatusFail, "no A records", OutNoData
	}
	return r
}

// ResolveUDP — прямой UDP-запрос к server (например "8.8.8.8:53"),
// мимо системного резолвера. Ловит подмену на уровне провайдерского DNS.
func ResolveUDP(ctx context.Context, host, server string) Result {
	start := time.Now()
	r := Result{Target: host, Method: "DNS·UDP", Path: PathDirect}
	query, id, err := buildQuery(host)
	if err != nil {
		r.Status, r.Detail, r.Outcome = StatusFail, err.Error(), OutOther
		return r
	}
	var d net.Dialer
	// Сетевые ошибки обязаны получать класс: с пустым Outcome «резолвер
	// молчит» неотличимо от «имени нет», и analyze не мог сказать ни
	// «сети нет», ни «UDP-DNS задушен».
	conn, err := d.DialContext(ctx, "udp", server)
	if err != nil {
		r.Latency = time.Since(start)
		r.Status, r.Detail, r.Outcome = StatusFail, err.Error(), classifyErr(err)
		return r
	}
	defer conn.Close()
	if dl, ok := ctx.Deadline(); ok {
		conn.SetDeadline(dl)
	}
	if _, err := conn.Write(query); err != nil {
		r.Latency = time.Since(start)
		r.Status, r.Detail, r.Outcome = StatusFail, err.Error(), classifyErr(err)
		return r
	}
	// Читаем до дедлайна, а не первый попавшийся пакет. Классическая
	// инжекция работает именно так: подделка от имени 8.8.8.8 приходит
	// раньше настоящего ответа, и кто выйдет по первому пакету — тот
	// подделку и запишет как «честный ответ мимо провайдера».
	buf := make([]byte, 4096)
	for {
		n, err := conn.Read(buf)
		r.Latency = time.Since(start)
		if err != nil {
			r.Status, r.Detail, r.Outcome = StatusFail, err.Error(), classifyErr(err)
			return r
		}
		ips, rcode, err := parseAnswers(buf[:n], id, host)
		if err != nil {
			if errors.Is(err, errForeignReply) {
				continue // не наш ответ — ждём настоящий
			}
			r.Status, r.Detail, r.Outcome = StatusFail, err.Error(), OutOther
			return r
		}
		switch rcode {
		case dnsmessage.RCodeNameError:
			r.Status, r.Detail, r.Outcome = StatusFail, "NXDOMAIN", OutNXDomain
			return r
		case dnsmessage.RCodeServerFailure, dnsmessage.RCodeRefused:
			r.Status, r.Detail, r.Outcome = StatusFail, rcode.String(), OutServFail
			return r
		}
		r.IPs, r.Status, r.Outcome = ips, StatusOK, OutOK
		if len(ips) == 0 {
			r.Status, r.Detail, r.Outcome = StatusFail, "no A records", OutNoData
		}
		return r
	}
}

// ResolveDoH — DNS-over-HTTPS (RFC 8484, POST application/dns-message).
func ResolveDoH(ctx context.Context, host, dohURL string) Result {
	start := time.Now()
	r := Result{Target: host, Method: "DNS·DoH", Path: PathDirect}
	query, id, err := buildQuery(host)
	if err != nil {
		r.Status, r.Detail, r.Outcome = StatusFail, err.Error(), OutOther
		return r
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, dohURL, bytes.NewReader(query))
	if err != nil {
		r.Status, r.Detail, r.Outcome = StatusFail, err.Error(), OutOther
		return r
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")
	resp, err := dohClient.Do(req)
	r.Latency = time.Since(start)
	if err != nil {
		// «DoH задушен» диагностируется классом отказа; пустой Outcome
		// делал эту ветку слепой — молчание сходило за «просто ошибка».
		r.Status, r.Detail, r.Outcome = StatusFail, err.Error(), classifyErr(err)
		return r
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		// HTTP-ошибка — это ответ, а не молчание; но и не DNS-ответ.
		r.Status, r.Detail, r.Outcome = StatusFail, fmt.Sprintf("http %d", resp.StatusCode), OutOther
		return r
	}
	// Ответ обязан быть DNS-сообщением. Капитивный портал охотно отдаёт
	// 200 с HTML-страницей, и без этой проверки он превращался в невнятную
	// ошибку разбора вместо честного «ответил не тот».
	if ct := resp.Header.Get("Content-Type"); ct != "" &&
		!strings.HasPrefix(ct, "application/dns-message") {
		r.Status, r.Detail, r.Outcome = StatusFail, "ответ не DNS: "+ct, OutInjected
		return r
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil {
		r.Status, r.Detail, r.Outcome = StatusFail, err.Error(), classifyErr(err)
		return r
	}
	ips, rcode, err := parseAnswers(body, id, host)
	if err != nil {
		r.Status, r.Detail, r.Outcome = StatusFail, err.Error(), OutOther
		if errors.Is(err, errForeignReply) {
			r.Outcome = OutInjected
		}
		return r
	}
	switch rcode {
	case dnsmessage.RCodeNameError:
		r.Status, r.Detail, r.Outcome = StatusFail, "NXDOMAIN", OutNXDomain
		return r
	case dnsmessage.RCodeServerFailure, dnsmessage.RCodeRefused:
		r.Status, r.Detail, r.Outcome = StatusFail, rcode.String(), OutServFail
		return r
	}
	r.IPs, r.Status, r.Outcome = ips, StatusOK, OutOK
	if len(ips) == 0 {
		r.Status, r.Detail, r.Outcome = StatusFail, "no A records", OutNoData
	}
	return r
}

// errForeignReply — пришёл не наш ответ: чужой идентификатор либо чужой
// вопрос. Для UDP это повод дочитать до настоящего, для DoH — улика.
var errForeignReply = errors.New("ответ не на наш запрос")

func buildQuery(host string) ([]byte, uint16, error) {
	name, err := dnsmessage.NewName(host + ".")
	if err != nil {
		return nil, 0, err
	}
	// Идентификатор берётся из криптографического источника. Прежний
	// «младшие биты наносекунд» предсказуем со стороны: подделать ответ
	// с угаданным ID мог кто угодно на пути.
	var idb [2]byte
	if _, err := rand.Read(idb[:]); err != nil {
		return nil, 0, err
	}
	id := binary.BigEndian.Uint16(idb[:])
	msg := dnsmessage.Message{
		Header: dnsmessage.Header{
			ID:               id,
			RecursionDesired: true,
		},
		Questions: []dnsmessage.Question{{
			Name:  name,
			Type:  dnsmessage.TypeA,
			Class: dnsmessage.ClassINET,
		}},
	}
	raw, err := msg.Pack()
	return raw, id, err
}

// parseAnswers разбирает ответ и сверяет, что он вообще наш.
//
// Прежняя версия принимала любой пакет и перебирала его Answers, не глядя
// ни на идентификатор, ни на заданный вопрос. Проба, написанная ловить
// подмену DNS, подмену как раз и не ловила: приклеенная в ответ запись
// для чужого имени принималась за ответ на наш.
func parseAnswers(raw []byte, wantID uint16, wantHost string) ([]string, dnsmessage.RCode, error) {
	var msg dnsmessage.Message
	if err := msg.Unpack(raw); err != nil {
		return nil, 0, err
	}
	if msg.Header.ID != wantID || !msg.Header.Response {
		return nil, 0, errForeignReply
	}
	want := strings.ToLower(wantHost) + "."
	if len(msg.Questions) != 1 ||
		!strings.EqualFold(msg.Questions[0].Name.String(), want) ||
		msg.Questions[0].Type != dnsmessage.TypeA {
		return nil, 0, errForeignReply
	}
	if msg.Header.Truncated {
		return nil, 0, errors.New("ответ обрезан (TC), нужен запрос по TCP")
	}

	// Принимаем адреса только для запрошенного имени и того, во что оно
	// раскрылось цепочкой CNAME. Иначе к ответу можно приклеить запись
	// для постороннего домена, и она сойдёт за наш адрес.
	chain := map[string]bool{want: true}
	for _, ans := range msg.Answers {
		if c, ok := ans.Body.(*dnsmessage.CNAMEResource); ok &&
			chain[strings.ToLower(ans.Header.Name.String())] {
			chain[strings.ToLower(c.CNAME.String())] = true
		}
	}
	var ips []string
	for _, ans := range msg.Answers {
		a, ok := ans.Body.(*dnsmessage.AResource)
		if !ok || !chain[strings.ToLower(ans.Header.Name.String())] {
			continue
		}
		ips = append(ips, net.IP(a.A[:]).String())
	}
	return ips, msg.Header.RCode, nil
}
