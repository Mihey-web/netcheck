package probe

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
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
		return r
	}
	r.IPs, r.Status = onlyIPv4(ips), StatusOK
	if len(r.IPs) == 0 {
		r.Status, r.Detail = StatusFail, "no A records"
	}
	return r
}

// ResolveUDP — прямой UDP-запрос к server (например "8.8.8.8:53"),
// мимо системного резолвера. Ловит подмену на уровне провайдерского DNS.
func ResolveUDP(ctx context.Context, host, server string) Result {
	start := time.Now()
	r := Result{Target: host, Method: "DNS·UDP", Path: PathDirect}
	query, err := buildQuery(host)
	if err != nil {
		r.Status, r.Detail = StatusFail, err.Error()
		return r
	}
	var d net.Dialer
	conn, err := d.DialContext(ctx, "udp", server)
	if err != nil {
		r.Latency = time.Since(start)
		r.Status, r.Detail = StatusFail, err.Error()
		return r
	}
	defer conn.Close()
	if dl, ok := ctx.Deadline(); ok {
		conn.SetDeadline(dl)
	}
	if _, err := conn.Write(query); err != nil {
		r.Latency = time.Since(start)
		r.Status, r.Detail = StatusFail, err.Error()
		return r
	}
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	r.Latency = time.Since(start)
	if err != nil {
		r.Status, r.Detail = StatusFail, err.Error()
		return r
	}
	ips, err := parseAnswers(buf[:n])
	if err != nil {
		r.Status, r.Detail = StatusFail, err.Error()
		return r
	}
	r.IPs, r.Status = ips, StatusOK
	if len(ips) == 0 {
		r.Status, r.Detail = StatusFail, "no A records"
	}
	return r
}

// ResolveDoH — DNS-over-HTTPS (RFC 8484, POST application/dns-message).
func ResolveDoH(ctx context.Context, host, dohURL string) Result {
	start := time.Now()
	r := Result{Target: host, Method: "DNS·DoH", Path: PathDirect}
	query, err := buildQuery(host)
	if err != nil {
		r.Status, r.Detail = StatusFail, err.Error()
		return r
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, dohURL, bytes.NewReader(query))
	if err != nil {
		r.Status, r.Detail = StatusFail, err.Error()
		return r
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")
	resp, err := dohClient.Do(req)
	r.Latency = time.Since(start)
	if err != nil {
		r.Status, r.Detail = StatusFail, err.Error()
		return r
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		r.Status, r.Detail = StatusFail, fmt.Sprintf("http %d", resp.StatusCode)
		return r
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil {
		r.Status, r.Detail = StatusFail, err.Error()
		return r
	}
	ips, err := parseAnswers(body)
	if err != nil {
		r.Status, r.Detail = StatusFail, err.Error()
		return r
	}
	r.IPs, r.Status = ips, StatusOK
	if len(ips) == 0 {
		r.Status, r.Detail = StatusFail, "no A records"
	}
	return r
}

func buildQuery(host string) ([]byte, error) {
	name, err := dnsmessage.NewName(host + ".")
	if err != nil {
		return nil, err
	}
	msg := dnsmessage.Message{
		Header: dnsmessage.Header{
			ID:               uint16(time.Now().UnixNano() & 0xffff),
			RecursionDesired: true,
		},
		Questions: []dnsmessage.Question{{
			Name:  name,
			Type:  dnsmessage.TypeA,
			Class: dnsmessage.ClassINET,
		}},
	}
	return msg.Pack()
}

func parseAnswers(raw []byte) ([]string, error) {
	var msg dnsmessage.Message
	if err := msg.Unpack(raw); err != nil {
		return nil, err
	}
	var ips []string
	for _, ans := range msg.Answers {
		if a, ok := ans.Body.(*dnsmessage.AResource); ok {
			ips = append(ips, net.IP(a.A[:]).String())
		}
	}
	return ips, nil
}
