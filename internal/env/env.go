// Package env собирает снимок сетевого окружения и признаки VPN:
// системный прокси, локальные прокси-листенеры, туннель-адаптеры, tailscale.
package env

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

type ProxyHint struct {
	Kind   string `json:"kind"`  // "system" | "env" | "listener"
	Proto  string `json:"proto"` // "socks5" | "http" | ""
	Addr   string `json:"addr"`
	Active bool   `json:"active"`
}

type Snapshot struct {
	Adapter          string      `json:"adapter"`
	Gateway          string      `json:"gateway"`
	IP               string      `json:"ip"`
	SystemProxyOn    bool        `json:"systemProxyOn"`
	SystemProxyAddr  string      `json:"systemProxyAddr"`
	Proxies          []ProxyHint `json:"proxies"`
	Tunnels          []string    `json:"tunnels"`
	DefaultViaTunnel bool        `json:"defaultViaTunnel"`
	Tailscale        string      `json:"tailscale"` // "" | "connected, no exit" | "exit: <node>"
}

// Detect — снимок окружения. proxyPorts — какие локальные порты щупать
// на предмет прокси (из конфига).
func Detect(ctx context.Context, proxyPorts []int) Snapshot {
	var s Snapshot

	s.SystemProxyOn, s.SystemProxyAddr = systemProxy()
	if s.SystemProxyOn {
		s.Proxies = append(s.Proxies, ProxyHint{Kind: "system", Proto: "http", Addr: s.SystemProxyAddr, Active: true})
	}
	for _, k := range []string{"HTTPS_PROXY", "HTTP_PROXY", "https_proxy", "http_proxy"} {
		if v := os.Getenv(k); v != "" {
			s.Proxies = append(s.Proxies, ProxyHint{Kind: "env", Addr: v, Active: true})
			break
		}
	}
	for _, p := range proxyPorts {
		// break внутри select выходил из select, а не из цикла: отмена
		// контекста перебор портов не останавливала, и он честно выстаивал
		// свои 300 мс на каждом.
		if ctx.Err() != nil {
			break
		}
		if proto, ok := classifyListener(p); ok {
			s.Proxies = append(s.Proxies, ProxyHint{
				Kind: "listener", Proto: proto,
				Addr: fmt.Sprintf("127.0.0.1:%d", p), Active: true,
			})
		}
	}

	s.Adapter, s.Gateway, s.IP, s.Tunnels, s.DefaultViaTunnel = routeInfo()
	s.Tailscale = tailscaleStatus(ctx)
	return s
}

// connectProbe — куда просим прокси установить туннель при классификации.
// Тот же хост, что у контрольного captive-запроса runner'а: лёгкий и не
// заблокированный из РФ.
const connectProbe = "www.msftconnecttest.com:80"

// classifyListener определяет, слушает ли 127.0.0.1:port прокси и какой:
// сначала SOCKS5 method-selection, затем HTTP CONNECT. Открытый порт с
// незнакомым протоколом прокси НЕ считается (чтобы не путать чужие сервисы).
func classifyListener(port int) (string, bool) {
	addr := fmt.Sprintf("127.0.0.1:%d", port)

	c, err := net.DialTimeout("tcp", addr, 300*time.Millisecond)
	if err != nil {
		return "", false
	}
	c.SetDeadline(time.Now().Add(500 * time.Millisecond))
	c.Write([]byte{0x05, 0x01, 0x00}) // VER=5, NMETHODS=1, NO-AUTH
	buf := make([]byte, 2)
	if _, err := io.ReadFull(c, buf); err == nil && buf[0] == 0x05 {
		c.Close()
		return "socks5", true
	}
	c.Close()

	c, err = net.DialTimeout("tcp", addr, 300*time.Millisecond)
	if err != nil {
		return "", false
	}
	defer c.Close()
	// HTTP-прокси опознаём по CONNECT: настоящий прокси отвечает 2xx (туннель
	// готов) или 407 (просит авторизацию). Раньше хватало любого "HTTP/" в
	// ответе на OPTIONS — и прокси объявлялся каждый локальный dev-сервер,
	// чей порт совпал со списком proxy_ports.
	c.SetDeadline(time.Now().Add(1200 * time.Millisecond)) // прокси нужно время реально установить туннель
	fmt.Fprintf(c, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", connectProbe, connectProbe)
	head := make([]byte, 12) // "HTTP/1.x NNN"
	if _, err := io.ReadFull(c, head); err != nil || !strings.HasPrefix(string(head), "HTTP/") {
		return "", false
	}
	code, err := strconv.Atoi(string(head[9:12]))
	if err != nil {
		return "", false
	}
	if code/100 == 2 || code == 407 {
		return "http", true
	}
	return "", false
}
