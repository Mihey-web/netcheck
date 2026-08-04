// Package env собирает снимок сетевого окружения и признаки VPN:
// системный прокси, локальные прокси-листенеры, туннель-адаптеры, tailscale.
package env

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
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

// classifyListener определяет, слушает ли 127.0.0.1:port прокси и какой:
// сначала SOCKS5 method-selection, затем HTTP. Открытый порт с незнакомым
// протоколом прокси НЕ считается (чтобы не путать чужие сервисы).
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
	c.SetDeadline(time.Now().Add(500 * time.Millisecond))
	fmt.Fprintf(c, "OPTIONS / HTTP/1.0\r\n\r\n")
	head := make([]byte, 5)
	if _, err := io.ReadFull(c, head); err == nil && string(head) == "HTTP/" {
		return "http", true
	}
	return "", false
}
