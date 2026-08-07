package env

import (
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"testing"
)

const tsRunningExit = `{
  "BackendState": "Running",
  "Self": {"HostName": "mihey-pc"},
  "Peer": {
    "key1": {"HostName": "de", "ExitNode": true, "Online": true},
    "key2": {"HostName": "ru", "ExitNode": false, "Online": true}
  }
}`

const tsRunningNoExit = `{
  "BackendState": "Running",
  "Self": {"HostName": "mihey-pc"},
  "Peer": {
    "key1": {"HostName": "de", "ExitNode": false, "Online": true}
  }
}`

const tsStopped = `{"BackendState": "Stopped"}`

func TestParseTailscaleStatus(t *testing.T) {
	if got := ParseTailscaleStatus([]byte(tsRunningExit)); got != "exit: de" {
		t.Fatalf("exit case: got %q", got)
	}
	if got := ParseTailscaleStatus([]byte(tsRunningNoExit)); got != "connected, no exit" {
		t.Fatalf("no-exit case: got %q", got)
	}
	if got := ParseTailscaleStatus([]byte(tsStopped)); got != "" {
		t.Fatalf("stopped case: got %q", got)
	}
	if got := ParseTailscaleStatus([]byte("not json")); got != "" {
		t.Fatalf("invalid json case: got %q", got)
	}
}

// fakeSocks5 отвечает на SOCKS5 method-selection (VER=5, METHOD=0).
func fakeSocks5(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				buf := make([]byte, 16)
				if _, err := conn.Read(buf); err != nil {
					return
				}
				conn.Write([]byte{0x05, 0x00})
			}(c)
		}
	}()
	_, portStr, _ := net.SplitHostPort(ln.Addr().String())
	port, _ := strconv.Atoi(portStr)
	return port
}

func TestClassifyListenerSocks5(t *testing.T) {
	port := fakeSocks5(t)
	proto, ok := classifyListener(port)
	if !ok || proto != "socks5" {
		t.Fatalf("want socks5/true, got %q/%v", proto, ok)
	}
}

func TestClassifyListenerClosed(t *testing.T) {
	// порт 1 закрыт
	if _, ok := classifyListener(1); ok {
		t.Fatal("closed port must not classify")
	}
}

// fakeConnectResponder отвечает на любой запрос заданной статусной строкой —
// имитирует HTTP-прокси, который на CONNECT говорит 200/407.
func fakeConnectResponder(t *testing.T, status string) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				buf := make([]byte, 512)
				if _, err := conn.Read(buf); err != nil {
					return
				}
				fmt.Fprintf(conn, "HTTP/1.1 %s\r\n\r\n", status)
			}(c)
		}
	}()
	_, portStr, _ := net.SplitHostPort(ln.Addr().String())
	port, _ := strconv.Atoi(portStr)
	return port
}

func TestClassifyListenerHTTPProxyConnect(t *testing.T) {
	port := fakeConnectResponder(t, "200 Connection established")
	proto, ok := classifyListener(port)
	if !ok || proto != "http" {
		t.Fatalf("want http/true, got %q/%v", proto, ok)
	}
}

func TestClassifyListenerHTTPProxyAuth(t *testing.T) {
	// 407 — прокси есть, просто просит логин; это всё равно прокси
	port := fakeConnectResponder(t, "407 Proxy Authentication Required")
	proto, ok := classifyListener(port)
	if !ok || proto != "http" {
		t.Fatalf("want http/true, got %q/%v", proto, ok)
	}
}

func TestClassifyListenerPlainHTTPServerIsNotProxy(t *testing.T) {
	// обычный локальный web-сервер (dev-сервер, панель) отвечает на HTTP,
	// но CONNECT не умеет — раньше он ошибочно объявлялся прокси
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodConnect {
			http.Error(w, "no tunnels here", http.StatusMethodNotAllowed)
			return
		}
		w.Write([]byte("hello"))
	}))
	defer srv.Close()
	_, portStr, _ := net.SplitHostPort(srv.Listener.Addr().String())
	port, _ := strconv.Atoi(portStr)
	if proto, ok := classifyListener(port); ok {
		t.Fatalf("plain HTTP server must not classify as proxy, got %q", proto)
	}
}

func TestClassifyTunnel(t *testing.T) {
	cases := []struct {
		name string
		in   adapterInfo
		want string
		ok   bool
	}{
		{"ethernet", adapterInfo{IfType: 6, Description: "Intel(R) Ethernet Connection I219-V", Alias: "Ethernet"}, "", false},
		{"wifi", adapterInfo{IfType: 71, Description: "Intel(R) Wi-Fi 6 AX201", Alias: "Wi-Fi"}, "", false},
		{"virtualbox host-only", adapterInfo{IfType: 6, Description: "VirtualBox Host-Only Ethernet Adapter", Alias: "VirtualBox Host-Only Network"}, "", false},
		{"wireguard с пользовательским именем конфига", adapterInfo{IfType: 53, Description: "WireGuard Tunnel", Alias: "home-de"}, "home-de", true},
		{"cloudflare warp", adapterInfo{IfType: 53, Description: "Cloudflare WARP Interface", Alias: "CloudflareWARP"}, "CloudflareWARP", true},
		{"штатный vpn windows (sstp) — ppp", adapterInfo{IfType: 23, Description: "WAN Miniport (SSTP)", Alias: "Мой VPN"}, "Мой VPN", true},
		{"ikev2 по iftype tunnel", adapterInfo{IfType: 131, Description: "WAN Miniport (IKEv2)", Alias: "Office"}, "Office", true},
		{"sing-box поверх wintun", adapterInfo{IfType: 53, Description: "Wintun Userspace Tunnel", Alias: "sing-box"}, "sing-box", true},
		{"openvpn tap (l2, iftype ethernet)", adapterInfo{IfType: 6, Description: "TAP-Windows Adapter V9", Alias: "Ethernet 2"}, "Ethernet 2", true},
		{"teredo — служебный, не vpn", adapterInfo{IfType: 131, Description: "Teredo Tunneling Pseudo-Interface", Alias: "Teredo Tunneling Pseudo-Interface"}, "", false},
		{"isatap — служебный, не vpn", adapterInfo{IfType: 131, Description: "Microsoft ISATAP Adapter", Alias: "isatap.home"}, "", false},
		{"ключевое слово только в alias", adapterInfo{IfType: 6, Description: "Some Virtual Adapter", Alias: "openvpn-office"}, "openvpn-office", true},
		{"пустой alias — имя из описания", adapterInfo{IfType: 131, Description: "WAN Miniport (IP)", Alias: ""}, "WAN Miniport (IP)", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := classifyTunnel(tc.in)
			if ok != tc.ok || got != tc.want {
				t.Fatalf("classifyTunnel(%+v) = %q/%v, want %q/%v", tc.in, got, ok, tc.want, tc.ok)
			}
		})
	}
}

func v4p(t *testing.T, addr string, bits int) netip.Prefix {
	t.Helper()
	return netip.PrefixFrom(netip.MustParseAddr(addr), bits)
}

func TestPickDefaultRoute(t *testing.T) {
	eth := func(t *testing.T) ipv4Route {
		return ipv4Route{Dest: v4p(t, "0.0.0.0", 0), Gateway: "192.168.1.1", IfKey: "5", Metric: 25}
	}
	low := func(t *testing.T) ipv4Route {
		return ipv4Route{Dest: v4p(t, "0.0.0.0", 1), Gateway: "On-link", IfKey: "33", Metric: 5}
	}
	high := func(t *testing.T) ipv4Route {
		return ipv4Route{Dest: v4p(t, "128.0.0.0", 1), Gateway: "On-link", IfKey: "33", Metric: 5}
	}

	t.Run("обычный default", func(t *testing.T) {
		ifKey, gw, ok := pickDefaultRoute([]ipv4Route{eth(t)})
		if !ok || ifKey != "5" || gw != "192.168.1.1" {
			t.Fatalf("got %q/%q/%v", ifKey, gw, ok)
		}
	})
	t.Run("пара /1 перекрывает default (redirect-gateway def1)", func(t *testing.T) {
		ifKey, gw, ok := pickDefaultRoute([]ipv4Route{eth(t), low(t), high(t)})
		if !ok || ifKey != "33" || gw != "On-link" {
			t.Fatalf("got %q/%q/%v", ifKey, gw, ok)
		}
	})
	t.Run("одна половина /1 не перекрывает default", func(t *testing.T) {
		ifKey, _, ok := pickDefaultRoute([]ipv4Route{eth(t), low(t)})
		if !ok || ifKey != "5" {
			t.Fatalf("got %q/%v", ifKey, ok)
		}
	})
	t.Run("из двух default выигрывает меньшая метрика", func(t *testing.T) {
		wifi := ipv4Route{Dest: v4p(t, "0.0.0.0", 0), Gateway: "192.168.1.1", IfKey: "7", Metric: 50}
		ifKey, _, ok := pickDefaultRoute([]ipv4Route{wifi, eth(t)})
		if !ok || ifKey != "5" {
			t.Fatalf("got %q/%v", ifKey, ok)
		}
	})
	t.Run("пустая таблица", func(t *testing.T) {
		if _, _, ok := pickDefaultRoute(nil); ok {
			t.Fatal("empty table must not pick")
		}
	})
}

// срез реального вывода `route print -4` при поднятом OpenVPN с
// redirect-gateway def1: default остаётся на Ethernet, но пара /1 заворачивает
// весь трафик в туннель.
const routePrintDef1 = `===========================================================================
Interface List
 33...........................WireGuard Tunnel
  5...00 11 22 33 44 55 ......Intel(R) Ethernet Connection
===========================================================================

IPv4 Route Table
===========================================================================
Active Routes:
Network Destination        Netmask          Gateway       Interface  Metric
          0.0.0.0          0.0.0.0      192.168.1.1     192.168.1.42     25
          0.0.0.0        128.0.0.0         On-link         10.2.0.2      5
        128.0.0.0        128.0.0.0         On-link         10.2.0.2      5
        127.0.0.0        255.0.0.0         On-link        127.0.0.1    331
===========================================================================
Persistent Routes:
  None
`

func TestParseRoutePrintDef1(t *testing.T) {
	routes := parseRoutePrint(routePrintDef1)
	if len(routes) != 3 {
		t.Fatalf("want 3 routes (/0 и обе половины /1), got %d: %+v", len(routes), routes)
	}
	ifKey, gw, ok := pickDefaultRoute(routes)
	if !ok || ifKey != "10.2.0.2" || gw != "On-link" {
		t.Fatalf("got %q/%q/%v, want tunnel iface 10.2.0.2", ifKey, gw, ok)
	}
}
