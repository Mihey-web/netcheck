//go:build windows

package env

import (
	"net"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
)

var tunnelKeywords = []string{"wireguard", "tailscale", "tap", "tun", "openvpn", "wintun", "vpn", "amnezia"}

func isTunnelName(name string) bool {
	low := strings.ToLower(name)
	for _, kw := range tunnelKeywords {
		if strings.Contains(low, kw) {
			return true
		}
	}
	return false
}

func hideConsole(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x08000000} // CREATE_NO_WINDOW
}

// routeInfo — активный адаптер, шлюз и IP по маршруту 0.0.0.0, плюс список
// поднятых туннель-адаптеров и признак «default route уходит в туннель».
func routeInfo() (adapter, gateway, ip string, tunnels []string, viaTunnel bool) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return
	}
	for _, ifc := range ifaces {
		if ifc.Flags&net.FlagUp != 0 && ifc.Flags&net.FlagLoopback == 0 && isTunnelName(ifc.Name) {
			tunnels = append(tunnels, ifc.Name)
		}
	}

	gateway, ifaceIP := defaultRoute()
	if ifaceIP == "" {
		return
	}
	ip = ifaceIP
	for _, ifc := range ifaces {
		addrs, err := ifc.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			if ipn, ok := a.(*net.IPNet); ok && ipn.IP.To4() != nil && ipn.IP.String() == ifaceIP {
				adapter = ifc.Name
				viaTunnel = isTunnelName(ifc.Name)
				return
			}
		}
	}
	return
}

// defaultRoute парсит `route print -4 0.0.0.0`: среди строк
// "0.0.0.0  0.0.0.0  <gateway>  <ifaceIP>  <metric>" берёт лучшую по метрике.
func defaultRoute() (gateway, ifaceIP string) {
	cmd := exec.Command("route", "print", "-4", "0.0.0.0")
	hideConsole(cmd)
	out, err := cmd.Output()
	if err != nil {
		return "", ""
	}
	best := int(^uint(0) >> 1)
	for _, line := range strings.Split(string(out), "\n") {
		f := strings.Fields(strings.TrimSpace(line))
		if len(f) >= 5 && f[0] == "0.0.0.0" && f[1] == "0.0.0.0" {
			metric, err := strconv.Atoi(f[4])
			if err != nil {
				continue
			}
			// "On-link" вместо шлюза бывает у туннелей — оставляем как есть
			if metric < best {
				best, gateway, ifaceIP = metric, f[2], f[3]
			}
		}
	}
	return
}
