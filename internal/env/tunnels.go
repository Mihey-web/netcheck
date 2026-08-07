package env

// Чистая логика детекта туннелей и маршрута по умолчанию: без syscall'ов,
// чтобы гонять её table-driven тестами на любой ОС. Платформенная обвязка
// (GetAdaptersAddresses, GetIpForwardTable2, route print) — в tunnels_windows.go.

import (
	"net"
	"net/netip"
	"strconv"
	"strings"
)

// Локальные копии констант IF_TYPE_* из iphlpapi: чистому коду нельзя тянуть
// golang.org/x/sys/windows, иначе он перестанет собираться вне Windows.
const (
	ifTypePPP    = 23  // WAN Miniport: штатный VPN Windows (SSTP/IKEv2/L2TP/PPTP)
	ifTypeTunnel = 131 // виртуальные туннели (IKEv2, но и служебные Teredo/ISATAP)
)

var tunnelKeywords = []string{"wireguard", "tailscale", "tap", "tun", "openvpn", "wintun", "vpn", "amnezia", "warp"}

// transitionKeywords — служебные IPv6-transition туннели самой Windows: их
// IfType тоже 131 (а в именах есть "tun"), но к VPN они отношения не имеют.
var transitionKeywords = []string{"teredo", "isatap", "6to4", "iphttps", "ip-https"}

func isTunnelName(name string) bool {
	low := strings.ToLower(name)
	for _, kw := range tunnelKeywords {
		if strings.Contains(low, kw) {
			return true
		}
	}
	return false
}

// adapterInfo — то, что нужно для классификации адаптера, в отрыве от winapi.
type adapterInfo struct {
	IfType      uint32 // IF_TYPE_* (131 — туннель, 23 — PPP)
	Description string // описание драйвера: "WireGuard Tunnel", "TAP-Windows Adapter V9"…
	Alias       string // имя подключения, которое видит юзер: "Ethernet", "warp-home"…
}

// classifyTunnel — является ли адаптер VPN-туннелем и под каким именем его
// показывать. Сначала IfType — он ловит штатный VPN Windows и туннели с
// пользовательскими именами конфигов, где в alias нет ни одного ключевого
// слова. Затем ключевые слова в описании драйвера (Wintun/TAP при
// «неговорящем» alias) и, как раньше, в самом alias.
func classifyTunnel(a adapterInfo) (string, bool) {
	for _, kw := range transitionKeywords {
		if strings.Contains(strings.ToLower(a.Description), kw) ||
			strings.Contains(strings.ToLower(a.Alias), kw) {
			return "", false
		}
	}
	name := a.Alias
	if name == "" {
		name = a.Description
	}
	if a.IfType == ifTypePPP || a.IfType == ifTypeTunnel {
		return name, true
	}
	if isTunnelName(a.Description) || isTunnelName(a.Alias) {
		return name, true
	}
	return "", false
}

// ipv4Route — строка таблицы маршрутов в удобном виде. IfKey — «ключ»
// интерфейса: индекс (данные из iphlpapi) либо IPv4-адрес интерфейса
// (данные из route print).
type ipv4Route struct {
	Dest    netip.Prefix
	Gateway string // IPv4 либо "On-link"
	IfKey   string
	Metric  uint32
}

var (
	v4Zero = netip.AddrFrom4([4]byte{0, 0, 0, 0})
	v4Half = netip.AddrFrom4([4]byte{128, 0, 0, 0})
)

// pickDefaultRoute — куда фактически уходит «весь трафик». Обычный случай —
// лучший по метрике 0.0.0.0/0. Но OpenVPN/sing-box (redirect-gateway def1)
// default не трогают, а добавляют пару 0.0.0.0/1 + 128.0.0.0/1: вдвоём они
// покрывают всё адресное пространство и выигрывают у /0 по длине префикса
// при любых метриках. Если пара на месте — реальный default именно она.
func pickDefaultRoute(routes []ipv4Route) (ifKey, gateway string, ok bool) {
	var def, low, high *ipv4Route
	better := func(cur, r *ipv4Route) *ipv4Route {
		if cur == nil || r.Metric < cur.Metric {
			return r
		}
		return cur
	}
	for i := range routes {
		r := &routes[i]
		switch {
		case r.Dest.Bits() == 0:
			def = better(def, r)
		case r.Dest.Bits() == 1 && r.Dest.Addr() == v4Zero:
			low = better(low, r)
		case r.Dest.Bits() == 1 && r.Dest.Addr() == v4Half:
			high = better(high, r)
		}
	}
	if low != nil && high != nil {
		// обе половины на месте; если они вдруг на разных интерфейсах —
		// берём нижнюю, точнее по таблице не скажешь
		return low.IfKey, low.Gateway, true
	}
	if def != nil {
		return def.IfKey, def.Gateway, true
	}
	return "", "", false
}

// parseRoutePrint — разбор текстового вывода `route print -4` (запасной путь
// на случай отказа iphlpapi; текст локале-хрупок, потому и запасной).
// Берём только 0.0.0.0/0 и обе половины /1; колонки: destination, netmask,
// gateway, interface, metric.
func parseRoutePrint(out string) []ipv4Route {
	var routes []ipv4Route
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(strings.TrimSpace(line))
		if len(f) < 5 {
			continue
		}
		var dest netip.Prefix
		switch {
		case f[0] == "0.0.0.0" && f[1] == "0.0.0.0":
			dest = netip.PrefixFrom(v4Zero, 0)
		case f[0] == "0.0.0.0" && f[1] == "128.0.0.0":
			dest = netip.PrefixFrom(v4Zero, 1)
		case f[0] == "128.0.0.0" && f[1] == "128.0.0.0":
			dest = netip.PrefixFrom(v4Half, 1)
		default:
			continue
		}
		// колонка interface обязана быть IPv4 — это отсекает раздел
		// persistent routes, где колонок столько же, но состав другой
		if ip := net.ParseIP(f[3]); ip == nil || ip.To4() == nil {
			continue
		}
		metric, err := strconv.Atoi(f[4])
		if err != nil {
			continue
		}
		routes = append(routes, ipv4Route{Dest: dest, Gateway: f[2], IfKey: f[3], Metric: uint32(metric)})
	}
	return routes
}
