//go:build windows

package env

import (
	"net"
	"net/netip"
	"os/exec"
	"sort"
	"strconv"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

func hideConsole(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x08000000} // CREATE_NO_WINDOW
}

// winAdapter — адаптер из GetAdaptersAddresses: то, что нужно для
// классификации туннелей и привязки маршрута к интерфейсу.
type winAdapter struct {
	info   adapterInfo
	ip     string // первый IPv4 unicast
	up     bool
	metric uint32 // метрика интерфейса; Windows складывает её с метрикой маршрута
}

// winAdapters — все адаптеры по индексу интерфейса; nil при ошибке API.
// Раньше туннели искали подстрокой в alias из net.Interfaces() — так не видно
// Cloudflare WARP, WireGuard с пользовательским именем конфига и штатный VPN
// Windows. GetAdaptersAddresses даёт IfType и описание драйвера.
func winAdapters() map[uint32]*winAdapter {
	const flags = windows.GAA_FLAG_SKIP_ANYCAST | windows.GAA_FLAG_SKIP_MULTICAST | windows.GAA_FLAG_SKIP_DNS_SERVER
	size := uint32(16 * 1024)
	var first *windows.IpAdapterAddresses
	for i := 0; i < 3; i++ { // буфер мог не влезть — API возвращает нужный размер
		buf := make([]byte, size)
		p := (*windows.IpAdapterAddresses)(unsafe.Pointer(&buf[0]))
		err := windows.GetAdaptersAddresses(windows.AF_INET, flags, 0, p, &size)
		if err == nil {
			first = p
			break
		}
		if err != windows.ERROR_BUFFER_OVERFLOW {
			return nil
		}
	}
	if first == nil {
		return nil
	}
	ads := make(map[uint32]*winAdapter)
	for aa := first; aa != nil; aa = aa.Next {
		if aa.IfType == windows.IF_TYPE_SOFTWARE_LOOPBACK {
			continue
		}
		a := &winAdapter{
			info: adapterInfo{
				IfType:      aa.IfType,
				Description: windows.UTF16PtrToString(aa.Description),
				Alias:       windows.UTF16PtrToString(aa.FriendlyName),
			},
			up:     aa.OperStatus == windows.IfOperStatusUp,
			metric: aa.Ipv4Metric,
		}
		for ua := aa.FirstUnicastAddress; ua != nil; ua = ua.Next {
			if ip := ua.Address.IP(); ip != nil {
				if v4 := ip.To4(); v4 != nil {
					a.ip = v4.String()
					break
				}
			}
		}
		ads[aa.IfIndex] = a
	}
	return ads
}

// sockaddrV4 — IPv4 из SOCKADDR_INET.
func sockaddrV4(sa *windows.RawSockaddrInet) (netip.Addr, bool) {
	if sa.Family != windows.AF_INET {
		return netip.Addr{}, false
	}
	sa4 := (*windows.RawSockaddrInet4)(unsafe.Pointer(sa))
	return netip.AddrFrom4(sa4.Addr), true
}

// forwardTable — маршруты 0.0.0.0/0 и /1 из GetIpForwardTable2. Текстовый
// route print такое не выдержал бы: команда с фильтром 0.0.0.0 не показывает
// 128.0.0.0/1, а без фильтра вывод локале-зависим. nil при ошибке API —
// тогда сработает запасной parseRoutePrint.
func forwardTable(ads map[uint32]*winAdapter) []ipv4Route {
	var tbl *windows.MibIpForwardTable2
	if err := windows.GetIpForwardTable2(windows.AF_INET, &tbl); err != nil {
		return nil
	}
	defer windows.FreeMibTable(unsafe.Pointer(tbl))
	var routes []ipv4Route
	for _, row := range tbl.Rows() {
		bits := row.DestinationPrefix.PrefixLength
		if bits > 1 {
			continue // интересуют только default и трюк с половинами /1
		}
		dest, ok := sockaddrV4(&row.DestinationPrefix.Prefix)
		if !ok {
			if bits != 0 {
				continue
			}
			dest = v4Zero // у 0.0.0.0/0 семейство адреса бывает не проставлено
		}
		a := ads[row.InterfaceIndex]
		if a == nil || !a.up {
			continue // маршрут на выключенном интерфейсе трафик не понесёт
		}
		gw := "On-link" // как в route print: без next hop — доставка напрямую
		if nh, ok := sockaddrV4(&row.NextHop); ok && nh != v4Zero {
			gw = nh.String()
		}
		routes = append(routes, ipv4Route{
			Dest:    netip.PrefixFrom(dest, int(bits)),
			Gateway: gw,
			IfKey:   strconv.FormatUint(uint64(row.InterfaceIndex), 10),
			// эффективная метрика = маршрут + интерфейс, так считает и Windows
			Metric: row.Metric + a.metric,
		})
	}
	return routes
}

// routePrintRoutes — запасной текстовый путь. Без фильтра по назначению:
// `route print -4 0.0.0.0` не показал бы 128.0.0.0/1.
func routePrintRoutes() []ipv4Route {
	cmd := exec.Command("route", "print", "-4")
	hideConsole(cmd)
	out, err := cmd.Output()
	if err != nil {
		return nil
	}
	return parseRoutePrint(string(out))
}

// routeInfo — активный адаптер, шлюз и IP по фактическому маршруту по
// умолчанию, плюс список туннель-адаптеров и признак «default уходит в туннель».
func routeInfo() (adapter, gateway, ip string, tunnels []string, viaTunnel bool) {
	ads := winAdapters()
	if ads == nil {
		return legacyRouteInfo()
	}
	for _, a := range ads {
		if !a.up {
			continue
		}
		if name, ok := classifyTunnel(a.info); ok {
			tunnels = append(tunnels, name)
		}
	}
	sort.Strings(tunnels) // порядок обхода map случаен, а список показывают юзеру

	routes := forwardTable(ads)
	if routes == nil {
		routes = routePrintRoutes()
	}
	ifKey, gw, ok := pickDefaultRoute(routes)
	if !ok {
		return
	}
	gateway = gw
	if idx, err := strconv.ParseUint(ifKey, 10, 32); err == nil {
		// ключ из forwardTable — индекс интерфейса
		if a := ads[uint32(idx)]; a != nil {
			adapter, ip = a.info.Alias, a.ip
			_, viaTunnel = classifyTunnel(a.info)
		}
		return
	}
	// ключ из route print — IPv4-адрес интерфейса
	ip = ifKey
	for _, a := range ads {
		if a.ip == ip {
			adapter = a.info.Alias
			_, viaTunnel = classifyTunnel(a.info)
			break
		}
	}
	return
}

// legacyRouteInfo — путь на случай отказа GetAdaptersAddresses (не должен
// случаться, но снимок окружения важнее красоты): старый детект по
// alias-именам из net.Interfaces + текстовый route print.
func legacyRouteInfo() (adapter, gateway, ip string, tunnels []string, viaTunnel bool) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return
	}
	for _, ifc := range ifaces {
		if ifc.Flags&net.FlagUp != 0 && ifc.Flags&net.FlagLoopback == 0 && isTunnelName(ifc.Name) {
			tunnels = append(tunnels, ifc.Name)
		}
	}
	ifKey, gw, ok := pickDefaultRoute(routePrintRoutes())
	if !ok {
		return
	}
	gateway, ip = gw, ifKey
	for _, ifc := range ifaces {
		addrs, err := ifc.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			if ipn, ok := a.(*net.IPNet); ok && ipn.IP.To4() != nil && ipn.IP.String() == ip {
				adapter = ifc.Name
				viaTunnel = isTunnelName(ifc.Name)
				return
			}
		}
	}
	return
}
