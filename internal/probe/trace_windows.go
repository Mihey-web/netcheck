//go:build windows

package probe

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

// ipOptionInformation — IP_OPTION_INFORMATION из ipexport.h (x64-раскладка).
// Нужна ровно ради одного поля: TTL. Именно им трассировка и делается —
// пакет с TTL=n умирает на n-м роутере, и тот представляется в ответе.
type ipOptionInformation struct {
	TTL         uint8
	TOS         uint8
	Flags       uint8
	OptionsSize uint8
	_           [4]byte
	OptionsData uintptr
}

// Коды из ipexport.h. Их различение — весь смысл трассировки: молчание
// и явный отказ означают разное.
const (
	ipSuccess             = 0
	ipDestNetUnreachable  = 11002
	ipDestHostUnreachable = 11003
	ipDestProtUnreachable = 11004
	ipDestPortUnreachable = 11005
	ipDestNoRoute         = 11007
	ipReqTimedOut         = 11010
	ipTTLExpiredTransit   = 11013
)

// Trace — трассировка до адреса через IcmpSendEcho с заданным TTL.
// Прав администратора не требует, в отличие от raw-сокетов.
//
// Все шаги опрашиваются одновременно, а не по очереди. Последовательная
// трассировка до недостижимой цели стоила бы двадцать таймаутов подряд —
// полминуты на одну цель, при том что весь прогон укладывается в двадцать
// секунд. Параллельно это стоит один таймаут.
func Trace(ctx context.Context, ip string) ([]Hop, error) {
	parsed := net.ParseIP(ip)
	if parsed == nil || parsed.To4() == nil {
		return nil, fmt.Errorf("trace: %q не адрес IPv4", ip)
	}
	target := binary.LittleEndian.Uint32(parsed.To4())

	timeout := hopTimeout
	if dl, ok := ctx.Deadline(); ok {
		if left := time.Until(dl); left < timeout {
			timeout = left
		}
	}
	if timeout <= 0 {
		return nil, context.DeadlineExceeded
	}

	hops := make([]Hop, maxTTL)
	var wg sync.WaitGroup
	for i := range hops {
		wg.Add(1)
		go func(ttl int) {
			defer wg.Done()
			hops[ttl-1] = probeTTL(target, uint8(ttl), timeout)
		}(i + 1)
	}
	wg.Wait()

	if err := ctx.Err(); err != nil {
		return nil, err
	}
	hops = TrimHops(hops)
	// Имена роутеров спрашиваем один раз на весь маршрут и уже после
	// трассировки: на замеры они не влияют, но именно по ним потом
	// определяется, где роутер стоит на самом деле.
	FillHostnames(ctx, hops)
	return hops, nil
}

func probeTTL(target uint32, ttl uint8, timeout time.Duration) Hop {
	hop := Hop{N: int(ttl), Status: HopSilent}

	handle, _, _ := procIcmpCreateFile.Call()
	if handle == uintptr(syscall.InvalidHandle) {
		hop.Detail = "IcmpCreateFile не отработал"
		return hop
	}
	defer procIcmpCloseHandle.Call(handle)

	opts := ipOptionInformation{TTL: ttl}
	payload := []byte("netcheck-trace")
	buf := make([]byte, int(unsafe.Sizeof(icmpEchoReply{}))+len(payload)+8)

	start := time.Now()
	ret, _, _ := procIcmpSendEcho.Call(
		handle,
		uintptr(target),
		uintptr(unsafe.Pointer(&payload[0])),
		uintptr(len(payload)),
		uintptr(unsafe.Pointer(&opts)),
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(len(buf)),
		uintptr(timeout.Milliseconds()),
	)
	if ret == 0 {
		// Ответа нет вовсе. Это не обязательно обрыв: половина роутеров
		// не отвечает на ICMP из принципа.
		return hop
	}

	reply := (*icmpEchoReply)(unsafe.Pointer(&buf[0]))
	hop.IP = addrFromWin(reply.Address).String()
	hop.RTTms = int64(reply.RoundTripTime)
	if hop.RTTms == 0 {
		// Разрешение поля — целые миллисекунды, а до соседнего роутера
		// бывает быстрее. Ноль превратил бы близкий хоп в «мгновенный».
		hop.RTTms = time.Since(start).Milliseconds()
	}

	switch reply.Status {
	case ipSuccess:
		hop.Status = HopFinal
	case ipTTLExpiredTransit:
		hop.Status = HopOK
	case ipReqTimedOut:
		hop.Status, hop.IP = HopSilent, ""
	case ipDestNetUnreachable:
		hop.Status, hop.Detail = HopUnreach, "сеть недостижима"
	case ipDestHostUnreachable:
		hop.Status, hop.Detail = HopUnreach, "узел недостижим"
	case ipDestProtUnreachable, ipDestPortUnreachable:
		hop.Status, hop.Detail = HopUnreach, "порт или протокол закрыт"
	case ipDestNoRoute:
		hop.Status, hop.Detail = HopUnreach, "маршрута нет"
	default:
		hop.Status = HopUnreach
		hop.Detail = fmt.Sprintf("код ICMP %d", reply.Status)
	}
	return hop
}

// addrFromWin разбирает поле Address ответа: там четыре октета адреса
// в сетевом порядке, уложенные в машинное слово.
func addrFromWin(v uint32) netip.Addr {
	var b [4]byte
	binary.LittleEndian.PutUint32(b[:], v)
	return netip.AddrFrom4(b)
}
