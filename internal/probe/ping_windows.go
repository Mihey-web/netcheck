//go:build windows

package probe

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"syscall"
	"time"
	"unsafe"
)

var (
	iphlpapi            = syscall.NewLazyDLL("iphlpapi.dll")
	procIcmpCreateFile  = iphlpapi.NewProc("IcmpCreateFile")
	procIcmpCloseHandle = iphlpapi.NewProc("IcmpCloseHandle")
	procIcmpSendEcho    = iphlpapi.NewProc("IcmpSendEcho")
)

// icmpEchoReply — ICMP_ECHO_REPLY из ipexport.h (x64-раскладка).
type icmpEchoReply struct {
	Address       uint32
	Status        uint32
	RoundTripTime uint32
	DataSize      uint16
	Reserved      uint16
	DataPtr       uintptr
	OptTTL        uint8
	OptTos        uint8
	OptFlags      uint8
	OptSize       uint8
	_             [4]byte
	OptionsData   uintptr
}

// Ping — ICMP echo через IcmpSendEcho: работает без прав администратора,
// в отличие от raw-сокетов.
func Ping(ctx context.Context, ip string) Result {
	r := Result{Target: ip, Method: "ping", Path: PathDirect}
	parsed := net.ParseIP(ip)
	if parsed == nil || parsed.To4() == nil {
		r.Status, r.Detail = StatusFail, "not an IPv4 address"
		return r
	}
	addr := binary.LittleEndian.Uint32(parsed.To4())

	timeoutMs := uint32(3000)
	if dl, ok := ctx.Deadline(); ok {
		if left := time.Until(dl).Milliseconds(); left > 0 {
			timeoutMs = uint32(left)
		} else {
			r.Status, r.Detail, r.Outcome = StatusFail, "context deadline exceeded", OutTimeout
			return r
		}
	}

	handle, _, callErr := procIcmpCreateFile.Call()
	if handle == uintptr(syscall.InvalidHandle) {
		r.Status, r.Detail = StatusFail, "IcmpCreateFile: "+callErr.Error()
		return r
	}
	defer procIcmpCloseHandle.Call(handle)

	payload := []byte("netcheck-echo-probe")
	replySize := unsafe.Sizeof(icmpEchoReply{})
	buf := make([]byte, int(replySize)+len(payload)+8)

	start := time.Now()
	ret, _, callErr := procIcmpSendEcho.Call(
		handle,
		uintptr(addr),
		uintptr(unsafe.Pointer(&payload[0])),
		uintptr(len(payload)),
		0, // без IP-опций
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(len(buf)),
		uintptr(timeoutMs),
	)
	r.Latency = time.Since(start)
	if ret == 0 {
		// Причина лежит в GetLastError: 11010 — молчание до конца бюджета,
		// 1100x — сеть отказалась нести пакет. Прежнее «timeout / unreachable»
		// одной строкой сваливало противоположные факты в кучу.
		var code uint32
		if errno, ok := callErr.(syscall.Errno); ok {
			code = uint32(errno)
		}
		r.Status, r.Detail, r.Outcome = StatusFail, pingDetail(code), pingOutcome(code)
		return r
	}
	reply := (*icmpEchoReply)(unsafe.Pointer(&buf[0]))
	if reply.Status != 0 { // 0 == IP_SUCCESS
		// Ответивший роутер кладёт код прямо в reply.Status — класс тот же.
		r.Status, r.Detail, r.Outcome = StatusFail, pingDetail(reply.Status), pingOutcome(reply.Status)
		return r
	}
	// точность IcmpSendEcho — миллисекунды; для локалхоста RTT будет 0
	r.Latency = time.Duration(reply.RoundTripTime) * time.Millisecond
	r.Status, r.Outcome = StatusOK, OutOK
	return r
}

// pingOutcome — класс исхода по коду из ipexport.h (константы объявлены
// в trace_windows.go). Молчание и unreachable — противоположные факты:
// первое означает «пакет ушёл и не вернулся», второе — «сеть отказалась
// его нести», и диагнозы у них разные.
func pingOutcome(code uint32) Outcome {
	switch code {
	case ipReqTimedOut:
		return OutTimeout
	case ipDestNetUnreachable, ipDestHostUnreachable, ipDestProtUnreachable,
		ipDestPortUnreachable, ipDestNoRoute:
		return OutUnreach
	}
	return OutOther
}

func pingDetail(code uint32) string {
	switch pingOutcome(code) {
	case OutTimeout:
		return "timeout"
	case OutUnreach:
		return "unreachable"
	}
	return fmt.Sprintf("icmp status %d", code)
}
