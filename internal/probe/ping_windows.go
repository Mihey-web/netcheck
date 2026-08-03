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
			r.Status, r.Detail = StatusFail, "context deadline exceeded"
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
	ret, _, _ := procIcmpSendEcho.Call(
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
		r.Status, r.Detail = StatusFail, "timeout / unreachable"
		return r
	}
	reply := (*icmpEchoReply)(unsafe.Pointer(&buf[0]))
	if reply.Status != 0 { // 0 == IP_SUCCESS
		r.Status, r.Detail = StatusFail, fmt.Sprintf("icmp status %d", reply.Status)
		return r
	}
	// точность IcmpSendEcho — миллисекунды; для локалхоста RTT будет 0
	r.Latency = time.Duration(reply.RoundTripTime) * time.Millisecond
	r.Status = StatusOK
	return r
}
