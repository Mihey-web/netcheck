//go:build !windows

package probe

import "context"

// Ping на не-Windows платформах пока не реализован (v1 — Windows-only).
func Ping(ctx context.Context, ip string) Result {
	return Result{Target: ip, Method: "ping", Path: PathDirect, Status: StatusFail, Detail: "ping unsupported on this platform"}
}
