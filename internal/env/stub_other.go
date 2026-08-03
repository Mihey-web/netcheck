//go:build !windows

package env

import "os/exec"

func systemProxy() (bool, string) { return false, "" }

func hideConsole(cmd *exec.Cmd) {}

func routeInfo() (adapter, gateway, ip string, tunnels []string, viaTunnel bool) {
	return "", "", "", nil, false
}
