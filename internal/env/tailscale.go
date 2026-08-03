package env

import (
	"context"
	"encoding/json"
	"os/exec"
)

// tailscaleStatus — "" если tailscale не установлен/не запущен.
func tailscaleStatus(ctx context.Context) string {
	path, err := exec.LookPath("tailscale")
	if err != nil {
		return ""
	}
	cmd := exec.CommandContext(ctx, path, "status", "--json")
	hideConsole(cmd)
	out, err := cmd.Output()
	if err != nil {
		return ""
	}
	return ParseTailscaleStatus(out)
}

// ParseTailscaleStatus — чистый разбор вывода `tailscale status --json`.
func ParseTailscaleStatus(raw []byte) string {
	var st struct {
		BackendState string
		Peer         map[string]struct {
			HostName string
			ExitNode bool
		}
	}
	if err := json.Unmarshal(raw, &st); err != nil {
		return ""
	}
	if st.BackendState != "Running" {
		return ""
	}
	for _, p := range st.Peer {
		if p.ExitNode {
			return "exit: " + p.HostName
		}
	}
	return "connected, no exit"
}
