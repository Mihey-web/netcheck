package verdict

import (
	"strings"
	"testing"

	"github.com/mihey/netcheck/internal/analyze"
	"github.com/mihey/netcheck/internal/env"
	"github.com/mihey/netcheck/internal/i18n"
	"github.com/mihey/netcheck/internal/probe"
)

// Сценарий из мокапа: интернет жив, блокировки с разными механизмами,
// x.com лежит даже через VPN, системный прокси выключен при живом листенере.
func TestBuildBlockedScenario(t *testing.T) {
	in := Input{
		Env: env.Snapshot{
			Proxies:       []env.ProxyHint{{Kind: "listener", Proto: "socks5", Addr: "127.0.0.1:10808", Active: true}},
			SystemProxyOn: false,
		},
		Layers: []LayerStatus{
			{Layer: "gateway", Status: probe.StatusOK},
			{Layer: "dns", Status: probe.StatusWarn},
			{Layer: "runet", Status: probe.StatusOK},
			{Layer: "global", Status: probe.StatusOK},
			{Layer: "blocked", Status: probe.StatusFail},
		},
		Services: []ServiceVerdict{
			{Host: "youtube.com", DirectOK: false, ProxyOK: true, Cause: analyze.CauseDPI},
			{Host: "discord.com", DirectOK: false, ProxyOK: true, Cause: analyze.CauseIPBlock},
			{Host: "instagram.com", DirectOK: false, ProxyOK: true, Cause: analyze.CauseDNSSpoof},
			{Host: "x.com", DirectOK: false, ProxyOK: false, Cause: analyze.CauseProxyToo},
		},
	}
	v := Build(i18n.RU, in)
	joined := strings.ToLower(strings.Join(append(append([]string{}, v.Lines...), v.Warnings...), " "))

	for _, want := range []string{"youtube", "discord", "instagram"} {
		if !strings.Contains(joined, want) {
			t.Errorf("verdict must mention %s: %q", want, joined)
		}
	}
	if !strings.Contains(joined, "мимо") {
		t.Error("verdict must warn that browser bypasses VPN (системный прокси выключен)")
	}
	if !strings.Contains(joined, "vpn") {
		t.Error("verdict must mention VPN for x.com case")
	}
	if len(v.Chain) != 5 {
		t.Errorf("chain must keep all 5 layers, got %d", len(v.Chain))
	}
}

func TestBuildAllOK(t *testing.T) {
	in := Input{
		Layers: []LayerStatus{
			{Layer: "gateway", Status: probe.StatusOK},
			{Layer: "dns", Status: probe.StatusOK},
			{Layer: "runet", Status: probe.StatusOK},
			{Layer: "global", Status: probe.StatusOK},
			{Layer: "blocked", Status: probe.StatusOK},
		},
	}
	v := Build(i18n.EN, in)
	if len(v.Lines) == 0 {
		t.Fatal("all-ok verdict must still say something")
	}
	if len(v.Warnings) != 0 {
		t.Fatalf("no warnings expected, got %v", v.Warnings)
	}
}

func TestBuildGatewayDown(t *testing.T) {
	in := Input{
		Layers: []LayerStatus{
			{Layer: "gateway", Status: probe.StatusFail},
			{Layer: "dns", Status: probe.StatusFail},
			{Layer: "runet", Status: probe.StatusFail},
			{Layer: "global", Status: probe.StatusFail},
			{Layer: "blocked", Status: probe.StatusFail},
		},
	}
	v := Build(i18n.RU, in)
	joined := strings.ToLower(strings.Join(v.Lines, " "))
	if !strings.Contains(joined, "роутер") && !strings.Contains(joined, "локальн") {
		t.Errorf("gateway-down verdict must point at local network: %q", joined)
	}
}
