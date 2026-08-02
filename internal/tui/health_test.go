package tui

import (
	"net/netip"
	"strings"
	"testing"

	bridge "golan/internal/bridge"
	"golan/internal/edge"
)

func TestShowHealthPrintsPayloadFreeSummaryInMainOutput(t *testing.T) {
	m := NewModelWithSize(120, 30)
	m.workspace = workspaceMain
	m.edgeMode = string(edge.ModeRoute)
	m.edgeSession = &edge.Session{
		Config: edge.Config{
			Mode: edge.ModeRoute, Downstream: "en7", Upstream: "en0",
			Subnet: netip.MustParsePrefix("10.77.2.0/24"),
		},
		Lease: edge.Lease{
			ServerIP: netip.MustParseAddr("10.77.2.1"), ClientIP: netip.MustParseAddr("10.77.2.2"),
			Gateway: netip.MustParseAddr("10.77.2.1"),
		},
	}
	m.bridgeMode = string(bridge.ModeControlled)
	m.bridge = &bridge.Session{Mode: bridge.ModeControlled}

	m.showHealth()
	view := strings.Join(m.output, "\n")
	for _, want := range []string{
		"health: adapters=0 runtime=bridge controlled",
		"edge path=en7>en0 subnet=10.77.2.0/24",
		"dhcp server=10.77.2.1 endpoint=10.77.2.2 gateway=10.77.2.1 replies=0",
		"pf anchor=com.apple/golan.edge loaded=false enable-token-owned=false",
		"edge packets original=0 forwarded=0 blocked=0",
		"bridge mode=controlled cleanup-pending=false",
		"bridge queue high-water=0/0 overload=0",
	} {
		if !strings.Contains(view, want) {
			t.Fatalf("health missing %q:\n%s", want, view)
		}
	}
	for _, retired := range []string{"proxy", "held", "bypass"} {
		if strings.Contains(strings.ToLower(view), retired) {
			t.Fatalf("health exposed retired %q detail:\n%s", retired, view)
		}
	}
}
