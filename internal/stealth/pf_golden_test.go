package stealth

import (
	"net/netip"
	"os"
	"path/filepath"
	"testing"

	"golan/internal/dataplane"
	"golan/internal/edge"
	"golan/internal/policy"
	"golan/internal/traffic"
)

func TestPFCompilerGolden(t *testing.T) {
	fast, err := CompileFastBridgePF("en11", "en12", "pf-v1", []policy.Rule{{
		ID: "fast-web", Priority: 100, Enabled: true,
		Match: policy.Match{
			Modes: []dataplane.Mode{dataplane.ModeFastBridge}, Directions: []traffic.Direction{traffic.DirectionOutbound},
			IPVersions: []uint8{4}, Protocols: []uint8{6}, DstPorts: policy.PortSet{Values: []uint16{80, 443}},
		},
		Actions: []policy.Action{{Kind: policy.ActionAllow}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	nat, err := CompileNATPF("bridge7", "pf-v1", []policy.Rule{{
		ID: "nat-admin", Priority: 100, Enabled: true,
		Match: policy.Match{
			Modes: []dataplane.Mode{dataplane.ModeNAT}, Directions: []traffic.Direction{traffic.DirectionOutbound},
			IPVersions: []uint8{4}, Protocols: []uint8{6}, DstPorts: policy.PortSet{Values: []uint16{22}},
		},
		Actions: []policy.Action{{Kind: policy.ActionBlock}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	edgePF, err := edge.CompilePFWithPolicy(edge.Config{
		Mode: edge.ModeRoute, Downstream: "en7", Upstream: "en0",
		Subnet: netip.MustParsePrefix("10.77.2.0/24"),
		PortForwards: []edge.PortForward{{
			Protocol: "tcp", ListenPort: 8443,
			TargetIP: netip.MustParseAddr("10.77.2.2"), TargetPort: 443,
		}},
	}, "pf-v1", []policy.Rule{{
		ID: "edge-admin", Priority: 100, Enabled: true,
		Match: policy.Match{
			Modes: []dataplane.Mode{dataplane.ModeEdgeRoute}, Directions: []traffic.Direction{traffic.DirectionInbound},
			IPVersions: []uint8{4}, Protocols: []uint8{6}, DstPorts: policy.PortSet{Values: []uint16{22}},
		},
		Actions: []policy.Action{{Kind: policy.ActionBlock}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	actual := "[fast-bridge]\n" + fast + "[nat]\n" + nat + "[edge-route]\n" + edgePF
	goldenPath := filepath.Join("testdata", "pf-v1.golden.txt")
	expected, err := os.ReadFile(goldenPath)
	if err != nil {
		t.Fatalf("read PF golden %s: %v\nreview and add this expected content:\n%s", goldenPath, err, actual)
	}
	if actual != string(expected) {
		t.Fatalf("PF compiler output changed; review the generated anchor diff\nactual:\n%s", actual)
	}
}
