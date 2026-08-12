//go:build darwin && golan_privileged

package hardwaretest

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/gopacket/pcapgo"

	"golan/internal/adapters"
	"golan/internal/bridge"
	"golan/internal/dataplane"
	"golan/internal/edge"
	"golan/internal/policy"
	"golan/internal/stealth"
	"golan/internal/traffic"
)

func TestPrivilegedMacOSHardware(t *testing.T) {
	cfg, err := loadConfig(os.Getenv)
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.Enabled {
		t.Skip("privileged macOS hardware suite is not explicitly enabled")
	}
	if os.Geteuid() != 0 {
		t.Fatal("privileged macOS hardware suite must run as root")
	}

	inventory := preflightInventory(t, cfg)
	for _, candidate := range cfg.Cases {
		candidate := candidate
		t.Run(string(candidate), func(t *testing.T) {
			switch candidate {
			case casePFSyntax:
				runPFSyntax(t, cfg)
			case caseFast:
				runFast(t, cfg, inventory, false)
			case caseFastDiscovery:
				runFast(t, cfg, inventory, true)
			case caseControlled:
				runControlled(t, cfg, inventory)
			case caseNAT:
				runNAT(t, cfg, inventory)
			case caseEdgeRoute:
				runEdge(t, cfg, inventory, edge.ModeRoute)
			case caseEdgeForward:
				runEdgePortForward(t, cfg, inventory)
			default:
				t.Fatalf("unhandled hardware case %q", candidate)
			}
		})
	}
}

type inventory struct {
	byName       map[string]adapters.Adapter
	defaultRoute string
}

func preflightInventory(t *testing.T, cfg config) inventory {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	items, err := adapters.Discover(ctx)
	if err != nil {
		t.Fatalf("discover macOS adapters: %v", err)
	}
	result := inventory{byName: make(map[string]adapters.Adapter, len(items))}
	for _, item := range items {
		result.byName[item.Name] = item
	}
	route, routeErr := edge.DiscoverDefaultRoute(ctx)
	if routeErr == nil {
		result.defaultRoute = route.Interface
	}

	live := selectedLiveCases(cfg.Cases)
	if live.inline {
		host := requirePhysicalAdapter(t, result, cfg.Host, "host")
		sw := requirePhysicalAdapter(t, result, cfg.Switch, "switch")
		if strings.EqualFold(host.HardwarePort, sw.HardwarePort) || strings.EqualFold(host.NetworkService, sw.NetworkService) || strings.EqualFold(host.MAC, sw.MAC) {
			t.Fatal("host and switch adapters must have distinct hardware ports, network services, and MAC addresses")
		}
		if !cfg.AllowDefaultRoute && result.defaultRoute != "" && (strings.EqualFold(cfg.Host, result.defaultRoute) || strings.EqualFold(cfg.Switch, result.defaultRoute)) {
			t.Fatalf("inline adapter is the default route %s; set %s=true only in an intentionally isolated lab", result.defaultRoute, envAllowDefaultRoute)
		}
	}
	if live.edge {
		downstream := requirePhysicalAdapter(t, result, cfg.Downstream, "downstream")
		if downstream.IsUp {
			t.Fatalf("downstream adapter %s must begin administratively down so edge cleanup can prove restoration", cfg.Downstream)
		}
		serviceState, err := networkServiceState(ctx, downstream.NetworkService)
		if err != nil {
			t.Fatalf("read downstream network service: %v", err)
		}
		if serviceState != "disabled" {
			t.Fatalf("downstream network service %s must begin disabled", downstream.NetworkService)
		}
		if result.defaultRoute != "" && strings.EqualFold(cfg.Downstream, result.defaultRoute) {
			t.Fatalf("downstream adapter %s cannot own the default route", cfg.Downstream)
		}
		if cfg.Upstream != "" && !strings.EqualFold(cfg.Upstream, "auto") {
			requireAdapter(t, result, cfg.Upstream, "upstream")
		}
	}
	return result
}

type selectedCases struct {
	inline bool
	edge   bool
}

func selectedLiveCases(cases []hardwareCase) selectedCases {
	var result selectedCases
	for _, candidate := range cases {
		switch candidate {
		case caseFast, caseFastDiscovery, caseControlled, caseNAT:
			result.inline = true
		case caseEdgeRoute, caseEdgeForward:
			result.edge = true
		}
	}
	return result
}

func requirePhysicalAdapter(t *testing.T, inventory inventory, name, role string) adapters.Adapter {
	t.Helper()
	item := requireAdapter(t, inventory, name, role)
	if item.HardwarePort == "" {
		t.Fatalf("%s adapter %s has no macOS hardware-port mapping", role, name)
	}
	if item.NetworkService == "" {
		t.Fatalf("%s adapter %s has no macOS network-service mapping", role, name)
	}
	if item.Kind == "wifi" {
		t.Fatalf("%s adapter %s is Wi-Fi; a wired Ethernet boundary is required", role, name)
	}
	mac, err := net.ParseMAC(item.MAC)
	if err != nil || len(mac) != 6 || mac[0]&1 != 0 || isZeroMAC(mac) {
		t.Fatalf("%s adapter %s has no usable unicast MAC", role, name)
	}
	return item
}

func requireAdapter(t *testing.T, inventory inventory, name, role string) adapters.Adapter {
	t.Helper()
	item, ok := inventory.byName[name]
	if !ok {
		t.Fatalf("%s adapter %s is not in live discovery", role, name)
	}
	return item
}

func runPFSyntax(t *testing.T, cfg config) {
	t.Helper()
	host, sw := cfg.Host, cfg.Switch
	if host == "" {
		host = "en98"
	}
	if sw == "" {
		sw = "en99"
	}
	rule := policy.Rule{
		ID: "hardware-pf", Name: "Hardware PF syntax", Priority: 100, Enabled: true, Revision: 1,
		Match: policy.Match{
			Directions: []traffic.Direction{traffic.DirectionOutbound}, IPVersions: []uint8{4},
			Protocols: []uint8{6}, DstPorts: policy.PortSet{Values: []uint16{443}},
		},
		Actions: []policy.Action{{Kind: policy.ActionAllow}},
	}
	fastRule := rule
	fastRule.Match.Modes = []dataplane.Mode{dataplane.ModeFastBridge}
	fastRules, err := stealth.CompileFastBridgePF(host, sw, "hardware-pf", []policy.Rule{fastRule})
	if err != nil {
		t.Fatal(err)
	}
	natRule := rule
	natRule.Match.Modes = []dataplane.Mode{dataplane.ModeNAT}
	natRules, err := stealth.CompileNATPF("bridge0", "hardware-pf", []policy.Rule{natRule})
	if err != nil {
		t.Fatal(err)
	}
	downstream, upstream := cfg.Downstream, cfg.Upstream
	if downstream == "" {
		downstream = "en97"
	}
	if upstream == "" || strings.EqualFold(upstream, "auto") {
		upstream = "en96"
	}
	edgeRule := rule
	edgeRule.Match.Modes = []dataplane.Mode{dataplane.ModeEdgeRoute}
	edgeRules, err := edge.CompilePFWithPolicy(edge.Config{
		Mode: edge.ModeRoute, Downstream: downstream, Upstream: upstream,
		Subnet: netip.MustParsePrefix("10.77.254.0/24"),
		PortForwards: []edge.PortForward{{
			Protocol: "tcp", ListenPort: 18443,
			TargetIP: netip.MustParseAddr("10.77.254.2"), TargetPort: 443,
		}},
	}, "hardware-pf", []policy.Rule{edgeRule})
	if err != nil {
		t.Fatal(err)
	}
	vpnRules, err := edge.CompilePFWithPolicy(edge.Config{
		Mode: edge.ModeRoute, Downstream: downstream, Upstream: "utun98", Egress: edge.EgressVPN,
		VPNDestinations: []netip.Prefix{netip.MustParsePrefix("10.20.0.0/16")},
		VPNRouteAddress: netip.MustParseAddr("10.8.0.2"),
		Subnet:          netip.MustParsePrefix("10.77.253.0/24"),
		DNS:             []netip.Addr{netip.MustParseAddr("10.20.0.53")},
	}, "hardware-pf", []policy.Rule{edgeRule})
	if err != nil {
		t.Fatal(err)
	}
	vpnLoopbackDNSRules, err := edge.CompilePF(edge.Config{
		Mode: edge.ModeRoute, Downstream: downstream, Upstream: "utun98", Egress: edge.EgressVPN,
		VPNDestinations: []netip.Prefix{netip.MustParsePrefix("198.51.100.0/24")},
		VPNRouteAddress: netip.MustParseAddr("10.8.0.1"),
		EgressMTU:       1280,
		Subnet:          netip.MustParsePrefix("10.77.252.0/24"),
		DNS:             []netip.Addr{netip.MustParseAddr("127.0.0.1")},
	})
	if err != nil {
		t.Fatal(err)
	}
	for name, rules := range map[string]string{
		"fast bridge":                 fastRules,
		"nat":                         natRules,
		"edge route":                  edgeRules,
		"edge VPN egress":             vpnRules,
		"edge VPN loopback DNS relay": vpnLoopbackDNSRules,
	} {
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			command := exec.CommandContext(ctx, "pfctl", "-vnf", "-")
			command.Stdin = strings.NewReader(rules)
			output, err := command.CombinedOutput()
			if err != nil {
				t.Fatalf("pfctl syntax validation: %v (%s)", err, strings.TrimSpace(string(output)))
			}
		})
	}
}

func runFast(t *testing.T, cfg config, inventory inventory, discovery bool) {
	t.Helper()
	host := bridgeAdapter(requirePhysicalAdapter(t, inventory, cfg.Host, "host"), "host")
	sw := bridgeAdapter(requirePhysicalAdapter(t, inventory, cfg.Switch, "switch"), "switch")
	if !discovery {
		host.TargetMAC = cfg.TargetMAC
	}
	baselines := snapshotBaselines(t, host.Name, sw.Name)
	session, err := bridge.StartModeWithPolicyOptions(host, sw, "", bridge.ModeFast, bridge.DefaultEAPOLPolicy(), "hardware-live", inlineHardwareRules(), bridge.DefaultControlledOptions())
	if err != nil {
		t.Fatal(err)
	}
	stopped := false
	defer func() {
		if !stopped {
			if stopErr := session.Stop(); stopErr != nil {
				t.Errorf("emergency fast bridge cleanup: %v", stopErr)
			}
		}
	}()
	monitor := monitorBridge(session.Events)
	waitForActive(t, monitor, cfg.ActiveTimeout)
	waitForExercise(t, monitor.stopped, cfg.Duration)
	if err := session.Stop(); err != nil {
		t.Fatalf("stop fast bridge: %v", err)
	}
	stopped = true
	if session.CleanupPending() {
		t.Fatal("fast bridge reports cleanup pending")
	}
	verifyRestored(t, baselines)
	stats := verifyFastArtifacts(t, session.Dir, cfg)
	if discovery && stats.packets < cfg.MinPackets {
		t.Fatalf("first-trigger capture packets=%d want at least %d", stats.packets, cfg.MinPackets)
	}
	t.Logf("fast bridge artifacts=%s packets=%d eapol=%d vlan=%d", session.Dir, stats.packets, stats.eapol, stats.vlan)
}

func runControlled(t *testing.T, cfg config, inventory inventory) {
	t.Helper()
	host := bridgeAdapter(requirePhysicalAdapter(t, inventory, cfg.Host, "host"), "host")
	sw := bridgeAdapter(requirePhysicalAdapter(t, inventory, cfg.Switch, "switch"), "switch")
	baselines := snapshotBaselines(t, host.Name, sw.Name)
	session, err := bridge.StartModeWithPolicyOptions(host, sw, "", bridge.ModeControlled, bridge.DefaultEAPOLPolicy(), "", nil, bridge.DefaultControlledOptions())
	if err != nil {
		t.Fatal(err)
	}
	stopped := false
	defer func() {
		if !stopped {
			if stopErr := session.Stop(); stopErr != nil {
				t.Errorf("emergency controlled bridge cleanup: %v", stopErr)
			}
		}
	}()
	monitor := monitorBridge(session.Events)
	waitForActive(t, monitor, cfg.ActiveTimeout)
	waitForExercise(t, monitor.stopped, cfg.Duration)
	stats := session.ControlledStats()
	if err := session.Stop(); err != nil {
		t.Fatalf("stop controlled bridge: %v", err)
	}
	stopped = true
	if session.CleanupPending() {
		t.Fatal("controlled bridge reports cleanup pending")
	}
	verifyRestored(t, baselines)
	verifyControlledArtifacts(t, session.Dir, cfg, stats)
	t.Logf("controlled bridge artifacts=%s original=%d forwarded=%d blocked=%d", session.Dir, stats.OriginalPackets, stats.ForwardedPackets, stats.BlockedPackets)
}

func runNAT(t *testing.T, cfg config, inventory inventory) {
	t.Helper()
	host := bridgeAdapter(requirePhysicalAdapter(t, inventory, cfg.Host, "host"), "host")
	host.TargetMAC = cfg.TargetMAC
	sw := bridgeAdapter(requirePhysicalAdapter(t, inventory, cfg.Switch, "switch"), "switch")
	baselines := snapshotBaselines(t, host.Name, sw.Name)
	session, err := bridge.StartModeWithPolicyOptions(host, sw, "", bridge.ModeFast, bridge.DefaultEAPOLPolicy(), "hardware-live", inlineHardwareRules(), bridge.DefaultControlledOptions())
	if err != nil {
		t.Fatal(err)
	}
	stopped := false
	defer func() {
		if !stopped {
			if stopErr := session.Stop(); stopErr != nil {
				t.Errorf("emergency nat cleanup: %v", stopErr)
			}
		}
	}()
	monitor := monitorBridge(session.Events)
	waitForActive(t, monitor, cfg.ActiveTimeout)
	nat := bridge.NATConfig{
		MAC: cfg.TargetMAC, IP: cfg.NATIP, CIDR: cfg.NATCIDR,
		Gateway: cfg.NATGateway, DNS: cfg.NATDNS,
	}
	if cfg.NATIP == "" {
		nat.DHCP = "auto"
	}
	if err := session.StartNAT(nat); err != nil {
		t.Fatal(err)
	}
	snapshot := session.NATSnapshot()
	if !snapshot.Active || !snapshot.PFEndpointRules || !snapshot.PFRestorationOwned || !snapshot.L2EndpointRules || !snapshot.L2RestorationOwned || !snapshot.ProxyActive || !snapshot.ProxyStopOwned {
		t.Fatalf("incomplete active nat ownership: %#v", snapshot)
	}
	waitForExercise(t, monitor.stopped, cfg.Duration)
	if err := session.StopNAT(); err != nil {
		t.Fatalf("stop nat: %v", err)
	}
	if snapshot := session.NATSnapshot(); snapshot.Active || snapshot.CleanupPending || snapshot.PFRestorationOwned || snapshot.L2RestorationOwned || snapshot.ProxyStopOwned {
		t.Fatalf("nat cleanup remains owned: %#v", snapshot)
	}
	if err := session.Stop(); err != nil {
		t.Fatalf("stop nat bridge: %v", err)
	}
	stopped = true
	if session.CleanupPending() {
		t.Fatal("nat bridge reports cleanup pending")
	}
	verifyRestored(t, baselines)
	stats := verifyFastArtifacts(t, session.Dir, cfg)
	t.Logf("nat artifacts=%s packets=%d eapol=%d vlan=%d", session.Dir, stats.packets, stats.eapol, stats.vlan)
}

func runEdge(t *testing.T, cfg config, inventory inventory, mode edge.Mode) {
	t.Helper()
	request := resolveEdgeConfig(t, cfg, inventory, mode)
	runEdgeConfig(t, cfg, request, mode, "", 0)
}

func runEdgePortForward(t *testing.T, cfg config, inventory inventory) {
	t.Helper()
	request := resolveEdgeConfig(t, cfg, inventory, edge.ModeRoute)
	lease, err := edge.LeaseForSubnet(request.Subnet, request.DNS)
	if err != nil {
		t.Fatal(err)
	}
	request.PortForwards = []edge.PortForward{{
		Protocol: cfg.PortForwardProto, ListenPort: cfg.PortForwardListen,
		TargetIP: lease.ClientIP, TargetPort: cfg.PortForwardTarget,
	}}
	runEdgeConfig(t, cfg, request, edge.ModeRoute, cfg.PortForwardProto, cfg.PortForwardTarget)
}

func resolveEdgeConfig(t *testing.T, cfg config, inventory inventory, mode edge.Mode) edge.Config {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	request, err := edge.AutoConfig(ctx, cfg.Downstream, cfg.Upstream, mode)
	cancel()
	if err != nil {
		t.Fatal(err)
	}
	requireAdapter(t, inventory, request.Upstream, "resolved upstream")
	return request
}

func runEdgeConfig(t *testing.T, cfg config, request edge.Config, mode edge.Mode, expectedProtocol string, expectedPort uint16) {
	t.Helper()
	baselines := snapshotBaselines(t, request.Downstream, request.Upstream)
	session, err := edge.Start(request, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	stopped := false
	defer func() {
		if !stopped {
			if stopErr := session.Stop(); stopErr != nil {
				t.Errorf("emergency edge cleanup: %v", stopErr)
			}
		}
	}()
	monitor := monitorEdge(session.Events)
	waitForActive(t, monitor, cfg.ActiveTimeout)
	waitForExercise(t, monitor.stopped, cfg.Duration)
	stats := session.Stats()
	if err := session.Stop(); err != nil {
		t.Fatalf("stop edge: %v", err)
	}
	stopped = true
	if session.CleanupPending() || session.Health().CleanupPending {
		t.Fatal("edge session reports cleanup pending")
	}
	verifyRestored(t, baselines)
	verifyEdgeArtifacts(t, session.Dir, cfg, mode, stats, expectedProtocol, expectedPort)
	t.Logf("edge %s artifacts=%s original=%d forwarded=%d dhcp=%d", mode, session.Dir, stats.OriginalPackets, stats.ForwardedPackets, stats.DHCPReplies)
}

func bridgeAdapter(item adapters.Adapter, role string) bridge.Adapter {
	return bridge.Adapter{Name: item.Name, Role: role, HardwarePort: item.HardwarePort, NetworkService: item.NetworkService, LocalMAC: item.MAC}
}

func inlineHardwareRules() []policy.Rule {
	base := policy.Rule{
		Name: "Hardware live PF", Priority: 100, Enabled: true, Revision: 1,
		Match: policy.Match{
			Directions: []traffic.Direction{traffic.DirectionOutbound}, IPVersions: []uint8{4},
			Protocols: []uint8{6}, DstPorts: policy.PortSet{Values: []uint16{443}},
		},
		Actions: []policy.Action{{Kind: policy.ActionAllow}},
	}
	fast := base
	fast.ID = "hardware-fast-pf"
	fast.Match.Modes = []dataplane.Mode{dataplane.ModeFastBridge}
	nat := base
	nat.ID = "hardware-nat-pf"
	nat.Match.Modes = []dataplane.Mode{dataplane.ModeNAT}
	return []policy.Rule{fast, nat}
}

type eventMonitor struct {
	active  <-chan error
	stopped <-chan error
}

func monitorBridge(events <-chan bridge.Event) eventMonitor {
	return monitorEvents(events,
		func(event bridge.Event) error {
			if event.Kind == bridge.KindError {
				return event.Err
			}
			return nil
		},
		func(event bridge.Event) bool {
			return event.Kind == bridge.KindState && event.State == "active"
		},
		"bridge",
	)
}

func monitorEdge(events <-chan edge.Event) eventMonitor {
	return monitorEvents(events,
		func(event edge.Event) error {
			if event.Kind == edge.KindError {
				return event.Err
			}
			return nil
		},
		func(event edge.Event) bool {
			return event.Kind == edge.KindState && event.State == "active"
		},
		"edge",
	)
}

func monitorEvents[T any](events <-chan T, eventError func(T) error, isActive func(T) bool, label string) eventMonitor {
	active := make(chan error, 1)
	stopped := make(chan error, 1)
	go func() {
		var runtimeErr error
		activeSent := false
		for event := range events {
			if err := eventError(event); err != nil {
				runtimeErr = errors.Join(runtimeErr, err)
			}
			if !activeSent && isActive(event) {
				active <- nil
				activeSent = true
			}
		}
		if !activeSent {
			if runtimeErr == nil {
				runtimeErr = fmt.Errorf("%s stopped before active state", label)
			}
			active <- runtimeErr
		}
		stopped <- runtimeErr
	}()
	return eventMonitor{active: active, stopped: stopped}
}

func waitForActive(t *testing.T, monitor eventMonitor, timeout time.Duration) {
	t.Helper()
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case err := <-monitor.active:
		if err != nil {
			t.Fatalf("session did not become active: %v", err)
		}
	case <-timer.C:
		t.Fatalf("session did not become active within %s", timeout)
	}
}

func waitForExercise(t *testing.T, stopped <-chan error, duration time.Duration) {
	t.Helper()
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case err := <-stopped:
		if err == nil {
			err = fmt.Errorf("session stopped unexpectedly")
		}
		t.Fatalf("session ended during hardware exercise: %v", err)
	case <-timer.C:
	}
}

type adapterBaseline struct {
	Name           string
	HardwarePort   string
	NetworkService string
	MAC            string
	Up             bool
	ServiceState   string
}

func snapshotBaselines(t *testing.T, names ...string) []adapterBaseline {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	items, err := adapters.Discover(ctx)
	if err != nil {
		t.Fatalf("snapshot adapters: %v", err)
	}
	byName := make(map[string]adapters.Adapter, len(items))
	for _, item := range items {
		byName[item.Name] = item
	}
	result := make([]adapterBaseline, 0, len(names))
	for _, name := range names {
		item, ok := byName[name]
		if !ok {
			t.Fatalf("snapshot adapter %s: not discovered", name)
		}
		state, err := networkServiceState(ctx, item.NetworkService)
		if err != nil {
			t.Fatalf("snapshot network service for %s: %v", name, err)
		}
		result = append(result, adapterBaseline{
			Name: name, HardwarePort: item.HardwarePort, NetworkService: item.NetworkService, MAC: strings.ToLower(item.MAC),
			Up: item.IsUp, ServiceState: state,
		})
	}
	return result
}

func verifyRestored(t *testing.T, expected []adapterBaseline) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	var lastErr error
	for {
		lastErr = compareBaselines(expected)
		if lastErr == nil {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("adapter restoration was not observed: %v", lastErr)
		}
		time.Sleep(250 * time.Millisecond)
	}
}

func compareBaselines(expected []adapterBaseline) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	items, err := adapters.Discover(ctx)
	if err != nil {
		return err
	}
	byName := make(map[string]adapters.Adapter, len(items))
	for _, item := range items {
		byName[item.Name] = item
	}
	for _, baseline := range expected {
		item, ok := byName[baseline.Name]
		if !ok {
			return fmt.Errorf("adapter %s is absent", baseline.Name)
		}
		state, err := networkServiceState(ctx, baseline.NetworkService)
		if err != nil {
			return err
		}
		if !strings.EqualFold(item.HardwarePort, baseline.HardwarePort) || !strings.EqualFold(item.NetworkService, baseline.NetworkService) || !strings.EqualFold(item.MAC, baseline.MAC) || item.IsUp != baseline.Up || state != baseline.ServiceState {
			return fmt.Errorf("adapter %s state differs: hardware=%q network-service=%q mac=%q up=%t service-state=%q", baseline.Name, item.HardwarePort, item.NetworkService, item.MAC, item.IsUp, state)
		}
	}
	return nil
}

func networkServiceState(ctx context.Context, hardwarePort string) (string, error) {
	if strings.TrimSpace(hardwarePort) == "" {
		return "", fmt.Errorf("hardware service is empty")
	}
	command := exec.CommandContext(ctx, "networksetup", "-getnetworkserviceenabled", hardwarePort)
	output, err := command.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("read service %s: %w (%s)", hardwarePort, err, strings.TrimSpace(string(output)))
	}
	state := strings.ToLower(strings.TrimSpace(string(output)))
	if state != "enabled" && state != "disabled" {
		return "", fmt.Errorf("read service %s: unexpected state %q", hardwarePort, state)
	}
	return state, nil
}

type captureStats struct {
	packets int
	eapol   int
	vlan    int
	frames  [][]byte
}

func verifyFastArtifacts(t *testing.T, directory string, cfg config) captureStats {
	t.Helper()
	verifyManifest(t, directory, string(bridge.ModeFast))
	paths, err := filepath.Glob(filepath.Join(directory, "*.pcap"))
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) < 3 {
		t.Fatalf("fast bridge capture files=%d want at least 3", len(paths))
	}
	var total captureStats
	for _, path := range paths {
		stats := readCapture(t, path)
		total.packets += stats.packets
		total.eapol += stats.eapol
		total.vlan += stats.vlan
	}
	verifyCaptureExpectations(t, total, cfg)
	if records := decodeJournalRecords(t, filepath.Join(directory, "decisions.jsonl")); records != uint64(total.packets) {
		t.Fatalf("fast decision records=%d captured packets=%d", records, total.packets)
	}
	return total
}

func verifyControlledArtifacts(t *testing.T, directory string, cfg config, stats bridge.ControlledStats) {
	t.Helper()
	verifyManifest(t, directory, string(bridge.ModeControlled))
	original := readCapture(t, filepath.Join(directory, "original.pcap"))
	forwarded := readCapture(t, filepath.Join(directory, "forwarded.pcap"))
	if original.packets < cfg.MinPackets || forwarded.packets < cfg.MinPackets {
		t.Fatalf("controlled packets original=%d forwarded=%d want each at least %d", original.packets, forwarded.packets, cfg.MinPackets)
	}
	if uint64(original.packets) != stats.OriginalPackets || uint64(forwarded.packets) != stats.ForwardedPackets {
		t.Fatalf("controlled PCAP/stats mismatch original=%d/%d forwarded=%d/%d", original.packets, stats.OriginalPackets, forwarded.packets, stats.ForwardedPackets)
	}
	verifyCaptureExpectations(t, original, cfg)
	verifyControlledPairing(t, directory, original.frames, forwarded.frames)
}

func verifyControlledPairing(t *testing.T, directory string, originals, forwarded [][]byte) {
	t.Helper()
	path := filepath.Join(directory, "decisions.jsonl")
	verifyOwnerOnly(t, path)
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	originalSeen := make(map[uint64]bool, len(originals))
	forwardedSeen := make(map[uint64]bool, len(forwarded))
	summary, err := policy.DecodeJournal(context.Background(), file, policy.JournalReadOptions{}, func(decision policy.Decision) error {
		originalOrdinal := decision.OriginalCaptureOrdinal
		if originalOrdinal == 0 || originalOrdinal > uint64(len(originals)) || originalSeen[originalOrdinal] {
			return fmt.Errorf("invalid original ordinal %d", originalOrdinal)
		}
		originalSeen[originalOrdinal] = true
		for _, forwardedOrdinal := range decision.ForwardedCaptureOrdinals {
			if forwardedOrdinal == 0 || forwardedOrdinal > uint64(len(forwarded)) || forwardedSeen[forwardedOrdinal] {
				return fmt.Errorf("invalid forwarded ordinal %d", forwardedOrdinal)
			}
			forwardedSeen[forwardedOrdinal] = true
			if !bytes.Equal(originals[originalOrdinal-1], forwarded[forwardedOrdinal-1]) {
				return fmt.Errorf("forwarded ordinal %d is not byte-identical to original ordinal %d", forwardedOrdinal, originalOrdinal)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if !summary.Complete || int(summary.Records) != len(originals) || len(originalSeen) != len(originals) || len(forwardedSeen) != len(forwarded) {
		t.Fatalf("incomplete controlled evidence links records=%d originals=%d/%d forwarded=%d/%d", summary.Records, len(originalSeen), len(originals), len(forwardedSeen), len(forwarded))
	}
}

func verifyEdgeArtifacts(t *testing.T, directory string, cfg config, mode edge.Mode, stats edge.Stats, expectedProtocol string, expectedPort uint16) {
	t.Helper()
	verifyManifest(t, directory, string(mode))
	original := readCapture(t, filepath.Join(directory, "original.pcap"))
	forwarded := readCapture(t, filepath.Join(directory, "forwarded.pcap"))
	if original.packets < cfg.MinPackets || forwarded.packets < cfg.MinPackets {
		t.Fatalf("edge packets original=%d forwarded=%d want each at least %d", original.packets, forwarded.packets, cfg.MinPackets)
	}
	if uint64(original.packets) != stats.OriginalPackets || uint64(forwarded.packets) != stats.ForwardedPackets {
		t.Fatalf("edge PCAP/stats mismatch original=%d/%d forwarded=%d/%d", original.packets, stats.OriginalPackets, forwarded.packets, stats.ForwardedPackets)
	}
	if stats.DHCPReplies == 0 {
		t.Fatal("edge case observed no DHCP reply; renew the disposable downstream client during the exercise interval")
	}
	verifyCaptureExpectations(t, original, cfg)
	rootRecords := decodeJournalRecords(t, filepath.Join(directory, "decisions.jsonl"))
	physicalRecords := uint64(original.packets + forwarded.packets)
	if rootRecords < physicalRecords {
		t.Fatalf("edge decision records=%d physical packets=%d", rootRecords, physicalRecords)
	}
	if expectedPort != 0 && (!captureHasTransportPort(original, expectedProtocol, expectedPort) || !captureHasTransportPort(forwarded, expectedProtocol, expectedPort)) {
		t.Fatalf("port-forward target %s/%d was not observed bidirectionally on the downstream capture boundary", expectedProtocol, expectedPort)
	}
}

func captureHasTransportPort(stats captureStats, protocol string, port uint16) bool {
	wantProtocol := uint8(6)
	if strings.EqualFold(protocol, "udp") {
		wantProtocol = 17
	}
	for _, raw := range stats.frames {
		frame := traffic.Normalize(raw, traffic.CaptureMetadata{}, "", traffic.SideDownstream, traffic.DirectionUnknown)
		decoded := frame.Decoded()
		if decoded.IPProtocol == wantProtocol && (decoded.SrcPort == port || decoded.DstPort == port) {
			return true
		}
	}
	return false
}

func decodeJournalRecords(t *testing.T, path string) uint64 {
	t.Helper()
	verifyOwnerOnly(t, path)
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	summary, err := policy.DecodeJournal(context.Background(), file, policy.JournalReadOptions{}, nil)
	if err != nil {
		t.Fatalf("decode %s: %v", filepath.Base(path), err)
	}
	if !summary.Complete {
		t.Fatalf("decision journal %s is incomplete", path)
	}
	return summary.Records
}

func verifyManifest(t *testing.T, directory, wantMode string) {
	t.Helper()
	path := filepath.Join(directory, "session.json")
	verifyOwnerOnly(t, path)
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var manifest struct {
		Version int    `json:"version"`
		Mode    string `json:"mode"`
		Error   string `json:"error"`
	}
	if err := json.Unmarshal(content, &manifest); err != nil {
		t.Fatalf("decode session manifest: %v", err)
	}
	if manifest.Version != 1 || manifest.Mode != wantMode || manifest.Error != "" {
		t.Fatalf("session manifest version=%d mode=%q error=%q", manifest.Version, manifest.Mode, manifest.Error)
	}
}

func verifyOwnerOnly(t *testing.T, path string) {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		t.Fatalf("artifact %s is not a regular file", path)
	}
	if info.Mode().Perm()&0o077 != 0 {
		t.Fatalf("artifact %s permissions=%#o want owner-only", path, info.Mode().Perm())
	}
}

func readCapture(t *testing.T, path string) captureStats {
	t.Helper()
	verifyOwnerOnly(t, path)
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	reader, err := pcapgo.NewReader(file)
	if err != nil {
		t.Fatal(err)
	}
	var result captureStats
	for {
		data, info, err := reader.ReadPacketData()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatalf("read capture %s: %v", filepath.Base(path), err)
		}
		frame := traffic.Normalize(data, traffic.CaptureMetadata{
			Timestamp:      info.Timestamp,
			CaptureLength:  info.CaptureLength,
			OriginalLength: info.Length,
			LinkType:       int(reader.LinkType()),
		}, "hardware-test", traffic.SideUnknown, traffic.DirectionUnknown)
		result.packets++
		result.frames = append(result.frames, frame.RawBytes())
		decoded := frame.Decoded()
		if decoded.EtherType == 0x888e {
			result.eapol++
		}
		if len(decoded.VLANs) > 0 {
			result.vlan++
		}
	}
	return result
}

func verifyCaptureExpectations(t *testing.T, stats captureStats, cfg config) {
	t.Helper()
	if stats.packets < cfg.MinPackets {
		t.Fatalf("captured packets=%d want at least %d", stats.packets, cfg.MinPackets)
	}
	if cfg.ExpectEAPOL && stats.eapol == 0 {
		t.Fatal("no EAPOL frame was observed")
	}
	if cfg.ExpectVLAN && stats.vlan == 0 {
		t.Fatal("no VLAN-tagged frame was observed")
	}
}
