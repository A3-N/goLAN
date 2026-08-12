package edge

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golan/internal/dataplane"
	"golan/internal/policy"
	"golan/internal/traffic"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type edgeLifecycleRunner struct {
	calls    []string
	outputs  map[string]string
	failures map[string][]error
}

func (r *edgeLifecycleRunner) Run(_ context.Context, name string, args []string, _ string) (string, error) {
	key := strings.TrimSpace(name + " " + strings.Join(args, " "))
	r.calls = append(r.calls, key)
	if failures := r.failures[key]; len(failures) > 0 {
		err := failures[0]
		r.failures[key] = failures[1:]
		return r.outputs[key], err
	}
	return r.outputs[key], nil
}

func (r *edgeLifecycleRunner) count(key string) int {
	count := 0
	for _, call := range r.calls {
		if call == key {
			count++
		}
	}
	return count
}

type fakePFCall struct {
	name  string
	args  []string
	input string
}

type fakePFRunner struct {
	calls []fakePFCall
}

func (r *fakePFRunner) Run(_ context.Context, name string, args []string, input string) (string, error) {
	r.calls = append(r.calls, fakePFCall{name: name, args: append([]string(nil), args...), input: input})
	switch strings.Join(args, " ") {
	case "-s info":
		return "Status: Disabled\n", nil
	case "-E":
		return "Token : 12345\n", nil
	default:
		return "", nil
	}
}

type routeRunner struct {
	output string
	args   []string
}

func (r *routeRunner) Run(_ context.Context, _ string, args []string, _ string) (string, error) {
	r.args = append([]string(nil), args...)
	return r.output, nil
}

func TestEvidenceEventIsLossyUnderBackpressure(t *testing.T) {
	events := make(chan Event, 1)
	events <- Event{Kind: KindState}
	session := &Session{events: events}
	session.send(Event{Kind: KindEvidence})
	if session.resultErr != nil || len(events) != 1 {
		t.Fatalf("lossy evidence result=%v queued=%d", session.resultErr, len(events))
	}
}

func TestEvidenceModeReflectsEdgeRuntime(t *testing.T) {
	if got := (&Session{Config: Config{Mode: ModeRoute}}).evidenceMode(); got != dataplane.ModeEdgeRoute {
		t.Fatalf("route evidence mode=%s", got)
	}
	if got := (*Session)(nil).evidenceMode(); got != dataplane.ModeEdgeRoute {
		t.Fatalf("nil evidence mode=%s", got)
	}
}

func TestHealthSnapshotIsPayloadFreeAndCallerSafe(t *testing.T) {
	backend := newPFBackend(&fakePFRunner{})
	if err := backend.Apply(context.Background(), "block drop quick inet6 all\n"); err != nil {
		t.Fatal(err)
	}
	session := &Session{
		Config: Config{
			Mode: ModeRoute, Downstream: "en7", Upstream: "en0",
			Subnet: netip.MustParsePrefix("10.77.2.0/24"),
		},
		Lease: Lease{
			Subnet: netip.MustParsePrefix("10.77.2.0/24"), ServerIP: netip.MustParseAddr("10.77.2.1"),
			ClientIP: netip.MustParseAddr("10.77.2.2"), Gateway: netip.MustParseAddr("10.77.2.1"),
			DNS: []netip.Addr{netip.MustParseAddr("192.0.2.53")},
		},
		pf: backend,
	}
	session.originalForwarding = "0"
	session.forwardingChanged = true
	session.aliasAdded = true
	session.interfaceRaised = true
	session.stats.dhcp.Add(2)
	session.stats.original.Add(3)
	session.stats.forwarded.Add(1)
	session.stats.blocked.Add(2)
	health := session.Health()
	if health.Mode != ModeRoute || health.PF.Anchor != PFAnchor || !health.PF.Loaded || !health.PF.EnableTokenOwned || health.Stats.DHCPReplies != 2 || !health.ForwardingSnapshot || !health.ForwardingChanged || !health.AliasAdded || !health.InterfaceRaised {
		t.Fatalf("health=%#v", health)
	}
	encoded, err := json.Marshal(health)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encoded, []byte("secret-token")) || bytes.Contains(encoded, []byte("private-payload")) {
		t.Fatalf("health leaked private state: %s", encoded)
	}
	health.DNS[0] = "changed"
	if session.Lease.DNS[0].String() != "192.0.2.53" {
		t.Fatal("health DNS aliases session storage")
	}
}

func TestPrepareAndCleanupPreserveDownstreamAdministrativeState(t *testing.T) {
	for _, originallyUp := range []bool{false, true} {
		t.Run(fmt.Sprintf("originally-up-%t", originallyUp), func(t *testing.T) {
			flags := "en7: flags=8822<BROADCAST,SMART> mtu 1500\n"
			if originallyUp {
				flags = "en7: flags=8863<UP,BROADCAST,RUNNING> mtu 1500\n"
			}
			runner := &edgeLifecycleRunner{outputs: map[string]string{
				"sysctl -n net.inet.ip.forwarding": "0\n",
				"ifconfig en7":                     flags,
			}}
			backend := newPFBackend(&fakePFRunner{})
			lease, err := LeaseForSubnet(netip.MustParsePrefix("10.77.20.0/24"), nil)
			if err != nil {
				t.Fatal(err)
			}
			session := &Session{
				Config: Config{Mode: ModeRoute, Downstream: "en7", Upstream: "en0", Subnet: lease.Subnet},
				Lease:  lease, Engine: policy.NewEngine(8), runner: runner, pf: backend,
			}
			if err := session.prepare(context.Background()); err != nil {
				t.Fatal(err)
			}
			if !session.interfaceStateKnown || session.originalInterfaceUp != originallyUp || session.interfaceRaised == originallyUp {
				t.Fatalf("snapshot known=%t original-up=%t raised=%t", session.interfaceStateKnown, session.originalInterfaceUp, session.interfaceRaised)
			}
			if err := session.cleanup(); err != nil {
				t.Fatal(err)
			}
			upCalls := runner.count("ifconfig en7 up")
			downCalls := runner.count("ifconfig en7 down")
			if originallyUp && (upCalls != 0 || downCalls != 0) {
				t.Fatalf("originally-up adapter was mutated: calls=%v", runner.calls)
			}
			if !originallyUp && (upCalls != 1 || downCalls != 1) {
				t.Fatalf("originally-down adapter was not restored: calls=%v", runner.calls)
			}
			for _, required := range []string{
				"sysctl -w net.inet.ip.forwarding=0",
				"ifconfig en7 inet 10.77.20.1 -alias",
			} {
				if runner.count(required) != 1 {
					t.Fatalf("missing cleanup call %q: %v", required, runner.calls)
				}
			}
		})
	}
}

func TestParseInterfaceAdminUpRequiresFlags(t *testing.T) {
	if up, err := parseInterfaceAdminUp("en7: flags=8863<UP,BROADCAST> mtu 1500\n"); err != nil || !up {
		t.Fatalf("up=%t err=%v", up, err)
	}
	if up, err := parseInterfaceAdminUp("en7: flags=8822<BROADCAST> mtu 1500\n"); err != nil || up {
		t.Fatalf("up=%t err=%v", up, err)
	}
	if _, err := parseInterfaceAdminUp("status: inactive\n"); err == nil {
		t.Fatal("missing flags were accepted")
	}
}

func TestCleanupRetriesOnlyFailedDownstreamRestoration(t *testing.T) {
	runner := &edgeLifecycleRunner{
		outputs: map[string]string{
			"sysctl -n net.inet.ip.forwarding": "0\n",
			"ifconfig en7":                     "en7: flags=8822<BROADCAST,SMART> mtu 1500\n",
		},
		failures: map[string][]error{
			"ifconfig en7 down": {errors.New("temporary interface failure"), nil},
		},
	}
	backend := newPFBackend(&fakePFRunner{})
	lease, err := LeaseForSubnet(netip.MustParsePrefix("10.77.21.0/24"), nil)
	if err != nil {
		t.Fatal(err)
	}
	session := &Session{
		Config: Config{Mode: ModeRoute, Downstream: "en7", Upstream: "en0", Subnet: lease.Subnet},
		Lease:  lease, Engine: policy.NewEngine(8), runner: runner, pf: backend,
	}
	if err := session.prepare(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := session.cleanup(); err == nil || !session.interfaceRaised {
		t.Fatalf("first cleanup error=%v raised=%t", err, session.interfaceRaised)
	}
	if err := session.cleanup(); err != nil || session.interfaceRaised {
		t.Fatalf("retry cleanup error=%v raised=%t", err, session.interfaceRaised)
	}
	if runner.count("ifconfig en7 down") != 2 || runner.count("sysctl -w net.inet.ip.forwarding=0") != 1 || runner.count("ifconfig en7 inet 10.77.21.1 -alias") != 1 {
		t.Fatalf("cleanup calls=%v", runner.calls)
	}
}

func TestOpenRecorderRemovesOnlyArtifactsCreatedBeforeFailure(t *testing.T) {
	for _, blocked := range []string{"forwarded.pcap", "decisions.jsonl"} {
		t.Run(blocked, func(t *testing.T) {
			directory := t.TempDir()
			blockedPath := filepath.Join(directory, blocked)
			const sentinel = "preexisting"
			if err := os.WriteFile(blockedPath, []byte(sentinel), 0o600); err != nil {
				t.Fatal(err)
			}
			if record, err := openRecorder(directory, layers.LinkTypeEthernet); err == nil || record != nil {
				t.Fatalf("record=%#v error=%v", record, err)
			}
			if _, err := os.Stat(filepath.Join(directory, "original.pcap")); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("incomplete original remains: %v", err)
			}
			if blocked == "decisions.jsonl" {
				if _, err := os.Stat(filepath.Join(directory, "forwarded.pcap")); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("incomplete forwarded remains: %v", err)
				}
			}
			content, err := os.ReadFile(blockedPath)
			if err != nil || string(content) != sentinel {
				t.Fatalf("preexisting artifact=%q error=%v", content, err)
			}
		})
	}
}

func TestEdgeSessionManifestDoesNotPersistErrorDetail(t *testing.T) {
	const privateMarker = "private-edge-error.example"
	directory := t.TempDir()
	subnet := netip.MustParsePrefix("10.77.9.0/24")
	lease, err := LeaseForSubnet(subnet, nil)
	if err != nil {
		t.Fatal(err)
	}
	session := &Session{
		Dir: directory,
		Config: Config{
			Mode: ModeRoute, Downstream: "en11", Upstream: "en12", Subnet: subnet,
		},
		Lease: lease,
	}
	if err := session.writeManifest(
		time.Unix(1, 0).UTC(), time.Unix(2, 0).UTC(), errors.New("runtime detail "+privateMarker),
	); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "session.json")
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	text := string(content)
	if strings.Contains(text, privateMarker) || !strings.Contains(text, edgeSessionErrorMarker(errors.New("failed"))) {
		t.Fatalf("manifest=%s", text)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("manifest mode=%v", info.Mode().Perm())
	}
}

func TestEdgeRecorderAssignsOneBasedCaptureOrdinals(t *testing.T) {
	directory := t.TempDir()
	record, err := openRecorder(directory, layers.LinkTypeEthernet)
	if err != nil {
		t.Fatal(err)
	}
	frame := testProjectFrameForEdgeRecorder()
	info := gopacket.CaptureInfo{
		Timestamp:     time.Unix(1, 0).UTC(),
		CaptureLength: len(frame),
		Length:        len(frame),
	}
	first, err := record.WriteOriginal(info, frame)
	if err != nil {
		t.Fatal(err)
	}
	second, err := record.WriteOriginal(info, frame)
	if err != nil {
		t.Fatal(err)
	}
	forwarded, err := record.WriteForwarded(info, frame)
	if err != nil {
		t.Fatal(err)
	}
	if first != 1 || second != 2 || forwarded != 1 {
		t.Fatalf(
			"recorder ordinals original=%d,%d forwarded=%d",
			first,
			second,
			forwarded,
		)
	}
	if err := record.WriteDecision(policy.Decision{
		OriginalCaptureOrdinal: second,
		EffectiveVerdict:       policy.VerdictBlock,
	}); err != nil {
		t.Fatal(err)
	}
	if err := record.Close(); err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(filepath.Join(directory, "decisions.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	var decision policy.Decision
	summary, decodeErr := policy.DecodeJournal(
		context.Background(),
		file,
		policy.JournalReadOptions{},
		func(candidate policy.Decision) error {
			decision = candidate
			return nil
		},
	)
	closeErr := file.Close()
	if err := errors.Join(decodeErr, closeErr); err != nil {
		t.Fatal(err)
	}
	if summary.Records != 1 ||
		!summary.Complete ||
		decision.OriginalCaptureOrdinal != 2 ||
		len(decision.ForwardedCaptureOrdinals) != 0 {
		t.Fatalf("edge journal summary=%#v decision=%#v", summary, decision)
	}
}

func TestSelectSubnetAndLease(t *testing.T) {
	occupied := []netip.Prefix{netip.MustParsePrefix("10.77.0.0/23"), netip.MustParsePrefix("192.168.0.0/16")}
	subnet, err := SelectSubnet(occupied)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := subnet.String(), "10.77.2.0/24"; got != want {
		t.Fatalf("subnet = %s, want %s", got, want)
	}
	lease, err := LeaseForSubnet(subnet, nil)
	if err != nil {
		t.Fatal(err)
	}
	if lease.ServerIP.String() != "10.77.2.1" || lease.ClientIP.String() != "10.77.2.2" {
		t.Fatalf("lease = %#v", lease)
	}
	if len(lease.DNS) != 0 {
		t.Fatalf("empty DNS input advertised a nonexistent resolver: %v", lease.DNS)
	}
}

func testProjectFrameForEdgeRecorder() []byte {
	frame := make([]byte, 60)
	frame[0], frame[6] = 2, 4
	frame[12], frame[13] = 0x08, 0x00
	return frame
}

func TestDiscoverRouteParsesScopedMacOSOutput(t *testing.T) {
	runner := &routeRunner{output: "   route to: default\n    gateway: 192.0.2.1\n  interface: en0\n"}
	route, err := discoverRoute(context.Background(), runner, "en0")
	if err != nil {
		t.Fatal(err)
	}
	if route.Interface != "en0" || route.Gateway.String() != "192.0.2.1" || !route.Default {
		t.Fatalf("route = %#v", route)
	}
	if got := strings.Join(runner.args, " "); got != "-n get -ifscope en0 default" {
		t.Fatalf("route args = %s", got)
	}
}

func TestSystemDNSFiltersIPv6AndDuplicates(t *testing.T) {
	got := SystemDNS("nameserver 192.0.2.53\nnameserver ::1\nnameserver 192.0.2.53\nnameserver 198.51.100.53\n")
	if len(got) != 2 || got[0].String() != "192.0.2.53" || got[1].String() != "198.51.100.53" {
		t.Fatalf("DNS = %v", got)
	}
}

func TestMacOSDNSDiscoverySeparatesDefaultAndScopedVPNResolvers(t *testing.T) {
	output := `DNS configuration

resolver #1
  search domain[0] : lan
  nameserver[0] : 192.0.2.53
  flags    : Request A records
  order    : 200000

resolver #2
  domain   : corp.example
  nameserver[0] : 127.0.0.1
  if_index : 18 (utun4)
  flags    : Scoped, Request A records
  order    : 101400

DNS configuration (for scoped queries)

resolver #1
  nameserver[0] : 127.0.0.1
  if_index : 18 (utun4)
  flags    : Scoped
`
	runner := &edgeLifecycleRunner{outputs: map[string]string{"scutil --dns": output}}
	defaultDNS, err := discoverMacOSDNS(context.Background(), runner, "")
	if err != nil || len(defaultDNS) != 1 || defaultDNS[0].String() != "192.0.2.53" {
		t.Fatalf("default DNS=%v error=%v", defaultDNS, err)
	}
	vpnDNS, err := discoverMacOSDNS(context.Background(), runner, "utun4")
	if err != nil || len(vpnDNS) != 1 || vpnDNS[0].String() != "127.0.0.1" {
		t.Fatalf("VPN DNS=%v error=%v", vpnDNS, err)
	}
	if _, err := discoverMacOSDNS(context.Background(), runner, "utun9"); err == nil || !strings.Contains(err.Error(), "set edge dns explicitly") {
		t.Fatalf("missing scoped resolver error=%v", err)
	}
}

func TestParsePointToPointPeerUsesDestinationAddress(t *testing.T) {
	peer, ok := parsePointToPointPeer(`utun4: flags=8051<UP,POINTOPOINT,RUNNING,MULTICAST> mtu 1280
	inet 10.8.0.2 --> 10.8.0.1 netmask 0xffffffff
`)
	if !ok || peer.String() != "10.8.0.1" {
		t.Fatalf("peer=%s ok=%t", peer, ok)
	}
}

func TestCompilePFUsesDedicatedAnchorSemantics(t *testing.T) {
	config := Config{
		Mode: ModeRoute, Downstream: "en7", Upstream: "en0",
		Subnet:       netip.MustParsePrefix("10.77.2.0/24"),
		PortForwards: []PortForward{{Protocol: "tcp", ListenPort: 8443, TargetIP: netip.MustParseAddr("10.77.2.2"), TargetPort: 443}},
	}
	rules, err := CompilePF(config)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"nat on en0",
		"block drop quick on en7 inet6 all",
		"block in quick on en0 inet from any to 10.77.2.0/24",
		"port 8443 -> 10.77.2.2 port 443",
	} {
		if !strings.Contains(rules, want) {
			t.Fatalf("rules missing %q:\n%s", want, rules)
		}
	}
	if strings.Index(rules, "block drop quick on en7 inet6") < strings.Index(rules, "nat on") {
		t.Fatalf("filter rules precede translation rules:\n%s", rules)
	}
	for _, reject := range []string{"block drop quick inet6 all", "block in quick on en0 inet all"} {
		if strings.Contains(rules, reject) {
			t.Fatalf("rules contain host-wide block %q:\n%s", reject, rules)
		}
	}
	if strings.Contains(rules, "/etc/pf.conf") || strings.Contains(rules, "-F all") {
		t.Fatalf("rules contain global mutation: %s", rules)
	}
}

func TestCompilePFVPNForcesTunnelAndFailsClosed(t *testing.T) {
	config := Config{
		Mode:            ModeRoute,
		Downstream:      "en7",
		Upstream:        "utun4",
		Egress:          EgressVPN,
		VPNDestinations: []netip.Prefix{netip.MustParsePrefix("10.20.0.0/16"), netip.MustParsePrefix("192.0.2.53/32")},
		VPNRouteAddress: netip.MustParseAddr("10.8.0.2"),
		Subnet:          netip.MustParsePrefix("10.77.2.0/24"),
		DNS:             []netip.Addr{netip.MustParseAddr("10.20.0.53")},
	}
	openInternet, err := policy.Preset("open-internet")
	if err != nil {
		t.Fatal(err)
	}
	rules, err := CompilePFWithPolicy(config, "vpn-pf", openInternet)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"table <golan_edge_vpn_destinations> const { 10.20.0.0/16, 192.0.2.53/32 }",
		"nat on utun4 inet from 10.77.2.0/24 to <golan_edge_vpn_destinations> -> (utun4)",
		"block in quick on en7 inet from ! 10.77.2.0/24 to any",
		"block in quick on en7 inet from 10.77.2.0/24 to ! <golan_edge_vpn_destinations>",
		"pass in quick on en7 route-to (utun4 10.8.0.2) inet from any to any keep state",
		"pass in quick on en7 route-to (utun4 10.8.0.2) inet from 10.77.2.0/24 to <golan_edge_vpn_destinations> keep state",
		"block out quick inet from 10.77.2.0/24 to any",
	} {
		if !strings.Contains(rules, want) {
			t.Fatalf("VPN rules missing %q:\n%s", want, rules)
		}
	}
	if strings.Index(rules, "block in quick on en7 inet from 10.77.2.0/24 to ! <golan_edge_vpn_destinations>") > strings.Index(rules, "pass in quick on en7 route-to") {
		t.Fatalf("destination guard must precede VPN allow:\n%s", rules)
	}
	for _, invalid := range []string{"to ! {", "route-to (utun4)"} {
		if strings.Contains(rules, invalid) {
			t.Fatalf("VPN rules retained macOS-incompatible syntax %q:\n%s", invalid, rules)
		}
	}
}

func TestCompilePFRelaysLoopbackDNSAndProtectsMacServices(t *testing.T) {
	config := Config{
		Mode: ModeRoute, Downstream: "en7", Upstream: "utun4", Egress: EgressVPN,
		VPNDestinations: []netip.Prefix{netip.MustParsePrefix("198.51.100.0/24")},
		VPNRouteAddress: netip.MustParseAddr("10.8.0.1"),
		EgressMTU:       1280,
		Subnet:          netip.MustParsePrefix("10.77.2.0/24"),
		DNS:             []netip.Addr{netip.MustParseAddr("127.0.0.1")},
	}
	rules, err := CompilePF(config)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"scrub in on en7 inet proto tcp max-mss 1240",
		"pass in quick on en7 inet proto { tcp, udp } from 10.77.2.0/24 to 10.77.2.1 port 53 keep state",
		"block in quick on en7 inet from 10.77.2.0/24 to self",
		"route-to (utun4 10.8.0.1)",
	} {
		if !strings.Contains(rules, want) {
			t.Fatalf("loopback DNS rules missing %q:\n%s", want, rules)
		}
	}
	if strings.Contains(rules, "127.0.0.1") {
		t.Fatalf("loopback DNS leaked into PF routing rules:\n%s", rules)
	}
}

func TestCompilePFVPNAllDoesNotCreateZeroPrefixTable(t *testing.T) {
	config := Config{
		Mode: ModeRoute, Downstream: "en7", Upstream: "utun4", Egress: EgressVPN,
		VPNDestinations: []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")},
		VPNRouteAddress: netip.MustParseAddr("10.8.0.2"),
		Subnet:          netip.MustParsePrefix("10.77.2.0/24"),
		DNS:             []netip.Addr{netip.MustParseAddr("10.20.0.53")},
	}
	rules, err := CompilePF(config)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(rules, pfVPNDestinationTable) || !strings.Contains(rules, "nat on utun4 inet from 10.77.2.0/24 to any -> (utun4)") ||
		!strings.Contains(rules, "route-to (utun4 10.8.0.2) inet from 10.77.2.0/24 to any") {
		t.Fatalf("full-tunnel VPN rules are invalid:\n%s", rules)
	}
}

func TestValidateConfigRejectsUnsafeVPNSettings(t *testing.T) {
	base := Config{
		Mode:            ModeRoute,
		Downstream:      "en7",
		Upstream:        "utun4",
		Egress:          EgressVPN,
		VPNDestinations: []netip.Prefix{netip.MustParsePrefix("10.20.0.0/16")},
		VPNRouteAddress: netip.MustParseAddr("10.8.0.2"),
		Subnet:          netip.MustParsePrefix("10.77.2.0/24"),
		DNS:             []netip.Addr{netip.MustParseAddr("10.20.0.53")},
	}
	tests := []struct {
		name   string
		mutate func(*Config)
		want   string
	}{
		{name: "missing destination", mutate: func(config *Config) { config.VPNDestinations = nil }, want: "at least one destination"},
		{name: "missing route address", mutate: func(config *Config) { config.VPNRouteAddress = netip.Addr{} }, want: "route address"},
		{name: "missing DNS", mutate: func(config *Config) { config.DNS = nil }, want: "at least one IPv4 DNS"},
		{name: "DNS outside destinations", mutate: func(config *Config) { config.DNS = []netip.Addr{netip.MustParseAddr("192.0.2.53")} }, want: "outside the permitted VPN destinations"},
		{name: "all mixed with prefix", mutate: func(config *Config) {
			config.VPNDestinations = append(config.VPNDestinations, netip.MustParsePrefix("0.0.0.0/0"))
		}, want: "cannot be combined"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config := base
			config.VPNDestinations = append([]netip.Prefix(nil), base.VPNDestinations...)
			config.DNS = append([]netip.Addr(nil), base.DNS...)
			test.mutate(&config)
			if err := ValidateConfig(config); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("ValidateConfig() error = %v, want containing %q", err, test.want)
			}
		})
	}
}

func TestCompilePFWithPolicyPreservesFirstMatchAndShadowsIncompatibleRules(t *testing.T) {
	config := Config{Mode: ModeRoute, Downstream: "en7", Upstream: "en0", Subnet: netip.MustParsePrefix("10.77.2.0/24")}
	rules := []policy.Rule{
		{
			ID: "web-only", Priority: 100, Enabled: true,
			Match:   policy.Match{Directions: []traffic.Direction{traffic.DirectionOutbound}, Protocols: []uint8{6}, DstPorts: policy.PortSet{Values: []uint16{80, 443}, Negate: true}},
			Actions: []policy.Action{{Kind: policy.ActionBlock}},
		},
		{
			ID: "http-host-userspace", Priority: 90, Enabled: true,
			Match:   policy.Match{HTTPMethods: []string{"POST"}},
			Actions: []policy.Action{{Kind: policy.ActionBlock}},
		},
	}
	compiled, err := CompilePFWithPolicy(config, "edge-1", rules)
	if err != nil {
		t.Fatal(err)
	}
	line := "block drop in quick on en7 inet proto tcp from any to any port != { 80, 443 }"
	if !strings.Contains(compiled, line) {
		t.Fatalf("compiled policy missing %q:\n%s", line, compiled)
	}
	if strings.Contains(compiled, "http-host-userspace") || strings.Contains(compiled, "POST") {
		t.Fatalf("incompatible rule was compiled:\n%s", compiled)
	}
	if strings.Index(compiled, line) > strings.Index(compiled, "pass in quick on en7 inet from 10.77.2.0/24") {
		t.Fatalf("policy did not precede default allow:\n%s", compiled)
	}
}

func TestCompilePFScopesInboundPolicyAwayFromMac(t *testing.T) {
	config := Config{Mode: ModeRoute, Downstream: "en7", Upstream: "en0", Subnet: netip.MustParsePrefix("10.77.2.0/24")}
	rules := []policy.Rule{{
		ID: "inbound-admin", Priority: 100, Enabled: true,
		Match: policy.Match{
			Directions: []traffic.Direction{traffic.DirectionInbound},
			Protocols:  []uint8{6},
			DstPorts:   policy.PortSet{Values: []uint16{22}},
		},
		Actions: []policy.Action{{Kind: policy.ActionBlock}},
	}}
	compiled, err := CompilePFWithPolicy(config, "edge-1", rules)
	if err != nil {
		t.Fatal(err)
	}
	want := "block drop in quick on en0 inet proto tcp from any to 10.77.2.0/24 port 22"
	if !strings.Contains(compiled, want) {
		t.Fatalf("inbound policy missing scoped rule %q:\n%s", want, compiled)
	}
	if strings.Contains(compiled, "block drop in quick on en0 inet proto tcp from any to any port 22") {
		t.Fatalf("inbound Edge policy can affect the Mac:\n%s", compiled)
	}
}

func TestWebOnlyPresetCompilesAllowListBeforeDefaultBlock(t *testing.T) {
	config := Config{Mode: ModeRoute, Downstream: "en7", Upstream: "en0", Subnet: netip.MustParsePrefix("10.77.3.0/24")}
	rules, err := policy.Preset("web-only")
	if err != nil {
		t.Fatal(err)
	}
	compiled, err := CompilePFWithPolicy(config, "web", rules)
	if err != nil {
		t.Fatal(err)
	}
	allow := "pass in quick on en7 inet proto tcp from any to any port { 80, 443 } keep state"
	block := "block drop in quick on en7 inet from any to any"
	if !strings.Contains(compiled, allow) || !strings.Contains(compiled, block) || strings.Index(compiled, allow) > strings.Index(compiled, block) {
		t.Fatalf("web-only ordering is invalid:\n%s", compiled)
	}
}

func TestPFBackendValidatesBeforeLoadingAndRestoresOnlyAnchor(t *testing.T) {
	runner := &fakePFRunner{}
	backend := newPFBackend(runner)
	if err := backend.Apply(context.Background(), "block drop quick inet6 all\n"); err != nil {
		t.Fatal(err)
	}
	if err := backend.Restore(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(runner.calls) != 6 {
		t.Fatalf("calls = %#v", runner.calls)
	}
	if got := strings.Join(runner.calls[0].args, " "); got != "-vnf -" {
		t.Fatalf("first call = %s", got)
	}
	if got := strings.Join(runner.calls[3].args, " "); got != "-a com.apple/golan.edge -f -" {
		t.Fatalf("load call = %s", got)
	}
	if got := strings.Join(runner.calls[4].args, " "); got != "-a com.apple/golan.edge -F all" {
		t.Fatalf("flush call = %s", got)
	}
	if got := strings.Join(runner.calls[5].args, " "); got != "-X 12345" {
		t.Fatalf("token release call = %s", got)
	}
	for _, call := range runner.calls {
		if strings.Join(call.args, " ") == "-F all" {
			t.Fatal("global PF flush was attempted")
		}
	}
}

func TestBuildDHCPReplyOffersDeterministicLease(t *testing.T) {
	request := syntheticDHCPDiscover(t)
	lease, err := LeaseForSubnet(netip.MustParsePrefix("10.77.4.0/24"), []netip.Addr{netip.MustParseAddr("192.0.2.53")})
	if err != nil {
		t.Fatal(err)
	}
	reply, ok, err := BuildDHCPReply(request, net.HardwareAddr{2, 0, 0, 0, 0, 1}, lease)
	if err != nil || !ok {
		t.Fatalf("reply ok=%v err=%v", ok, err)
	}
	packet := gopacket.NewPacket(reply, layers.LayerTypeEthernet, gopacket.Default)
	dhcp, ok := packet.Layer(layers.LayerTypeDHCPv4).(*layers.DHCPv4)
	if !ok || !dhcp.YourClientIP.Equal(net.ParseIP("10.77.4.2")) {
		t.Fatalf("DHCP reply = %#v", dhcp)
	}
}

func syntheticDHCPDiscover(t *testing.T) []byte {
	t.Helper()
	clientMAC := net.HardwareAddr{2, 0, 0, 0, 0, 2}
	ethernet := &layers.Ethernet{
		SrcMAC:       clientMAC,
		DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		EthernetType: layers.EthernetTypeIPv4,
	}
	ipv4 := &layers.IPv4{
		Version: 4, IHL: 5, TTL: 64, Protocol: layers.IPProtocolUDP,
		SrcIP: net.IPv4zero, DstIP: net.IPv4bcast,
	}
	udp := &layers.UDP{SrcPort: 68, DstPort: 67}
	if err := udp.SetNetworkLayerForChecksum(ipv4); err != nil {
		t.Fatal(err)
	}
	dhcp := &layers.DHCPv4{
		Operation: layers.DHCPOpRequest, HardwareType: layers.LinkTypeEthernet,
		HardwareLen: 6, Xid: 0x01020304, ClientHWAddr: clientMAC,
		Options: []layers.DHCPOption{
			layers.NewDHCPOption(layers.DHCPOptMessageType, []byte{byte(layers.DHCPMsgTypeDiscover)}),
		},
	}
	buffer := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, ethernet, ipv4, udp, dhcp); err != nil {
		t.Fatal(err)
	}
	return buffer.Bytes()
}
