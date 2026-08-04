package bridge

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"golan/internal/dataplane"
	"golan/internal/policy"
	"golan/internal/traffic"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type fakeFastPolicyBackend struct {
	applyCalls   int
	restoreCalls int
	applyRules   string
	applyHistory []string
	applyErr     error
	restoreErr   error
	onRestore    func()
}

func (f *fakeFastPolicyBackend) Apply(_ context.Context, rules string) error {
	f.applyCalls++
	f.applyRules = rules
	f.applyHistory = append(f.applyHistory, rules)
	return f.applyErr
}

func (f *fakeFastPolicyBackend) Restore(context.Context) error {
	f.restoreCalls++
	if f.onRestore != nil {
		f.onRestore()
	}
	return f.restoreErr
}

type fakeBridgeIPFilter struct {
	calls      int
	bridgeName string
	err        error
	onEnable   func()
}

type fakeBridgeRuleManager struct {
	calls []string
	err   error
}

func (f *fakeBridgeRuleManager) Reset(string) error {
	f.calls = append(f.calls, "reset")
	return f.err
}

func (f *fakeBridgeRuleManager) InstallSafety(string, []net.HardwareAddr) error {
	f.calls = append(f.calls, "safety")
	return f.err
}

func (f *fakeBridgeRuleManager) SuppressLeaks(string) error {
	f.calls = append(f.calls, "leaks")
	return f.err
}

func (f *fakeBridgeRuleManager) SuppressEAPOL(string, string, string) error {
	f.calls = append(f.calls, "eapol")
	return f.err
}

func (f *fakeBridgeRuleManager) InstallPolicy(string, string, string, []policy.Rule) error {
	f.calls = append(f.calls, "policy")
	return f.err
}

func (f *fakeBridgeIPFilter) Enable(bridgeName string) error {
	f.calls++
	f.bridgeName = bridgeName
	if f.onEnable != nil {
		f.onEnable()
	}
	return f.err
}

func TestCreateBridgeRequiresSysctlSnapshotBeforeMutation(t *testing.T) {
	runner := &fakeCommandRunner{responses: []fakeCommandResponse{{
		output: "permission denied",
		err:    errors.New("exit status 1"),
	}}}
	session := &Session{runner: runner, Host: Adapter{Name: "en11"}}

	if _, err := session.createBridgeInterface(context.Background()); err == nil {
		t.Fatal("expected snapshot error")
	}
	if len(runner.calls) != 1 || runner.calls[0].name != "sysctl" {
		t.Fatalf("commands after failed snapshot = %#v", runner.calls)
	}
}

func TestCreateBridgeRejectsUnexpectedInterfaceName(t *testing.T) {
	runner := &fakeCommandRunner{responses: []fakeCommandResponse{
		{output: "net.inet6.ip6.forwarding: 1\n"},
		{output: "bridgebad\n"},
	}}
	session := &Session{runner: runner, Host: Adapter{Name: "en11"}}

	if _, err := session.createBridgeInterface(context.Background()); err == nil {
		t.Fatal("expected invalid bridge name error")
	}
	if session.bridgeName != "" || session.BridgeName != "" {
		t.Fatalf("invalid bridge name was retained: %q / %q", session.bridgeName, session.BridgeName)
	}
}

func TestValidateAdaptersNormalizesTrustedInventory(t *testing.T) {
	host, sw, err := validateAdapters(
		Adapter{Name: " en11 ", Role: "wrong", HardwarePort: " Host LAN ", NetworkService: " Renamed Host Service ", LocalMAC: "02-00-00-00-00-11"},
		Adapter{Name: "en12", Role: "wrong", HardwarePort: "Switch LAN", NetworkService: "Renamed Switch Service", LocalMAC: "02:00:00:00:00:12"},
	)
	if err != nil {
		t.Fatalf("validateAdapters: %v", err)
	}
	if host.Name != "en11" || host.Role != "host" || host.HardwarePort != "Host LAN" || host.NetworkService != "Renamed Host Service" || host.LocalMAC != "02:00:00:00:00:11" {
		t.Fatalf("host = %+v", host)
	}
	if sw.Role != "switch" {
		t.Fatalf("switch = %+v", sw)
	}
}

func TestValidateAdaptersRejectsUnrestorablePairs(t *testing.T) {
	validHost := Adapter{Name: "en11", HardwarePort: "Host Port", NetworkService: "Host LAN", LocalMAC: "02:00:00:00:00:11"}
	validSwitch := Adapter{Name: "en12", HardwarePort: "Switch Port", NetworkService: "Switch LAN", LocalMAC: "02:00:00:00:00:12"}
	tests := []struct {
		host Adapter
		sw   Adapter
	}{
		{host: Adapter{}, sw: validSwitch},
		{host: Adapter{Name: "-a", HardwarePort: "Host LAN", LocalMAC: validHost.LocalMAC}, sw: validSwitch},
		{host: validHost, sw: Adapter{Name: "en12", LocalMAC: validSwitch.LocalMAC}},
		{host: validHost, sw: Adapter{Name: "en12", HardwarePort: "Switch LAN", LocalMAC: "bad"}},
		{host: validHost, sw: Adapter{Name: "en11", HardwarePort: "Switch LAN", LocalMAC: validSwitch.LocalMAC}},
		{host: validHost, sw: Adapter{Name: "en12", HardwarePort: "Switch LAN", LocalMAC: validHost.LocalMAC}},
		{host: validHost, sw: Adapter{Name: "en12", HardwarePort: "Host Port", NetworkService: "Other Service", LocalMAC: validSwitch.LocalMAC}},
		{host: Adapter{Name: "en11", HardwarePort: "Host LAN", NetworkService: "Shared Service", LocalMAC: validHost.LocalMAC}, sw: Adapter{Name: "en12", HardwarePort: "Switch LAN", NetworkService: "Shared Service", LocalMAC: validSwitch.LocalMAC}},
	}
	for _, test := range tests {
		if _, _, err := validateAdapters(test.host, test.sw); err == nil {
			t.Errorf("validateAdapters(%+v, %+v) succeeded", test.host, test.sw)
		}
	}
}

func TestFastCapturedPacketsAlwaysAppendPayloadFreeDecisions(t *testing.T) {
	directory := t.TempDir()
	journal, err := policy.OpenJournal(filepath.Join(directory, "decisions.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	engine := policy.NewEngine(8)
	if err := engine.Policies.Activate("fast-journal", []policy.Rule{{
		ID: "block-host", Enabled: true,
		Match:   policy.Match{Directions: []traffic.Direction{traffic.DirectionHostToSwitch}},
		Actions: []policy.Action{{Kind: policy.ActionBlock}},
	}}); err != nil {
		t.Fatal(err)
	}
	target := net.HardwareAddr{2, 0, 0, 0, 0, 1}
	session := &Session{Dir: directory, policyEngine: engine, targetMAC: target}
	frames := [][]byte{
		testEthernetFrame(1, 2),
		testEthernetFrame(2, 1),
	}
	directions := []traffic.Direction{
		traffic.DirectionHostToSwitch,
		traffic.DirectionSwitchToHost,
	}
	packetIDs := make([]traffic.PacketID, 0, len(frames))
	for index, frame := range frames {
		packet := gopacket.NewPacket(frame, layers.LinkTypeEthernet, gopacket.Default)
		packet.Metadata().CaptureInfo = gopacket.CaptureInfo{
			Timestamp:     time.Unix(int64(index+1), 0).UTC(),
			CaptureLength: len(frame), Length: len(frame),
		}
		result, mode, err := session.processFastCapturedPacket(
			Adapter{Name: "en7", Role: "host"},
			packet,
			layers.LinkTypeEthernet,
			journal,
		)
		if err != nil {
			t.Fatal(err)
		}
		if mode != dataplane.ModeFastBridge {
			t.Fatalf("packet %d mode=%s", index, mode)
		}
		if result.Original.Direction != directions[index] {
			t.Fatalf("packet %d direction=%s want=%s", index, result.Original.Direction, directions[index])
		}
		packetIDs = append(packetIDs, result.Original.ID)
	}
	if err := journal.Close(); err != nil {
		t.Fatal(err)
	}
	decisions := readControlledDecisions(t, directory)
	if len(decisions) != len(frames) {
		t.Fatalf("fast decisions=%#v", decisions)
	}
	for index, decision := range decisions {
		if decision.PacketID != packetIDs[index] ||
			decision.OriginalCaptureOrdinal != 0 ||
			len(decision.ForwardedCaptureOrdinals) != 0 {
			t.Fatalf("fast decision %d=%#v", index, decision)
		}
	}
	if decisions[0].EffectiveVerdict != policy.VerdictBlock ||
		decisions[1].EffectiveVerdict != policy.VerdictAllow {
		t.Fatalf("fast verdicts=%#v", decisions)
	}
}

func TestNATCaptureUsesEndpointModeAndDirections(t *testing.T) {
	directory := t.TempDir()
	journal, err := policy.OpenJournal(filepath.Join(directory, "decisions.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	defer journal.Close()
	engine := policy.NewEngine(8)
	if err := engine.Policies.Activate("nat-capture", []policy.Rule{{
		ID: "broad-frame-block", Enabled: true, Actions: []policy.Action{{Kind: policy.ActionBlock}},
	}}); err != nil {
		t.Fatal(err)
	}
	target := net.HardwareAddr{2, 0, 0, 0, 0, 1}
	session := &Session{
		Dir: directory, policyEngine: engine, targetMAC: target,
		nat: &NATState{HostDetached: true},
	}
	packet := gopacket.NewPacket(testEthernetFrame(1, 2), layers.LinkTypeEthernet, gopacket.Default)
	packet.Metadata().CaptureInfo = gopacket.CaptureInfo{Timestamp: time.Unix(1, 0).UTC(), CaptureLength: 60, Length: 60}
	result, mode, err := session.processFastCapturedPacket(Adapter{Name: "bridge7", Role: "bridge"}, packet, layers.LinkTypeEthernet, journal)
	if err != nil {
		t.Fatal(err)
	}
	if mode != dataplane.ModeNAT || result.Original.Direction != traffic.DirectionOutbound {
		t.Fatalf("mode=%s direction=%s", mode, result.Original.Direction)
	}
	if result.Decision.Status != dataplane.StatusShadow || result.Decision.EffectiveVerdict != policy.VerdictAllow {
		t.Fatalf("non-IPv4 nat decision=%#v", result.Decision)
	}
}

func TestFastBridgePFPreflightRejectsAmbiguousRevisionBeforeArtifacts(t *testing.T) {
	artifactDir := filepath.Join(t.TempDir(), "not-created")
	host := Adapter{Name: "en11", HardwarePort: "Host Port", NetworkService: "Host LAN", LocalMAC: "02:00:00:00:00:11"}
	sw := Adapter{Name: "en12", HardwarePort: "Switch Port", NetworkService: "Switch LAN", LocalMAC: "02:00:00:00:00:12"}
	rules := []policy.Rule{
		{ID: "allow-all", Priority: 20, Enabled: true, Actions: []policy.Action{{Kind: policy.ActionAllow}}},
		{ID: "block-v4", Priority: 10, Enabled: true, Match: policy.Match{IPVersions: []uint8{4}}, Actions: []policy.Action{{Kind: policy.ActionBlock}}},
	}
	if _, err := StartModeWithPolicyOptions(host, sw, artifactDir, ModeFast, DefaultEAPOLPolicy(), "mixed", rules, DefaultControlledOptions()); err == nil || !strings.Contains(err.Error(), "overlapping Layer 2 rule allow-all") {
		t.Fatalf("preflight error=%v", err)
	}
	if _, err := os.Stat(artifactDir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("artifact path was mutated before preflight: %v", err)
	}
}

func TestInstallFastPFLoadsAnchorBeforeEnablingBridgeHooks(t *testing.T) {
	var order []string
	backend := &fakeFastPolicyBackend{}
	filter := &fakeBridgeIPFilter{onEnable: func() { order = append(order, "enable") }}
	backendWithOrder := &orderedFastPolicyBackend{delegate: backend, order: &order}
	session := &Session{
		bridgeName: "bridge7", fastPFRules: "block drop inet all\n",
		fastPF: backendWithOrder, ipFilter: filter,
	}

	if err := session.installFastPF(context.Background()); err != nil {
		t.Fatalf("installFastPF: %v", err)
	}
	if !reflect.DeepEqual(order, []string{"apply", "enable"}) {
		t.Fatalf("installation order=%v", order)
	}
	if backend.applyCalls != 1 || backend.applyRules != session.fastPFRules || filter.calls != 1 || filter.bridgeName != "bridge7" {
		t.Fatalf("backend=%+v filter=%+v", backend, filter)
	}

	want := errors.New("validation failed")
	backend.applyErr = want
	filter.calls = 0
	if err := session.installFastPF(context.Background()); !errors.Is(err, want) {
		t.Fatalf("install error=%v", err)
	}
	if filter.calls != 0 {
		t.Fatal("bridge hooks enabled after PF apply failure")
	}
}

type orderedFastPolicyBackend struct {
	delegate *fakeFastPolicyBackend
	order    *[]string
}

func (b *orderedFastPolicyBackend) Apply(ctx context.Context, rules string) error {
	*b.order = append(*b.order, "apply")
	return b.delegate.Apply(ctx, rules)
}

func (b *orderedFastPolicyBackend) Restore(ctx context.Context) error {
	return b.delegate.Restore(ctx)
}

func TestCleanupDestroysBridgeBeforeRestoringFastPFAndRetriesFailures(t *testing.T) {
	runner := &fakeCommandRunner{}
	backend := &fakeFastPolicyBackend{}
	session := &Session{bridgeName: "bridge7", BridgeName: "bridge7", runner: runner, fastPF: backend}
	backend.onRestore = func() {
		if session.bridgeName != "" {
			t.Errorf("PF restored while bridge %s could still forward", session.bridgeName)
		}
	}
	if err := session.cleanup(); err != nil {
		t.Fatalf("cleanup: %v", err)
	}
	if backend.restoreCalls != 1 || session.fastPF != nil {
		t.Fatalf("PF cleanup calls=%d retained=%v", backend.restoreCalls, session.fastPF != nil)
	}

	destroyErr := errors.New("busy")
	runner = &fakeCommandRunner{responses: []fakeCommandResponse{{output: "busy", err: destroyErr}}}
	backend = &fakeFastPolicyBackend{}
	session = &Session{bridgeName: "bridge8", BridgeName: "bridge8", runner: runner, fastPF: backend}
	if err := session.cleanup(); !errors.Is(err, destroyErr) {
		t.Fatalf("failed destroy cleanup error=%v", err)
	}
	if backend.restoreCalls != 0 || session.fastPF == nil {
		t.Fatal("PF state was restored or discarded while bridge destruction failed")
	}
	runner.responses = []fakeCommandResponse{{}}
	if err := session.cleanup(); err != nil {
		t.Fatalf("cleanup retry: %v", err)
	}
	if backend.restoreCalls != 1 || session.fastPF != nil {
		t.Fatal("PF cleanup was not retried after bridge destruction")
	}

	restoreErr := errors.New("anchor busy")
	backend = &fakeFastPolicyBackend{restoreErr: restoreErr}
	session = &Session{fastPF: backend, runner: &fakeCommandRunner{}}
	if err := session.cleanup(); !errors.Is(err, restoreErr) {
		t.Fatalf("failed restore cleanup error=%v", err)
	}
	if session.fastPF == nil {
		t.Fatal("failed PF restoration state was discarded")
	}
	backend.restoreErr = nil
	if err := session.cleanup(); err != nil || session.fastPF != nil || backend.restoreCalls != 2 {
		t.Fatalf("PF restoration retry error=%v retained=%v calls=%d", err, session.fastPF != nil, backend.restoreCalls)
	}
}

func TestPrepareInterfacesRetainsCompletedSnapshots(t *testing.T) {
	runner := &fakeCommandRunner{responses: []fakeCommandResponse{
		{output: "Enabled\n"},
		{output: "en11: flags=8863<UP,BROADCAST,RUNNING> mtu 1500\n"},
		{},
		{output: "unavailable", err: errors.New("exit status 1")},
	}}
	session := &Session{
		Host:   Adapter{Name: "en11", HardwarePort: "Host Port", NetworkService: "Host LAN"},
		Switch: Adapter{Name: "en12", HardwarePort: "Switch Port", NetworkService: "Switch LAN"},
		runner: runner,
	}

	if err := session.prepareInterfaces(context.Background()); err == nil {
		t.Fatal("expected second snapshot failure")
	}
	if len(session.interfaces) != 1 || session.interfaces[0].NetworkService != "Host LAN" || !session.interfaces[0].InterfaceUp {
		t.Fatalf("restore state = %+v", session.interfaces)
	}

	runner.responses = []fakeCommandResponse{{}, {}}
	if err := session.restoreInterfaces(); err != nil {
		t.Fatalf("restoreInterfaces: %v", err)
	}
	wantLast := []commandCall{
		{name: "networksetup", args: []string{"-setnetworkserviceenabled", "Host LAN", "on"}},
		{name: "ifconfig", args: []string{"en11", "up"}},
	}
	if got := runner.calls[len(runner.calls)-2:]; !reflect.DeepEqual(got, wantLast) {
		t.Fatalf("restore calls = %#v", got)
	}
}

func TestCleanupUsesReverseDependencyOrder(t *testing.T) {
	runner := &fakeCommandRunner{}
	session := &Session{
		bridgeName:  "bridge7",
		BridgeName:  "bridge7",
		origIPv6Fwd: "1",
		macRestore: []adapterMACRestore{
			{Name: "en11", MAC: "02:00:00:00:00:11"},
			{Name: "en12", MAC: "02:00:00:00:00:12"},
		},
		interfaces: []InterfaceRestoreState{
			{IfName: "en11", NetworkService: "Host LAN", ServiceStateKnown: true, ServiceEnabled: true, InterfaceStateKnown: true},
			{IfName: "en12", NetworkService: "Switch LAN", ServiceStateKnown: true, ServiceEnabled: true, InterfaceStateKnown: true},
		},
		runner: runner,
	}

	if err := session.cleanup(); err != nil {
		t.Fatalf("cleanup: %v", err)
	}
	want := []commandCall{
		{name: "ifconfig", args: []string{"bridge7", "destroy"}},
		{name: "sysctl", args: []string{"-w", "net.inet6.ip6.forwarding=1"}},
		{name: "ifconfig", args: []string{"en12", "ether", "02:00:00:00:00:12"}},
		{name: "ifconfig", args: []string{"en11", "ether", "02:00:00:00:00:11"}},
		{name: "networksetup", args: []string{"-setnetworkserviceenabled", "Switch LAN", "on"}},
		{name: "ifconfig", args: []string{"en12", "down"}},
		{name: "networksetup", args: []string{"-setnetworkserviceenabled", "Host LAN", "on"}},
		{name: "ifconfig", args: []string{"en11", "down"}},
	}
	if !reflect.DeepEqual(runner.calls, want) {
		t.Fatalf("calls = %#v, want %#v", runner.calls, want)
	}
	if session.bridgeName != "" || session.origIPv6Fwd != "" || len(session.macRestore) != 0 || len(session.interfaces) != 0 {
		t.Fatalf("cleanup state was not cleared: %+v", session)
	}
}

func TestCleanupRetainsFailedRestorationState(t *testing.T) {
	runner := &fakeCommandRunner{responses: []fakeCommandResponse{
		{output: "busy", err: errors.New("exit status 1")},
		{output: "denied", err: errors.New("exit status 1")},
	}}
	session := &Session{
		bridgeName: "bridge7",
		BridgeName: "bridge7",
		macRestore: []adapterMACRestore{{Name: "en11", MAC: "02:00:00:00:00:11"}},
		runner:     runner,
	}

	err := session.cleanup()
	if err == nil || !strings.Contains(err.Error(), "destroy bridge") || strings.Contains(err.Error(), "restore adapter MAC") {
		t.Fatalf("cleanup error = %v", err)
	}
	if session.bridgeName != "bridge7" || len(session.macRestore) != 1 || len(runner.calls) != 1 {
		t.Fatalf("failed state was discarded: bridge=%q mac=%+v", session.bridgeName, session.macRestore)
	}
}

func TestRestoreInterfacesRetainsOnlyFailedState(t *testing.T) {
	runner := &fakeCommandRunner{responses: []fakeCommandResponse{
		{output: "denied", err: errors.New("exit status 1")},
		{},
	}}
	session := &Session{
		interfaces: []InterfaceRestoreState{{
			IfName:              "en11",
			NetworkService:      "Host LAN",
			ServiceStateKnown:   true,
			ServiceEnabled:      false,
			InterfaceStateKnown: true,
		}},
		runner: runner,
	}

	if err := session.restoreInterfaces(); err == nil {
		t.Fatal("expected interface restoration error")
	}
	if len(session.interfaces) != 1 || session.interfaces[0].IfName != "en11" {
		t.Fatalf("failed state = %+v", session.interfaces)
	}
	runner.responses = []fakeCommandResponse{{}, {}}
	if err := session.restoreInterfaces(); err != nil {
		t.Fatalf("restoreInterfaces retry: %v", err)
	}
	if len(session.interfaces) != 0 {
		t.Fatalf("restored state remains: %+v", session.interfaces)
	}
}

func TestStopReturnsRecordedSessionError(t *testing.T) {
	want := errors.New("cleanup failed")
	done := make(chan struct{})
	close(done)
	session := &Session{done: done, resultErr: want}

	if err := session.Stop(); !errors.Is(err, want) {
		t.Fatalf("Stop error = %v", err)
	}
}

func TestStopRetriesPendingCleanup(t *testing.T) {
	done := make(chan struct{})
	close(done)
	runner := &fakeCommandRunner{}
	session := &Session{
		done:       done,
		bridgeName: "bridge7",
		BridgeName: "bridge7",
		runner:     runner,
		cleanupErr: errors.New("destroy bridge bridge7: busy"),
		resultErr:  errors.New("destroy bridge bridge7: busy"),
	}

	if err := session.Stop(); err != nil {
		t.Fatalf("Stop retry: %v", err)
	}
	if session.bridgeName != "" || session.cleanupErr != nil || session.resultErr != nil {
		t.Fatalf("cleanup retry state = bridge:%q cleanup:%v result:%v", session.bridgeName, session.cleanupErr, session.resultErr)
	}
	if len(runner.calls) != 1 || runner.calls[0].name != "ifconfig" {
		t.Fatalf("calls = %#v", runner.calls)
	}
}

func TestStopRetainsOnlyCurrentCleanupFailures(t *testing.T) {
	done := make(chan struct{})
	close(done)
	runner := &fakeCommandRunner{responses: []fakeCommandResponse{{output: "busy", err: errors.New("exit status 1")}}}
	session := &Session{
		done:       done,
		bridgeName: "bridge7",
		BridgeName: "bridge7",
		runner:     runner,
		cleanupErr: errors.New("previous cleanup failure"),
		resultErr:  errors.New("previous cleanup failure"),
	}

	if err := session.Stop(); err == nil || !strings.Contains(err.Error(), "busy") || strings.Contains(err.Error(), "previous cleanup failure") {
		t.Fatalf("first Stop error = %v", err)
	}
	if !session.CleanupPending() {
		t.Fatal("failed cleanup was not exposed as pending")
	}
	if err := session.Stop(); err != nil {
		t.Fatalf("second Stop retry: %v", err)
	}
	if session.CleanupPending() {
		t.Fatal("cleanup remains pending after successful retry")
	}
}

func TestSendDropsOnlyLossyEvents(t *testing.T) {
	events := make(chan Event, 1)
	events <- Event{Kind: KindState}
	session := &Session{events: events}

	session.send(Event{Kind: KindTraffic})
	session.send(Event{Kind: KindEvidence})
	if session.resultErr != nil {
		t.Fatalf("lossy event result = %v", session.resultErr)
	}

	session.send(Event{Kind: KindSignal})
	if session.resultErr == nil || !strings.Contains(session.resultErr.Error(), "deliver signal event: timed out") {
		t.Fatalf("critical event result = %v", session.resultErr)
	}
}

func TestCloseEventsPreventsSendAfterClose(t *testing.T) {
	events := make(chan Event, 1)
	session := &Session{events: events}

	session.closeEvents()
	session.send(Event{Kind: KindState})
	session.closeEvents()

	if _, ok := <-events; ok {
		t.Fatal("events channel remains open")
	}
}

func TestPcapWriterCreatesOwnerOnlyExclusiveFile(t *testing.T) {
	dir := t.TempDir()
	path, _, file, err := pcapWriter(dir, "host", "en11", layers.LinkTypeEthernet)
	if err != nil {
		t.Fatalf("pcapWriter: %v", err)
	}
	if err := file.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("mode = %o", got)
	}
	if _, _, duplicate, err := pcapWriter(dir, "host", "en11", layers.LinkTypeEthernet); err == nil {
		if duplicate != nil {
			_ = duplicate.Close()
		}
		t.Fatal("expected exclusive-create error")
	}
}

func TestStopNATRetriesOnlyFailedState(t *testing.T) {
	runner := &fakeCommandRunner{responses: []fakeCommandResponse{{
		output: "permission denied",
		err:    errors.New("exit status 1"),
	}}}
	session := &Session{
		nat:    &NATState{RouteAdded: true, Gateway: "192.0.2.1"},
		runner: runner,
	}

	if err := session.StopNAT(); err == nil {
		t.Fatal("expected route cleanup error")
	}
	if session.nat == nil || !session.nat.RouteAdded {
		t.Fatalf("failed route state was discarded: %+v", session.nat)
	}
	if err := session.StopNAT(); err != nil {
		t.Fatalf("retry StopNAT: %v", err)
	}
	if session.nat != nil {
		t.Fatalf("NAT state remains after retry: %+v", session.nat)
	}
}

func TestStopNATKeepsPFBoundaryAcrossHostReattach(t *testing.T) {
	runner := &fakeCommandRunner{}
	backend := &fakeFastPolicyBackend{}
	state := &NATState{
		BridgeName: "bridge7", HostDetached: true, PFEndpointRules: true,
		PFRestorePending: true, natPFRules: "nat-rules\n",
	}
	session := &Session{
		Host: Adapter{Name: "en11"}, runner: runner, nat: state,
		fastPF: backend, fastPFRules: "fast-rules\n",
	}

	if err := session.StopNAT(); err != nil {
		t.Fatalf("StopNAT: %v", err)
	}
	if session.nat != nil {
		t.Fatalf("nat state remains: %+v", session.nat)
	}
	wantPF := []string{"fast-rules\nnat-rules\n", "fast-rules\n"}
	if !reflect.DeepEqual(backend.applyHistory, wantPF) {
		t.Fatalf("PF transition history=%q want=%q", backend.applyHistory, wantPF)
	}
	wantCommands := []commandCall{
		{name: "ifconfig", args: []string{"bridge7", "addm", "en11"}},
		{name: "ifconfig", args: []string{"bridge7", "stp", "en11", "disabled"}},
	}
	if !reflect.DeepEqual(runner.calls, wantCommands) {
		t.Fatalf("reattach calls=%#v want=%#v", runner.calls, wantCommands)
	}
}

func TestStartNATPreflightsAndTransitionsCompletePolicyBoundary(t *testing.T) {
	runner := &fakeCommandRunner{responses: []fakeCommandResponse{{
		output: "bridge7: flags=8843\n\tether 02:00:00:00:00:77\n",
	}}}
	backend := &fakeFastPolicyBackend{}
	l2 := &fakeBridgeRuleManager{}
	engine := policy.NewEngine(8)
	if err := engine.Policies.Activate("nat-1", []policy.Rule{{
		ID: "block-web", Priority: 10, Enabled: true,
		Match: policy.Match{
			Modes:      []dataplane.Mode{dataplane.ModeNAT},
			Directions: []traffic.Direction{traffic.DirectionOutbound},
			IPVersions: []uint8{4}, Protocols: []uint8{6},
			DstPorts: policy.PortSet{Values: []uint16{80}},
		},
		Actions: []policy.Action{{Kind: policy.ActionBlock}},
	}}); err != nil {
		t.Fatal(err)
	}
	session := &Session{
		bridgeName: "bridge7", BridgeName: "bridge7", Dir: t.TempDir(), runner: runner,
		Host:         Adapter{Name: "en11", LocalMAC: "02:00:00:00:00:11"},
		Switch:       Adapter{Name: "en12", LocalMAC: "02:00:00:00:00:12"},
		targetMAC:    net.HardwareAddr{2, 0, 0, 0, 0, 1},
		policyEngine: engine, fastPF: backend, fastPFRules: "fast-rules\n", l2Rules: l2,
	}
	if err := session.StartNAT(NATConfig{
		MAC: "auto", IP: "192.0.2.10", CIDR: "24", DNS: "192.0.2.53", DHCP: "off",
	}); err != nil {
		t.Fatalf("StartNAT: %v", err)
	}
	snapshot := session.NATSnapshot()
	if !snapshot.Active || !snapshot.PFEndpointRules || !snapshot.PFRestorationOwned ||
		!snapshot.L2EndpointRules || !snapshot.L2RestorationOwned ||
		snapshot.LivePolicyRules != 1 || snapshot.ShadowPolicyRules != 0 ||
		snapshot.PolicyRevision != "nat-1" {
		t.Fatalf("snapshot=%+v", snapshot)
	}
	if len(backend.applyHistory) != 2 ||
		!strings.Contains(backend.applyHistory[0], "fast-rules") ||
		!strings.Contains(backend.applyHistory[0], "block drop out quick on bridge7") ||
		strings.Contains(backend.applyHistory[1], "fast-rules") {
		t.Fatalf("PF start transition=%q", backend.applyHistory)
	}
	if !reflect.DeepEqual(l2.calls, []string{"reset", "safety", "leaks", "eapol"}) {
		t.Fatalf("L2 start transition=%v", l2.calls)
	}
	if err := session.StopNAT(); err != nil {
		t.Fatalf("StopNAT: %v", err)
	}
	if session.NATSnapshot().Active || session.nat != nil {
		t.Fatalf("nat remained after stop: %+v", session.NATSnapshot())
	}
	if got := backend.applyHistory[len(backend.applyHistory)-1]; got != "fast-rules\n" {
		t.Fatalf("final PF rules=%q", got)
	}
}
func TestNATL2TransitionRemovesAndRestoresFastPolicy(t *testing.T) {
	manager := &fakeBridgeRuleManager{}
	session := &Session{
		Host:      Adapter{Name: "en11", LocalMAC: "02:00:00:00:00:11"},
		Switch:    Adapter{Name: "en12", LocalMAC: "02:00:00:00:00:12"},
		targetMAC: net.HardwareAddr{2, 0, 0, 0, 0, 1}, l2Rules: manager,
	}
	state := &NATState{BridgeName: "bridge7", L2RestorePending: true}
	if err := session.installNATL2Rules(state); err != nil {
		t.Fatal(err)
	}
	if !state.L2EndpointRules || !reflect.DeepEqual(manager.calls, []string{"reset", "safety", "leaks", "eapol"}) {
		t.Fatalf("nat L2 state=%+v calls=%v", state, manager.calls)
	}
	manager.calls = nil
	if err := session.restoreFastL2Rules(state); err != nil {
		t.Fatal(err)
	}
	if state.L2EndpointRules || state.L2RestorePending || !reflect.DeepEqual(manager.calls, []string{"reset", "safety", "leaks", "policy", "eapol"}) {
		t.Fatalf("restored L2 state=%+v calls=%v", state, manager.calls)
	}
}

func TestNATL2RestoreFailurePreventsHostReattach(t *testing.T) {
	want := errors.New("rules busy")
	manager := &fakeBridgeRuleManager{err: want}
	runner := &fakeCommandRunner{}
	backend := &fakeFastPolicyBackend{}
	session := &Session{
		Host: Adapter{Name: "en11"}, Switch: Adapter{Name: "en12"}, runner: runner,
		fastPF: backend, fastPFRules: "fast-rules\n", l2Rules: manager,
		nat: &NATState{
			BridgeName: "bridge7", HostDetached: true, PFRestorePending: true,
			natPFRules: "nat-rules\n", L2RestorePending: true,
		},
	}
	if err := session.StopNAT(); !errors.Is(err, want) {
		t.Fatalf("StopNAT error=%v", err)
	}
	if len(runner.calls) != 0 || session.nat == nil || !session.nat.HostDetached {
		t.Fatalf("host reattached across L2 restore failure: calls=%#v state=%+v", runner.calls, session.nat)
	}
}

func TestStopNATRetainsFailedPFTransitionBeforeReattach(t *testing.T) {
	want := errors.New("PF busy")
	runner := &fakeCommandRunner{}
	backend := &fakeFastPolicyBackend{applyErr: want}
	session := &Session{
		Host: Adapter{Name: "en11"}, runner: runner, fastPF: backend,
		fastPFRules: "fast-rules\n",
		nat: &NATState{
			BridgeName: "bridge7", HostDetached: true, PFEndpointRules: true,
			PFRestorePending: true, natPFRules: "nat-rules\n",
		},
	}
	if err := session.StopNAT(); !errors.Is(err, want) {
		t.Fatalf("first stop error=%v", err)
	}
	if len(runner.calls) != 0 || session.nat == nil || !session.nat.HostDetached {
		t.Fatalf("host reattached across failed transition: calls=%#v state=%+v", runner.calls, session.nat)
	}
	backend.applyErr = nil
	if err := session.StopNAT(); err != nil {
		t.Fatalf("retry StopNAT: %v", err)
	}
	if session.nat != nil {
		t.Fatalf("nat state remains after retry: %+v", session.nat)
	}
}

func TestStopNATRetriesSTPRestoration(t *testing.T) {
	want := errors.New("stp busy")
	runner := &fakeCommandRunner{responses: []fakeCommandResponse{{}, {output: "busy", err: want}}}
	session := &Session{
		Host: Adapter{Name: "en11"}, runner: runner,
		nat: &NATState{BridgeName: "bridge7", HostDetached: true, Started: true},
	}
	if err := session.StopNAT(); !errors.Is(err, want) {
		t.Fatalf("first StopNAT error=%v", err)
	}
	snapshot := session.NATSnapshot()
	if snapshot.Active || !snapshot.CleanupPending || session.nat == nil || !session.nat.HostSTPRestorePending {
		t.Fatalf("failed STP state=%+v snapshot=%+v", session.nat, snapshot)
	}
	if err := session.StartNAT(NATConfig{}); err == nil || !strings.Contains(err.Error(), "cleanup is pending") {
		t.Fatalf("restart during cleanup error=%v", err)
	}
	if err := session.StopNAT(); err != nil {
		t.Fatalf("retry StopNAT: %v", err)
	}
	if session.nat != nil {
		t.Fatalf("nat state remains after STP retry: %+v", session.nat)
	}
}

func TestStopNATRestoresBackendCreatedOnlyForEndpoint(t *testing.T) {
	backend := &fakeFastPolicyBackend{}
	session := &Session{
		fastPF: backend,
		nat:    &NATState{PFCreated: true, PFEndpointRules: true, PFRestorePending: true},
	}
	if err := session.StopNAT(); err != nil {
		t.Fatal(err)
	}
	if backend.restoreCalls != 1 || session.fastPF != nil || session.nat != nil {
		t.Fatalf("restore calls=%d backend retained=%t state=%+v", backend.restoreCalls, session.fastPF != nil, session.nat)
	}
}

func TestCleanupRetainsBridgeWhileNATRestorationIsPending(t *testing.T) {
	want := errors.New("route busy")
	runner := &fakeCommandRunner{responses: []fakeCommandResponse{{output: "busy", err: want}}}
	session := &Session{
		bridgeName: "bridge7", BridgeName: "bridge7", runner: runner,
		nat: &NATState{RouteAdded: true, Gateway: "192.0.2.1"}, origIPv6Fwd: "1",
		macRestore: []adapterMACRestore{{Name: "en12", MAC: "02:00:00:00:00:12"}},
		interfaces: []InterfaceRestoreState{{IfName: "en11", NetworkService: "Host LAN", ServiceStateKnown: true, ServiceEnabled: true}},
	}
	if err := session.cleanup(); !errors.Is(err, want) {
		t.Fatalf("cleanup error=%v", err)
	}
	if session.bridgeName != "bridge7" || session.nat == nil {
		t.Fatalf("bridge or nat state discarded: bridge=%q state=%+v", session.bridgeName, session.nat)
	}
	if len(runner.calls) != 1 || runner.calls[0].name != "route" {
		t.Fatalf("unrelated restoration ran before nat cleanup: %#v", runner.calls)
	}
	for _, call := range runner.calls {
		if call.name == "ifconfig" && reflect.DeepEqual(call.args, []string{"bridge7", "destroy"}) {
			t.Fatal("bridge destroyed while nat restoration remained pending")
		}
	}
}

func TestParseCurrentMACRejectsNonUnicastValues(t *testing.T) {
	if got := parseCurrentMAC("\tether 02:00:00:00:00:11\n"); got != "02:00:00:00:00:11" {
		t.Fatalf("MAC = %q", got)
	}
	if got := parseCurrentMAC("\tether ff:ff:ff:ff:ff:ff\n"); got != "" {
		t.Fatalf("broadcast MAC = %q", got)
	}
}
