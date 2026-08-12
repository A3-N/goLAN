package bridge

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golan/internal/dataplane"
	"golan/internal/policy"
	"golan/internal/traffic"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func TestControlledBridgeAppliesPolicyInBothDirections(t *testing.T) {
	engine := policy.NewEngine(32)
	err := engine.Policies.Activate("test-1", []policy.Rule{{
		ID: "block-host", Name: "block host direction", Enabled: true,
		Match:   policy.Match{Directions: []traffic.Direction{traffic.DirectionHostToSwitch}},
		Actions: []policy.Action{{Kind: policy.ActionBlock}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	session := &Session{Dir: t.TempDir(), policyEngine: engine}
	hostFrame := testEthernetFrame(2, 3)
	switchFrame := testEthernetFrame(3, 2)
	host := &memoryPacketPort{name: "en7", packets: [][]byte{hostFrame}}
	switchPort := &memoryPacketPort{name: "en8", packets: [][]byte{switchFrame}}
	recorder, err := openControlledRecorder(session.Dir)
	if err != nil {
		t.Fatal(err)
	}
	var counters controlledCounters
	if err := session.forwardControlled(context.Background(), host, switchPort, recorder, DefaultControlledOptions(), &counters); err != nil {
		t.Fatal(err)
	}
	if err := recorder.Close(); err != nil {
		t.Fatal(err)
	}
	stats := counters.snapshot()
	if stats.OriginalPackets != 2 || stats.ForwardedPackets != 1 || stats.BlockedPackets != 1 {
		t.Fatalf("stats = %#v", stats)
	}
	if got := host.writtenFrames(); len(got) != 1 || string(got[0]) != string(switchFrame) {
		t.Fatalf("host output = %#v", got)
	}
	if got := switchPort.writtenFrames(); len(got) != 0 {
		t.Fatalf("switch output should be blocked, got %#v", got)
	}
	assertCompleteControlledOrdinalLink(
		t,
		readControlledDecisions(t, session.Dir),
		stats.OriginalPackets,
		stats.ForwardedPackets,
	)
}

func TestFastBridgePolicyUpdateRequiresRestartAndRetainsRevision(t *testing.T) {
	engine := policy.NewEngine(8)
	if err := engine.Policies.Activate("before", []policy.Rule{{ID: "before", Enabled: true, Actions: []policy.Action{{Kind: policy.ActionAllow}}}}); err != nil {
		t.Fatal(err)
	}
	session := &Session{Mode: ModeFast, policyEngine: engine}
	err := session.SetPolicy("after", []policy.Rule{{ID: "after", Enabled: true, Match: policy.Match{IPVersions: []uint8{4}}, Actions: []policy.Action{{Kind: policy.ActionBlock}}}})
	if err == nil || !strings.Contains(err.Error(), "stop and restart") {
		t.Fatalf("SetPolicy error=%v", err)
	}
	active, ok := engine.Policies.Active()
	if !ok || active.Revision() != "before" {
		t.Fatalf("active revision=%q ok=%v", active.Revision(), ok)
	}
}

func TestControlledOptionsValidateBeforeMutationAndPersistInManifest(t *testing.T) {
	defaults := DefaultControlledOptions()
	if err := ValidateControlledOptions(defaults); err != nil {
		t.Fatalf("defaults: %v", err)
	}
	if got := normalizeControlledOptions(ControlledOptions{}); got != defaults {
		t.Fatalf("normalized defaults=%#v want=%#v", got, defaults)
	}
	minimum := defaults
	minimum.QueueDepth = MinControlledQueueDepth
	maximum := defaults
	maximum.QueueDepth = MaxControlledQueueDepth
	for name, options := range map[string]ControlledOptions{"minimum": minimum, "maximum": maximum} {
		if err := ValidateControlledOptions(options); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
	}
	invalid := map[string]func(*ControlledOptions){
		"negative queue":  func(options *ControlledOptions) { options.QueueDepth = -1 },
		"oversized queue": func(options *ControlledOptions) { options.QueueDepth = MaxControlledQueueDepth + 1 },
		"overload":        func(options *ControlledOptions) { options.Overload = "direct" },
	}
	for name, mutate := range invalid {
		t.Run(name, func(t *testing.T) {
			options := defaults
			mutate(&options)
			if err := ValidateControlledOptions(options); err == nil {
				t.Fatalf("invalid options accepted: %#v", options)
			}
		})
	}
	invalidOptions := defaults
	invalidOptions.QueueDepth = -1
	artifactDir := filepath.Join(t.TempDir(), "must-not-exist")
	host := Adapter{Name: "en11", HardwarePort: "Host Port", NetworkService: "Host LAN", LocalMAC: "02:00:00:00:00:11"}
	sw := Adapter{Name: "en12", HardwarePort: "Switch Port", NetworkService: "Switch LAN", LocalMAC: "02:00:00:00:00:12"}
	if _, err := StartModeWithPolicyOptions(host, sw, artifactDir, ModeControlled, DefaultEAPOLPolicy(), "", nil, invalidOptions); err == nil {
		t.Fatal("invalid controlled options started a session")
	}
	if _, err := os.Stat(artifactDir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("invalid preflight mutated artifact path: %v", err)
	}
	if err := (&Session{}).forwardControlled(context.Background(), nil, nil, nil, invalidOptions, nil); err == nil {
		t.Fatal("direct runtime accepted invalid options")
	}

	options := defaults
	options.QueueDepth = 7
	options.Overload = OverloadFailClosed
	session := &Session{Dir: t.TempDir(), Host: host, Switch: sw, controlledOptions: options}
	if got := session.ControlledOptions(); got != options {
		t.Fatalf("session options=%#v want=%#v", got, options)
	}
	if err := session.writeControlledManifest(time.Unix(1, 0).UTC(), time.Unix(2, 0).UTC(), ControlledStats{}, nil); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(session.Dir, "session.json"))
	if err != nil {
		t.Fatal(err)
	}
	var manifest struct {
		Options ControlledOptions `json:"controlled_options"`
	}
	if err := json.Unmarshal(data, &manifest); err != nil || manifest.Options != options {
		t.Fatalf("manifest options=%#v err=%v", manifest.Options, err)
	}
}

func TestOpenControlledRecorderRemovesOnlyArtifactsCreatedBeforeFailure(t *testing.T) {
	for _, blocked := range []string{"forwarded.pcap", "decisions.jsonl"} {
		t.Run(blocked, func(t *testing.T) {
			directory := t.TempDir()
			blockedPath := filepath.Join(directory, blocked)
			const sentinel = "preexisting"
			if err := os.WriteFile(blockedPath, []byte(sentinel), 0o600); err != nil {
				t.Fatal(err)
			}
			recorder, err := openControlledRecorder(directory)
			if err == nil || recorder != nil {
				t.Fatalf("recorder=%#v error=%v", recorder, err)
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

func TestControlledStatsSnapshotUsesSessionCounters(t *testing.T) {
	counters := &controlledCounters{}
	counters.original.Add(7)
	counters.forwarded.Add(5)
	counters.blocked.Add(2)
	counters.overload.Add(3)
	counters.highWater.Store(9)
	session := &Session{Mode: ModeControlled, controlledStats: counters}
	got := session.ControlledStats()
	if got.OriginalPackets != 7 || got.ForwardedPackets != 5 || got.BlockedPackets != 2 || got.OverloadPackets != 3 || got.QueueHighWater != 9 {
		t.Fatalf("stats=%#v", got)
	}
	if got := (&Session{Mode: ModeFast, controlledStats: counters}).ControlledStats(); got != (ControlledStats{}) {
		t.Fatalf("fast stats=%#v", got)
	}
}

func TestControlledFailOpenOverloadPreservesPerDirectionOrder(t *testing.T) {
	frames := numberedEthernetFrames(12)
	session := controlledPressureSession(t)
	host := &memoryPacketPort{name: "en7", packets: frames}
	switchPort := &memoryPacketPort{name: "en8"}
	recorder, err := openControlledRecorder(session.Dir)
	if err != nil {
		t.Fatal(err)
	}
	options := DefaultControlledOptions()
	options.QueueDepth = 1
	options.Overload = OverloadFailOpen
	var counters controlledCounters
	if err := session.forwardControlled(context.Background(), host, switchPort, recorder, options, &counters); err != nil {
		t.Fatal(err)
	}
	if err := recorder.Close(); err != nil {
		t.Fatal(err)
	}
	written := switchPort.writtenFrames()
	assertFrameOrder(t, written, frames)
	stats := counters.snapshot()
	if stats.OriginalPackets != uint64(len(frames)) || stats.ForwardedPackets != uint64(len(frames)) || stats.BlockedPackets != 0 || stats.OverloadPackets == 0 || stats.QueueHighWater > 1 {
		t.Fatalf("stats=%#v", stats)
	}
	decisions := readControlledDecisions(t, session.Dir)
	assertDecisionOrder(t, decisions, frames, session.Dir)
	assertCompleteControlledOrdinalLink(
		t,
		decisions,
		stats.OriginalPackets,
		stats.ForwardedPackets,
	)
	overloadDecisions := 0
	for _, decision := range decisions {
		if decision.Explanation == "controlled queue overload; ordered fail-open forwarding" {
			overloadDecisions++
			if decision.EffectiveVerdict != policy.VerdictAllow || decision.ForwardedPacketID == "" {
				t.Fatalf("fail-open decision=%#v", decision)
			}
		}
	}
	if uint64(overloadDecisions) != stats.OverloadPackets {
		t.Fatalf("overload decisions=%d stats=%d", overloadDecisions, stats.OverloadPackets)
	}
}

func TestControlledFailClosedOverloadDropsInOrderAndJournalsEveryFrame(t *testing.T) {
	frames := numberedEthernetFrames(12)
	session := controlledPressureSession(t)
	host := &memoryPacketPort{name: "en7", packets: frames}
	switchPort := &memoryPacketPort{name: "en8"}
	recorder, err := openControlledRecorder(session.Dir)
	if err != nil {
		t.Fatal(err)
	}
	options := DefaultControlledOptions()
	options.QueueDepth = 1
	options.Overload = OverloadFailClosed
	var counters controlledCounters
	if err := session.forwardControlled(context.Background(), host, switchPort, recorder, options, &counters); err != nil {
		t.Fatal(err)
	}
	if err := recorder.Close(); err != nil {
		t.Fatal(err)
	}
	decisions := readControlledDecisions(t, session.Dir)
	assertDecisionOrder(t, decisions, frames, session.Dir)
	frameByID := make(map[traffic.PacketID][]byte, len(frames))
	for _, frame := range frames {
		frameByID[controlledFrameID(frame, session.Dir)] = frame
	}
	var expectedForwarded [][]byte
	blocked := 0
	for _, decision := range decisions {
		if decision.EffectiveVerdict == policy.VerdictBlock {
			blocked++
			if decision.Explanation != "controlled queue overload; ordered fail-closed drop" || decision.ForwardedPacketID != "" {
				t.Fatalf("fail-closed decision=%#v", decision)
			}
			continue
		}
		expectedForwarded = append(expectedForwarded, frameByID[decision.PacketID])
	}
	assertFrameOrder(t, switchPort.writtenFrames(), expectedForwarded)
	stats := counters.snapshot()
	if stats.OriginalPackets != uint64(len(frames)) || stats.OverloadPackets == 0 || stats.BlockedPackets != stats.OverloadPackets || stats.BlockedPackets != uint64(blocked) || stats.ForwardedPackets != uint64(len(expectedForwarded)) || stats.QueueHighWater > 1 {
		t.Fatalf("stats=%#v blocked decisions=%d", stats, blocked)
	}
	assertCompleteControlledOrdinalLink(
		t,
		decisions,
		stats.OriginalPackets,
		stats.ForwardedPackets,
	)
}

func TestControlledInjectionFailureStillJournalsPayloadFreeDecision(t *testing.T) {
	session := &Session{
		Dir: t.TempDir(), policyEngine: policy.NewEngine(8),
	}
	recorder, err := openControlledRecorder(session.Dir)
	if err != nil {
		t.Fatal(err)
	}
	frame := testEthernetFrame(1, 2)
	info := gopacket.CaptureInfo{
		Timestamp: time.Unix(1, 0).UTC(), CaptureLength: len(frame), Length: len(frame),
	}
	ordinal, err := recorder.WriteOriginal(info, frame)
	if err != nil {
		t.Fatal(err)
	}
	host := &memoryPacketPort{name: "en7"}
	switchPort := &memoryPacketPort{name: "en8", writeErr: errors.New("secret-payload-marker")}
	queued := controlledQueuedFrame(
		frame,
		host,
		switchPort,
		traffic.SideHost,
		traffic.DirectionHostToSwitch,
	)
	queued.originalOrdinal = ordinal
	var counters controlledCounters
	err = session.processControlled(
		context.Background(),
		queued,
		recorder,
		&counters,
	)
	if err == nil || !strings.Contains(err.Error(), "secret-payload-marker") {
		t.Fatalf("injection error=%v", err)
	}
	if err := recorder.Close(); err != nil {
		t.Fatal(err)
	}
	decisions := readControlledDecisions(t, session.Dir)
	if len(decisions) != 1 ||
		decisions[0].OriginalCaptureOrdinal != ordinal ||
		decisions[0].EffectiveVerdict != policy.VerdictBlock ||
		!strings.Contains(decisions[0].Explanation, "runtime failure before forwarding") ||
		strings.Contains(decisions[0].Explanation, "secret-payload-marker") {
		t.Fatalf("injection decision=%#v", decisions)
	}
	if stats := counters.snapshot(); stats.BlockedPackets != 1 || stats.ForwardedPackets != 0 {
		t.Fatalf("injection stats=%#v", stats)
	}
}

func TestControlledEvidenceCarriesDecisionSummary(t *testing.T) {
	session := &Session{
		Mode:         ModeControlled,
		Dir:          t.TempDir(),
		policyEngine: policy.NewEngine(8),
		events:       make(chan Event, 4),
	}
	recorder, err := openControlledRecorder(session.Dir)
	if err != nil {
		t.Fatal(err)
	}
	host := &memoryPacketPort{name: "en7"}
	switchPort := &memoryPacketPort{name: "en8"}
	queued := controlledQueuedFrame(
		testEthernetFrame(1, 0xf0),
		host,
		switchPort,
		traffic.SideHost,
		traffic.DirectionHostToSwitch,
	)
	queued.overload = OverloadFailClosed
	var counters controlledCounters
	if err := session.processControlledOverload(queued, recorder, &counters); err != nil {
		t.Fatal(err)
	}
	if err := recorder.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case event := <-session.events:
		if event.Kind != KindEvidence ||
			event.Decision.Status != dataplane.StatusLive ||
			event.Decision.EffectiveVerdict != policy.VerdictBlock ||
			event.Decision.PacketID == "" ||
			event.Decision.Edited {
			t.Fatalf(
				"evidence kind=%s status=%s verdict=%s packet=%s edited=%t",
				event.Kind,
				event.Decision.Status,
				event.Decision.EffectiveVerdict,
				event.Decision.PacketID,
				event.Decision.Edited,
			)
		}
	default:
		t.Fatal("controlled evidence event was not emitted")
	}
}

func controlledPressureSession(t *testing.T) *Session {
	t.Helper()
	engine := policy.NewEngine(64)
	if err := engine.Policies.Activate("pressure", []policy.Rule{{
		ID: "slow-allow", Enabled: true,
		Actions: []policy.Action{{Kind: policy.ActionAllow}, {Kind: policy.ActionDelay, Duration: 20 * time.Millisecond}},
	}}); err != nil {
		t.Fatal(err)
	}
	return &Session{Dir: t.TempDir(), policyEngine: engine}
}

func controlledQueuedFrame(data []byte, from, to PacketPort, side traffic.TopologySide, direction traffic.Direction) queuedFrame {
	return queuedFrame{
		data: append([]byte(nil), data...),
		capture: gopacket.CaptureInfo{
			Timestamp: time.Unix(1, 0).UTC(), CaptureLength: len(data), Length: len(data),
		},
		from: from, to: to, side: side, direction: direction,
	}
}

func numberedEthernetFrames(count int) [][]byte {
	frames := make([][]byte, count)
	for index := range frames {
		frames[index] = testEthernetFrame(byte(index+1), 0xf0)
	}
	return frames
}

func assertFrameOrder(t *testing.T, got, want [][]byte) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("written frames=%d want=%d", len(got), len(want))
	}
	for index := range want {
		if string(got[index]) != string(want[index]) {
			t.Fatalf("frame %d arrived out of order: source=%d want=%d", index, got[index][11], want[index][11])
		}
	}
}

func readControlledDecisions(t *testing.T, directory string) []policy.Decision {
	t.Helper()
	file, err := os.Open(filepath.Join(directory, "decisions.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	var decisions []policy.Decision
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		var decision policy.Decision
		if err := json.Unmarshal(scanner.Bytes(), &decision); err != nil {
			t.Fatal(err)
		}
		decisions = append(decisions, decision)
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	return decisions
}

func assertDecisionOrder(t *testing.T, decisions []policy.Decision, frames [][]byte, directory string) {
	t.Helper()
	if len(decisions) != len(frames) {
		t.Fatalf("decisions=%d frames=%d", len(decisions), len(frames))
	}
	for index, frame := range frames {
		if want := controlledFrameID(frame, directory); decisions[index].PacketID != want {
			t.Fatalf("decision %d packet=%s want=%s", index, decisions[index].PacketID, want)
		}
	}
}

func assertCompleteControlledOrdinalLink(
	t *testing.T,
	decisions []policy.Decision,
	originals,
	forwarded uint64,
) {
	t.Helper()
	originalOrdinals := make(map[uint64]bool, len(decisions))
	forwardedOrdinals := make(map[uint64]bool)
	for _, decision := range decisions {
		if decision.OriginalCaptureOrdinal == 0 ||
			originalOrdinals[decision.OriginalCaptureOrdinal] {
			t.Fatalf("invalid original ordinal decision=%#v", decision)
		}
		originalOrdinals[decision.OriginalCaptureOrdinal] = true
		if decision.EffectiveVerdict == policy.VerdictBlock &&
			len(decision.ForwardedCaptureOrdinals) != 0 {
			t.Fatalf("blocked decision links forwarded evidence=%#v", decision)
		}
		for _, ordinal := range decision.ForwardedCaptureOrdinals {
			if ordinal == 0 || forwardedOrdinals[ordinal] {
				t.Fatalf("invalid forwarded ordinal decision=%#v", decision)
			}
			forwardedOrdinals[ordinal] = true
		}
	}
	if uint64(len(originalOrdinals)) != originals ||
		uint64(len(forwardedOrdinals)) != forwarded {
		t.Fatalf(
			"ordinal coverage originals=%d/%d forwarded=%d/%d decisions=%#v",
			len(originalOrdinals),
			originals,
			len(forwardedOrdinals),
			forwarded,
			decisions,
		)
	}
	for ordinal := uint64(1); ordinal <= originals; ordinal++ {
		if !originalOrdinals[ordinal] {
			t.Fatalf("original ordinal %d is missing", ordinal)
		}
	}
	for ordinal := uint64(1); ordinal <= forwarded; ordinal++ {
		if !forwardedOrdinals[ordinal] {
			t.Fatalf("forwarded ordinal %d is missing", ordinal)
		}
	}
}

func controlledFrameID(data []byte, directory string) traffic.PacketID {
	info := gopacket.CaptureInfo{Timestamp: time.Unix(1, 0).UTC(), CaptureLength: len(data), Length: len(data)}
	return traffic.Normalize(data, traffic.CaptureMetadata{
		Timestamp: info.Timestamp, CaptureLength: info.CaptureLength, OriginalLength: info.Length,
		LinkType: int(layers.LinkTypeEthernet), Source: directory,
	}, "en7", traffic.SideHost, traffic.DirectionHostToSwitch).ID
}

type memoryPacketPort struct {
	name     string
	mu       sync.Mutex
	packets  [][]byte
	read     [][]byte
	writes   [][]byte
	writeErr error
	closed   bool
}

func (p *memoryPacketPort) Name() string              { return p.name }
func (p *memoryPacketPort) LinkType() layers.LinkType { return layers.LinkTypeEthernet }
func (p *memoryPacketPort) ReadPacketData() ([]byte, gopacket.CaptureInfo, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.packets) == 0 {
		return nil, gopacket.CaptureInfo{}, io.EOF
	}
	data := append([]byte(nil), p.packets[0]...)
	p.packets = p.packets[1:]
	p.read = append(p.read, append([]byte(nil), data...))
	info := gopacket.CaptureInfo{Timestamp: time.Unix(1, 0).UTC(), CaptureLength: len(data), Length: len(data)}
	return data, info, nil
}
func (p *memoryPacketPort) WritePacketData(data []byte) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.writeErr != nil {
		return p.writeErr
	}
	p.writes = append(p.writes, append([]byte(nil), data...))
	return nil
}
func (p *memoryPacketPort) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.closed = true
	return nil
}
func (p *memoryPacketPort) writtenFrames() [][]byte {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make([][]byte, len(p.writes))
	for index := range p.writes {
		out[index] = append([]byte(nil), p.writes[index]...)
	}
	return out
}

func testEthernetFrame(sourceLast, destinationLast byte) []byte {
	frame := make([]byte, 60)
	copy(frame[0:6], []byte{2, 0, 0, 0, 0, destinationLast})
	copy(frame[6:12], []byte{2, 0, 0, 0, 0, sourceLast})
	frame[12], frame[13] = 0x88, 0xb5
	return frame
}
