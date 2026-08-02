package policy

import (
	"encoding/binary"
	"errors"
	"strings"
	"testing"
	"time"

	"golan/internal/dataplane"
	"golan/internal/traffic"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func TestCompileRejectsSessionTranslationActions(t *testing.T) {
	for _, kind := range []ActionKind{ActionNAT, ActionRedirect, ActionPortForward} {
		t.Run(string(kind), func(t *testing.T) {
			_, err := Compile("session-setting", []Rule{{
				ID: "legacy-" + string(kind), Enabled: true,
				Actions: []Action{{Kind: kind, Value: "legacy-free-form-target"}},
			}})
			if err == nil || !strings.Contains(err.Error(), "session-level network setting") {
				t.Fatalf("compile error = %v", err)
			}
		})
	}
}

func TestEvaluateOrderingExplanationAndShadow(t *testing.T) {
	rules := []Rule{
		{ID: "block-web", Priority: 10, Enabled: true, Match: Match{Protocols: []uint8{6}, DstPorts: PortSet{Values: []uint16{80}}}, Actions: []Action{{Kind: ActionBlock}}},
		{ID: "tag-all", Priority: 20, Enabled: true, Actions: []Action{{Kind: ActionTag, Value: "seen"}}},
	}
	ruleSet, err := Compile("r1", rules)
	if err != nil {
		t.Fatal(err)
	}
	frame := testTCPFrame(t, 80, []byte("GET / HTTP/1.1\r\nHost: example.test\r\n\r\n"))
	flow := traffic.NewTracker(10).Observe(frame)
	decision := ruleSet.Evaluate(frame, flow, dataplane.ForMode(dataplane.ModeListen))
	if decision.WinningRuleID != "block-web" || decision.Verdict != VerdictBlock || decision.EffectiveVerdict != VerdictAllow || decision.Status != dataplane.StatusShadow {
		t.Fatalf("decision = %#v", decision)
	}
	if len(decision.MatchingRuleIDs) != 2 || len(decision.Tags) != 1 || decision.Tags[0] != "seen" {
		t.Fatalf("decision path = %#v", decision)
	}
	controlled := ruleSet.Evaluate(frame, flow, dataplane.ForMode(dataplane.ModeControlledBridge))
	if controlled.Status != dataplane.StatusLive || controlled.EffectiveVerdict != VerdictBlock {
		t.Fatalf("controlled decision = %#v", controlled)
	}
}

func TestTagActionRemainsDecisionMetadata(t *testing.T) {
	ruleSet, err := Compile("tags", []Rule{{
		ID: "tag-web", Enabled: true,
		Match:   Match{DstPorts: PortSet{Values: []uint16{80}}},
		Actions: []Action{{Kind: ActionTag, Value: "web"}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	frame := testTCPFrame(t, 80, nil)
	decision := ruleSet.Evaluate(
		frame,
		traffic.NewTracker(8).Observe(frame),
		dataplane.ForMode(dataplane.ModeControlledBridge),
	)
	if len(decision.Tags) != 1 || decision.Tags[0] != "web" {
		t.Fatalf("decision tags=%v", decision.Tags)
	}
}

func TestProcessMarksChangedTransformationAsEdited(t *testing.T) {
	engine := NewEngine(8)
	if err := engine.Policies.Activate("edit", []Rule{{
		ID:      "replace",
		Enabled: true,
		Match: Match{
			Protocols: []uint8{6},
			DstPorts:  PortSet{Values: []uint16{80}},
		},
		Actions: []Action{{Kind: ActionAllow}},
		Transformations: []Transformation{{
			Kind: TransformLiteral, Search: "old", Replace: "new",
		}},
	}}); err != nil {
		t.Fatal(err)
	}
	result, err := engine.Process(
		testTCPFrame(t, 80, []byte("old")),
		dataplane.ForMode(dataplane.ModeControlledBridge),
	)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Decision.Edited ||
		!result.Decision.Summary().Edited ||
		result.Decision.ForwardedPacketID == result.Decision.PacketID {
		t.Fatalf(
			"edited=%t summary=%t original=%s forwarded=%s",
			result.Decision.Edited,
			result.Decision.Summary().Edited,
			result.Decision.PacketID,
			result.Decision.ForwardedPacketID,
		)
	}
}

func TestFastBridgeIncompatibleRuleIsShadow(t *testing.T) {
	rule := Rule{ID: "http-host", Enabled: true, Match: Match{HTTPHosts: []BytePattern{{Kind: PatternLiteral, Value: "example.test"}}}, Actions: []Action{{Kind: ActionBlock}}}
	ruleSet, err := Compile("r1", []Rule{rule})
	if err != nil {
		t.Fatal(err)
	}
	frame := testTCPFrame(t, 80, []byte("GET / HTTP/1.1\r\nHost: example.test\r\n\r\n"))
	decision := ruleSet.Evaluate(frame, traffic.NewTracker(10).Observe(frame), dataplane.ForMode(dataplane.ModeFastBridge))
	if decision.Status != dataplane.StatusShadow || decision.EffectiveVerdict != VerdictAllow {
		t.Fatalf("decision = %#v", decision)
	}
}

func TestFastBridgePFCompatibilityMakesExactIPRulesLive(t *testing.T) {
	rule := Rule{
		ID: "block-fast-web", Enabled: true,
		Match: Match{
			Modes:      []dataplane.Mode{dataplane.ModeFastBridge},
			Directions: []traffic.Direction{traffic.DirectionHostToSwitch},
			IPVersions: []uint8{4}, DstCIDRs: []string{"198.51.100.0/24"},
			Protocols: []uint8{6}, DstPorts: PortSet{Values: []uint16{80, 443}},
		},
		Actions: []Action{{Kind: ActionBlock}},
	}
	if !FastBridgePFCompatible(rule) || FastBridgeL2Compatible(rule) || !FastBridgeCompatible(rule) {
		t.Fatalf("compatibility PF=%v L2=%v fast=%v", FastBridgePFCompatible(rule), FastBridgeL2Compatible(rule), FastBridgeCompatible(rule))
	}
	status, _, reason := Compatibility(rule, dataplane.ForMode(dataplane.ModeFastBridge))
	if status != dataplane.StatusLive || reason != "" {
		t.Fatalf("status=%s reason=%q", status, reason)
	}

	rule.Match.HTTPHosts = []BytePattern{{Kind: PatternLiteral, Value: "example.test"}}
	if FastBridgePFCompatible(rule) || FastBridgeCompatible(rule) {
		t.Fatalf("application rule unexpectedly compatible: %#v", rule)
	}
	status, _, _ = Compatibility(rule, dataplane.ForMode(dataplane.ModeFastBridge))
	if status != dataplane.StatusShadow {
		t.Fatalf("application rule status=%s", status)
	}
}

func TestEdgeRouteCompatibilityMatchesPFCompilerBoundary(t *testing.T) {
	rules := []Rule{
		{ID: "http-userspace", Priority: 20, Enabled: true, Match: Match{HTTPMethods: []string{"GET"}}, Actions: []Action{{Kind: ActionBlock}}},
		{ID: "block-port", Priority: 10, Enabled: true, Match: Match{Protocols: []uint8{6}, DstPorts: PortSet{Values: []uint16{80}}}, Actions: []Action{{Kind: ActionBlock}}},
	}
	ruleSet, err := Compile("edge", rules)
	if err != nil {
		t.Fatal(err)
	}
	frame := testTCPFrame(t, 80, []byte("GET / HTTP/1.1\r\nHost: example.test\r\n\r\n"))
	flow := traffic.NewTracker(10).Observe(frame)
	decision := ruleSet.Evaluate(frame, flow, dataplane.ForMode(dataplane.ModeEdgeRoute))
	if decision.WinningRuleID != "http-userspace" || decision.Status != dataplane.StatusShadow || decision.EffectiveVerdict != VerdictAllow {
		t.Fatalf("userspace decision = %#v", decision)
	}
	status, _, _ := Compatibility(rules[1], dataplane.ForMode(dataplane.ModeEdgeRoute))
	if status != dataplane.StatusLive || !EdgeRouteCompatible(rules[1]) {
		t.Fatalf("PF-compatible rule status=%s compatible=%v", status, EdgeRouteCompatible(rules[1]))
	}
}

func TestTakeoverCompatibilityMatchesEndpointPFBoundary(t *testing.T) {
	live := Rule{
		ID: "block-takeover-web", Enabled: true,
		Match: Match{
			Modes:      []dataplane.Mode{dataplane.ModeTakeover},
			Directions: []traffic.Direction{traffic.DirectionOutbound},
			IPVersions: []uint8{4}, Protocols: []uint8{6},
			DstPorts: PortSet{Values: []uint16{80}},
		},
		Actions: []Action{{Kind: ActionBlock}},
	}
	status, capability, reason := Compatibility(live, dataplane.ForMode(dataplane.ModeTakeover))
	if status != dataplane.StatusLive || capability != dataplane.CapabilityStatefulFilter || reason != "" || !TakeoverPFCompatible(live) {
		t.Fatalf("live status=%s capability=%s compatible=%t reason=%q", status, capability, TakeoverPFCompatible(live), reason)
	}

	application := live
	application.ID = "http-semantic"
	application.Match.HTTPMethods = []string{"POST"}
	status, _, reason = Compatibility(application, dataplane.ForMode(dataplane.ModeTakeover))
	if status != dataplane.StatusShadow || reason == "" || TakeoverPFCompatible(application) {
		t.Fatalf("application status=%s PF=%t reason=%q", status, TakeoverPFCompatible(application), reason)
	}

	ethernet := live
	ethernet.ID = "ethernet-only"
	ethernet.Match = Match{EtherTypes: []uint16{0x0806}}
	status, _, reason = Compatibility(ethernet, dataplane.ForMode(dataplane.ModeTakeover))
	if status != dataplane.StatusShadow || reason == "" || TakeoverPFCompatible(ethernet) {
		t.Fatalf("ethernet status=%s compatible=%t reason=%q", status, TakeoverPFCompatible(ethernet), reason)
	}
}

func TestStoreRetainsPriorRevisionOnCompileFailure(t *testing.T) {
	var store Store
	if err := store.Activate("good", []Rule{{ID: "allow", Enabled: true, Actions: []Action{{Kind: ActionAllow}}}}); err != nil {
		t.Fatal(err)
	}
	err := store.Activate("bad", []Rule{{ID: "bad", Enabled: true, Match: Match{Payload: []BytePattern{{Kind: PatternRE2, Value: "("}}}}})
	if err == nil {
		t.Fatal("invalid revision activated")
	}
	active, ok := store.Active()
	if !ok || active.Revision() != "good" {
		t.Fatalf("active revision = %q, %v", active.Revision(), ok)
	}
}

func TestStoreRetainsHistoryAndActivatesNamedRevision(t *testing.T) {
	var store Store
	first := []Rule{{ID: "allow", Enabled: true, Actions: []Action{{Kind: ActionAllow}}}}
	second := []Rule{{ID: "block", Enabled: true, Actions: []Action{{Kind: ActionBlock}}}}
	if err := store.Activate("first", first); err != nil {
		t.Fatal(err)
	}
	if err := store.Activate("second", second); err != nil {
		t.Fatal(err)
	}
	history := store.History()
	if len(history) != 2 || history[0].Revision != "second" || !history[0].Active || history[1].Revision != "first" {
		t.Fatalf("history = %#v", history)
	}
	if err := store.ActivateRevision("first"); err != nil {
		t.Fatal(err)
	}
	active, ok := store.Active()
	if !ok || active.Revision() != "first" || active.Rules()[0].ID != "allow" {
		t.Fatalf("active = %#v, %v", active.Rules(), ok)
	}
	history = store.History()
	if !history[1].Active || history[0].Active {
		t.Fatalf("rollback history = %#v", history)
	}
}

func TestStoreRegistersInactiveRevisionAndRejectsNameReuse(t *testing.T) {
	var store Store
	allow := []Rule{{ID: "allow", Enabled: true, Actions: []Action{{Kind: ActionAllow}}}}
	if err := store.Register("saved", allow); err != nil {
		t.Fatal(err)
	}
	if _, ok := store.Active(); ok {
		t.Fatal("register unexpectedly activated the revision")
	}
	if _, ok := store.Revision("saved"); !ok {
		t.Fatal("registered revision is missing")
	}
	if err := store.Register("saved", allow); err != nil {
		t.Fatalf("identical registration failed: %v", err)
	}
	block := []Rule{{ID: "block", Enabled: true, Actions: []Action{{Kind: ActionBlock}}}}
	if err := store.Activate("saved", block); err == nil {
		t.Fatal("revision name was reused for different rules")
	}
	if _, ok := store.Active(); ok {
		t.Fatal("failed name reuse changed the active revision")
	}
}

func TestApplyTransformationsRepairsFrameAndPreservesOwnership(t *testing.T) {
	frame := testTCPFrame(t, 80, []byte("token=old"))
	decision := Decision{
		Status: dataplane.StatusLive, EffectiveVerdict: VerdictAllow,
		Transformations: []Transformation{
			{Kind: TransformField, Field: traffic.FieldDstPort, Replace: "8080"},
			{Kind: TransformLiteral, Search: "old", Replace: "new", Occurrence: OccurrenceFirst},
		},
	}
	forwarded, err := ApplyTransformations(frame, decision)
	if err != nil {
		t.Fatal(err)
	}
	decoded := forwarded.Decoded()
	if decoded.DstPort != 8080 {
		t.Fatalf("destination port = %d", decoded.DstPort)
	}
	ranges := forwarded.Ranges(traffic.FieldPayload)
	payload := forwarded.RawBytes()[ranges[0].Start:ranges[0].End]
	if string(payload) != "token=new" {
		t.Fatalf("payload = %q", payload)
	}
	if frame.Decoded().DstPort != 80 {
		t.Fatal("original frame was mutated")
	}
	checksum := forwarded.Ranges(traffic.FieldTCPChecksum)[0]
	if binary.BigEndian.Uint16(forwarded.RawBytes()[checksum.Start:checksum.End]) == 0 {
		t.Fatal("TCP checksum was not repaired")
	}
}

func TestTLSLengthChangeIsUnsupported(t *testing.T) {
	ruleSet, err := Compile("tls", []Rule{{
		ID: "rewrite-tls", Enabled: true, Match: Match{DstPorts: PortSet{Values: []uint16{443}}},
		Actions:         []Action{{Kind: ActionAllow}},
		Transformations: []Transformation{{Kind: TransformLiteral, Search: "old", Replace: "new"}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	frame := testTCPFrame(t, 443, []byte("encrypted"))
	decision := ruleSet.Evaluate(frame, traffic.NewTracker(10).Observe(frame), dataplane.ForMode(dataplane.ModeControlledBridge))
	if decision.Status != dataplane.StatusUnsupported || decision.EffectiveVerdict != VerdictAllow {
		t.Fatalf("decision = %#v", decision)
	}
}

func TestApplyShadowTransformReturnsTypedError(t *testing.T) {
	_, err := ApplyTransformations(testTCPFrame(t, 80, []byte("old")), Decision{Status: dataplane.StatusShadow, Transformations: []Transformation{{Kind: TransformLiteral, Search: "old", Replace: "new"}}})
	if !errors.Is(err, ErrDecisionNotLive) {
		t.Fatalf("error = %v", err)
	}
}

func testTCPFrame(t *testing.T, destinationPort uint16, payload []byte) traffic.Frame {
	t.Helper()
	eth := &layers.Ethernet{SrcMAC: []byte{2, 0, 0, 0, 0, 1}, DstMAC: []byte{2, 0, 0, 0, 0, 2}, EthernetType: layers.EthernetTypeIPv4}
	ip := &layers.IPv4{Version: 4, IHL: 5, TTL: 64, Protocol: layers.IPProtocolTCP, SrcIP: []byte{192, 0, 2, 1}, DstIP: []byte{198, 51, 100, 2}}
	tcp := &layers.TCP{SrcPort: 40000, DstPort: layers.TCPPort(destinationPort), SYN: true, Window: 4096}
	if err := tcp.SetNetworkLayerForChecksum(ip); err != nil {
		t.Fatal(err)
	}
	buffer := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, eth, ip, tcp, gopacket.Payload(payload)); err != nil {
		t.Fatal(err)
	}
	return traffic.Normalize(buffer.Bytes(), traffic.CaptureMetadata{Timestamp: time.Unix(100, 0)}, "en1", traffic.SideHost, traffic.DirectionHostToSwitch)
}
