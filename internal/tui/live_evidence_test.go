package tui

import (
	"bytes"
	"strings"
	"testing"
	"time"

	bridge "golan/internal/bridge"
	"golan/internal/dataplane"
	"golan/internal/edge"
	"golan/internal/listen"
	"golan/internal/policy"
	"golan/internal/traffic"

	tea "github.com/charmbracelet/bubbletea"
)

func TestLiveEvidenceBufferBoundsAndCopiesOwnership(t *testing.T) {
	t.Parallel()
	var m Model
	tracker := traffic.NewTracker(maxLiveEvidenceFrames + 2)
	var firstRetained traffic.PacketID
	for index := 0; index < maxLiveEvidenceFrames+1; index++ {
		frame := liveEvidenceFrame([]byte{byte(index)}, traffic.DirectionOutbound)
		flow := tracker.Observe(frame)
		flow.DirectionCount = map[traffic.Direction]int{traffic.DirectionOutbound: 1}
		m.addLiveEvidenceDecision(frame, flow, dataplane.ModeControlledBridge, policy.DecisionSummary{})
		if index == 1 {
			firstRetained = frame.ID
		}
	}
	if len(m.liveEvidence) != maxLiveEvidenceFrames ||
		m.liveEvidence[0].Frame.ID != firstRetained ||
		m.liveEvidenceBytes <= 0 || m.liveEvidenceBytes > maxLiveEvidenceBytes {
		t.Fatalf("live evidence count=%d first=%s bytes=%d", len(m.liveEvidence), m.liveEvidence[0].Frame.ID, m.liveEvidenceBytes)
	}

	snapshot := m.liveEvidenceSnapshot()
	snapshot[0].Flow.DirectionCount[traffic.DirectionOutbound] = 99
	snapshot[0].Frame.RawBytes()[0] ^= 0xff
	again := m.liveEvidenceSnapshot()
	if again[0].Flow.DirectionCount[traffic.DirectionOutbound] != 1 ||
		!bytes.Equal(again[0].Frame.RawBytes(), m.liveEvidence[0].Frame.RawBytes()) {
		t.Fatal("live evidence snapshot leaked mutable ownership")
	}
}

func TestLiveEvidenceBufferEnforcesByteLimitAndClear(t *testing.T) {
	t.Parallel()
	var m Model
	for index := 0; index < 3; index++ {
		payload := bytes.Repeat([]byte{byte(index + 1)}, 900<<10)
		m.addLiveEvidenceDecision(liveEvidenceFrame(payload, traffic.DirectionOutbound), traffic.Flow{}, dataplane.ModeListen, policy.DecisionSummary{})
	}
	if len(m.liveEvidence) != 2 || m.liveEvidenceBytes > maxLiveEvidenceBytes {
		t.Fatalf("live evidence count=%d bytes=%d", len(m.liveEvidence), m.liveEvidenceBytes)
	}
	oversized := liveEvidenceFrame(bytes.Repeat([]byte{0xaa}, maxLiveEvidenceBytes+1), traffic.DirectionOutbound)
	m.addLiveEvidenceDecision(oversized, traffic.Flow{}, dataplane.ModeListen, policy.DecisionSummary{})
	if len(m.liveEvidence) != 2 {
		t.Fatalf("oversized evidence changed buffer count=%d", len(m.liveEvidence))
	}
	m.executeCommand("clear")
	if len(m.liveEvidence) != 0 || m.liveEvidenceBytes != 0 {
		t.Fatalf("clear retained private evidence count=%d bytes=%d", len(m.liveEvidence), m.liveEvidenceBytes)
	}
	m.addLiveEvidenceDecision(liveEvidenceFrame([]byte("new-project"), traffic.DirectionOutbound), traffic.Flow{}, dataplane.ModeListen, policy.DecisionSummary{})
	m.attachProject(nil)
	if len(m.liveEvidence) != 0 || m.liveEvidenceBytes != 0 {
		t.Fatalf("project switch retained private evidence count=%d bytes=%d", len(m.liveEvidence), m.liveEvidenceBytes)
	}
}

func TestLiveEvidenceEventsNeverRenderFrameBytes(t *testing.T) {
	t.Parallel()
	listenFrame := liveEvidenceFrame([]byte("private-live-payload-1"), traffic.DirectionOutbound)
	bridgeFrame := liveEvidenceFrame([]byte("private-live-payload-2"), traffic.DirectionOutbound)
	edgeFrame := liveEvidenceFrame([]byte("private-live-payload-3"), traffic.DirectionOutbound)
	tracker := traffic.NewTracker(3)
	m := NewModel()
	m.handleListenEvent(listen.Event{
		Kind: listen.KindEvidence, Frame: listenFrame, Flow: tracker.Observe(listenFrame), Mode: dataplane.ModeListen,
		Decision: policy.DecisionSummary{PacketID: listenFrame.ID, Verdict: policy.VerdictBlock, EffectiveVerdict: policy.VerdictAllow, Status: dataplane.StatusShadow, WinningRuleID: "listen-shadow"},
	})
	m.handleBridgeEvent(nil, bridge.Event{
		Kind: bridge.KindEvidence, Frame: bridgeFrame, Flow: tracker.Observe(bridgeFrame), Mode: dataplane.ModeControlledBridge,
		Decision: policy.DecisionSummary{PacketID: bridgeFrame.ID, ForwardedPacketID: bridgeFrame.ID, Verdict: policy.VerdictAllow, EffectiveVerdict: policy.VerdictAllow, Status: dataplane.StatusLive, WinningRuleID: "bridge-allow"},
	})
	m.handleEdgeEvent(nil, edge.Event{
		Kind: edge.KindEvidence, Frame: edgeFrame, Flow: tracker.Observe(edgeFrame), Mode: dataplane.ModeEdgeRoute,
		Decision: policy.DecisionSummary{PacketID: edgeFrame.ID, EffectiveVerdict: policy.VerdictBlock, Verdict: policy.VerdictBlock, Status: dataplane.StatusLive, WinningRuleID: "edge-block"},
	})
	if len(m.liveEvidence) != 3 {
		t.Fatalf("live evidence count=%d", len(m.liveEvidence))
	}
	if strings.Contains(strings.Join(m.output, "\n"), "private-live-payload") {
		t.Fatalf("evidence payload entered generic output: %q", m.output)
	}
}

func TestRuleLivePreviewUsesModeAndImmutableSnapshot(t *testing.T) {
	t.Parallel()
	matching := liveEvidenceFrame([]byte("token=old"), traffic.DirectionOutbound)
	unmatched := liveEvidenceFrame([]byte("token=safe"), traffic.DirectionOutbound)
	tracker := traffic.NewTracker(2)
	records := []liveEvidenceRecord{
		{Frame: matching, Flow: tracker.Observe(matching), Mode: dataplane.ModeControlledBridge},
		{Frame: unmatched, Flow: tracker.Observe(unmatched), Mode: dataplane.ModeControlledBridge},
	}
	rule := policy.Rule{
		ID: "live-replace", Enabled: true,
		Match: policy.Match{
			Modes: []dataplane.Mode{dataplane.ModeControlledBridge}, Directions: []traffic.Direction{traffic.DirectionOutbound},
			Protocols: []uint8{6}, DstPorts: policy.PortSet{Values: []uint16{80}},
			Payload: []policy.BytePattern{{Kind: policy.PatternLiteral, Value: "old"}},
		},
		Actions:         []policy.Action{{Kind: policy.ActionAllow}},
		Transformations: []policy.Transformation{{Kind: policy.TransformLiteral, Search: "old", Replace: "new", Occurrence: policy.OccurrenceFirst}},
	}
	before := matching.RawBytes()
	msg := previewRuleLiveCmd(records, rule, 91)().(rulePreviewMsg)
	if msg.err != nil || msg.source != ruleEvidenceSourceLive || msg.packets != 2 || msg.matches != 1 || msg.sample == nil || msg.sampleErr != nil {
		t.Fatalf("live preview message=%#v", msg)
	}
	if !bytes.Equal(before, matching.RawBytes()) {
		t.Fatal("live preview mutated buffered evidence")
	}
}

func TestRuleEditorUsesBufferedLiveFramesWithoutFilePrompt(t *testing.T) {
	t.Parallel()
	m := NewModel()
	m.height = 80
	frame := liveEvidenceFrame(nil, traffic.DirectionOutbound)
	m.addLiveEvidenceDecision(frame, traffic.NewTracker(1).Observe(frame), dataplane.ModeControlledBridge, policy.DecisionSummary{})
	m.openRuleEditor(false)
	next, cmd := m.updateRuleEditor(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'t'}})
	m = next.(Model)
	if cmd == nil || m.ruleEditor.previewSource != ruleEvidenceSourceLive {
		t.Fatalf("buffered live preview did not start: editor=%#v", m.ruleEditor)
	}
	next, _ = m.Update(cmd().(rulePreviewMsg))
	m = next.(Model)
	view := m.View()
	if !strings.Contains(view, "Buffered live evidence: 1 packets tested") || !strings.Contains(view, "sample packet=") {
		t.Fatalf("buffered live result missing:\n%s", view)
	}
}

func TestReplacementMatchSupportsBridgeDirectionsAndICMPv6(t *testing.T) {
	t.Parallel()
	for name, test := range map[string]struct {
		direction string
		protocol  string
		wantDir   traffic.Direction
		wantProto uint8
	}{
		"host to switch":        {direction: "host-to-switch", protocol: "tcp", wantDir: traffic.DirectionHostToSwitch, wantProto: 6},
		"switch to host ICMPv6": {direction: "switch-to-host", protocol: "icmpv6", wantDir: traffic.DirectionSwitchToHost, wantProto: 58},
	} {
		t.Run(name, func(t *testing.T) {
			match, err := (guidedRuleDraft{direction: test.direction, protocol: test.protocol, ports: "any"}).legacyReplacementMatch()
			if err != nil {
				t.Fatal(err)
			}
			if len(match.Directions) != 1 || match.Directions[0] != test.wantDir || len(match.Protocols) != 1 || match.Protocols[0] != test.wantProto {
				t.Fatalf("replacement match=%#v", match)
			}
		})
	}
}

func liveEvidenceFrame(payload []byte, direction traffic.Direction) traffic.Frame {
	return traffic.Normalize(
		rulePreviewTCPFrame(payload),
		traffic.CaptureMetadata{Timestamp: time.Unix(100, 0)},
		"en1", traffic.SideHost, direction,
	)
}
