package tui

import (
	"encoding/binary"
	"encoding/json"
	"strings"
	"testing"

	"golan/internal/policy"
)

func TestRuleEditorSeparatesLiveEvidenceFromStaticDeploymentPreview(t *testing.T) {
	m := NewModel()
	m.height = 24
	m.openRuleEditor(false)

	view := m.View()
	for _, want := range []string{
		"Buffered live evidence:",
		"0 frames available",
		"Static deployment:",
		"no transformations · packet bytes unchanged",
		"Compatibility:",
		"listen=SHADOW · fast=LIVE",
		"controlled=LIVE · nat=LIVE",
		"edge-observe=SHADOW · edge-route=LIVE",
		"Active mode:",
	} {
		if !strings.Contains(view, want) {
			t.Fatalf("rule preview does not contain %q:\n%s", want, view)
		}
	}
}

func TestMatchReplaceEditorPreviewsStaticTransformationImpact(t *testing.T) {
	m := NewModel()
	m.height = 80
	m.openRuleEditor(true)
	m.ruleEditor.draft.search = "old"
	m.ruleEditor.draft.replace = "new"
	m.refreshRuleDiagnostic()

	view := m.View()
	for _, want := range []string{
		"1 literal",
		"boundary=controlled-frame",
		"length=preserved",
		"requires=rewrite-payload-same-length",
		"repair=IPv4 checksum",
	} {
		if !strings.Contains(view, want) {
			t.Fatalf("transformation preview does not contain %q:\n%s", want, view)
		}
	}
}

func TestInvalidAdvancedEditClearsStaticDeploymentPreview(t *testing.T) {
	m := NewModel()
	m.height = 80
	rule := policy.Rule{
		ID:       "replace",
		Name:     "Replace",
		Priority: 100,
		Enabled:  true,
		Revision: 1,
		Match: policy.Match{
			Payload: []policy.BytePattern{{Kind: policy.PatternLiteral, Value: "old"}},
		},
		Actions: []policy.Action{{Kind: policy.ActionAllow}},
		Transformations: []policy.Transformation{{
			Kind: policy.TransformLiteral, Search: "old", Replace: "new",
			Occurrence: policy.OccurrenceFirst,
		}},
	}
	openAdvancedRuleForTest(t, &m, rule)
	if !m.ruleEditor.advanced || len(m.ruleEditor.compatibility) == 0 || len(m.ruleEditor.impacts) == 0 {
		t.Fatalf("valid advanced preview missing: %#v", m.ruleEditor)
	}

	m.ruleEditor.rawLines = []string{`{"id":`}
	m.refreshRuleDiagnostic()
	view := m.View()
	if len(m.ruleEditor.compatibility) != 0 || len(m.ruleEditor.impacts) != 0 {
		t.Fatalf("invalid draft retained static details: compatibility=%v impacts=%v", m.ruleEditor.compatibility, m.ruleEditor.impacts)
	}
	if !strings.Contains(view, "unavailable until the draft is valid") ||
		!strings.Contains(view, "advanced JSON") ||
		strings.Contains(view, "caller mutation") {
		t.Fatalf("invalid advanced preview is stale or unexplained:\n%s", view)
	}
}

func TestTransformationPreviewBoundsVisibleDetails(t *testing.T) {
	transforms := make([]policy.Transformation, 6)
	for index := range transforms {
		transforms[index] = policy.Transformation{
			Kind: policy.TransformLiteral, Search: "old", Replace: "new",
			Occurrence: policy.OccurrenceFirst,
		}
	}
	rule := policy.Rule{
		ID:       "many-transforms",
		Name:     "Many transforms",
		Priority: 100,
		Enabled:  true,
		Revision: 1,
		Match: policy.Match{
			Payload: []policy.BytePattern{{Kind: policy.PatternLiteral, Value: "old"}},
		},
		Actions:         []policy.Action{{Kind: policy.ActionAllow}},
		Transformations: transforms,
	}
	m := NewModel()
	openAdvancedRuleForTest(t, &m, rule)
	wantLines := maxVisibleTransformationImpacts*2 + 1
	if len(m.ruleEditor.impacts) != wantLines {
		t.Fatalf("impact lines=%d want=%d: %v", len(m.ruleEditor.impacts), wantLines, m.ruleEditor.impacts)
	}
	if got := m.ruleEditor.impacts[len(m.ruleEditor.impacts)-1]; got != "+2 more transformation(s)" {
		t.Fatalf("overflow summary=%q", got)
	}
	for index := 0; index < maxVisibleTransformationImpacts; index++ {
		impact := strings.Join(m.ruleEditor.impacts[index*2:index*2+2], " ")
		if !strings.Contains(impact, "boundary=controlled-frame") ||
			!strings.Contains(impact, "length=preserved") ||
			!strings.Contains(impact, "requires=rewrite-payload-same-length") {
			t.Fatalf("incomplete bounded impact: %q", impact)
		}
	}
}

func openAdvancedRuleForTest(t *testing.T, m *Model, rule policy.Rule) {
	t.Helper()
	content, err := json.MarshalIndent(rule, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	m.ruleEditor = ruleEditorState{
		open: true, advanced: true, rawLines: strings.Split(string(content), "\n"),
		previewSource: ruleEvidenceSourceLive,
		preview:       "0 frames available · start a live session to collect a bounded preview sample",
	}
	m.refreshRuleDiagnostic()
}

func TestRuleEditorIgnoresLateLivePreview(t *testing.T) {
	m := NewModel()
	m.ruleEditor = ruleEditorState{
		open: true, previewEpoch: 9, preview: "current draft has newer live evidence",
		previewSource: ruleEvidenceSourceLive, evidence: []string{"current evidence"},
	}
	next, _ := m.Update(rulePreviewMsg{
		epoch: 8, source: ruleEvidenceSourceLive, packets: 10, matches: 4,
	})
	m = next.(Model)
	if m.ruleEditor.preview != "current draft has newer live evidence" ||
		m.ruleEditor.previewSource != ruleEvidenceSourceLive ||
		len(m.ruleEditor.evidence) != 1 || m.ruleEditor.evidence[0] != "current evidence" {
		t.Fatalf("late preview replaced current state: %#v", m.ruleEditor)
	}
}

func TestRulePreviewEpochAdvancesForDraftChangesAndReopens(t *testing.T) {
	m := NewModel()
	m.openRuleEditor(false)
	first := m.ruleEditor.previewEpoch
	m.ruleEditor.preview = "testing old draft"
	m.ruleEditor.evidence = []string{"old evidence"}
	m.ruleEditor.draft.name = "Changed"
	m.refreshRuleDiagnostic()
	second := m.ruleEditor.previewEpoch
	if second <= first || len(m.ruleEditor.evidence) != 0 ||
		!strings.Contains(m.ruleEditor.preview, "0 frames available") {
		t.Fatalf("draft refresh did not invalidate evidence: first=%d second=%d editor=%#v", first, second, m.ruleEditor)
	}
	m.ruleEditor = ruleEditorState{}
	m.openRuleEditor(false)
	if m.ruleEditor.previewEpoch <= second {
		t.Fatalf("new editor reused preview epoch: second=%d reopened=%d", second, m.ruleEditor.previewEpoch)
	}
}

func rulePreviewTCPFrame(payload []byte) []byte {
	return rulePreviewTCPFramePort(80, payload)
}

func rulePreviewTCPFramePort(destinationPort uint16, payload []byte) []byte {
	const ethernetHeader = 14
	const ipv4Header = 20
	const tcpHeader = 20
	data := make([]byte, ethernetHeader+ipv4Header+tcpHeader+len(payload))
	copy(data[0:6], []byte{2, 0, 0, 0, 0, 2})
	copy(data[6:12], []byte{2, 0, 0, 0, 0, 1})
	binary.BigEndian.PutUint16(data[12:14], 0x0800)
	ip := data[ethernetHeader : ethernetHeader+ipv4Header]
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:4], uint16(ipv4Header+tcpHeader+len(payload)))
	ip[8] = 64
	ip[9] = 6
	copy(ip[12:16], []byte{192, 0, 2, 1})
	copy(ip[16:20], []byte{198, 51, 100, 2})
	tcp := data[ethernetHeader+ipv4Header : ethernetHeader+ipv4Header+tcpHeader]
	binary.BigEndian.PutUint16(tcp[0:2], 40000)
	binary.BigEndian.PutUint16(tcp[2:4], destinationPort)
	tcp[12] = 5 << 4
	copy(data[ethernetHeader+ipv4Header+tcpHeader:], payload)
	return data
}
