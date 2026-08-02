package tui

import (
	"reflect"
	"strings"
	"testing"

	"golan/internal/dataplane"
	"golan/internal/policy"
	"golan/internal/traffic"

	tea "github.com/charmbracelet/bubbletea"
)

func TestGuidedConditionDefaultsCompile(t *testing.T) {
	for _, spec := range guidedConditionSpecs {
		spec := spec
		t.Run(string(spec.Kind), func(t *testing.T) {
			draft := guidedRuleDraft{
				id:         "test-" + string(spec.Kind),
				name:       spec.Label,
				action:     string(policy.ActionBlock),
				conditions: []guidedCondition{newGuidedCondition(spec.Kind)},
			}
			rule, err := draft.rule(false, 100)
			if err != nil {
				t.Fatalf("build rule: %v", err)
			}
			if _, err := policy.Compile("guided-default", []policy.Rule{rule}); err != nil {
				t.Fatalf("compile rule: %v", err)
			}
		})
	}
}

func TestGuidedRuleDraftBuildsTypedConditions(t *testing.T) {
	draft := guidedRuleDraft{
		id:     "typed",
		name:   "Typed conditions",
		action: string(policy.ActionBlock),
		conditions: []guidedCondition{
			{Kind: conditionMode, Value: "edge-route"},
			{Kind: conditionDirection, Value: "inbound"},
			{Kind: conditionSrcCIDR, Value: "192.0.2.7/24"},
			{Kind: conditionDstPort, Value: "80,443,8000-8010", Negate: true},
			{Kind: conditionTCPFlags, Value: "syn,ack"},
			{Kind: conditionHTTPHeader, Value: "content-type=text/plain; x-lab=yes"},
			{Kind: conditionHTTPStatus, Value: "202,404"},
		},
	}

	rule, err := draft.rule(false, 250)
	if err != nil {
		t.Fatalf("rule: %v", err)
	}
	if _, err := policy.Compile("typed", []policy.Rule{rule}); err != nil {
		t.Fatalf("compile: %v", err)
	}
	if !reflect.DeepEqual(rule.Match.Modes, []dataplane.Mode{dataplane.ModeEdgeRoute}) ||
		!reflect.DeepEqual(rule.Match.Directions, []traffic.Direction{traffic.DirectionInbound}) ||
		!reflect.DeepEqual(rule.Match.SrcCIDRs, []string{"192.0.2.0/24"}) {
		t.Fatalf("typed match = %#v", rule.Match)
	}
	if !rule.Match.DstPorts.Negate || !reflect.DeepEqual(rule.Match.DstPorts.Values, []uint16{80, 443}) ||
		!reflect.DeepEqual(rule.Match.DstPorts.Ranges, []policy.PortRange{{First: 8000, Last: 8010}}) {
		t.Fatalf("destination ports = %#v", rule.Match.DstPorts)
	}
	if rule.Match.TCPFlagMask != traffic.TCPFlags(0x12) || rule.Match.TCPFlags != traffic.TCPFlags(0x12) {
		t.Fatalf("TCP flags mask=%#x value=%#x", rule.Match.TCPFlagMask, rule.Match.TCPFlags)
	}
	if len(rule.Match.HTTPHeaders) != 2 || rule.Match.HTTPHeaders[1].Name != "x-lab" || rule.Match.HTTPHeaders[1].Value.Value != "yes" {
		t.Fatalf("HTTP headers = %#v", rule.Match.HTTPHeaders)
	}
	if !reflect.DeepEqual(rule.Match.HTTPStatuses, []uint16{202, 404}) {
		t.Fatalf("HTTP statuses = %#v", rule.Match.HTTPStatuses)
	}
}

func TestGuidedEditorAddsRemovesAndReordersConditions(t *testing.T) {
	m := NewModel()
	m.openRuleEditor(false)
	m.ruleEditor.cursor = 6 // Destination-port type.

	next, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'a'}})
	m = next.(Model)
	if len(m.ruleEditor.draft.conditions) != 4 || m.ruleEditor.draft.conditions[3].Kind != conditionSrcPort || m.ruleEditor.cursor != 8 {
		t.Fatalf("after add: cursor=%d conditions=%#v", m.ruleEditor.cursor, m.ruleEditor.draft.conditions)
	}

	next, _ = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'!'}})
	m = next.(Model)
	if !m.ruleEditor.draft.conditions[3].Negate {
		t.Fatalf("source-port operator = %#v", m.ruleEditor.draft.conditions[3])
	}

	next, _ = m.Update(tea.KeyMsg{Type: tea.KeyShiftUp})
	m = next.(Model)
	if m.ruleEditor.draft.conditions[2].Kind != conditionSrcPort || m.ruleEditor.cursor != 6 {
		t.Fatalf("after reorder: cursor=%d conditions=%#v", m.ruleEditor.cursor, m.ruleEditor.draft.conditions)
	}

	next, _ = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'d'}})
	m = next.(Model)
	if len(m.ruleEditor.draft.conditions) != 3 || m.ruleEditor.draft.conditions[2].Kind != conditionDstPort {
		t.Fatalf("after remove: cursor=%d conditions=%#v", m.ruleEditor.cursor, m.ruleEditor.draft.conditions)
	}
}

func TestGuidedEditorEditsRawPortValueWithoutRenderedOperator(t *testing.T) {
	m := NewModel()
	m.openRuleEditor(false)
	m.ruleEditor.cursor = 7 // Destination-port value.

	next, _ := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = next.(Model)
	if !m.ruleEditor.editing || m.ruleEditor.buffer != "80,443" {
		t.Fatalf("editing=%v buffer=%q", m.ruleEditor.editing, m.ruleEditor.buffer)
	}
}

func TestGuidedEditorTypesMultiValueEnumeratedConditions(t *testing.T) {
	m := NewModel()
	m.openRuleEditor(false)
	m.ruleEditor.cursor = 3 // Direction value.

	next, _ := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = next.(Model)
	if !m.ruleEditor.editing || m.ruleEditor.buffer != "outbound" {
		t.Fatalf("direction editing=%v buffer=%q", m.ruleEditor.editing, m.ruleEditor.buffer)
	}
	m.ruleEditor.buffer = "outbound,inbound"
	next, _ = m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = next.(Model)
	if m.ruleEditor.editing || m.ruleEditor.draft.conditions[0].Value != "outbound,inbound" {
		t.Fatalf("direction condition=%#v", m.ruleEditor.draft.conditions[0])
	}
	rule, err := m.ruleEditor.currentRule(100)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(rule.Match.Directions, []traffic.Direction{
		traffic.DirectionOutbound, traffic.DirectionInbound,
	}) {
		t.Fatalf("directions=%#v", rule.Match.Directions)
	}

	// Arrow keys retain the fast single-choice path without opening an editor.
	m.ruleEditor.cursor = 5 // Protocol value.
	next, _ = m.Update(tea.KeyMsg{Type: tea.KeyRight})
	m = next.(Model)
	if m.ruleEditor.editing || m.ruleEditor.draft.conditions[1].Value != "udp" {
		t.Fatalf("cycled protocol=%#v editing=%t", m.ruleEditor.draft.conditions[1], m.ruleEditor.editing)
	}
}

func TestGuidedEditorRejectsInvalidConditionWithoutReplacingPolicy(t *testing.T) {
	m := NewModel()
	if err := m.policyStore.Activate("baseline", nil); err != nil {
		t.Fatal(err)
	}
	m.openRuleEditor(false)
	m.ruleEditor.draft.conditions[2].Value = "443-80"
	m.refreshRuleDiagnostic()
	if !strings.Contains(m.ruleEditor.diagnostic, "port range") {
		t.Fatalf("diagnostic = %q", m.ruleEditor.diagnostic)
	}

	next, _ := m.Update(tea.KeyMsg{Type: tea.KeyCtrlS})
	m = next.(Model)
	active, ok := m.policyStore.Active()
	if !ok || active.Revision() != "baseline" || !m.ruleEditor.open {
		t.Fatalf("active=%v revision=%q editor=%v", ok, active.Revision(), m.ruleEditor.open)
	}
}

func TestGuidedEditorRendersAllTrafficAfterRemovingConditions(t *testing.T) {
	m := NewModel()
	m.openRuleEditor(false)
	for len(m.ruleEditor.draft.conditions) > 0 {
		m.ruleEditor.cursor = 2
		m.ruleEditor.removeCondition()
	}
	view := m.renderRuleEditor()
	if !strings.Contains(view, "WHEN") || !strings.Contains(view, "all traffic") || !strings.Contains(view, "THEN") {
		t.Fatalf("editor view:\n%s", view)
	}
}
