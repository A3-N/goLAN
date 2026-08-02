package tui

import (
	"strings"
	"testing"

	"golan/internal/policy"
	"golan/internal/traffic"

	tea "github.com/charmbracelet/bubbletea"
)

func TestShowRulesAndRulesInspectorExposeSharedDiagnostics(t *testing.T) {
	m := NewModel()
	rules := []policy.Rule{
		{
			ID: "block-web", Priority: 200, Enabled: true,
			Match: policy.Match{
				Directions: []traffic.Direction{traffic.DirectionOutbound},
				Protocols:  []uint8{6},
				DstPorts:   policy.PortSet{Values: []uint16{80}},
			},
			Actions: []policy.Action{{Kind: policy.ActionBlock}},
		},
		{
			ID: "allow-client-ports", Priority: 100, Enabled: true,
			Match: policy.Match{
				Directions: []traffic.Direction{traffic.DirectionOutbound},
				Protocols:  []uint8{6},
				SrcPorts:   policy.PortSet{Ranges: []policy.PortRange{{First: 1000, Last: 2000}}},
			},
			Actions: []policy.Action{{Kind: policy.ActionAllow}},
		},
	}
	if err := m.policyStore.Activate("diagnostics", rules); err != nil {
		t.Fatalf("Activate: %v", err)
	}

	m.showRules()
	if !containsOutput(m.output, "WARN conflict rule=allow-client-ports related=block-web mode=listen") {
		t.Fatalf("show rules output does not include conflict: %v", m.output)
	}
	m.workspace = workspaceRules
	m.selectedRuleID = "allow-client-ports"
	inspector := m.renderRuleInspector(100, 20)
	if !strings.Contains(inspector, "WARN conflict rule=allow-client-ports") {
		t.Fatalf("rules Inspector omitted diagnostics:\n%s", inspector)
	}
}

func TestRuleEditorPreviewsWholeRevisionWarningsWithoutBlockingCommit(t *testing.T) {
	m := NewModel()
	if err := m.policyStore.Activate("baseline", []policy.Rule{{
		ID: "block-outbound", Priority: 100, Enabled: true,
		Match:   policy.Match{Directions: []traffic.Direction{traffic.DirectionOutbound}},
		Actions: []policy.Action{{Kind: policy.ActionBlock}},
	}}); err != nil {
		t.Fatalf("Activate: %v", err)
	}
	m.openRuleEditor(false)
	m.ruleEditor.draft.action = string(policy.ActionAllow)
	m.ruleEditor.draft.priority = 0
	m.ruleEditor.draft.prioritySet = true
	m.refreshRuleDiagnostic()
	if !strings.Contains(m.ruleEditor.diagnostic, "WARN unreachable") ||
		!strings.Contains(m.ruleEditor.diagnostic, "block-outbound") {
		t.Fatalf("draft diagnostic = %q", m.ruleEditor.diagnostic)
	}

	next, _ := m.Update(tea.KeyMsg{Type: tea.KeyCtrlS})
	m = next.(Model)
	revision, ok := m.policyStore.Active()
	if !ok || m.ruleEditor.open || len(revision.Rules()) != 2 {
		t.Fatalf("advisory warning blocked commit: active=%t editor=%t rules=%#v output=%v", ok, m.ruleEditor.open, revision.Rules(), m.output)
	}
}
