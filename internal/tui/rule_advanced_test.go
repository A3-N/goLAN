package tui

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"golan/internal/policy"

	tea "github.com/charmbracelet/bubbletea"
)

func TestAdvancedRuleRoundTripsEveryGuidedCondition(t *testing.T) {
	conditions := make([]guidedCondition, 0, len(guidedConditionSpecs))
	for _, spec := range guidedConditionSpecs {
		conditions = append(conditions, newGuidedCondition(spec.Kind))
	}
	draft := guidedRuleDraft{
		id: "round-trip", name: "Every guided condition", priority: 230, prioritySet: true,
		revision: 7, revisionSet: true, conditions: conditions, action: string(policy.ActionBlock),
	}
	want, err := draft.rule(false, 100)
	if err != nil {
		t.Fatal(err)
	}
	content, err := json.Marshal(want)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := decodeAdvancedRule(string(content))
	if err != nil {
		t.Fatal(err)
	}
	converted, err := guidedDraftFromRule(decoded)
	if err != nil {
		t.Fatal(err)
	}
	got, err := converted.rule(false, 100)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("guided/raw round trip differs:\n got: %#v\nwant: %#v", got, want)
	}
}

func TestAdvancedEditorEditsTypedASTAndReturnsToGuided(t *testing.T) {
	m := NewModel()
	m.openRuleEditor(false)

	next, _ := m.Update(tea.KeyMsg{Type: tea.KeyTab})
	m = next.(Model)
	if !m.ruleEditor.advanced || !strings.Contains(m.View(), "ADVANCED RULE AST") {
		t.Fatalf("advanced editor did not open:\n%s", m.View())
	}
	for index, line := range m.ruleEditor.rawLines {
		if strings.Contains(line, `"outbound"`) {
			m.ruleEditor.rawCursor = index
			break
		}
	}
	next, _ = m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = next.(Model)
	if !m.ruleEditor.editing {
		t.Fatal("advanced line did not enter edit mode")
	}
	m.ruleEditor.buffer = strings.Replace(m.ruleEditor.buffer, `"outbound"`, `"inbound"`, 1)
	next, _ = m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = next.(Model)
	if m.ruleEditor.editing || strings.Contains(m.ruleEditor.diagnostic, "advanced JSON") {
		t.Fatalf("line edit failed: %q", m.ruleEditor.diagnostic)
	}

	next, _ = m.Update(tea.KeyMsg{Type: tea.KeyTab})
	m = next.(Model)
	if m.ruleEditor.advanced || m.ruleEditor.draft.conditions[0].Value != "inbound" {
		t.Fatalf("guided draft did not receive advanced edit: %#v", m.ruleEditor.draft.conditions)
	}
}

func TestAdvancedOnlyRuleStaysAdvancedAndCommits(t *testing.T) {
	m := NewModel()
	m.openRuleEditor(false)
	if err := m.ruleEditor.enterAdvanced(); err != nil {
		t.Fatal(err)
	}
	rule := policy.Rule{
		ID: "regex", Name: "Advanced regex", Priority: 300, Enabled: true, Revision: 1,
		Match:   policy.Match{Payload: []policy.BytePattern{{Kind: policy.PatternRE2, Value: `token=[a-z]+`}}},
		Actions: []policy.Action{{Kind: policy.ActionBlock}},
	}
	content, err := json.MarshalIndent(rule, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	m.ruleEditor.rawLines = strings.Split(string(content), "\n")

	next, _ := m.Update(tea.KeyMsg{Type: tea.KeyTab})
	m = next.(Model)
	if !m.ruleEditor.advanced || !strings.Contains(m.ruleEditor.diagnostic, "advanced-only") {
		t.Fatalf("lossy guided conversion was not refused: advanced=%v diagnostic=%q", m.ruleEditor.advanced, m.ruleEditor.diagnostic)
	}
	next, _ = m.Update(tea.KeyMsg{Type: tea.KeyCtrlS})
	m = next.(Model)
	active, ok := m.policyStore.Active()
	if !ok || m.ruleEditor.open {
		t.Fatalf("advanced rule did not commit: active=%v editor=%v", ok, m.ruleEditor.open)
	}
	got := active.Rules()[0]
	if got.Match.Payload[0].Kind != policy.PatternRE2 || got.Match.Payload[0].Value != `token=[a-z]+` {
		t.Fatalf("committed advanced rule = %#v", got)
	}
}

func TestAdvancedRuleRejectsUnknownAndRuntimeFields(t *testing.T) {
	for name, raw := range map[string]string{
		"unknown": `{"id":"x","name":"x","priority":1,"enabled":true,"revision":1,"match":{},"actions":[{"kind":"block"}],"surprise":true}`,
		"runtime": `{"id":"x","name":"x","priority":1,"enabled":true,"revision":1,"match":{},"actions":[{"kind":"block"}],"hit_count":9}`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := decodeAdvancedRule(raw); err == nil {
				t.Fatal("unsafe advanced field was accepted")
			}
		})
	}
}

func TestAdvancedEditorKeepsActiveRevisionOnMalformedJSON(t *testing.T) {
	m := NewModel()
	if err := m.policyStore.Activate("baseline", nil); err != nil {
		t.Fatal(err)
	}
	m.openRuleEditor(false)
	if err := m.ruleEditor.enterAdvanced(); err != nil {
		t.Fatal(err)
	}
	m.ruleEditor.rawLines = []string{`{"id":`}

	next, _ := m.Update(tea.KeyMsg{Type: tea.KeyCtrlS})
	m = next.(Model)
	active, ok := m.policyStore.Active()
	if !ok || active.Revision() != "baseline" || !m.ruleEditor.open || !m.ruleEditor.advanced {
		t.Fatalf("active=%v revision=%q editor=%v advanced=%v", ok, active.Revision(), m.ruleEditor.open, m.ruleEditor.advanced)
	}
	if !strings.Contains(m.ruleEditor.diagnostic, "advanced JSON") {
		t.Fatalf("diagnostic = %q", m.ruleEditor.diagnostic)
	}
}
