package tui

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"golan/internal/dataplane"
	"golan/internal/policy"

	tea "github.com/charmbracelet/bubbletea"
)

type ruleEditorState struct {
	open          bool
	replace       bool
	advanced      bool
	cursor        int
	rawCursor     int
	editing       bool
	buffer        string
	rawLines      []string
	draft         guidedRuleDraft
	diagnostic    string
	previewSource string
	preview       string
	compatibility []string
	impacts       []string
	evidence      []string
	previewEpoch  uint64
}

type guidedRuleDraft struct {
	id          string
	name        string
	priority    int
	prioritySet bool
	revision    uint64
	revisionSet bool
	conditions  []guidedCondition
	direction   string
	protocol    string
	ports       string
	negate      bool
	action      string
	pattern     string
	search      string
	replace     string
	occurrence  string
}

type rulePreviewMsg struct {
	epoch          uint64
	source         string
	packets        uint64
	matches        uint64
	sample         *policy.TransformationEvidencePreview
	samplePacketID string
	sampleErr      error
	err            error
}

func (m *Model) openRuleEditor(replace bool) {
	draft := guidedRuleDraft{
		id: m.nextRuleID(), name: "New rule", direction: "outbound",
		priority: m.nextRulePriority(), prioritySet: true, revision: 1, revisionSet: true,
		protocol: "tcp", ports: "80,443",
		action: "block", pattern: "literal", occurrence: "first",
		conditions: defaultGuidedConditions(),
	}
	if replace {
		draft.name = "Match and replace"
		draft.ports = "80"
		draft.action = "allow"
	}
	m.ruleEditor = ruleEditorState{open: true, replace: replace, draft: draft}
	m.refreshRuleDiagnostic()
}

func (m Model) nextRuleID() string {
	used := make(map[string]bool)
	if active, ok := m.policyStore.Active(); ok {
		for _, rule := range active.Rules() {
			used[rule.ID] = true
		}
	}
	for index := 1; ; index++ {
		candidate := "rule-" + strconv.Itoa(index)
		if !used[candidate] {
			return candidate
		}
	}
}

func (m Model) updateRuleEditor(key tea.KeyMsg) (tea.Model, tea.Cmd) {
	editor := &m.ruleEditor
	name := key.String()
	if editor.editing {
		switch name {
		case "esc":
			editor.editing = false
			editor.buffer = ""
		case "enter":
			if editor.advanced {
				editor.setRawLine(editor.buffer)
			} else {
				editor.setTextValue(editor.cursor, editor.buffer)
			}
			editor.editing = false
			editor.buffer = ""
			m.refreshRuleDiagnostic()
		case "backspace", "ctrl+h":
			editor.buffer = trimLastRune(editor.buffer)
		default:
			if key.Type == tea.KeyRunes {
				editor.buffer += string(key.Runes)
			}
		}
		return m, nil
	}
	if name == "tab" && !editor.replace {
		if editor.advanced {
			if err := editor.leaveAdvanced(); err != nil {
				editor.diagnostic = "Guided view unavailable: " + err.Error()
				return m, nil
			}
		} else if err := editor.enterAdvanced(); err != nil {
			editor.diagnostic = err.Error()
			return m, nil
		}
		m.refreshRuleDiagnostic()
		return m, nil
	}
	if editor.advanced {
		return m.updateAdvancedRuleEditor(key)
	}
	switch name {
	case "esc":
		m.ruleEditor = ruleEditorState{}
	case "shift+up":
		if !editor.replace && editor.reorderCondition(-1) {
			m.refreshRuleDiagnostic()
		}
	case "shift+down":
		if !editor.replace && editor.reorderCondition(1) {
			m.refreshRuleDiagnostic()
		}
	case "up", "k":
		editor.cursor = (editor.cursor - 1 + editor.fieldCount()) % editor.fieldCount()
	case "down", "j":
		editor.cursor = (editor.cursor + 1) % editor.fieldCount()
	case "left":
		editor.cycle(-1)
		m.refreshRuleDiagnostic()
	case "right":
		editor.cycle(1)
		m.refreshRuleDiagnostic()
	case "enter":
		if editor.textField(editor.cursor) {
			editor.editing = true
			editor.buffer = editor.textValue(editor.cursor)
		} else {
			editor.cycle(1)
			m.refreshRuleDiagnostic()
		}
	case "a":
		if !editor.replace {
			if !editor.addCondition() {
				editor.diagnostic = "all guided condition types are already present"
				return m, nil
			}
		} else if editor.draft.ports == "" || strings.EqualFold(editor.draft.ports, "any") {
			editor.draft.ports = "80"
		}
		m.refreshRuleDiagnostic()
	case "d":
		if editor.replace {
			editor.clearSelected()
		} else {
			editor.removeCondition()
		}
		m.refreshRuleDiagnostic()
	case "!":
		if !editor.replace {
			editor.toggleConditionNegation()
		}
		m.refreshRuleDiagnostic()
	case "t", "T":
		return m.startRuleLivePreview()
	case "ctrl+s":
		return m.commitRuleEditor()
	}
	return m, nil
}

func (m Model) commitRuleEditor() (tea.Model, tea.Cmd) {
	editor := &m.ruleEditor
	rule, err := editor.currentRule(m.nextRulePriority())
	if err != nil {
		editor.diagnostic = err.Error()
		return m, nil
	}
	rules, base := m.rulesWithDraft(rule)
	revision := fmt.Sprintf("%s-edit-%d", base, time.Now().UTC().UnixNano())
	editorName := "Guided editor"
	if editor.advanced {
		editorName = "Advanced editor"
	}
	if err := m.commitRules(revision, editorName, rules); err != nil {
		editor.diagnostic = err.Error()
		return m, nil
	}
	m.ruleEditor = ruleEditorState{}
	m.workspace = workspaceRules
	m.print("policy: committed " + revision + " (PROJECT*)")
	return m, nil
}

func (m *Model) refreshRuleDiagnostic() {
	if !m.ruleEditor.open {
		return
	}
	m.ruleEditor.compatibility = nil
	m.ruleEditor.impacts = nil
	m.ruleEditor.evidence = nil
	m.ruleEditor.previewSource = ruleEvidenceSourceLive
	m.ruleEditor.preview = "0 frames available · start a live session to collect a bounded preview sample"
	if count := len(m.liveEvidence); count > 0 {
		m.ruleEditor.preview = fmt.Sprintf("0 packets tested · press T to test %d buffered live frame(s)", count)
	}
	m.rulePreviewEpoch++
	m.ruleEditor.previewEpoch = m.rulePreviewEpoch
	rule, err := m.ruleEditor.currentRule(100)
	if err != nil {
		m.ruleEditor.diagnostic = err.Error()
		return
	}
	rules, _ := m.rulesWithDraft(rule)
	revision, err := policy.Compile("draft", rules)
	if err != nil {
		m.ruleEditor.diagnostic = err.Error()
		return
	}
	status, capability, reason := m.compatibilityForCapabilities(rule, m.currentCapabilities())
	m.ruleEditor.diagnostic = fmt.Sprintf("%s · requires %s", status, capability)
	if reason != "" {
		m.ruleEditor.diagnostic += " · " + reason
	}
	if warnings := ruleDiagnosticSummary(revision.DiagnosticsForRule(m.currentCapabilities(), rule.ID), rule.ID); warnings != "" {
		m.ruleEditor.diagnostic += " · " + warnings
	}
	m.ruleEditor.compatibility = formatRuleCompatibility(policy.CompatibilityMatrix(rule))
	impacts, err := policy.TransformationImpacts(rule)
	if err != nil {
		m.ruleEditor.diagnostic = err.Error()
		m.ruleEditor.compatibility = nil
		return
	}
	m.ruleEditor.impacts = formatTransformationImpacts(impacts)
}

func (m Model) rulesWithDraft(rule policy.Rule) ([]policy.Rule, string) {
	rules := []policy.Rule{rule}
	base := "policy"
	if active, ok := m.policyStore.Active(); ok {
		rules = active.Rules()
		base = active.Revision()
		for index := range rules {
			if rules[index].ID == rule.ID {
				rules[index] = rule
				return rules, base
			}
		}
		rules = append(rules, rule)
	}
	return rules, base
}

func ruleDiagnosticSummary(diagnostics []policy.Diagnostic, ruleID string) string {
	const visibleWarnings = 2
	parts := make([]string, 0, visibleWarnings)
	total := 0
	for _, diagnostic := range diagnostics {
		if diagnostic.RuleID != ruleID && diagnostic.RelatedRuleID != ruleID {
			continue
		}
		total++
		if len(parts) == visibleWarnings {
			continue
		}
		message := fmt.Sprintf("WARN %s: %s", diagnostic.Kind, diagnostic.Message)
		if diagnostic.RuleID != ruleID {
			message = fmt.Sprintf("WARN %s: rule %s %s", diagnostic.Kind, diagnostic.RuleID, diagnostic.Message)
		}
		if diagnostic.RelatedRuleID != "" {
			message += " (related " + diagnostic.RelatedRuleID + ")"
		}
		parts = append(parts, message)
	}
	if total > len(parts) {
		parts = append(parts, fmt.Sprintf("+%d more warning(s)", total-len(parts)))
	}
	return strings.Join(parts, " · ")
}

func (m Model) nextRulePriority() int {
	priority := 100
	if active, ok := m.policyStore.Active(); ok {
		for _, rule := range active.Rules() {
			if rule.Priority >= priority {
				priority = rule.Priority + 10
			}
		}
	}
	return priority
}

func previewRuleLiveCmd(records []liveEvidenceRecord, rule policy.Rule, epoch uint64) tea.Cmd {
	return func() tea.Msg {
		preview, err := newRulePreviewAccumulator(rule)
		if err != nil {
			return rulePreviewMsg{epoch: epoch, source: ruleEvidenceSourceLive, err: err}
		}
		for _, record := range records {
			preview.observe(record.Frame, record.Flow, dataplane.ForMode(record.Mode))
		}
		return preview.message(epoch, ruleEvidenceSourceLive, uint64(len(records)), nil)
	}
}

func (m *Model) startRuleLivePreview() (tea.Model, tea.Cmd) {
	editor := &m.ruleEditor
	if len(m.liveEvidence) == 0 {
		editor.diagnostic = "no buffered live frames; start a live session and try again"
		return *m, nil
	}
	rule, err := editor.currentRule(100)
	if err != nil {
		editor.diagnostic = err.Error()
		return *m, nil
	}
	records := m.liveEvidenceSnapshot()
	editor.evidence = nil
	m.rulePreviewEpoch++
	editor.previewEpoch = m.rulePreviewEpoch
	editor.previewSource = ruleEvidenceSourceLive
	editor.preview = fmt.Sprintf("testing %d buffered frame(s) …", len(records))
	return *m, previewRuleLiveCmd(records, rule, editor.previewEpoch)
}

func (d guidedRuleDraft) rule(replace bool, priority int) (policy.Rule, error) {
	id := strings.TrimSpace(d.id)
	if id == "" {
		return policy.Rule{}, fmt.Errorf("rule ID is required")
	}
	match, err := d.policyMatch(replace)
	if err != nil {
		return policy.Rule{}, err
	}
	action := policy.ActionKind(d.action)
	switch action {
	case policy.ActionAllow, policy.ActionBlock:
	default:
		return policy.Rule{}, fmt.Errorf("action is invalid")
	}
	if d.prioritySet {
		priority = d.priority
	}
	revision := d.revision
	if !d.revisionSet {
		revision = 1
	}
	rule := policy.Rule{ID: id, Name: strings.TrimSpace(d.name), Priority: priority, Enabled: true, Revision: revision, Match: match, Actions: []policy.Action{{Kind: action}}}
	if replace {
		kind := policy.PatternKind(d.pattern)
		switch kind {
		case policy.PatternLiteral, policy.PatternRE2, policy.PatternMasked:
		default:
			return policy.Rule{}, fmt.Errorf("replacement pattern is invalid")
		}
		match.Payload = []policy.BytePattern{{Kind: kind, Value: d.search}}
		rule.Match = match
		transformKind := policy.TransformLiteral
		if kind == policy.PatternRE2 {
			transformKind = policy.TransformRE2
		} else if kind == policy.PatternMasked {
			transformKind = policy.TransformMasked
		}
		rule.Transformations = []policy.Transformation{{Kind: transformKind, Search: d.search, Replace: d.replace, Occurrence: policy.Occurrence(d.occurrence)}}
	}
	return rule, nil
}

func (e ruleEditorState) fieldCount() int {
	if e.replace {
		return 10
	}
	return 3 + len(e.draft.conditions)*2
}

func (e ruleEditorState) textField(index int) bool {
	if e.replace {
		return index == 0 || index == 1 || index == 4 || index == 6 || index == 7
	}
	if index == 0 || index == 1 {
		return true
	}
	_, part, ok := e.conditionAtCursor(index)
	return ok && part == conditionValueField
}

func (e ruleEditorState) textValue(index int) string {
	if !e.replace {
		if condition, part, ok := e.conditionAtCursor(index); ok && part == conditionValueField {
			return e.draft.conditions[condition.Index].Value
		}
	}
	values := e.values()
	if index < 0 || index >= len(values) {
		return ""
	}
	return values[index]
}

func (e *ruleEditorState) setTextValue(index int, value string) {
	if e.replace {
		switch index {
		case 0:
			e.draft.id = value
		case 1:
			e.draft.name = value
		case 4:
			e.draft.ports = value
		case 6:
			e.draft.search = value
		case 7:
			e.draft.replace = value
		}
		return
	}
	switch index {
	case 0:
		e.draft.id = value
	case 1:
		e.draft.name = value
	default:
		condition, part, ok := e.conditionAtCursor(index)
		if ok && part == conditionValueField {
			e.draft.conditions[condition.Index].Value = value
		}
	}
}

func (e *ruleEditorState) cycle(delta int) {
	cycle := func(current string, values []string) string {
		index := 0
		for i, value := range values {
			if value == current {
				index = i
				break
			}
		}
		return values[(index+delta+len(values))%len(values)]
	}
	if e.replace {
		switch e.cursor {
		case 2:
			e.draft.direction = cycle(e.draft.direction, []string{
				"outbound", "inbound", "host-to-switch", "switch-to-host", "any",
			})
		case 3:
			e.draft.protocol = cycle(e.draft.protocol, []string{"tcp", "udp", "icmp", "icmpv6", "any"})
		case 5:
			e.draft.pattern = cycle(e.draft.pattern, []string{"literal", "re2", "masked"})
		case 8:
			e.draft.occurrence = cycle(e.draft.occurrence, []string{"first", "all"})
		case 9:
			e.draft.action = cycle(e.draft.action, []string{"allow", "block"})
		}
		return
	}
	if e.cursor == e.fieldCount()-1 {
		e.draft.action = cycle(e.draft.action, []string{"allow", "block"})
		return
	}
	condition, part, ok := e.conditionAtCursor(e.cursor)
	if !ok {
		return
	}
	if part == conditionKindField {
		e.cycleConditionKind(condition.Index, delta)
		return
	}
	spec := guidedConditionSpecFor(e.draft.conditions[condition.Index].Kind)
	if len(spec.Options) > 0 {
		e.draft.conditions[condition.Index].Value = cycle(e.draft.conditions[condition.Index].Value, spec.Options)
	}
}

func (e *ruleEditorState) clearSelected() {
	if e.replace {
		switch e.cursor {
		case 2:
			e.draft.direction = "any"
		case 3:
			e.draft.protocol = "any"
		case 4:
			e.draft.ports = "any"
		case 6:
			e.draft.search = ""
		case 7:
			e.draft.replace = ""
		}
		return
	}
	switch e.cursor {
	case 2:
		e.draft.direction = "any"
	case 3:
		e.draft.protocol = "any"
	case 4:
		e.draft.ports = "any"
	case 5:
		e.draft.negate = false
	}
}

func (e ruleEditorState) labels() []string {
	if e.replace {
		return []string{"Rule ID", "Name", "Direction", "Protocol", "Destination port", "Pattern", "Search", "Replace", "Occurrence", "Action"}
	}
	labels := []string{"Rule ID", "Name"}
	for index, condition := range e.draft.conditions {
		labels = append(labels, fmt.Sprintf("Condition %d type", index+1), guidedConditionSpecFor(condition.Kind).Label)
	}
	return append(labels, "Action")
}

func (e ruleEditorState) values() []string {
	if e.replace {
		return []string{e.draft.id, e.draft.name, e.draft.direction, e.draft.protocol, e.draft.ports, e.draft.pattern, e.draft.search, e.draft.replace, e.draft.occurrence, e.draft.action}
	}
	values := []string{e.draft.id, e.draft.name}
	for _, condition := range e.draft.conditions {
		spec := guidedConditionSpecFor(condition.Kind)
		value := condition.Value
		if spec.Negatable {
			operator := "one of"
			if condition.Negate {
				operator = "not one of"
			}
			value = operator + " " + value
		}
		values = append(values, spec.Label, value)
	}
	return append(values, e.draft.action)
}

func (m Model) renderRuleEditor() string {
	if m.ruleEditor.advanced {
		return m.renderAdvancedRuleEditor()
	}
	width := renderWidth(terminalWidth(m.width))
	height := renderHeight(terminalHeight(m.height))
	title := "GUIDED RULE EDITOR"
	if m.ruleEditor.replace {
		title = "MATCH AND REPLACE"
	}
	lines := []string{}
	labels, values := m.ruleEditor.labels(), m.ruleEditor.values()
	for index := range labels {
		section := ""
		if index == 2 && (m.ruleEditor.replace || len(m.ruleEditor.draft.conditions) > 0) {
			section = "\n" + styleMuted.Render("WHEN") + "\n"
		}
		if !m.ruleEditor.replace && index == len(labels)-1 && len(m.ruleEditor.draft.conditions) == 0 {
			section = "\n" + styleMuted.Render("WHEN") + "\n  all traffic\n"
		}
		if (!m.ruleEditor.replace && index == len(labels)-1) || (m.ruleEditor.replace && index == 10) {
			section = "\n" + styleMuted.Render("THEN") + "\n"
			if !m.ruleEditor.replace && len(m.ruleEditor.draft.conditions) == 0 {
				section = "\n" + styleMuted.Render("WHEN") + "\n  all traffic\n\n" + styleMuted.Render("THEN") + "\n"
			}
		}
		prefix := "  "
		if index == m.ruleEditor.cursor {
			prefix = "> "
		}
		value := values[index]
		if m.ruleEditor.editing && index == m.ruleEditor.cursor {
			value = m.ruleEditor.buffer + "|"
		}
		lines = append(lines, section+prefix+fmt.Sprintf("%-20s [%s]", labels[index], value))
	}
	lines = append(lines, m.ruleEditor.previewLines()...)
	footer := "Enter edit/cycle · T test buffered live sample · Ctrl+S commit · Esc cancel"
	if !m.ruleEditor.replace {
		footer = "Tab Advanced · ←/→ cycle · Enter edit value · a add · d remove · Shift+↑/↓ reorder · ! port operator · T test · Ctrl+S commit · Esc cancel"
	}
	return fullscreenPanel(
		title,
		lines,
		footer,
		width,
		height,
		horizontalMargin(terminalWidth(m.width)),
	)
}
