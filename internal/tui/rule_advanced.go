package tui

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"

	"golan/internal/dataplane"
	"golan/internal/policy"
	"golan/internal/traffic"

	tea "github.com/charmbracelet/bubbletea"
)

const (
	maxAdvancedRuleBytes = 64 << 10
	maxAdvancedRuleLines = 512
)

func (e ruleEditorState) currentRule(priority int) (policy.Rule, error) {
	if e.advanced {
		rule, err := decodeAdvancedRule(strings.Join(e.rawLines, "\n"))
		if err != nil {
			return policy.Rule{}, err
		}
		return rule, nil
	}
	return e.draft.rule(e.replace, priority)
}

func (e *ruleEditorState) enterAdvanced() error {
	rule, err := e.draft.rule(false, e.draft.priority)
	if err != nil {
		return err
	}
	content, err := json.MarshalIndent(rule, "", "  ")
	if err != nil {
		return fmt.Errorf("encode advanced rule: %w", err)
	}
	e.advanced = true
	e.rawLines = strings.Split(string(content), "\n")
	e.rawCursor = 0
	e.cursor = 0
	e.editing = false
	e.buffer = ""
	return nil
}

func (e *ruleEditorState) leaveAdvanced() error {
	rule, err := decodeAdvancedRule(strings.Join(e.rawLines, "\n"))
	if err != nil {
		return err
	}
	draft, err := guidedDraftFromRule(rule)
	if err != nil {
		return err
	}
	e.draft = draft
	e.advanced = false
	e.rawLines = nil
	e.rawCursor = 0
	e.cursor = min(e.cursor, e.fieldCount()-1)
	return nil
}

func (e *ruleEditorState) setRawLine(value string) {
	if e.rawCursor < 0 || e.rawCursor >= len(e.rawLines) {
		return
	}
	e.rawLines[e.rawCursor] = value
}

func decodeAdvancedRule(raw string) (policy.Rule, error) {
	if len(raw) > maxAdvancedRuleBytes {
		return policy.Rule{}, fmt.Errorf("advanced rule exceeds %d KiB", maxAdvancedRuleBytes>>10)
	}
	decoder := json.NewDecoder(bytes.NewBufferString(raw))
	decoder.DisallowUnknownFields()
	var rule policy.Rule
	if err := decoder.Decode(&rule); err != nil {
		return policy.Rule{}, fmt.Errorf("advanced JSON: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return policy.Rule{}, fmt.Errorf("advanced JSON contains more than one value")
		}
		return policy.Rule{}, fmt.Errorf("advanced JSON: %w", err)
	}
	if rule.HitCount != 0 || rule.LastMatch != nil {
		return policy.Rule{}, fmt.Errorf("hit_count and last_match are runtime-only")
	}
	compiled, err := policy.Compile("advanced-draft", []policy.Rule{rule})
	if err != nil {
		return policy.Rule{}, err
	}
	rule = compiled.Rules()[0]
	return rule, nil
}

func (m Model) updateAdvancedRuleEditor(key tea.KeyMsg) (tea.Model, tea.Cmd) {
	editor := &m.ruleEditor
	if len(editor.rawLines) == 0 {
		editor.rawLines = []string{"{}"}
	}
	switch key.String() {
	case "esc":
		m.ruleEditor = ruleEditorState{}
	case "up", "k":
		editor.rawCursor = (editor.rawCursor - 1 + len(editor.rawLines)) % len(editor.rawLines)
	case "down", "j":
		editor.rawCursor = (editor.rawCursor + 1) % len(editor.rawLines)
	case "home":
		editor.rawCursor = 0
	case "end":
		editor.rawCursor = len(editor.rawLines) - 1
	case "shift+up":
		if editor.rawCursor > 0 {
			index := editor.rawCursor
			editor.rawLines[index-1], editor.rawLines[index] = editor.rawLines[index], editor.rawLines[index-1]
			editor.rawCursor--
			m.refreshRuleDiagnostic()
		}
	case "shift+down":
		if editor.rawCursor+1 < len(editor.rawLines) {
			index := editor.rawCursor
			editor.rawLines[index], editor.rawLines[index+1] = editor.rawLines[index+1], editor.rawLines[index]
			editor.rawCursor++
			m.refreshRuleDiagnostic()
		}
	case "enter":
		editor.editing = true
		editor.buffer = editor.rawLines[editor.rawCursor]
	case "o":
		if len(editor.rawLines) >= maxAdvancedRuleLines {
			editor.diagnostic = fmt.Sprintf("advanced rule is limited to %d lines", maxAdvancedRuleLines)
			return m, nil
		}
		indent := editor.rawLines[editor.rawCursor][:len(editor.rawLines[editor.rawCursor])-len(strings.TrimLeft(editor.rawLines[editor.rawCursor], " \t"))]
		index := editor.rawCursor + 1
		editor.rawLines = append(editor.rawLines, "")
		copy(editor.rawLines[index+1:], editor.rawLines[index:])
		editor.rawLines[index] = indent
		editor.rawCursor = index
		editor.editing = true
		editor.buffer = indent
	case "d":
		if len(editor.rawLines) == 1 {
			editor.rawLines[0] = ""
		} else {
			index := editor.rawCursor
			editor.rawLines = append(editor.rawLines[:index], editor.rawLines[index+1:]...)
			editor.rawCursor = min(index, len(editor.rawLines)-1)
		}
		m.refreshRuleDiagnostic()
	case "t", "T":
		return m.startRuleLivePreview()
	case "ctrl+s":
		return m.commitRuleEditor()
	}
	return m, nil
}

func (m Model) renderAdvancedRuleEditor() string {
	width := renderWidth(terminalWidth(m.width))
	height := renderHeight(terminalHeight(m.height))
	lines := []string{styleMuted.Render("Guided  [Advanced] · strict typed JSON"), ""}

	visible := max(4, height-len(m.ruleEditor.previewLines())-7)
	start := max(0, m.ruleEditor.rawCursor-visible/2)
	if end := start + visible; end > len(m.ruleEditor.rawLines) {
		start = max(0, len(m.ruleEditor.rawLines)-visible)
	}
	end := min(len(m.ruleEditor.rawLines), start+visible)
	if start > 0 {
		lines = append(lines, styleMuted.Render(fmt.Sprintf("  … %d lines above", start)))
	}
	for index := start; index < end; index++ {
		prefix := "  "
		if index == m.ruleEditor.rawCursor {
			prefix = "> "
		}
		value := m.ruleEditor.rawLines[index]
		if m.ruleEditor.editing && index == m.ruleEditor.rawCursor {
			value = m.ruleEditor.buffer + "|"
		}
		lines = append(lines, fmt.Sprintf("%s%3d %s", prefix, index+1, value))
	}
	if end < len(m.ruleEditor.rawLines) {
		lines = append(lines, styleMuted.Render(fmt.Sprintf("  … %d lines below", len(m.ruleEditor.rawLines)-end)))
	}
	lines = append(lines, m.ruleEditor.previewLines()...)
	footer := "Tab Guided · ↑/↓ line · Enter edit · o add · d delete · Shift+↑/↓ move · T test buffered live sample · Ctrl+S commit · Esc cancel"
	return fullscreenPanel(
		"ADVANCED RULE AST",
		lines,
		footer,
		width,
		height,
		horizontalMargin(terminalWidth(m.width)),
	)
}

func guidedDraftFromRule(rule policy.Rule) (guidedRuleDraft, error) {
	if !rule.Enabled {
		return guidedRuleDraft{}, fmt.Errorf("disabled rules are advanced-only")
	}
	if len(rule.Transformations) != 0 {
		return guidedRuleDraft{}, fmt.Errorf("transformations are advanced-only")
	}
	if len(rule.Actions) != 1 {
		return guidedRuleDraft{}, fmt.Errorf("guided view requires exactly one terminal action")
	}
	action := rule.Actions[0]
	switch action.Kind {
	case policy.ActionAllow, policy.ActionBlock:
	default:
		return guidedRuleDraft{}, fmt.Errorf("action %q is advanced-only", action.Kind)
	}
	if action.Value != "" || action.Duration != 0 || action.Rate != 0 || action.Percent != 0 {
		return guidedRuleDraft{}, fmt.Errorf("action parameters are advanced-only")
	}
	if len(rule.Metadata) != 0 {
		return guidedRuleDraft{}, fmt.Errorf("metadata is advanced-only")
	}
	conditions, err := guidedConditionsFromMatch(rule.Match)
	if err != nil {
		return guidedRuleDraft{}, err
	}
	return guidedRuleDraft{
		id: rule.ID, name: rule.Name, priority: rule.Priority, prioritySet: true,
		revision: rule.Revision, revisionSet: true, conditions: conditions,
		action: string(action.Kind), pattern: string(policy.PatternLiteral), occurrence: string(policy.OccurrenceFirst),
	}, nil
}

func guidedConditionsFromMatch(match policy.Match) ([]guidedCondition, error) {
	conditions := make([]guidedCondition, 0, len(guidedConditionSpecs))
	add := func(kind guidedConditionKind, value string, negate bool) {
		if value != "" {
			conditions = append(conditions, guidedCondition{Kind: kind, Value: value, Negate: negate})
		}
	}

	add(conditionMode, joinModes(match.Modes), false)
	add(conditionTopology, joinTopologySides(match.Topologies), false)
	ingress, err := joinRawStrings("ingress adapters", match.Ingress, ",")
	if err != nil {
		return nil, err
	}
	add(conditionIngress, ingress, false)
	add(conditionEgress, joinTopologySides(match.Egress), false)
	add(conditionDirection, joinDirections(match.Directions), false)
	srcMAC, err := joinRawStrings("source MACs", match.SrcMAC, ",")
	if err != nil {
		return nil, err
	}
	add(conditionSrcMAC, srcMAC, false)
	dstMAC, err := joinRawStrings("destination MACs", match.DstMAC, ",")
	if err != nil {
		return nil, err
	}
	add(conditionDstMAC, dstMAC, false)
	add(conditionEtherType, joinUint16(match.EtherTypes), false)
	add(conditionVLAN, joinUint16(match.VLANs), false)
	add(conditionIPVersion, joinUint8(match.IPVersions), false)
	srcCIDRs, err := joinRawStrings("source CIDRs", match.SrcCIDRs, ",")
	if err != nil {
		return nil, err
	}
	add(conditionSrcCIDR, srcCIDRs, false)
	dstCIDRs, err := joinRawStrings("destination CIDRs", match.DstCIDRs, ",")
	if err != nil {
		return nil, err
	}
	add(conditionDstCIDR, dstCIDRs, false)
	add(conditionProtocol, joinProtocols(match.Protocols), false)
	add(conditionDSCP, joinUint8(match.DSCP), false)
	add(conditionTTL, joinUint8(match.TTL), false)
	if value := formatPortSet(match.SrcPorts); value != "" {
		add(conditionSrcPort, value, match.SrcPorts.Negate)
	} else if match.SrcPorts.Negate {
		return nil, fmt.Errorf("empty negated source port set is advanced-only")
	}
	if value := formatPortSet(match.DstPorts); value != "" {
		add(conditionDstPort, value, match.DstPorts.Negate)
	} else if match.DstPorts.Negate {
		return nil, fmt.Errorf("empty negated destination port set is advanced-only")
	}
	flags, err := formatTCPFlags(match.TCPFlagMask, match.TCPFlags)
	if err != nil {
		return nil, err
	}
	add(conditionTCPFlags, flags, false)
	add(conditionICMPType, joinUint8(match.ICMPTypes), false)
	add(conditionICMPCode, joinUint8(match.ICMPCodes), false)
	add(conditionEAPOLType, joinUint8(match.EAPOLTypes), false)
	dnsNames, err := formatLiteralPatterns("DNS names", match.DNSNames, true)
	if err != nil {
		return nil, err
	}
	add(conditionDNSName, dnsNames, false)
	add(conditionDNSType, joinUint16(match.DNSTypes), false)
	httpMethods, err := joinRawStrings("HTTP methods", match.HTTPMethods, ",")
	if err != nil {
		return nil, err
	}
	add(conditionHTTPMethod, httpMethods, false)
	add(conditionHTTPStatus, joinUint16(match.HTTPStatuses), false)
	httpHosts, err := formatLiteralPatterns("HTTP hosts", match.HTTPHosts, true)
	if err != nil {
		return nil, err
	}
	add(conditionHTTPHost, httpHosts, false)
	httpPaths, err := formatLiteralPatterns("HTTP paths", match.HTTPPaths, true)
	if err != nil {
		return nil, err
	}
	add(conditionHTTPPath, httpPaths, false)
	headers, err := formatHTTPHeaders(match.HTTPHeaders)
	if err != nil {
		return nil, err
	}
	add(conditionHTTPHeader, headers, false)
	payload, err := formatLiteralPatterns("payload", match.Payload, false)
	if err != nil {
		return nil, err
	}
	add(conditionPayload, payload, false)
	return conditions, nil
}

func joinModes(values []dataplane.Mode) string {
	result := make([]string, len(values))
	for index, value := range values {
		result[index] = string(value)
	}
	return strings.Join(result, ",")
}

func joinTopologySides(values []traffic.TopologySide) string {
	result := make([]string, len(values))
	for index, value := range values {
		result[index] = string(value)
	}
	return strings.Join(result, ",")
}

func joinDirections(values []traffic.Direction) string {
	result := make([]string, len(values))
	for index, value := range values {
		result[index] = string(value)
	}
	return strings.Join(result, ",")
}

func joinRawStrings(label string, values []string, separator string) (string, error) {
	for _, value := range values {
		if strings.Contains(value, separator) {
			return "", fmt.Errorf("%s containing %q are advanced-only", label, separator)
		}
	}
	return strings.Join(values, separator), nil
}

func joinUint8(values []uint8) string {
	result := make([]string, len(values))
	for index, value := range values {
		result[index] = strconv.FormatUint(uint64(value), 10)
	}
	return strings.Join(result, ",")
}

func joinUint16(values []uint16) string {
	result := make([]string, len(values))
	for index, value := range values {
		result[index] = strconv.FormatUint(uint64(value), 10)
	}
	return strings.Join(result, ",")
}

func joinProtocols(values []uint8) string {
	known := map[uint8]string{1: "icmp", 6: "tcp", 17: "udp", 58: "icmpv6"}
	result := make([]string, len(values))
	for index, value := range values {
		if name, ok := known[value]; ok {
			result[index] = name
		} else {
			result[index] = strconv.FormatUint(uint64(value), 10)
		}
	}
	return strings.Join(result, ",")
}

func formatPortSet(set policy.PortSet) string {
	values := make([]string, 0, len(set.Values)+len(set.Ranges))
	for _, value := range set.Values {
		values = append(values, strconv.FormatUint(uint64(value), 10))
	}
	for _, value := range set.Ranges {
		values = append(values, fmt.Sprintf("%d-%d", value.First, value.Last))
	}
	return strings.Join(values, ",")
}

func formatTCPFlags(mask, value traffic.TCPFlags) (string, error) {
	if mask == 0 && value == 0 {
		return "", nil
	}
	if mask != value {
		return "", fmt.Errorf("TCP flag masks that test cleared bits are advanced-only")
	}
	known := []struct {
		name string
		flag traffic.TCPFlags
	}{{"fin", 0x001}, {"syn", 0x002}, {"rst", 0x004}, {"psh", 0x008}, {"ack", 0x010}, {"urg", 0x020}, {"ece", 0x040}, {"cwr", 0x080}, {"ns", 0x100}}
	remaining := value
	names := make([]string, 0, len(known))
	for _, item := range known {
		if remaining&item.flag != 0 {
			names = append(names, item.name)
			remaining &^= item.flag
		}
	}
	if remaining != 0 {
		return "", fmt.Errorf("unknown TCP flag bits %#x are advanced-only", uint16(remaining))
	}
	return strings.Join(names, ","), nil
}

func formatLiteralPatterns(label string, patterns []policy.BytePattern, multiple bool) (string, error) {
	if !multiple && len(patterns) > 1 {
		return "", fmt.Errorf("multiple %s patterns are advanced-only", label)
	}
	values := make([]string, len(patterns))
	for index, pattern := range patterns {
		if pattern.Kind != policy.PatternLiteral {
			return "", fmt.Errorf("%s pattern kind %q is advanced-only", label, pattern.Kind)
		}
		if multiple && strings.Contains(pattern.Value, ",") {
			return "", fmt.Errorf("%s containing commas are advanced-only", label)
		}
		values[index] = pattern.Value
	}
	return strings.Join(values, ","), nil
}

func formatHTTPHeaders(headers []policy.HeaderMatch) (string, error) {
	values := make([]string, len(headers))
	for index, header := range headers {
		if header.Value.Kind != policy.PatternLiteral {
			return "", fmt.Errorf("HTTP header pattern kind %q is advanced-only", header.Value.Kind)
		}
		if strings.ContainsAny(header.Name, ";=") || strings.Contains(header.Value.Value, ";") {
			return "", fmt.Errorf("HTTP headers containing guided delimiters are advanced-only")
		}
		values[index] = header.Name + "=" + header.Value.Value
	}
	return strings.Join(values, "; "), nil
}
