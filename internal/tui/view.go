package tui

import (
	"fmt"
	"strings"
	"unicode/utf8"

	"golan/internal/policy"

	"github.com/charmbracelet/lipgloss"
)

// View renders the current model without side effects.
func (m Model) View() string {
	if m.help.open {
		return m.renderHelp()
	}
	if m.commandPalette.open {
		return m.renderCommandPalette()
	}
	if m.settingsEditor.open {
		return m.renderSettingsEditor()
	}
	if m.startup.open {
		return m.renderStartupChooser()
	}
	if m.bundleExport.open {
		return m.renderBundleExport()
	}
	if m.ruleEditor.open {
		return m.renderRuleEditor()
	}
	geometry := m.workbenchGeometry()
	status := m.renderStatus(geometry.ContentWidth)
	tabs := m.renderTabs(geometry.ContentWidth)
	main := m.renderWorkbenchMain(geometry)
	footer := m.renderFooter(geometry.ContentWidth)
	return insetBlock(
		clampBlock(
			lipgloss.JoinVertical(lipgloss.Left, status, tabs, main, footer),
			geometry.ContentWidth,
			geometry.Height,
		),
		geometry.Margin,
	)
}

func (m Model) renderWorkbenchMain(geometry workbenchGeometry) string {
	renderPane := func(pane paneCell) string {
		switch pane.Card {
		case cardCLI:
			return m.renderCLI(pane.Rect.Width, pane.Rect.Height)
		case cardInspector:
			return m.renderTraffic(pane.Rect.Width, pane.Rect.Height)
		default:
			return m.renderOutput(pane.Rect.Width, pane.Rect.Height)
		}
	}
	paneFor := func(card cardFocus) (paneCell, bool) {
		for _, pane := range geometry.Panes {
			if pane.Card == card {
				return pane, true
			}
		}
		return paneCell{}, false
	}
	renderPrimary := func() string {
		output, outputOK := paneFor(cardOutput)
		cli, cliOK := paneFor(cardCLI)
		switch {
		case outputOK && cliOK:
			return lipgloss.JoinVertical(lipgloss.Left, renderPane(output), renderPane(cli))
		case outputOK:
			return renderPane(output)
		case cliOK:
			return renderPane(cli)
		default:
			return ""
		}
	}

	switch geometry.Mode {
	case layoutMaximized:
		if len(geometry.Panes) == 0 {
			return ""
		}
		return renderPane(geometry.Panes[0])
	case layoutNarrow:
		main := renderPrimary()
		if inspector, ok := paneFor(cardInspector); ok {
			return lipgloss.JoinVertical(lipgloss.Left, main, renderPane(inspector))
		}
		return main
	case layoutMedium:
		primary := renderPrimary()
		inspector, inspectorOK := paneFor(cardInspector)
		if inspectorOK {
			return lipgloss.JoinVertical(lipgloss.Left, primary, renderPane(inspector))
		}
		return primary
	default:
		parts := []string{renderPrimary()}
		if inspector, ok := paneFor(cardInspector); ok {
			parts = append(parts, styleCanvas.Render(" "), renderPane(inspector))
		}
		return lipgloss.JoinHorizontal(lipgloss.Top, parts...)
	}
}

func (m Model) renderStatus(width int) string {
	project := "NO PROJECT"
	if m.project != nil {
		project = m.project.Manifest().Name
		if m.project.Dirty() {
			project += "*"
		}
	}
	bridgeState := "offline"
	runtimeOnline := false
	if m.bridge != nil {
		bridgeState = "bridge " + m.bridgeState
		runtimeOnline = true
	} else if m.edgeSession != nil {
		bridgeState = "edge " + m.edgeMode
		runtimeOnline = true
	} else if m.listener != nil {
		bridgeState = "observe"
		runtimeOnline = true
	}
	project = safeDisplayText(project)
	runtimeStyle := styleStatusLabel
	if runtimeOnline {
		runtimeStyle = styleStatusOnline
	}
	line := styleBrand.Render(" goLAN ") +
		styleProduct.Render(" WORKBENCH ") +
		styleStatusLabel.Render("│ PROJECT ") +
		styleStatusValue.Render(project+" ") +
		styleStatusLabel.Render("│ RUNTIME ") +
		runtimeStyle.Render(strings.ToUpper(bridgeState)+" ") +
		styleStatusLabel.Render("│ FOCUS (Shift+←/→) ") +
		styleStatusValue.Render(cardFocusLabel(m.activeCard)+" ")
	return renderStyleLayer(styleTopBar, fit(line, width))
}

func cardFocusLabel(card cardFocus) string {
	switch card {
	case cardNone:
		return "ALL PANES"
	case cardOutput:
		return "OUTPUT"
	case cardCLI:
		return "CLI"
	case cardInspector:
		return "INSPECTOR"
	default:
		return "UNKNOWN"
	}
}

func (m Model) renderTabs(width int) string {
	rows := workspaceTabRows(width)
	renderedRows := make([]string, 0, len(rows))
	for _, row := range rows {
		var rendered strings.Builder
		for index, tab := range row {
			if index > 0 {
				rendered.WriteByte(' ')
			}
			if tab.Workspace == m.workspace {
				label := "[" + strings.TrimSpace(tab.Label) + "]"
				rendered.WriteString(styleTabActive.Render(label))
			} else {
				rendered.WriteString(styleTab.Render(tab.Label))
			}
		}
		renderedRows = append(renderedRows, renderStyleLayer(styleTabBar, fit(rendered.String(), width)))
	}
	if len(renderedRows) == 0 {
		return fit("", width)
	}
	return strings.Join(renderedRows, "\n")
}

func (m Model) renderOutput(width, height int) string {
	switch m.workspace {
	case workspaceNetwork:
		return m.renderNetworkDevices(width, height)
	case workspaceRules:
		return m.renderRulesList(width, height)
	}
	available := max(1, height-3)
	rows := wrapOutputLinesStyled(m.output, m.outputMuted, m.outputLiteral, max(1, width-4))
	maxOffset := max(0, len(rows)-available)
	offset := clamp(m.outputScroll, 0, maxOffset)
	end := len(rows) - offset
	if end < 0 {
		end = 0
	}
	start := end - available
	if start < 0 {
		start = 0
	}
	return box(m.cardTitle("output", cardOutput), styledOutputRows(rows[start:end]), width, height, m.activeCard == cardOutput)
}

func (m Model) renderCLI(width, height int) string {
	cursor := " "
	if m.cursorVisible && m.activeCard == cardCLI {
		cursor = "|"
	}
	innerWidth := max(1, width-2)
	lines := []string{
		styleCLILine(fit(m.prompt()+m.input+cursor, innerWidth)),
	}
	if len(m.completions) > 0 {
		lines = append(lines, styleAutocompleteLine(fit(strings.Join(limitStrings(m.completions, 8), "  "), innerWidth)))
		for _, hint := range m.completionHelpHints(2) {
			lines = append(lines, styleAutocompleteLine(fit("↳ "+hint, innerWidth)))
		}
	}
	return box(m.cardTitle("cli", cardCLI), lines, width, height, m.activeCard == cardCLI)
}

func styleCLILine(line string) string {
	if line == "" {
		return line
	}
	return styleCLIInput.Render(line)
}

func styleAutocompleteLine(line string) string {
	if line == "" {
		return line
	}
	return styleAutocomplete.Render(line)
}

func (m Model) renderTraffic(width, height int) string {
	if m.workspace == workspaceNetwork {
		return m.renderNetworkInspector(width, height)
	}
	if m.workspace == workspaceRules {
		return m.renderRuleInspector(width, height)
	}
	return box("inspector", []string{"no inspector for this workspace"}, width, height, m.activeCard == cardInspector)
}

func (m Model) renderRulesList(width, height int) string {
	available := max(1, height-3)
	rules, revision := m.activeRules()
	rows := []string{"no active revision · press r to create a rule"}
	selected := -1
	if len(rules) > 0 {
		rows = make([]string, 0, len(rules)+1)
		rows = append(rows, "revision "+revision)
		selectedID := m.selectedRuleID
		if selectedID == "" {
			selectedID = rules[0].ID
		}
		capabilities := m.currentCapabilities()
		for index, rule := range rules {
			marker := "  "
			if rule.ID == selectedID {
				marker = "> "
				selected = index + 1
			}
			status, _, _ := m.compatibilityForCapabilities(rule, capabilities)
			enabled := "off"
			if rule.Enabled {
				enabled = "on"
			}
			rows = append(rows, fmt.Sprintf("%s%s · p=%d · %s · %s", marker, rule.Name, rule.Priority, enabled, status))
		}
	}
	start := visibleSelectionStart(selected, len(rows), available)
	end := min(len(rows), start+available)
	return box(m.cardTitle("rules", cardOutput), rows[start:end], width, height, m.activeCard == cardOutput)
}

func (m Model) renderRuleInspector(width, height int) string {
	available := max(1, height-3)
	rule, ok := m.selectedRule()
	if !ok {
		return box(m.cardTitle("inspector", cardInspector), []string{"select or create a rule"}, width, height, m.activeCard == cardInspector)
	}
	status, required, reason := m.compatibilityForCapabilities(rule, m.currentCapabilities())
	actions := make([]string, 0, len(rule.Actions))
	for _, action := range rule.Actions {
		actions = append(actions, string(action.Kind))
	}
	actionLabel := strings.Join(actions, ", ")
	if actionLabel == "" {
		actionLabel = "none"
	}
	rows := []string{
		"name " + rule.Name,
		"id " + rule.ID,
		fmt.Sprintf("priority %d · revision %d · enabled %t", rule.Priority, rule.Revision, rule.Enabled),
		fmt.Sprintf("matches %d groups · actions %s · transforms %d", ruleMatchGroupCount(rule.Match), actionLabel, len(rule.Transformations)),
		fmt.Sprintf("runtime %s · requires %s", status, required),
	}
	if reason != "" {
		rows = append(rows, "reason "+reason)
	}
	if revision, active := m.policyStore.Active(); active {
		for _, diagnostic := range revision.DiagnosticsForRule(m.currentCapabilities(), rule.ID) {
			rows = append(rows, diagnostic.String())
		}
	}
	rows = append(rows, "r edit/new · M match and replace · enable|disable rule <id>")
	return box(m.cardTitle("inspector", cardInspector), rows[:min(len(rows), available)], width, height, m.activeCard == cardInspector)
}

func (m Model) activeRules() ([]policy.Rule, string) {
	revision, ok := m.policyStore.Active()
	if !ok {
		return nil, ""
	}
	return revision.Rules(), revision.Revision()
}

func (m Model) selectedRule() (policy.Rule, bool) {
	rules, _ := m.activeRules()
	if len(rules) == 0 {
		return policy.Rule{}, false
	}
	for _, rule := range rules {
		if rule.ID == m.selectedRuleID {
			return rule, true
		}
	}
	return rules[0], true
}

func (m *Model) moveRuleSelection(delta int) {
	rules, _ := m.activeRules()
	if len(rules) == 0 || delta == 0 {
		return
	}
	index := 0
	for candidate, rule := range rules {
		if rule.ID == m.selectedRuleID {
			index = candidate
			break
		}
	}
	index = clamp(index+delta, 0, len(rules)-1)
	m.selectedRuleID = rules[index].ID
}

func ruleMatchGroupCount(match policy.Match) int {
	count := 0
	if len(match.Modes)+len(match.Topologies)+len(match.Ingress)+len(match.Egress)+len(match.Directions) > 0 {
		count++
	}
	if len(match.SrcMAC)+len(match.DstMAC)+len(match.EtherTypes)+len(match.VLANs) > 0 {
		count++
	}
	if len(match.IPVersions)+len(match.SrcCIDRs)+len(match.DstCIDRs)+len(match.Protocols) > 0 {
		count++
	}
	if len(match.SrcPorts.Values)+len(match.SrcPorts.Ranges)+len(match.DstPorts.Values)+len(match.DstPorts.Ranges) > 0 {
		count++
	}
	if len(match.DNSNames)+len(match.DNSTypes)+len(match.HTTPMethods)+len(match.HTTPStatuses)+len(match.HTTPHosts)+len(match.HTTPPaths)+len(match.HTTPHeaders) > 0 {
		count++
	}
	if len(match.Payload) > 0 {
		count++
	}
	return count
}

func mainAreaHeight(height, footerHeight int) int {
	return max(4, height-footerHeight)
}

func (m Model) renderFooter(width int) string {
	footer := spacedFooter(width, footerHelp(m.workspace))
	return styleFooterBar.Render(footer)
}

func spacedFooter(width int, items []string) string {
	if width <= 0 {
		return ""
	}
	if len(items) == 0 {
		return strings.Repeat(" ", width)
	}
	total := 0
	for _, item := range items {
		total += lipgloss.Width(item)
	}
	gaps := len(items) - 1
	if gaps <= 0 || total+gaps > width {
		return fit(strings.Join(items, "   "), width)
	}

	spaces := width - total
	base := spaces / gaps
	remainder := spaces % gaps
	var out strings.Builder
	for i, item := range items {
		if i > 0 {
			gap := base
			if i <= remainder {
				gap++
			}
			out.WriteString(strings.Repeat(" ", gap))
		}
		out.WriteString(item)
	}
	return fit(out.String(), width)
}

func (m Model) cardTitle(title string, card cardFocus) string {
	return title
}

func box(title string, lines []string, width, height int, active bool) string {
	if width < 12 {
		width = 12
	}
	if height < 4 {
		height = 4
	}

	innerWidth := width - 2
	innerHeight := height - 2
	clean := make([]string, 0, height)
	clean = append(clean, paneHeader(title, width, active))
	for _, line := range lines {
		if len(clean) == innerHeight+1 {
			break
		}
		clean = append(clean, paneLine(line, innerWidth))
	}
	for len(clean) < innerHeight+1 {
		clean = append(clean, paneLine("", innerWidth))
	}
	clean = append(clean, paneRule(width, active))
	return strings.Join(clean, "\n")
}

func paneHeader(title string, width int, active bool) string {
	marker := "▏ "
	style := stylePaneHeader
	if active {
		marker = "▌ "
		style = stylePaneHeaderActive
	}
	return style.Render(fit(marker+title, width))
}

func paneLine(line string, innerWidth int) string {
	selected := strings.HasPrefix(line, "> ")
	content := " " + fit(styleTypedLine(line), innerWidth) + " "
	if selected {
		return renderStyleLayer(styleSelectedRow, content)
	}
	return renderStyleLayer(stylePaneBody, content)
}

func paneRule(width int, active bool) string {
	if width <= 0 {
		return ""
	}
	if !active {
		return stylePaneRule.Render(strings.Repeat("─", width))
	}
	railWidth := min(4, width)
	return stylePaneRuleActive.Render(strings.Repeat("━", railWidth)) +
		stylePaneRule.Render(strings.Repeat("─", width-railWidth))
}

func fullscreenPanel(title string, rows []string, footer string, width, height, margin int) string {
	flattened := make([]string, 0, len(rows))
	for _, row := range rows {
		flattened = append(flattened, strings.Split(row, "\n")...)
	}
	content := box(title, flattened, width, max(4, height-1), true)
	view := lipgloss.JoinVertical(
		lipgloss.Left,
		content,
		styleFooterBar.Render(fit(footer, width)),
	)
	return insetBlock(clampBlock(view, width, height), margin)
}

func fit(value string, width int) string {
	if width <= 0 {
		return ""
	}
	visible := lipgloss.Width(value)
	if visible <= width {
		return value + strings.Repeat(" ", width-visible)
	}
	if width <= 1 {
		return ""
	}
	out := truncateCells(value, width-1) + "…"
	if strings.Contains(out, "\x1b[") {
		out += "\x1b[0m"
	}
	if pad := width - lipgloss.Width(out); pad > 0 {
		out += strings.Repeat(" ", pad)
	}
	return out
}

func clampBlock(value string, width, height int) string {
	if width <= 0 {
		return ""
	}
	lines := strings.Split(value, "\n")
	if height > 0 && len(lines) > height {
		lines = lines[:height]
	}
	for i, line := range lines {
		lines[i] = fit(line, width)
	}
	return strings.Join(lines, "\n")
}

func insetBlock(value string, margin int) string {
	if margin <= 0 || value == "" {
		return value
	}
	prefix := styleCanvas.Render(strings.Repeat(" ", margin))
	lines := strings.Split(value, "\n")
	for i, line := range lines {
		lines[i] = prefix + line
	}
	return strings.Join(lines, "\n")
}

func truncateCells(value string, width int) string {
	if width <= 0 {
		return ""
	}
	var out strings.Builder
	cells := 0
	for i := 0; i < len(value); {
		if value[i] == '\x1b' && i+1 < len(value) && value[i+1] == '[' {
			start := i
			i += 2
			for i < len(value) {
				b := value[i]
				i++
				if b >= 0x40 && b <= 0x7e {
					break
				}
			}
			out.WriteString(value[start:i])
			continue
		}
		r, size := rune(value[i]), 1
		if r >= 0x80 {
			r, size = utf8.DecodeRuneInString(value[i:])
		}
		rw := lipgloss.Width(string(r))
		if cells+rw > width {
			break
		}
		out.WriteRune(r)
		cells += rw
		i += size
	}
	return out.String()
}

type outputRow struct {
	line    string
	muted   bool
	literal bool
}

func wrapOutputLinesStyled(lines []string, muted, literal []bool, width int) []outputRow {
	if width <= 0 {
		return nil
	}
	var out []outputRow
	for i, line := range lines {
		lineMuted := isCommandLevelOutput(line)
		if i < len(muted) {
			lineMuted = muted[i]
		}
		lineLiteral := i < len(literal) && literal[i]
		for _, wrapped := range wrapOutputLine(line, width) {
			out = append(out, outputRow{line: wrapped, muted: lineMuted, literal: lineLiteral})
		}
	}
	return out
}

func styledOutputRows(rows []outputRow) []string {
	out := make([]string, len(rows))
	for i, row := range rows {
		if row.literal {
			out[i] = styleLiteralOutputLine(row.line)
		} else {
			out[i] = styleOutputLine(row.line, row.muted)
		}
	}
	return out
}

func styleLiteralOutputLine(line string) string {
	// Keep the semantic bypass even under a no-color renderer where a Lip Gloss
	// style may otherwise emit no SGR sequence for paneLine to recognize.
	return ansiFullReset + styleText.Render(line)
}

func wrapOutputLine(line string, width int) []string {
	indent, ok := doctorContinuationIndent(line)
	if !ok {
		return wrapLine(line, width)
	}
	leading := line[:len(line)-len(strings.TrimLeft(line, " "))]
	return wrapLineWithPrefixes(line, width, leading, indent)
}

func doctorContinuationIndent(line string) (string, bool) {
	leading := len(line) - len(strings.TrimLeft(line, " "))
	trimmed := line[leading:]
	close := strings.Index(trimmed, "] ")
	if !strings.HasPrefix(trimmed, "[") || close <= 1 {
		return "", false
	}
	status := trimmed[1:close]
	switch status {
	case "PASS", "WARN", "FAIL", "SKIP":
	default:
		return "", false
	}
	return strings.Repeat(" ", leading+close+2), true
}

func wrapLineWithPrefixes(line string, width int, firstPrefix, continuationPrefix string) []string {
	if width <= 0 || lipgloss.Width(continuationPrefix) >= width {
		return wrapLine(line, width)
	}
	words := strings.Fields(line)
	if len(words) == 0 {
		return []string{firstPrefix}
	}
	prefix := firstPrefix
	current := prefix
	hasWord := false
	var out []string
	for _, word := range words {
		separator := ""
		if hasWord {
			separator = " "
		}
		if lipgloss.Width(current+separator+word) <= width {
			current += separator + word
			hasWord = true
			continue
		}
		if hasWord {
			out = append(out, current)
			prefix, current, hasWord = continuationPrefix, continuationPrefix, false
		}
		available := width - lipgloss.Width(prefix)
		chunks := hardWrap(word, available)
		for len(chunks) > 1 {
			out = append(out, prefix+chunks[0])
			chunks = chunks[1:]
			prefix = continuationPrefix
		}
		current = prefix + chunks[0]
		hasWord = true
	}
	if hasWord {
		out = append(out, current)
	}
	return out
}

func wrapLine(line string, width int) []string {
	if width <= 0 {
		return []string{""}
	}
	if line == "" {
		return []string{""}
	}
	if lipgloss.Width(line) <= width {
		return []string{line}
	}

	words := strings.Fields(line)
	if len(words) == 0 {
		return hardWrap(line, width)
	}

	var out []string
	current := ""
	for _, word := range words {
		if lipgloss.Width(word) > width {
			if current != "" {
				out = append(out, current)
				current = ""
			}
			out = append(out, hardWrap(word, width)...)
			continue
		}
		if current == "" {
			current = word
			continue
		}
		next := current + " " + word
		if lipgloss.Width(next) <= width {
			current = next
			continue
		}
		out = append(out, current)
		current = word
	}
	if current != "" {
		out = append(out, current)
	}
	return out
}

func hardWrap(value string, width int) []string {
	var out []string
	var current strings.Builder
	for _, r := range value {
		next := current.String() + string(r)
		if current.Len() > 0 && lipgloss.Width(next) > width {
			out = append(out, current.String())
			current.Reset()
		}
		current.WriteRune(r)
	}
	if current.Len() > 0 {
		out = append(out, current.String())
	}
	if len(out) == 0 {
		return []string{""}
	}
	return out
}

func limitStrings(values []string, limit int) []string {
	if len(values) <= limit {
		return values
	}
	out := append([]string(nil), values[:limit]...)
	out = append(out, "...")
	return out
}

func terminalWidth(width int) int {
	if width <= 0 {
		return 100
	}
	return max(20, width)
}

func renderWidth(width int) int {
	return max(1, width-horizontalMargin(width)*2)
}

func terminalHeight(height int) int {
	if height <= 0 {
		return 20
	}
	return max(8, height)
}

func renderHeight(height int) int {
	return max(1, height)
}

func horizontalMargin(width int) int {
	if width <= 2 {
		return 0
	}
	return 1
}

func clamp(value, minValue, maxValue int) int {
	if value < minValue {
		return minValue
	}
	if value > maxValue {
		return maxValue
	}
	return value
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
