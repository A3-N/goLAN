package tui

import (
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/charmbracelet/lipgloss"
	"golan/internal/profile"
)

func (m Model) View() string {
	terminalCols := terminalWidth(m.width)
	width := renderWidth(terminalCols)
	margin := horizontalMargin(terminalCols)
	terminalRows := terminalHeight(m.height)
	height := renderHeight(terminalRows)

	footer := m.renderFooter(width)
	footerHeight := lipgloss.Height(footer)
	mainHeight := mainAreaHeight(height, footerHeight)

	leftWidth, rightWidth := splitWidths(width)
	cliHeight := clamp(mainHeight/4, 4, 8)
	if mainHeight-cliHeight < 4 {
		cliHeight = max(4, mainHeight-4)
	}
	outputHeight := max(4, mainHeight-cliHeight)

	left := lipgloss.JoinVertical(
		lipgloss.Left,
		m.renderOutput(leftWidth, outputHeight),
		m.renderCLI(leftWidth, cliHeight),
	)
	rightTopHeight, trafficHeight := rightPaneHeights(mainHeight)
	right := lipgloss.JoinVertical(
		lipgloss.Left,
		m.renderRightTop(rightWidth, rightTopHeight),
		m.renderTraffic(rightWidth, trafficHeight),
	)

	main := lipgloss.JoinHorizontal(lipgloss.Top, left, " ", right)
	return insetBlock(clampBlock(lipgloss.JoinVertical(lipgloss.Left, main, footer), width, height), margin)
}

func (m Model) renderOutput(width, height int) string {
	available := max(1, height-3)
	rows := wrapOutputLines(m.output, m.outputMuted, max(1, width-4))
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
	if m.cursorVisible {
		cursor = "|"
	}
	lines := []string{
		styleCLILine(m.prompt() + m.input + cursor),
	}
	if len(m.completions) > 0 {
		lines = append(lines, styleAutocompleteLine(strings.Join(limitStrings(m.completions, 8), "  ")))
	}
	return box(m.cardTitle("cli", cardCLI), lines, width, height, m.activeCard == cardCLI)
}

func styleCLILine(line string) string {
	if line == "" {
		return line
	}
	return styleText.Render(line)
}

func styleAutocompleteLine(line string) string {
	if line == "" {
		return line
	}
	return styleMuted.Render(line)
}

func (m Model) renderRightTop(width, height int) string {
	available := max(1, height-3)
	start := len(m.findings) - available
	if start < 0 {
		start = 0
	}
	return box(m.cardTitle("findings", cardMisc), m.findings[start:], width, height, m.activeCard == cardMisc)
}

func (m Model) renderTraffic(width, height int) string {
	available := max(1, height-3)
	start := len(m.traffic) - available
	if start < 0 {
		start = 0
	}
	return box(m.cardTitle("traffic", cardMisc), m.traffic[start:], width, height, m.activeCard == cardMisc)
}

func (m Model) renderMisc(width, height int) string {
	lines := []string{
		"golan init",
		"",
		"adapters: " + m.adapterStatus(),
		fmt.Sprintf("selected: %d/%d", len(m.profile.Adapters), profile.MaxAdapters),
		"active: " + m.activeStatus(),
		"cap: " + m.captureStatus(),
		fmt.Sprintf("bridge: %d", len(m.profile.Bridge.Observations)),
		"",
		"commands",
		"show adapters",
		"show bridge",
		"show secrets",
		"set <adapter> <role>",
		"conf <name|bridge>",
		"unset",
		"load <name>",
		"start listen|bridge|nat",
		"stop listen|bridge|nat",
		"send eapol start",
		"enable eapol drop-logoff",
		"disable eapol drop-logoff",
		"enable eapol macsec-downgrade",
		"disable eapol macsec-downgrade",
		"set ip <value|auto>",
		"set mac <value|auto>",
		"set state up|down|auto",
		"clear",
		"",
		"properties",
	}

	if isBridgeContext(m.activeAdapter) {
		lines = append(lines, m.renderConfigLines(m.profile.BridgeAdapterSnapshot())...)
	} else if cfg, ok := m.profile.ByName(m.activeAdapter); ok {
		lines = append(lines, m.renderConfigLines(*cfg)...)
	} else if len(m.profile.Adapters) > 0 {
		lines = append(lines, "no active context")
		lines = append(lines, "run: conf <adapter|bridge>")
	} else {
		lines = append(lines, "none staged")
	}

	if len(m.profile.Adapters) > 0 {
		lines = append(lines, "", "staged")
		for _, cfg := range m.profile.Adapters {
			marker := " "
			if strings.EqualFold(cfg.Name, m.activeAdapter) {
				marker = "*"
			}
			lines = append(lines, fmt.Sprintf("%s %s %s", marker, cfg.AdapterRole, cfg.Name))
		}
		bridgeMarker := " "
		if isBridgeContext(m.activeAdapter) {
			bridgeMarker = "*"
		}
		lines = append(lines, fmt.Sprintf("%s bridge bridge", bridgeMarker))
	}

	available := max(1, height-3)
	maxOffset := max(0, len(lines)-available)
	offset := clamp(m.miscScroll, 0, maxOffset)
	end := offset + available
	if end > len(lines) {
		end = len(lines)
	}

	return box(m.cardTitle("misc", cardMisc), lines[offset:end], width, height, m.activeCard == cardMisc)
}

func rightPaneHeights(height int) (int, int) {
	if height < 8 {
		return 4, 4
	}
	top := height / 3
	if top < 4 {
		top = 4
	}
	bottom := height - top
	if bottom < 4 {
		bottom = 4
		top = height - bottom
		if top < 4 {
			top = 4
		}
	}
	if top+bottom > height {
		bottom = max(4, height-top)
	}
	return top, bottom
}

func mainAreaHeight(height, footerHeight int) int {
	return max(4, height-footerHeight)
}

func (m Model) renderFooter(width int) string {
	footer := spacedFooter(width, []string{
		"left/right card",
		"up/down scroll/history",
		"ctrl+s save",
		"ctrl+c quit",
	})
	return styleMuted.Render(footer)
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
	if m.activeCard == card {
		return title + " *"
	}
	return title
}

func (m Model) renderConfigLines(cfg profile.AdapterConfig) []string {
	lines := []string{
		"role: " + cfg.AdapterRole,
		"name: " + cfg.Name,
		"kind: " + cfg.Kind,
		"current mac: " + emptyAs(cfg.CurrentMAC, "unknown"),
		fmt.Sprintf("current mtu: %d", cfg.CurrentMTU),
		"",
	}
	for _, field := range profile.Fields {
		lines = append(lines, fmt.Sprintf("%-7s %s", field.Key+":", cfg.Value(field.Key)))
	}
	if len(cfg.Discovered) > 0 {
		lines = append(lines, "", "discovered")
		for _, item := range cfg.Discovered {
			lines = append(lines, fmt.Sprintf("%s %s (%s)", item.Field, item.Value, item.Packet))
		}
	}
	return lines
}

func (m Model) adapterStatus() string {
	if m.loading {
		return "loading"
	}
	if m.err != nil {
		return "error"
	}
	return fmt.Sprintf("%d found", len(m.adapters))
}

func (m Model) activeStatus() string {
	if m.activeAdapter == "" {
		return "none"
	}
	return m.activeAdapter
}

func (m Model) captureStatus() string {
	if m.natActive {
		return "nat"
	}
	if m.bridge != nil {
		return "bridge"
	}
	if m.listener == nil {
		return "off"
	}
	if m.capMode == "" {
		return "on"
	}
	return m.capMode
}

func box(title string, lines []string, width, height int, active bool) string {
	if width < 12 {
		width = 12
	}
	if height < 4 {
		height = 4
	}

	innerWidth := width - 4
	innerHeight := height - 2
	clean := make([]string, 0, innerHeight)
	clean = append(clean, styleHeader.Render(title))
	for _, line := range lines {
		if len(clean) == innerHeight {
			break
		}
		clean = append(clean, fit(styleTypedLine(line), innerWidth))
	}
	for len(clean) < innerHeight {
		clean = append(clean, strings.Repeat(" ", innerWidth))
	}

	borderColor := colorPanel
	if active {
		borderColor = colorAccent
	}

	content := strings.Join(clean, "\n")
	return lipgloss.NewStyle().
		Width(width-2).
		Height(innerHeight).
		Border(lipgloss.RoundedBorder()).
		BorderForeground(borderColor).
		Padding(0, 1).
		Render(content)
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
	out := truncateCells(value, width-1) + "."
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
	prefix := strings.Repeat(" ", margin)
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

func wrapLines(lines []string, width int) []string {
	if width <= 0 {
		return nil
	}
	var out []string
	for _, line := range lines {
		out = append(out, wrapLine(line, width)...)
	}
	return out
}

type outputRow struct {
	line  string
	muted bool
}

func wrapOutputLines(lines []string, muted []bool, width int) []outputRow {
	if width <= 0 {
		return nil
	}
	var out []outputRow
	for i, line := range lines {
		lineMuted := isCommandLevelOutput(line)
		if i < len(muted) {
			lineMuted = muted[i]
		}
		for _, wrapped := range wrapLine(line, width) {
			out = append(out, outputRow{line: wrapped, muted: lineMuted})
		}
	}
	return out
}

func styledOutputRows(rows []outputRow) []string {
	out := make([]string, len(rows))
	for i, row := range rows {
		out[i] = styleOutputLine(row.line, row.muted)
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

func emptyAs(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
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

func splitWidths(width int) (int, int) {
	gap := 1
	available := width - gap
	if available < 2 {
		return width, 0
	}
	left := (available * 2) / 3
	right := available - left
	if right < 22 && available >= 46 {
		right = 22
		left = available - right
	}
	if left < 24 && available >= 46 {
		left = 24
		right = available - left
	}
	return left, right
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
