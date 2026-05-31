package tui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"golan/internal/profile"
)

func (m Model) View() string {
	width := terminalWidth(m.width)
	height := terminalHeight(m.height)

	footer := m.renderFooter(width)
	footerHeight := lipgloss.Height(footer)
	mainHeight := max(8, height-footerHeight-2)

	leftWidth, rightWidth := splitWidths(width)
	cliHeight := clamp(mainHeight/4, 4, 8)
	if mainHeight-cliHeight-1 < 4 {
		cliHeight = max(4, mainHeight-5)
	}
	outputHeight := max(4, mainHeight-cliHeight-1)

	left := lipgloss.JoinVertical(
		lipgloss.Left,
		m.renderOutput(leftWidth, outputHeight),
		m.renderCLI(leftWidth, cliHeight),
	)
	right := m.renderMisc(rightWidth, mainHeight)

	main := lipgloss.JoinHorizontal(lipgloss.Top, left, " ", right)
	return lipgloss.JoinVertical(lipgloss.Left, main, footer)
}

func (m Model) renderOutput(width, height int) string {
	available := max(1, height-3)
	rows := wrapLines(m.output, max(1, width-4))
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
	return box(m.cardTitle("output", cardOutput), rows[start:end], width, height, m.activeCard == cardOutput)
}

func (m Model) renderCLI(width, height int) string {
	cursor := " "
	if m.cursorVisible {
		cursor = "|"
	}
	lines := []string{
		m.prompt() + m.input + cursor,
	}
	if len(m.completions) > 0 {
		lines = append(lines, strings.Join(limitStrings(m.completions, 8), "  "))
	}
	return box(m.cardTitle("cli", cardCLI), lines, width, height, m.activeCard == cardCLI)
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
		"set <adapter> <role>",
		"conf <name>",
		"unset",
		"load <name>",
		"start listen|bridge",
		"stop listen|bridge",
		"set ip <value|auto>",
		"set mac <value|auto>",
		"set state up|down|auto",
		"clear",
		"",
		"properties",
	}

	if cfg, ok := m.profile.ByName(m.activeAdapter); ok {
		lines = append(lines, m.renderConfigLines(*cfg)...)
	} else if len(m.profile.Adapters) > 0 {
		lines = append(lines, "no active context")
		lines = append(lines, "run: conf <adapter>")
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

func (m Model) renderFooter(width int) string {
	footer := fmt.Sprintf("card %s   left/right card   up/down scroll/history   tab autocomplete   enter run   ctrl+s save   ctrl+c quit", m.activeCard.String())
	return styleMuted.Render(fit(footer, width))
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
		clean = append(clean, fit(line, innerWidth))
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
		Width(innerWidth).
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
	runes := []rune(value)
	if width <= 1 {
		return ""
	}
	if len(runes) > width {
		return string(runes[:width-1]) + "."
	}
	return value
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

func terminalHeight(height int) int {
	if height <= 0 {
		return 30
	}
	return max(8, height)
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
