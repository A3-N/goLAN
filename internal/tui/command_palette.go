package tui

import (
	"sort"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	tea "github.com/charmbracelet/bubbletea"
)

const (
	commandPaletteMaxQueryRunes = 128
	commandPaletteMaxResults    = 64
)

type commandPaletteState struct {
	open       bool
	query      string
	selected   int
	results    []commandPaletteItem
	returnCard cardFocus
}

type commandPaletteItem struct {
	topic       string
	command     string
	description string
	workspaces  []workspace
	score       int
}

func (m *Model) openCommandPalette() {
	if m.commandPalette.open {
		return
	}
	m.commandPalette = commandPaletteState{
		open:       true,
		returnCard: m.activeCard,
	}
	m.refreshCommandPalette()
}

func (m *Model) closeCommandPalette() {
	if !m.commandPalette.open {
		return
	}
	m.activeCard = m.commandPalette.returnCard
	m.commandPalette = commandPaletteState{}
}

func (m Model) updateCommandPalette(key tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch key.String() {
	case "ctrl+c":
		return m, tea.Quit
	case "ctrl+p", "esc":
		m.closeCommandPalette()
	case "enter":
		m.stageCommandPaletteSelection()
	case "up":
		m.moveCommandPaletteSelection(-1)
	case "down":
		m.moveCommandPaletteSelection(1)
	case "pgup":
		m.moveCommandPaletteSelection(-m.commandPalettePageSize())
	case "pgdown":
		m.moveCommandPaletteSelection(m.commandPalettePageSize())
	case "home":
		m.commandPalette.selected = 0
	case "end":
		m.commandPalette.selected = max(0, len(m.commandPalette.results)-1)
	case "backspace", "ctrl+h":
		m.commandPalette.query = trimLastRune(m.commandPalette.query)
		m.refreshCommandPalette()
	case "ctrl+u":
		m.commandPalette.query = ""
		m.refreshCommandPalette()
	case " ":
		if utf8.RuneCountInString(m.commandPalette.query) < commandPaletteMaxQueryRunes {
			m.commandPalette.query += " "
			m.refreshCommandPalette()
		}
	default:
		if key.Type == tea.KeyRunes && len(key.Runes) > 0 {
			remaining := commandPaletteMaxQueryRunes - utf8.RuneCountInString(m.commandPalette.query)
			if remaining > 0 {
				addition := key.Runes
				if len(addition) > remaining {
					addition = addition[:remaining]
				}
				m.commandPalette.query += string(addition)
				m.refreshCommandPalette()
			}
		}
	}
	return m, nil
}

func (m *Model) updateCommandPaletteMouse(msg tea.MouseMsg) {
	switch msg.Button {
	case tea.MouseButtonWheelUp:
		m.moveCommandPaletteSelection(-1)
	case tea.MouseButtonWheelDown:
		m.moveCommandPaletteSelection(1)
	}
}

func (m *Model) refreshCommandPalette() {
	m.commandPalette.results = commandPaletteResults(m.workspace, m.commandPalette.query)
	m.commandPalette.selected = clamp(m.commandPalette.selected, 0, max(0, len(m.commandPalette.results)-1))
}

func (m *Model) moveCommandPaletteSelection(delta int) {
	count := len(m.commandPalette.results)
	if count == 0 {
		m.commandPalette.selected = 0
		return
	}
	m.commandPalette.selected = clamp(m.commandPalette.selected+delta, 0, count-1)
}

func (m *Model) stageCommandPaletteSelection() {
	if len(m.commandPalette.results) == 0 {
		return
	}
	selected := clamp(m.commandPalette.selected, 0, len(m.commandPalette.results)-1)
	seed := commandPaletteSeed(m.commandPalette.results[selected].command)
	m.commandPalette = commandPaletteState{}
	m.selectWorkspace(workspaceMain)
	m.activeCard = cardCLI
	m.inputMode = modeCommand
	m.input = seed
	m.completions = nil
	m.resetCompletionCycle()
	m.refreshCompletions()
	m.cursorVisible = true
}

func commandPaletteResults(active workspace, query string) []commandPaletteItem {
	query = normalizePaletteText(query)
	items := make([]commandPaletteItem, 0, len(helpRegistry))
	for _, entry := range helpRegistry {
		if entry.Command == "" {
			continue
		}
		item := commandPaletteItem{
			topic:       entry.Topic,
			command:     entry.Command,
			description: entry.Description,
			workspaces:  append([]workspace(nil), entry.Workspaces...),
		}
		score, ok := commandPaletteScore(item, active, query)
		if !ok {
			continue
		}
		item.score = score
		items = append(items, item)
	}
	sort.SliceStable(items, func(i, j int) bool {
		if items[i].score != items[j].score {
			return items[i].score > items[j].score
		}
		if items[i].command != items[j].command {
			return items[i].command < items[j].command
		}
		return items[i].topic < items[j].topic
	})
	if len(items) > commandPaletteMaxResults {
		items = items[:commandPaletteMaxResults]
	}
	return items
}

func commandPaletteScore(item commandPaletteItem, active workspace, query string) (int, bool) {
	contextScore := 0
	if containsWorkspace(item.workspaces, active) {
		contextScore = 80
	} else if len(item.workspaces) == 0 {
		contextScore = 20
	}
	if query == "" {
		return contextScore, true
	}

	command := normalizePaletteText(item.command)
	topic := normalizePaletteText(item.topic)
	description := normalizePaletteText(item.description)
	score := contextScore
	for _, field := range strings.Fields(query) {
		best := 0
		switch {
		case strings.HasPrefix(command, field):
			best = 1_000 - min(200, len(command)-len(field))
		case strings.Contains(command, field):
			best = 800
		case fuzzySubsequence(command, field):
			best = 600
		case strings.Contains(topic, field):
			best = 500
		case fuzzySubsequence(topic, field):
			best = 350
		case strings.Contains(description, field):
			best = 250
		case fuzzySubsequence(description, field):
			best = 100
		default:
			return 0, false
		}
		score += best
	}
	return score, true
}

func normalizePaletteText(value string) string {
	return strings.ToLower(strings.Join(strings.Fields(value), " "))
}

func fuzzySubsequence(value, query string) bool {
	if query == "" {
		return true
	}
	queryRunes := []rune(query)
	index := 0
	for _, candidate := range value {
		if unicode.ToLower(candidate) == unicode.ToLower(queryRunes[index]) {
			index++
			if index == len(queryRunes) {
				return true
			}
		}
	}
	return false
}

func commandPaletteSeed(command string) string {
	parts := strings.Fields(command)
	seed := make([]string, 0, len(parts))
	needsValue := false
	for _, part := range parts {
		if part == "|" || strings.HasPrefix(part, "<") || strings.HasPrefix(part, "[") {
			needsValue = strings.HasPrefix(part, "<")
			break
		}
		if alternative := strings.IndexByte(part, '|'); alternative >= 0 {
			if first := part[:alternative]; first != "" {
				seed = append(seed, first)
			}
			break
		}
		seed = append(seed, part)
	}
	value := strings.Join(seed, " ")
	if needsValue && value != "" {
		value += " "
	}
	return value
}

func (m Model) completionHelpHints(limit int) []string {
	if limit <= 0 || strings.TrimSpace(m.input) == "" {
		return nil
	}
	results := commandPaletteResults(m.workspace, m.input)
	hints := make([]string, 0, min(limit, len(results)))
	seen := make(map[string]bool, len(results))
	for _, result := range results {
		hint := result.topic + " — " + result.description
		if seen[hint] {
			continue
		}
		seen[hint] = true
		hints = append(hints, hint)
		if len(hints) == limit {
			break
		}
	}
	return hints
}

func (m Model) commandPalettePageSize() int {
	return max(1, (terminalHeight(m.height)-5)/2)
}

func (m Model) renderCommandPalette() string {
	width := terminalWidth(m.width)
	height := terminalHeight(m.height)
	pageSize := m.commandPalettePageSize()
	selected := clamp(m.commandPalette.selected, 0, max(0, len(m.commandPalette.results)-1))
	start := 0
	if selected >= pageSize {
		start = selected - pageSize + 1
	}
	end := min(len(m.commandPalette.results), start+pageSize)

	rows := make([]string, 0, height)
	rows = append(rows, renderStyleLayer(styleTopBar, fit(styleBrand.Render(" goLAN ")+styleProduct.Render(" COMMAND PALETTE "), width)))
	query := safeDisplayText(m.commandPalette.query)
	rows = append(rows, renderStyleLayer(stylePaneBody, fit(styleCommand.Render("> ")+styleText.Render(query)+styleFocus.Render("│"), width)))
	status := "fuzzy command + topic + description"
	if len(m.commandPalette.results) == 0 {
		status = "no matching documented commands"
	} else {
		status = strconv.Itoa(len(m.commandPalette.results)) + " matches · " + string(m.workspace) + " context · Enter stages only"
	}
	rows = append(rows, renderStyleLayer(stylePaneBody, fit(styleMuted.Render(status), width)))

	for index := start; index < end; index++ {
		item := m.commandPalette.results[index]
		command := "  " + item.command
		description := "    " + item.topic + " — " + item.description
		if index == selected {
			command = "> " + item.command
			rows = append(rows, renderStyleLayer(stylePaneBody, fit(styleFocus.Render(command), width)))
		} else {
			rows = append(rows, renderStyleLayer(stylePaneBody, fit(styleCommand.Render(command), width)))
		}
		rows = append(rows, renderStyleLayer(stylePaneBody, fit(styleMuted.Render(description), width)))
	}
	for len(rows) < height-1 {
		rows = append(rows, stylePaneBody.Render(strings.Repeat(" ", width)))
	}
	footer := " type to search   ↑/↓ select   PgUp/PgDn   Enter stage in CLI   Esc cancel   F1 help "
	rows = append(rows, styleFooterBar.Render(fit(footer, width)))
	return strings.Join(rows[:height], "\n")
}
