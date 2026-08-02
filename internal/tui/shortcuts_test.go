package tui

import (
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

func helpRegistryText() string {
	var lines []string
	for _, entry := range helpRegistry {
		lines = append(lines, entry.Topic, entry.Command, entry.Description, entry.Category, entry.Group)
		lines = append(lines, entry.Keys...)
		lines = append(lines, entry.Details...)
	}
	return strings.Join(lines, "\n")
}

func TestWorkbenchShortcutRegistryHasNoConflictsOrOptionBindings(t *testing.T) {
	keys := make(map[string]workbenchShortcutID)
	ids := make(map[workbenchShortcutID]string)
	for _, shortcut := range workbenchShortcuts {
		if shortcut.ID == "" || shortcut.Key == "" || shortcut.Label == "" || shortcut.Topic == "" || shortcut.Description == "" {
			t.Fatalf("incomplete shortcut=%#v", shortcut)
		}
		if previous, ok := keys[shortcut.Key]; ok {
			t.Fatalf("key %q conflicts between %q and %q", shortcut.Key, previous, shortcut.ID)
		}
		if previous, ok := ids[shortcut.ID]; ok {
			t.Fatalf("shortcut ID %q repeats keys %q and %q", shortcut.ID, previous, shortcut.Key)
		}
		lower := strings.ToLower(shortcut.Key + " " + shortcut.Label)
		if strings.Contains(lower, "alt+") || strings.Contains(lower, "option+") {
			t.Fatalf("macOS-unsafe Option shortcut=%#v", shortcut)
		}
		keys[shortcut.Key], ids[shortcut.ID] = shortcut.ID, shortcut.Key
	}
}

func TestWorkbenchShortcutKeysMatchBubbleTeaTerminalEvents(t *testing.T) {
	events := map[workbenchShortcutID]tea.KeyMsg{
		shortcutPanePrevious:      {Type: tea.KeyShiftLeft},
		shortcutPaneNext:          {Type: tea.KeyShiftRight},
		shortcutWorkspacePrevious: {Type: tea.KeyCtrlShiftLeft},
		shortcutWorkspaceNext:     {Type: tea.KeyCtrlShiftRight},
		shortcutPaneMaximize:      {Type: tea.KeyCtrlShiftUp},
		shortcutInspectorToggle:   {Type: tea.KeyCtrlT},
		shortcutCommandPalette:    {Type: tea.KeyCtrlP},
	}
	if len(events) != len(workbenchShortcuts) {
		t.Fatalf("terminal event proofs=%d shortcuts=%d", len(events), len(workbenchShortcuts))
	}
	for _, shortcut := range workbenchShortcuts {
		event, ok := events[shortcut.ID]
		if !ok || event.String() != shortcut.Key {
			t.Fatalf("shortcut %q key=%q event=%q present=%t", shortcut.ID, shortcut.Key, event.String(), ok)
		}
	}
}

func TestWorkspaceShortcutRegistryIsExactF2ThroughF4(t *testing.T) {
	want := []workspaceShortcut{
		{Workspace: workspaceMain, Key: "f2", Label: "F2"},
		{Workspace: workspaceNetwork, Key: "f3", Label: "F3"},
		{Workspace: workspaceRules, Key: "f4", Label: "F4"},
	}
	if len(workspaces) != 3 || len(workspaceShortcuts) != len(want) {
		t.Fatalf("workspaces=%v shortcuts=%#v", workspaces, workspaceShortcuts)
	}
	for index := range want {
		if workspaceShortcuts[index] != want[index] || workspaces[index] != want[index].Workspace {
			t.Fatalf("shortcut[%d]=%#v workspace=%q want=%#v", index, workspaceShortcuts[index], workspaces[index], want[index])
		}
	}
}

func TestEscapeReturnsFocusedPaneToOverviewWithoutOpeningCLI(t *testing.T) {
	tests := []struct {
		workspace workspace
		card      cardFocus
	}{{workspaceMain, cardOutput}, {workspaceMain, cardCLI}, {workspaceNetwork, cardOutput}, {workspaceNetwork, cardInspector}, {workspaceRules, cardInspector}}
	for _, test := range tests {
		m := NewModelWithSize(160, 40)
		m.workspace, m.activeCard, m.maximized = test.workspace, test.card, true
		m.input, m.completions, m.cursorVisible = "draft command", []string{"draft completion"}, true
		next, command := m.Update(tea.KeyMsg{Type: tea.KeyEsc})
		got := next.(Model)
		if command != nil || got.activeCard != cardNone || got.maximized {
			t.Fatalf("workspace=%s card=%v command=%v focus=%v maximized=%t", test.workspace, test.card, command != nil, got.activeCard, got.maximized)
		}
		if got.input != "draft command" || strings.Join(got.completions, ",") != "draft completion" || got.cursorVisible {
			t.Fatalf("workspace=%s card=%v input=%q completions=%v cursor=%t", test.workspace, test.card, got.input, got.completions, got.cursorVisible)
		}
		if !strings.Contains(got.View(), "ALL PANES") {
			t.Fatalf("overview state is not visible:\n%s", got.View())
		}
	}
}

func TestEscapeDoesNothingFromPaneOverview(t *testing.T) {
	m := NewModel()
	m.activeCard, m.input, m.completions = cardNone, "preserved", []string{"one", "two"}
	next, command := m.Update(tea.KeyMsg{Type: tea.KeyEsc})
	got := next.(Model)
	if command != nil || got.activeCard != cardNone || got.maximized || got.input != "preserved" || strings.Join(got.completions, ",") != "one,two" {
		t.Fatalf("overview Escape mutated state: %#v", got)
	}
}

func TestNonMainPrintableKeysNeverOpenOrEditCLI(t *testing.T) {
	for _, target := range []workspace{workspaceNetwork, workspaceRules} {
		for _, card := range []cardFocus{cardNone, cardOutput, cardInspector} {
			m := NewModel()
			m.workspace, m.activeCard = target, card
			next, command := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'ß'}})
			got := next.(Model)
			if command != nil || got.activeCard != card || got.input != "" {
				t.Fatalf("workspace=%s card=%v composed Option text leaked: command=%v focus=%v input=%q", target, card, command != nil, got.activeCard, got.input)
			}
		}
	}
}

func TestMainOverviewTypingExplicitlyFocusesCLI(t *testing.T) {
	m := NewModel()
	m.activeCard = cardNone
	next, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'x'}})
	got := next.(Model)
	if got.activeCard != cardCLI || got.input != "x" {
		t.Fatalf("Main typing focus=%v input=%q", got.activeCard, got.input)
	}
}

func TestGlobalNavigationMappingsOperateWithoutPrintableKeys(t *testing.T) {
	m := NewModel()
	m.workspace, m.activeCard = workspaceNetwork, cardOutput
	next, _ := m.Update(tea.KeyMsg{Type: tea.KeyShiftRight})
	m = next.(Model)
	if m.activeCard != cardInspector {
		t.Fatalf("Shift+Right card=%v", m.activeCard)
	}
	m.workspace, m.activeCard = workspaceMain, cardOutput
	next, _ = m.Update(tea.KeyMsg{Type: tea.KeyCtrlShiftRight})
	m = next.(Model)
	if m.workspace != workspaceNetwork {
		t.Fatalf("Ctrl+Shift+Right workspace=%q", m.workspace)
	}
	next, _ = m.Update(tea.KeyMsg{Type: tea.KeyCtrlShiftUp})
	m = next.(Model)
	if !m.maximized {
		t.Fatal("Ctrl+Shift+Up did not maximize")
	}
	next, _ = m.Update(tea.KeyMsg{Type: tea.KeyCtrlShiftUp})
	m = next.(Model)
	if m.maximized {
		t.Fatal("Ctrl+Shift+Up did not restore")
	}
	m.activeCard = cardInspector
	next, _ = m.Update(tea.KeyMsg{Type: tea.KeyCtrlT})
	m = next.(Model)
	if m.inspectorVisible || m.activeCard != cardOutput {
		t.Fatalf("Ctrl+T inspector=%t card=%v", m.inspectorVisible, m.activeCard)
	}
}

func TestFunctionKeysOpenEveryWorkspaceAndRestoreLayout(t *testing.T) {
	for _, shortcut := range workspaceShortcuts {
		m := NewModel()
		m.workspace, m.activeCard, m.maximized = workspaceMain, cardOutput, true
		next, command := m.Update(tea.KeyMsg{Type: functionKeyType(shortcut.Key)})
		got := next.(Model)
		if command != nil || got.workspace != shortcut.Workspace || got.maximized {
			t.Fatalf("key=%s workspace=%q maximized=%t command=%v", shortcut.Key, got.workspace, got.maximized, command != nil)
		}
	}
}

func functionKeyType(key string) tea.KeyType {
	switch key {
	case "f2":
		return tea.KeyF2
	case "f3":
		return tea.KeyF3
	case "f4":
		return tea.KeyF4
	case "f5":
		return tea.KeyF5
	default:
		return tea.KeyNull
	}
}

func TestHelpRegistryUsesProgressiveDisclosureAndCurrentScope(t *testing.T) {
	joined := strings.ToLower(helpRegistryText())
	for _, want := range []string{"main owns output and cli", "network", "rules", "pcap", "show health", "canvas build", "f2 main"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("help missing %q", want)
		}
	}
	for _, retired := range []string{"repeater", "intercept", "logger", "findings workspace", "flows workspace", "option+", "alt+"} {
		if strings.Contains(joined, retired) {
			t.Fatalf("help retained retired or macOS-unsafe term %q", retired)
		}
	}

	m := NewModelWithSize(120, 36)
	m.openHelp()
	view := m.renderHelp()
	if !strings.Contains(view, "[-] Start here") || !strings.Contains(view, "  [-] Basics") {
		t.Fatalf("default nested help is incomplete:\n%s", view)
	}
	m.help.selected = helpCategoryID("Network")
	m.updateHelpKey("enter")
	view = m.renderHelp()
	if !strings.Contains(view, "[-] Network") || !strings.Contains(view, "  [+] Observe") || strings.Contains(view, "Filter the device inventory") {
		t.Fatalf("category disclosure boundary is incorrect:\n%s", view)
	}
	m.help.selected = helpGroupID("Network", "Observe")
	m.updateHelpKey("enter")
	view = m.renderHelp()
	if !strings.Contains(view, "[+] Network view") || strings.Contains(view, "Filter the device inventory") {
		t.Fatalf("group disclosure boundary is incorrect:\n%s", view)
	}
	m.help.selected = helpTopicID(helpEntry{Topic: "Network view"})
	m.updateHelpKey("enter")
	if !strings.Contains(m.renderHelp(), "Filter the device inventory") {
		t.Fatalf("topic detail did not expand:\n%s", m.renderHelp())
	}
}

func TestHelpTaxonomyClassifiesEveryTopicUniquely(t *testing.T) {
	seen := make(map[string]bool, len(helpRegistry))
	for _, entry := range helpRegistry {
		if entry.Category == "" || entry.Group == "" || entry.Group == "Other" {
			t.Errorf("help topic %q has no deliberate taxonomy path: category=%q group=%q", entry.Topic, entry.Category, entry.Group)
		}
		id := helpTopicID(entry)
		if seen[id] {
			t.Errorf("duplicate help topic id %q", id)
		}
		seen[id] = true
	}
}

func TestHelpDocumentsEveryCommandAndGlobalShortcut(t *testing.T) {
	commandText := make([]string, 0, len(helpRegistry))
	keyText := make([]string, 0, len(helpRegistry))
	for _, entry := range helpRegistry {
		if strings.TrimSpace(entry.Description) == "" {
			t.Errorf("help topic %q has no explanation", entry.Topic)
		}
		replacer := strings.NewReplacer("|", " ", "<", " ", ">", " ", "[", " ", "]", " ", "(", " ", ")", " ")
		commandText = append(commandText, strings.Fields(replacer.Replace(strings.ToLower(entry.Command)))...)
		for _, key := range entry.Keys {
			keyText = append(keyText, strings.ToLower(key))
		}
	}
	for _, command := range topLevelCommands() {
		if !containsString(commandText, command) {
			t.Errorf("top-level command %q is absent from help", command)
		}
	}
	for _, shortcut := range workbenchShortcuts {
		if !containsString(keyText, strings.ToLower(shortcut.Label)) {
			t.Errorf("global shortcut %q is absent from help", shortcut.Label)
		}
	}
	for _, shortcut := range workspaceShortcuts {
		if !containsString(keyText, strings.ToLower(shortcut.Label+" "+string(shortcut.Workspace))) {
			t.Errorf("workspace shortcut %q is absent from help", shortcut.Label)
		}
	}
}

func TestCLIHelpPrintsCompleteLiteralReference(t *testing.T) {
	m := NewModel()
	want := commandHelpLines()
	m.showHelp()
	if len(m.output) != len(want) || len(m.outputLiteral) != len(want) {
		t.Fatalf("CLI help lines=%d literal=%d want=%d", len(m.output), len(m.outputLiteral), len(want))
	}
	for index, literal := range m.outputLiteral {
		if !literal || m.output[index] != want[index] {
			t.Fatalf("help line %d lost literal identity: literal=%t got=%q want=%q", index, literal, m.output[index], want[index])
		}
	}
	for _, prefix := range []string{"      Command: start listen", "      Command: canvas build"} {
		index := -1
		for candidate, line := range m.output {
			if strings.HasPrefix(line, prefix) {
				index = candidate
				break
			}
		}
		if index < 0 {
			t.Fatalf("literal help omitted %q", prefix)
		}
		row := styledOutputRows(wrapOutputLinesStyled(m.output[index:index+1], m.outputMuted[index:index+1], m.outputLiteral[index:index+1], 512))[0]
		if row != styleLiteralOutputLine(m.output[index]) || !strings.Contains(row, ansiFullReset) {
			t.Fatalf("help line inherited runtime coloring: %q", row)
		}
	}
}

func TestVerboseHelpWrapsWithoutDiscardingDetail(t *testing.T) {
	m := NewModelWithSize(48, 32)
	m.openHelp()
	document := helpDisplayDocument(m.help, 48)
	var text []string
	for _, line := range document {
		if got := lipgloss.Width(line.Text); got > 48 {
			t.Fatalf("help line width=%d exceeds 48: %q", got, line.Text)
		}
		text = append(text, line.Text)
	}
	normalized := strings.Join(strings.Fields(strings.Join(text, " ")), " ")
	for _, want := range []string{"What it does:", "exact command syntax", "where it applies."} {
		if !strings.Contains(normalized, want) {
			t.Fatalf("wrapped help lost %q:\n%s", want, normalized)
		}
	}
}

func TestWorkspaceFootersExposeOnlyCurrentActions(t *testing.T) {
	for _, target := range workspaces {
		footer := strings.ToLower(strings.Join(footerHelp(target), "\n"))
		if !strings.Contains(footer, "f2-f4 workspace") || !strings.Contains(footer, "esc overview") {
			t.Fatalf("workspace=%s footer=%q", target, footer)
		}
		for _, retired := range []string{"repeater", "intercept", "logger", "flow"} {
			if strings.Contains(footer, retired) {
				t.Fatalf("workspace=%s footer retained %q: %q", target, retired, footer)
			}
		}
	}
}
