package tui

import (
	"strings"
	"testing"
	"unicode/utf8"

	tea "github.com/charmbracelet/bubbletea"
)

func TestCommandPaletteFuzzyStagesRegistryCommandWithoutExecuting(t *testing.T) {
	m := NewModelWithSize(100, 28)
	m.workspace = workspaceNetwork
	m.activeCard = cardOutput

	next, _ := m.Update(tea.KeyMsg{Type: tea.KeyCtrlP})
	m = next.(Model)
	if !m.commandPalette.open || !strings.Contains(m.View(), "COMMAND PALETTE") {
		t.Fatal("Ctrl+P did not open the command palette")
	}
	for _, key := range "health" {
		next, _ = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{key}})
		m = next.(Model)
	}
	if len(m.commandPalette.results) == 0 || m.commandPalette.results[0].topic != "Health" {
		t.Fatalf("results=%#v", m.commandPalette.results)
	}
	if view := m.View(); !strings.Contains(view, "payload-free runtime") || !strings.Contains(view, "Enter stages only") {
		t.Fatalf("palette omitted registry description or staging boundary:\n%s", view)
	}

	next, command := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = next.(Model)
	if command != nil || m.commandPalette.open || m.workspace != workspaceMain || m.activeCard != cardCLI || m.input != "show health" {
		t.Fatalf("command=%v open=%t card=%v input=%q", command, m.commandPalette.open, m.activeCard, m.input)
	}
	if len(m.output) != 0 || m.edgeSession != nil {
		t.Fatalf("palette selection executed or mutated state: output=%v session=%v", m.output, m.edgeSession)
	}
}

func TestCommandPaletteCancelRestoresCLIAndFocusExactly(t *testing.T) {
	m := NewModelWithSize(90, 24)
	m.workspace = workspaceRules
	m.activeCard = cardInspector
	m.input = "draft command"
	m.inputMode = modeSaveName
	m.completions = []string{"before"}

	next, _ := m.Update(tea.KeyMsg{Type: tea.KeyCtrlP})
	m = next.(Model)
	for _, key := range "canvas" {
		next, _ = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{key}})
		m = next.(Model)
	}
	next, _ = m.Update(tea.KeyMsg{Type: tea.KeyEsc})
	m = next.(Model)
	if m.commandPalette.open || m.activeCard != cardInspector || m.input != "draft command" || m.inputMode != modeSaveName || len(m.completions) != 1 || m.completions[0] != "before" {
		t.Fatalf("cancel did not preserve state: palette=%#v card=%v input=%q mode=%v completions=%v", m.commandPalette, m.activeCard, m.input, m.inputMode, m.completions)
	}
}

func TestCommandPaletteIsBoundedAndHelpReturnsToPalette(t *testing.T) {
	m := NewModelWithSize(72, 20)
	next, _ := m.Update(tea.KeyMsg{Type: tea.KeyCtrlP})
	m = next.(Model)
	if len(m.commandPalette.results) == 0 || len(m.commandPalette.results) > commandPaletteMaxResults {
		t.Fatalf("result count=%d", len(m.commandPalette.results))
	}
	for range commandPaletteMaxQueryRunes + 20 {
		next, _ = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'x'}})
		m = next.(Model)
	}
	if got := utf8.RuneCountInString(m.commandPalette.query); got != commandPaletteMaxQueryRunes {
		t.Fatalf("query runes=%d", got)
	}

	next, _ = m.Update(tea.KeyMsg{Type: tea.KeyF1})
	m = next.(Model)
	if !m.help.open || !m.commandPalette.open || !strings.Contains(m.View(), "HELP") {
		t.Fatal("F1 did not layer Help over the command palette")
	}
	next, _ = m.Update(tea.KeyMsg{Type: tea.KeyF1})
	m = next.(Model)
	if m.help.open || !m.commandPalette.open || !strings.Contains(m.View(), "COMMAND PALETTE") {
		t.Fatal("closing Help did not return to the command palette")
	}
}

func TestCommandPaletteQuestionMarkSearchDoesNotOpenHelp(t *testing.T) {
	m := NewModel()
	m.activeCard = cardOutput
	next, _ := m.Update(tea.KeyMsg{Type: tea.KeyCtrlP})
	m = next.(Model)
	next, _ = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'?'}})
	m = next.(Model)
	if m.help.open || !m.commandPalette.open || m.commandPalette.query != "?" {
		t.Fatalf("help=%t palette=%t query=%q", m.help.open, m.commandPalette.open, m.commandPalette.query)
	}
}

func TestCommandPaletteSeedUsesSafeInitialAlternative(t *testing.T) {
	tests := map[string]string{
		"project new|open|save|close":                  "project new",
		"set edge upstream <auto|adapter>":             "set edge upstream ",
		"project filter list | set <name> <spec.json>": "project filter list",
		"show adapters":                                "show adapters",
	}
	for command, want := range tests {
		if got := commandPaletteSeed(command); got != want {
			t.Errorf("commandPaletteSeed(%q)=%q want %q", command, got, want)
		}
	}
}

func TestCLICompletionDescriptionsComeFromHelpRegistry(t *testing.T) {
	m := NewModelWithSize(100, 12)
	m.input = "show hea"
	m.refreshCompletions()
	view := m.renderCLI(100, 8)
	if !strings.Contains(view, "Health") || !strings.Contains(view, "payload-free runtime") {
		t.Fatalf("completion description missing from CLI:\n%s", view)
	}
	if got := len(m.completionHelpHints(2)); got == 0 || got > 2 {
		t.Fatalf("completion hints=%d", got)
	}
}
