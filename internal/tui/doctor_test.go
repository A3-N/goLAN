package tui

import (
	"strings"
	"testing"

	"golan/internal/adapters"
	"golan/internal/paths"

	"github.com/charmbracelet/lipgloss"
)

func TestDoctorCommandReportsBoundedReadOnlyChecks(t *testing.T) {
	t.Setenv(paths.EnvConfigDir, t.TempDir())
	m := NewModel()
	m.loading = false
	m.adapters = []adapters.Adapter{{Name: "en0", IsUp: true}}
	command := m.executeCommand("doctor")
	if command == nil {
		t.Fatal("doctor did not start an asynchronous check")
	}
	message := command()
	next, followup := m.Update(message)
	got := next.(Model)
	if followup != nil {
		t.Fatal("doctor unexpectedly scheduled a mutating follow-up")
	}
	output := strings.Join(got.output, "\n")
	for _, want := range []string{
		"doctor: running read-only checks",
		"[PASS] restoration/ownership",
		"doctor summary:",
	} {
		if !strings.Contains(output, want) {
			t.Fatalf("doctor output missing %q:\n%s", want, output)
		}
	}
	if got.runtimeOperation != "" || got.project != nil || got.listener != nil ||
		got.bridge != nil || got.edgeSession != nil {
		t.Fatalf("doctor changed runtime state: %#v", got)
	}
}

func TestDoctorCommandUsageCompletionHelpAndStaleResult(t *testing.T) {
	m := NewModel()
	if command := m.executeCommand("doctor now"); command != nil ||
		!strings.Contains(strings.Join(m.output, "\n"), "use: doctor") {
		t.Fatalf("invalid doctor arguments were accepted: command=%v output=%v", command != nil, m.output)
	}
	if !containsString(topLevelCommands(), "doctor") ||
		!containsString(m.allCompletionCandidates("doc"), "doctor") {
		t.Fatal("doctor is absent from top-level completion")
	}
	help := helpRegistryText()
	if !strings.Contains(help, "doctor") ||
		!strings.Contains(help, "bounded read-only environment") {
		t.Fatalf("doctor help is incomplete:\n%s", help)
	}

	m.doctorEpoch = 2
	m.output = nil
	next, _ := m.Update(doctorMsg{epoch: 1})
	got := next.(Model)
	if len(got.output) != 0 {
		t.Fatalf("stale doctor result changed output: %v", got.output)
	}
}

func TestDoctorStatusesUseSemanticColorsAndHangingWrap(t *testing.T) {
	for _, test := range []struct {
		status string
		style  lipgloss.Style
		color  lipgloss.TerminalColor
	}{
		{status: "PASS", style: styleSuccess, color: colorAccent},
		{status: "WARN", style: styleWarn, color: colorWarn},
		{status: "FAIL", style: styleError, color: colorError},
		{status: "SKIP", style: styleMuted, color: colorMuted},
	} {
		if rendered := styleTypedLine("  [" + test.status + "] check"); !strings.Contains(rendered, test.style.Render("["+test.status+"]")) {
			t.Errorf("status %s was not styled semantically: %q", test.status, rendered)
		}
		if got := test.style.GetForeground(); got != test.color {
			t.Errorf("status %s foreground=%v want=%v", test.status, got, test.color)
		}
	}
	failure := "  [FAIL] PF/readiness: probe failed with an error"
	if isCommandLevelOutput(failure) {
		t.Fatal("doctor failure was incorrectly classified as a muted command log")
	}
	if rendered := styleTypedLine(styleOutputLine(failure, isCommandLevelOutput(failure))); !strings.Contains(rendered, styleError.Render("[FAIL]")) {
		t.Fatalf("doctor failure lost its red status style: %q", rendered)
	}

	line := "  [WARN] adapters/inventory: one or more physical adapters lack a network-service mapping and require review"
	rows := wrapOutputLinesStyled([]string{line}, []bool{false}, nil, 42)
	if len(rows) < 2 || !strings.HasPrefix(rows[0].line, "  [WARN] ") {
		t.Fatalf("doctor line did not wrap with its original indent: %#v", rows)
	}
	continuation := strings.Repeat(" ", len("  [WARN] "))
	for _, row := range rows[1:] {
		if !strings.HasPrefix(row.line, continuation) || strings.HasPrefix(strings.TrimSpace(row.line), "[WARN]") {
			t.Fatalf("doctor continuation does not hang after status: %q", row.line)
		}
	}
}
