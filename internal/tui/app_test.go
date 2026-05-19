package tui

import (
	"strings"
	"testing"

	"github.com/charmbracelet/lipgloss"
)

func TestShutdownViewFitsTerminal(t *testing.T) {
	m := Model{
		width:          80,
		height:         24,
		quitting:       true,
		shutdownFrame:  1,
		shutdownPhrase: 2,
	}

	view := m.View()
	if got := lipgloss.Width(view); got != 80 {
		t.Fatalf("shutdown view width = %d, want 80", got)
	}
	if got := lipgloss.Height(view); got != 24 {
		t.Fatalf("shutdown view height = %d, want 24", got)
	}
	if !strings.Contains(stripANSI(view), "Shutting down bridge and restoring settings") {
		t.Fatalf("shutdown view missing status text: %q", view)
	}
}

func TestShutdownDotsCycle(t *testing.T) {
	want := []string{".", "..", "...", "", ".", "..", "...", ""}
	for frame, expected := range want {
		if got := shutdownDots(frame); got != expected {
			t.Fatalf("shutdownDots(%d) = %q, want %q", frame, got, expected)
		}
	}
}
