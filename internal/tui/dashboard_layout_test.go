package tui

import (
	"regexp"
	"strings"
	"testing"

	"github.com/charmbracelet/lipgloss"
)

var ansiEscapePattern = regexp.MustCompile(`\x1b\[[0-9;:]*[A-Za-z]`)

func stripANSI(s string) string {
	return ansiEscapePattern.ReplaceAllString(s, "")
}

func assertCompleteCardFrame(t *testing.T, rendered string, width int) {
	t.Helper()
	for i, line := range strings.Split(strings.TrimRight(rendered, "\n"), "\n") {
		plain := stripANSI(line)
		if plain == "" {
			continue
		}
		if got := lipgloss.Width(plain); got != width {
			t.Fatalf("line %d width = %d, want %d: %q", i, got, width, plain)
		}
		runes := []rune(plain)
		first := runes[0]
		last := runes[len(runes)-1]
		switch first {
		case '╭':
			if last != '╮' {
				t.Fatalf("line %d has incomplete top border: %q", i, plain)
			}
		case '╰':
			if last != '╯' {
				t.Fatalf("line %d has incomplete bottom border: %q", i, plain)
			}
		case '│':
			if last != '│' {
				t.Fatalf("line %d has incomplete side border: %q", i, plain)
			}
		default:
			t.Fatalf("line %d is not framed: %q", i, plain)
		}
	}
}

func TestRenderCardUsesOuterWidth(t *testing.T) {
	for _, width := range []int{20, 40, 96} {
		card := renderCard(width, "card body")
		if got := lipgloss.Width(card); got != width {
			t.Fatalf("renderCard(%d) width = %d, want %d", width, got, width)
		}
	}
}

func TestRenderCardHasCompleteFrame(t *testing.T) {
	card := renderCard(40, strings.Repeat("long content ", 12))
	assertCompleteCardFrame(t, card, 40)
}

func TestRenderFixedCardUsesOuterDimensions(t *testing.T) {
	content := strings.Repeat("line\n", 20)
	card := renderFixedCard(48, 12, content)
	if got := lipgloss.Width(card); got != 48 {
		t.Fatalf("renderFixedCard width = %d, want 48", got)
	}
	if got := lipgloss.Height(card); got != 12 {
		t.Fatalf("renderFixedCard height = %d, want 12", got)
	}
}

func TestRenderFixedCardHasCompleteFrame(t *testing.T) {
	card := renderFixedCard(48, 8, strings.Repeat("line\n", 20))
	assertCompleteCardFrame(t, card, 48)
}

func TestRenderFixedCardStackHasCompleteFrames(t *testing.T) {
	stack := renderFixedCardStack(44, 18, []string{
		"one\n" + strings.Repeat("line\n", 8),
		"two\n" + strings.Repeat("line\n", 8),
		"three\n" + strings.Repeat("line\n", 8),
	})
	assertCompleteCardFrame(t, stack, 44)
	if got := lipgloss.Height(stack); got != 18 {
		t.Fatalf("stack height = %d, want 18", got)
	}
}

func TestRenderFramePinsFooterAtTerminalHeight(t *testing.T) {
	m := DashboardModel{width: 80, height: 24}
	frame := m.renderFrame("header", strings.Repeat("body\n", 3), "footer")
	if got := lipgloss.Height(frame); got != 24 {
		t.Fatalf("frame height = %d, want 24", got)
	}
}

func TestRenderFooterUsesTerminalWidth(t *testing.T) {
	m := DashboardModel{width: 80}
	footer := m.renderFooter()
	if got := lipgloss.Width(footer); got != 80 {
		t.Fatalf("footer width = %d, want 80", got)
	}
}

func TestOversizedFramedBodyScrollsInsteadOfSectionError(t *testing.T) {
	m := DashboardModel{width: 80, height: 24}
	body := renderCard(80, strings.Repeat("line\n", 40))
	fit := m.fitBodyHeight(body, 10, 0)
	if strings.Contains(fit, "section exceeds terminal height") {
		t.Fatalf("oversized framed body returned section error: %q", fit)
	}
	if got := lipgloss.Height(fit); got != 10 {
		t.Fatalf("fit body height = %d, want 10", got)
	}
	assertCompleteCardFrame(t, fit, 80)
}
