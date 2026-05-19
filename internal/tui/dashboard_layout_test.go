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

func TestNetworkGraphContentUsesTopologyLanWanModes(t *testing.T) {
	graph := networkGraph{
		Nodes: []networkNode{
			{Key: "local:golan", Kind: "local", Label: "goLAN", IPs: []string{"192.168.1.200"}, MAC: "aa:bb:cc:dd:ee:ff"},
			{Key: "switch:en11", Kind: "switch", Label: "Observed network"},
			{Key: "ip:192.168.1.10", Kind: "target", Label: "PC", IPs: []string{"192.168.1.10"}},
			{Key: "ip:192.168.1.20", Kind: "host", Label: "printer", IPs: []string{"192.168.1.20"}},
			{Key: "ip:8.8.8.8", Kind: "external", Label: "dns", IPs: []string{"8.8.8.8"}},
		},
		Edges: []networkEdge{
			{SrcKey: "local:golan", DstKey: "switch:en11", Protocol: "inline"},
			{SrcKey: "switch:en11", DstKey: "ip:192.168.1.10", Protocol: "L2"},
			{SrcKey: "switch:en11", DstKey: "ip:192.168.1.20", Protocol: "L2"},
			{SrcKey: "switch:en11", DstKey: "ip:8.8.8.8", Protocol: "L2"},
			{SrcKey: "ip:192.168.1.10", DstKey: "ip:192.168.1.20", Protocol: "SNMP", DstPort: 161, Packets: 2},
			{SrcKey: "ip:192.168.1.10", DstKey: "ip:8.8.8.8", Protocol: "DNS", DstPort: 53, Packets: 3},
		},
		Filters:  networkGraphFilters{ShowLAN: true},
		Selected: 2,
	}

	content, _ := DashboardModel{}.networkGraphContent(filterNetworkGraph(graph), 100)
	plain := stripANSI(content)
	for _, want := range []string{"Network Layout", "==inline==", "==L2==", "SNMP:161", ">(192.168.1.20)"} {
		if !strings.Contains(plain, want) {
			t.Fatalf("LAN topology missing %q:\n%s", want, plain)
		}
	}
	if strings.Contains(plain, "> (") {
		t.Fatalf("LAN topology should not include a space between arrow and peer:\n%s", plain)
	}
	if strings.Contains(plain, "links:") {
		t.Fatalf("LAN topology should not render links label:\n%s", plain)
	}
	if strings.Contains(plain, ">>") {
		t.Fatalf("selected topology line changed indentation with marker:\n%s", plain)
	}
	if strings.Contains(plain, "WAN DNS:53") {
		t.Fatalf("LAN topology included WAN edge:\n%s", plain)
	}

	graph.Filters = networkGraphFilters{ShowWAN: true}
	content, _ = DashboardModel{}.networkGraphContent(filterNetworkGraph(graph), 100)
	plain = stripANSI(content)
	if !strings.Contains(plain, "DNS:53") || !strings.Contains(plain, ">(8.8.8.8)") {
		t.Fatalf("WAN topology missing WAN edge:\n%s", plain)
	}
	if strings.Contains(plain, "LAN SNMP:161") {
		t.Fatalf("WAN topology included LAN edge:\n%s", plain)
	}
}
