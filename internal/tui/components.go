package tui

import (
	"fmt"
	"math"
	"strings"

	"github.com/charmbracelet/lipgloss"
)

// Sparkline block characters, from lowest to highest.
var sparkBlocks = []rune{'▁', '▂', '▃', '▄', '▅', '▆', '▇', '█'}

// renderSparkline renders a unicode sparkline from a slice of values.
func renderSparkline(data []float64, width int, style lipgloss.Style) string {
	if len(data) == 0 {
		return style.Render(strings.Repeat("▁", width))
	}

	start := 0
	if len(data) > width {
		start = len(data) - width
	}
	visible := data[start:]

	maxVal := 0.0
	for _, v := range visible {
		if v > maxVal {
			maxVal = v
		}
	}

	var sb strings.Builder

	padLen := width - len(visible)
	for i := 0; i < padLen; i++ {
		sb.WriteRune(sparkBlocks[0])
	}

	for _, v := range visible {
		idx := 0
		if maxVal > 0 {
			normalized := v / maxVal
			idx = int(math.Round(normalized * float64(len(sparkBlocks)-1)))
			if idx >= len(sparkBlocks) {
				idx = len(sparkBlocks) - 1
			}
		}
		sb.WriteRune(sparkBlocks[idx])
	}

	return style.Render(sb.String())
}

// renderBridgeWire renders the horizontal bridge connector between two interface cards.
func renderBridgeWire(active bool, width int) string {
	style := styleBridgeWire
	if active {
		style = styleBridgeWireActive
	}

	if width < 5 {
		width = 5
	}

	label := " BRIDGE "
	wireLen := (width - len(label) - 2) / 2
	if wireLen < 1 {
		wireLen = 1
	}

	left := strings.Repeat("═", wireLen) + "╡"
	right := "╞" + strings.Repeat("═", wireLen)

	return style.Render(left) +
		styleBridgeLabel.Render(label) +
		style.Render(right)
}

// renderKeyValue renders a label: value pair with consistent styling.
func renderKeyValue(label, value string) string {
	return styleLabelCol.Render(label+":") + " " + styleValueCol.Render(value)
}

// humanizePacketRate formats a packet rate with appropriate units.
func humanizePacketRate(pps float64) string {
	switch {
	case pps >= 1_000_000:
		return fmt.Sprintf("%.1f Mpps", pps/1_000_000)
	case pps >= 1_000:
		return fmt.Sprintf("%.1f Kpps", pps/1_000)
	default:
		return fmt.Sprintf("%.0f pps", pps)
	}
}
