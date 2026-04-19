package tui

import "github.com/charmbracelet/lipgloss"

// ─── Color Palette — dark cyberpunk / hacker aesthetic ──────────────────────

var (
	colorBg        = lipgloss.Color("#0a0e14")
	colorFg        = lipgloss.Color("#c5c8c6")
	colorDim       = lipgloss.Color("#5c6370")
	colorAccent    = lipgloss.Color("#00e5ff") // UI accent — cyan/blue
	colorGreen     = lipgloss.Color("#00e676") // Success
	colorRed       = lipgloss.Color("#ff1744") // Fail / warning
	colorYellow    = lipgloss.Color("#ffd740")
	colorBorder    = lipgloss.Color("#1e2a3a")
	colorHighlight = lipgloss.Color("#1a2332")
	colorSelected  = lipgloss.Color("#12293d")

	// Port identity colors — NOT blue/green/red (those are reserved).
	colorDevice = lipgloss.Color("#ff9100") // Orange — Device port
	colorSwitch = lipgloss.Color("#e040fb") // Magenta — Switch port
	colorConflict = lipgloss.Color("#ff1744") // Red — both on same row
	color802dot1X = lipgloss.Color("#7c4dff") // Purple — 802.1X indicators
)

// ─── Layout Styles ──────────────────────────────────────────────────────────

var (
	styleApp = lipgloss.NewStyle().
			Background(colorBg).
			Foreground(colorFg)

	styleTitleBar = lipgloss.NewStyle().
			Foreground(colorAccent).
			Bold(true).
			Border(lipgloss.NormalBorder(), false, false, true, false).
			BorderForeground(colorBorder).
			Padding(0, 1).
			MarginBottom(1)
)

// ─── Table Styles ───────────────────────────────────────────────────────────

var (
	styleTableHeader = lipgloss.NewStyle().
				Foreground(colorAccent).
				Bold(true).
				Padding(0, 1)

	styleTableRow = lipgloss.NewStyle().
			Foreground(colorFg).
			Padding(0, 1)

	styleTableSelected = lipgloss.NewStyle().
				Foreground(colorAccent).
				Background(colorSelected).
				Bold(true).
				Padding(0, 1)
)

// ─── Status Indicators ─────────────────────────────────────────────────────

var (
	styleUp = lipgloss.NewStyle().
		Foreground(colorGreen).
		Bold(true)

	styleDown = lipgloss.NewStyle().
			Foreground(colorRed)

	styleSpoofed = lipgloss.NewStyle().
			Foreground(colorYellow).
			Bold(true)

	styleUSB = lipgloss.NewStyle().
			Foreground(colorDevice) // Orange for USB too
)

// ─── Text Styles ────────────────────────────────────────────────────────────

var (
	styleKey = lipgloss.NewStyle().
			Foreground(colorAccent).
			Bold(true)

	styleKeyDesc = lipgloss.NewStyle().
			Foreground(colorDim)

	styleLabel = lipgloss.NewStyle().
			Foreground(colorAccent).
			Bold(true)

	styleSuccess = lipgloss.NewStyle().
			Foreground(colorGreen).
			Bold(true)

	styleError = lipgloss.NewStyle().
			Foreground(colorRed).
			Bold(true)

	styleWarning = lipgloss.NewStyle().
			Foreground(colorYellow).
			Bold(true)

	styleDim = lipgloss.NewStyle().
			Foreground(colorDim)

	styleVal = lipgloss.NewStyle().
			Foreground(colorFg)
)

// ─── Selector Panel Styles ──────────────────────────────────────────────────

var (
	stylePanelBorder = lipgloss.NewStyle().
				Border(lipgloss.RoundedBorder()).
				BorderForeground(colorBorder).
				Padding(0, 0)

	stylePanelBorderDevice = lipgloss.NewStyle().
				Border(lipgloss.RoundedBorder()).
				BorderForeground(colorDevice).
				Padding(0, 0)

	stylePanelBorderSwitch = lipgloss.NewStyle().
				Border(lipgloss.RoundedBorder()).
				BorderForeground(colorSwitch).
				Padding(0, 0)

	stylePanelHeaderDevice = lipgloss.NewStyle().
				Foreground(colorDevice).
				Bold(true)

	stylePanelHeaderSwitch = lipgloss.NewStyle().
				Foreground(colorSwitch).
				Bold(true)
)

// ─── Dashboard Styles ───────────────────────────────────────────────────────

var (
	styleIfaceCardDevice = lipgloss.NewStyle().
				Border(lipgloss.RoundedBorder()).
				BorderForeground(colorDevice).
				Padding(0, 1)

	styleIfaceCardSwitch = lipgloss.NewStyle().
				Border(lipgloss.RoundedBorder()).
				BorderForeground(colorSwitch).
				Padding(0, 1)

	styleIfaceNameDevice = lipgloss.NewStyle().
				Foreground(colorDevice).
				Bold(true)

	styleIfaceNameSwitch = lipgloss.NewStyle().
				Foreground(colorSwitch).
				Bold(true)

	styleStatsBox = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(colorBorder).
			Padding(0, 1)

	styleSparkDevice = lipgloss.NewStyle().
			Foreground(colorDevice)

	styleSparkSwitch = lipgloss.NewStyle().
			Foreground(colorSwitch)

	styleBridgeWire = lipgloss.NewStyle().
			Foreground(colorAccent).
			Bold(true)

	styleBridgeWireActive = lipgloss.NewStyle().
				Foreground(colorGreen).
				Bold(true)

	styleBridgeLabel = lipgloss.NewStyle().
			Foreground(colorDim).
			Italic(true)

	styleLabelCol = lipgloss.NewStyle().
			Foreground(colorDim).
			Width(14)

	styleValueCol = lipgloss.NewStyle().
			Foreground(colorFg).
			Bold(true)
)

// ─── Footer ─────────────────────────────────────────────────────────────────

var (
	styleFooter = lipgloss.NewStyle().
			Border(lipgloss.NormalBorder(), true, false, false, false).
			BorderForeground(colorBorder).
			Padding(0, 1).
			MarginTop(1)
)

// keyHint renders a key hint like "[R] Random".
func keyHint(key, desc string) string {
	return styleKey.Render("["+key+"]") + " " + styleKeyDesc.Render(desc)
}
