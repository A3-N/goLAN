package tui

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"
	"github.com/mcrn/goLAN/internal/bridge"
	"github.com/mcrn/goLAN/internal/stats"

	tea "github.com/charmbracelet/bubbletea"
)

// DashboardModel is the main bridge monitoring dashboard.
type DashboardModel struct {
	bridge    *bridge.Bridge
	collector *stats.Collector
	cancel    context.CancelFunc
	statsCh   <-chan stats.StatsUpdate

	ifaceA bridge.NetInterface // Device port (from selector LAN 1)
	ifaceB bridge.NetInterface // Switch port (from selector LAN 2)

	latestStats stats.StatsUpdate
	hasStats    bool

	width  int
	height int
	err    error
}

// statsMsg wraps a stats update for the Bubbletea update loop.
type statsMsg stats.StatsUpdate

// bridgeCreatedMsg signals that the bridge was successfully created.
type bridgeCreatedMsg struct {
	bridge *bridge.Bridge
}

// bridgeErrorMsg signals that bridge creation failed.
type bridgeErrorMsg struct {
	err error
}

// NewDashboardModel creates the dashboard for monitoring an active bridge.
func NewDashboardModel(ifA, ifB bridge.NetInterface) DashboardModel {
	return DashboardModel{
		ifaceA: ifA, // Device port
		ifaceB: ifB, // Switch port
	}
}

// createBridge is a tea.Cmd that creates the kernel bridge.
func createBridge(ifA, ifB string) tea.Cmd {
	return func() tea.Msg {
		br, err := bridge.NewBridge(ifA, ifB)
		if err != nil {
			return bridgeErrorMsg{err: err}
		}
		return bridgeCreatedMsg{bridge: br}
	}
}

// waitForStats returns a tea.Cmd that reads the next stats update from the channel.
func waitForStats(ch <-chan stats.StatsUpdate) tea.Cmd {
	return func() tea.Msg {
		update, ok := <-ch
		if !ok {
			return nil
		}
		return statsMsg(update)
	}
}

func (m DashboardModel) Init() tea.Cmd {
	return createBridge(m.ifaceA.Name, m.ifaceB.Name)
}

func (m DashboardModel) Update(msg tea.Msg) (DashboardModel, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		return m, nil

	case bridgeCreatedMsg:
		m.bridge = msg.bridge
		ctx, cancel := context.WithCancel(context.Background())
		m.cancel = cancel
		m.collector = stats.NewCollector(
			m.ifaceA.Name,
			m.ifaceB.Name,
			m.bridge.Name(),
			500*time.Millisecond,
		)
		m.statsCh = m.collector.Start(ctx)
		return m, waitForStats(m.statsCh)

	case bridgeErrorMsg:
		m.err = msg.err
		return m, nil

	case statsMsg:
		m.latestStats = stats.StatsUpdate(msg)
		m.hasStats = true
		return m, waitForStats(m.statsCh)

	case tea.KeyMsg:
		// Key handling at dashboard level (esc/q handled by root model).
	}

	return m, nil
}

// Shutdown cleans up the bridge and stats collector.
func (m *DashboardModel) Shutdown() error {
	if m.cancel != nil {
		m.cancel()
	}
	if m.bridge != nil {
		return m.bridge.Destroy()
	}
	return nil
}

func (m DashboardModel) View() string {
	if m.width == 0 {
		return ""
	}

	var sb strings.Builder
	contentWidth := m.width
	if contentWidth < 80 {
		contentWidth = 80
	}

	// ── Header with Status ──────────────────────────────────────
	sb.WriteString(m.renderHeader(contentWidth))
	sb.WriteString("\n")

	// ── Error State ─────────────────────────────────────────────
	if m.err != nil {
		sb.WriteString(m.renderError())
		return sb.String()
	}

	// ── Loading State ───────────────────────────────────────────
	if m.bridge == nil {
		sb.WriteString("\n")
		sb.WriteString(styleDim.Render("  ⟳ Creating bridge between " + m.ifaceA.Name + " and " + m.ifaceB.Name + "..."))
		return sb.String()
	}

	// ── Bridge Diagram ──────────────────────────────────────────
	sb.WriteString(m.renderBridgeDiagram(contentWidth))
	sb.WriteString("\n")

	// ── Traffic Statistics ───────────────────────────────────────
	sb.WriteString(m.renderTrafficStats(contentWidth))
	sb.WriteString("\n")

	// ── Sparkline Throughput ─────────────────────────────────────
	if m.collector != nil {
		sb.WriteString(m.renderThroughputGraphs(contentWidth))
		sb.WriteString("\n")
	}

	// ── Footer ──────────────────────────────────────────────────
	sb.WriteString(m.renderFooter())

	return sb.String()
}

func (m DashboardModel) renderHeader(width int) string {
	state := styleUp.Render("● ACTIVE")
	if m.bridge == nil {
		state = styleDim.Render("○ CONNECTING")
	}

	uptime := ""
	if m.hasStats {
		uptime = styleDim.Render("uptime " + stats.HumanizeDuration(m.latestStats.Uptime))
	}

	bridgeName := ""
	if m.bridge != nil {
		bridgeName = styleDim.Render("(" + m.bridge.Name() + ")")
	}

	left := "  " + state + "  " + bridgeName
	right := uptime + "  "

	gap := width - lipgloss.Width(left) - lipgloss.Width(right) - 4
	if gap < 1 {
		gap = 1
	}

	return left + strings.Repeat(" ", gap) + right
}

func (m DashboardModel) renderError() string {
	var sb strings.Builder
	sb.WriteString("\n")
	sb.WriteString(styleError.Render("  ✗ Bridge creation failed:") + "\n\n")
	sb.WriteString(styleError.Render("    "+m.err.Error()) + "\n\n")
	sb.WriteString(styleDim.Render("  Possible causes:") + "\n")
	sb.WriteString(styleDim.Render("  • Not running as root (try: sudo golan)") + "\n")
	sb.WriteString(styleDim.Render("  • Interfaces managed by System Settings") + "\n")
	sb.WriteString(styleDim.Render("  • Another bridge already exists (try: golan --cleanup)") + "\n\n")
	sb.WriteString(keyHint("q", "quit"))
	return sb.String()
}

func (m DashboardModel) renderBridgeDiagram(contentWidth int) string {
	macA := m.ifaceA.CurrentMAC
	if macA == "" {
		macA = "N/A"
	}
	macB := m.ifaceB.CurrentMAC
	if macB == "" {
		macB = "N/A"
	}

	cardWidth := 30

	// Left card = Device (orange).
	cardA := styleIfaceCardDevice.Width(cardWidth).Render(
		styleIfaceNameDevice.Render("● "+m.ifaceA.Name) + "\n" +
			styleDim.Render("Device Port") + "\n" +
			styleDim.Render("MAC: "+macA) + "\n" +
			styleDim.Render(fmt.Sprintf("MTU: %d", m.ifaceA.MTU)),
	)

	// Right card = Switch (magenta).
	cardB := styleIfaceCardSwitch.Width(cardWidth).Render(
		styleIfaceNameSwitch.Render("● "+m.ifaceB.Name) + "\n" +
			styleDim.Render("Switch Port") + "\n" +
			styleDim.Render("MAC: "+macB) + "\n" +
			styleDim.Render(fmt.Sprintf("MTU: %d", m.ifaceB.MTU)),
	)

	// Middle Man box — always green (it always exists as the passthrough).
	middleManBox := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(colorGreen).
		Foreground(colorGreen).
		Bold(true).
		Padding(1, 2).
		Render("Middle Man")

	// Connection wires — green if bridge is active, red if not.
	wireActive := m.bridge != nil && m.bridge.State() == bridge.BridgeStateUp
	wireStyle := lipgloss.NewStyle().Foreground(colorRed).Bold(true)
	if wireActive {
		wireStyle = lipgloss.NewStyle().Foreground(colorGreen).Bold(true)
	}

	wire := wireStyle.Render(" ══════ ")

	diagram := lipgloss.JoinHorizontal(
		lipgloss.Center,
		cardA,
		wire,
		middleManBox,
		wire,
		cardB,
	)

	return lipgloss.NewStyle().MarginLeft(2).Render(diagram)
}

func (m DashboardModel) renderTrafficStats(width int) string {
	var s stats.StatsUpdate
	if m.hasStats {
		s = m.latestStats
	}

	renderIface := func(label string, d stats.InterfaceDelta, nameStyle lipgloss.Style) string {
		var sb strings.Builder
		sb.WriteString(nameStyle.Render(label) + "\n\n")
		sb.WriteString(renderKeyValue("RX Total", stats.HumanizeBytes(d.Stats.RxBytes)) + "\n")
		sb.WriteString(renderKeyValue("TX Total", stats.HumanizeBytes(d.Stats.TxBytes)) + "\n")
		sb.WriteString(renderKeyValue("RX Rate", stats.HumanizeThroughput(d.RxBytesPerSec)) + "\n")
		sb.WriteString(renderKeyValue("TX Rate", stats.HumanizeThroughput(d.TxBytesPerSec)) + "\n")
		sb.WriteString(renderKeyValue("RX Packets", humanizePacketRate(d.RxPktPerSec)) + "\n")
		sb.WriteString(renderKeyValue("TX Packets", humanizePacketRate(d.TxPktPerSec)) + "\n")
		sb.WriteString(renderKeyValue("Errors", fmt.Sprintf("RX:%d TX:%d", d.Stats.RxErrors, d.Stats.TxErrors)) + "\n")
		return sb.String()
	}

	// Device (orange) on left, Switch (magenta) on right.
	statsA := renderIface(
		"▎ "+m.ifaceA.Name+" (Device)",
		s.IfaceA,
		styleIfaceNameDevice,
	)

	statsB := renderIface(
		"▎ "+m.ifaceB.Name+" (Switch)",
		s.IfaceB,
		styleIfaceNameSwitch,
	)

	cardWidth := (width - 10) / 2
	if cardWidth < 34 {
		cardWidth = 34
	}

	boxA := styleStatsBox.Width(cardWidth).Render(statsA)
	boxB := styleStatsBox.Width(cardWidth).Render(statsB)

	boxes := lipgloss.JoinHorizontal(
		lipgloss.Top,
		boxA,
		lipgloss.NewStyle().MarginLeft(2).Render(boxB),
	)

	section := "  " + styleLabel.Render("Traffic Statistics") + "\n" +
		lipgloss.NewStyle().MarginLeft(2).Render(boxes)

	return section
}

func (m DashboardModel) renderThroughputGraphs(width int) string {
	sparkWidth := (width - 16) / 2
	if sparkWidth < 20 {
		sparkWidth = 20
	}
	if sparkWidth > 60 {
		sparkWidth = 60
	}

	histARx := m.collector.History(m.ifaceA.Name + "_rx")
	histATx := m.collector.History(m.ifaceA.Name + "_tx")
	histBRx := m.collector.History(m.ifaceB.Name + "_rx")
	histBTx := m.collector.History(m.ifaceB.Name + "_tx")

	renderSpark := func(label string, rxHist, txHist []float64, style lipgloss.Style) string {
		var sb strings.Builder
		sb.WriteString(styleDim.Render("  "+label) + "\n")
		sb.WriteString(styleDim.Render("  RX ") + renderSparkline(rxHist, sparkWidth, style) + "\n")
		sb.WriteString(styleDim.Render("  TX ") + renderSparkline(txHist, sparkWidth, style) + "\n")
		return sb.String()
	}

	graphA := renderSpark(m.ifaceA.Name+" (Device)", histARx, histATx, styleSparkDevice)
	graphB := renderSpark(m.ifaceB.Name+" (Switch)", histBRx, histBTx, styleSparkSwitch)

	return "  " + styleLabel.Render("Throughput") + "\n" + graphA + graphB
}

func (m DashboardModel) renderFooter() string {
	parts := []string{
		keyHint("Esc", "back"),
		keyHint("q", "quit & teardown"),
	}
	return styleFooter.Width(m.width - 4).Render("  " + strings.Join(parts, "   "))
}
