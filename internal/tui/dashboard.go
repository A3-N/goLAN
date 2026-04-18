package tui

import (
	"context"
	"fmt"
	"regexp"
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
	logScroll int
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

func (m DashboardModel) createBridgeCmd(ifA, ifB string, ignoreMAC string) tea.Cmd {
	return func() tea.Msg {
		br, err := bridge.NewBridge(ifA, ifB, ignoreMAC)
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
	// Lock down both interfaces explicitly before initiating bridge creation
	// to prevent OS leaks to the physical wire. This happens synchronously
	// in the TUI thread.
	_ = bridge.LockdownInterface(m.ifaceA.Name, m.ifaceA.HardwarePort)
	_ = bridge.LockdownInterface(m.ifaceB.Name, m.ifaceB.HardwarePort)

	return m.createBridgeCmd(m.ifaceA.Name, m.ifaceB.Name, m.ifaceA.CurrentMAC)
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
		switch msg.String() {
		case "up", "k":
			m.logScroll++
		case "down", "j":
			m.logScroll--
		}
		
		maxVis := 6
		logsLen := 0
		if m.bridge != nil {
			logsLen = len(m.bridge.Status().ReconLogs)
		}
		
		if m.logScroll > logsLen - maxVis {
			if logsLen > maxVis {
				m.logScroll = logsLen - maxVis
			} else {
				m.logScroll = 0
			}
		}
		if m.logScroll < 0 {
			m.logScroll = 0
		}
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

	// ── Sparkline Throughput & Recon Logs ────────────────────────
	if m.collector != nil {
		sb.WriteString(m.renderBottomSection(contentWidth))
		sb.WriteString("\n")
	}

	// ── Footer ──────────────────────────────────────────────────
	sb.WriteString(m.renderFooter())

	return sb.String()
}



func (m DashboardModel) renderHeader(width int) string {
	var stateStr string
	bState := bridge.BridgeStateDown
	if m.bridge != nil {
		bState = m.bridge.State()
	}

	switch bState {
	case bridge.BridgeStateUp:
		stateStr = styleUp.Render("● ACTIVE")
	case bridge.BridgeStateSniffing:
		stateStr = styleWarning.Render("○ RECONNAISSANCE: Sniffing Target Identity...")
	case bridge.BridgeStateStealthActive:
		stateStr = styleUp.Render("● STEALTH ACTIVE")
	default:
		stateStr = styleDim.Render("○ CONNECTING")
	}

	state := stateStr

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

	middleContent := lipgloss.NewStyle().Foreground(colorGreen).Bold(true).Render("● goLAN Engine") + "\n" +
		styleDim.Render("Middle Man Proxy") + "\n"
	
	bState := bridge.BridgeStateDown
	if m.bridge != nil {
		bState = m.bridge.State()
	}

	if m.bridge != nil {
		if bState == bridge.BridgeStateStealthActive {
			middleContent += styleDim.Render("Bridged (Spoofed)") + "\n" +
				lipgloss.NewStyle().Foreground(colorGreen).Render("NAT Masqueraded")
		} else if bState == bridge.BridgeStateSniffing {
			middleContent += lipgloss.NewStyle().Foreground(colorYellow).Render("Reconnaissance...") + "\n" +
				styleDim.Render("Air-gapped (Secure)")
		} else {
			middleContent += styleDim.Render("Transparent") + "\n" +
				styleDim.Render("L2 Passthrough")
		}
	} else {
		middleContent += "\n\n"
	}

	// Make the middle man box exactly the same layout structure as the outer cards.
	middleManBox := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(colorGreen).
		Padding(0, 1).
		Width(cardWidth).
		Render(middleContent)

	// Connection wires — green if bridge is active, red sequence if not.
	wireActive := bState == bridge.BridgeStateUp || bState == bridge.BridgeStateStealthActive
	
	wireStrA := " ═══❌═══ "
	wireStrB := " ═══❌═══ "
	wireStyleA := lipgloss.NewStyle().Foreground(colorRed).Bold(true)
	wireStyleB := lipgloss.NewStyle().Foreground(colorRed).Bold(true)
	
	if wireActive {
		wireStrA = " ════════ "
		wireStrB = " ════════ "
		wireStyleA = lipgloss.NewStyle().Foreground(colorGreen).Bold(true)
		wireStyleB = lipgloss.NewStyle().Foreground(colorGreen).Bold(true)
	}

	// Physical overrides: If media is physically inactive (cable unplugged), force the X.
	if m.hasStats {
		if !m.latestStats.IfaceA.Stats.MediaActive {
			wireStrA = " ═══❌═══ "
			wireStyleA = lipgloss.NewStyle().Foreground(colorRed).Bold(true)
		}
		if !m.latestStats.IfaceB.Stats.MediaActive {
			wireStrB = " ═══❌═══ "
			wireStyleB = lipgloss.NewStyle().Foreground(colorRed).Bold(true)
		}
	}

	wireA := wireStyleA.Render(wireStrA)
	wireB := wireStyleB.Render(wireStrB)

	diagram := lipgloss.JoinHorizontal(
		lipgloss.Center,
		cardA,
		wireA,
		middleManBox,
		wireB,
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

func (m DashboardModel) renderBottomSection(width int) string {
	sparkWidth := (width - 20) / 3
	if sparkWidth < 20 {
		sparkWidth = 20
	}
	if sparkWidth > 50 {
		sparkWidth = 50
	}

	histARx := m.collector.History(m.ifaceA.Name + "_rx")
	histATx := m.collector.History(m.ifaceA.Name + "_tx")
	histBRx := m.collector.History(m.ifaceB.Name + "_rx")
	histBTx := m.collector.History(m.ifaceB.Name + "_tx")

	renderSpark := func(label string, rxHist, txHist []float64, style lipgloss.Style) string {
		var sb strings.Builder
		sb.WriteString(styleLabel.Render(label) + "\n")
		sb.WriteString(styleDim.Render("RX ") + renderSparkline(rxHist, sparkWidth, style) + "\n")
		sb.WriteString(styleDim.Render("TX ") + renderSparkline(txHist, sparkWidth, style) + "\n")
		return sb.String()
	}

	graphA := renderSpark(m.ifaceA.Name+" (Device)", histARx, histATx, styleSparkDevice)
	graphB := renderSpark(m.ifaceB.Name+" (Switch)", histBRx, histBTx, styleSparkSwitch)
	graphs := graphA + "\n" + graphB

	// ── Recon Logs ──────────────────────────────────────────────────
	var logsPanel string
	if m.bridge != nil {
		status := m.bridge.Status()
		// Only render logs if we have them, or if we are actively sniffing
		if len(status.ReconLogs) > 0 || status.State == bridge.BridgeStateSniffing || status.State == bridge.BridgeStateStealthActive {
			var sb strings.Builder
			sb.WriteString(styleLabel.Render("Reconnaissance Log") + styleDim.Render("  (Use Up/Down or J/K to scroll)") + "\n")
			logs := []string{"[*] Waiting for sniffer to initialize..."}
			if len(status.ReconLogs) > 0 {
				logs = status.ReconLogs
			}
			
			maxVis := 6
			logsLen := len(logs)
			
			start := logsLen - maxVis - m.logScroll
			if start < 0 { start = 0 }
			end := start + maxVis
			if end > logsLen { end = logsLen }
			
			for _, log := range logs[start:end] {
				sb.WriteString(formatLogLine(log) + "\n")
			}
			// Wrap in a fixed-height container so the UI never physically jumps
			logsPanel = lipgloss.NewStyle().Height(10).Render(sb.String())
		}
	}

	// Join both columns horizontally
	columns := lipgloss.JoinHorizontal(
		lipgloss.Top,
		lipgloss.NewStyle().Width(sparkWidth + 10).Render(graphs),
		lipgloss.NewStyle().MarginLeft(4).Render(logsPanel),
	)

	return "  " + styleLabel.Render("Throughput & Identity") + "\n" +
		lipgloss.NewStyle().MarginLeft(2).Render(columns)
}

var (
	colorBulletBlue  = lipgloss.NewStyle().Foreground(lipgloss.Color("39")).Bold(true)
	colorBulletGreen = lipgloss.NewStyle().Foreground(lipgloss.Color("42")).Bold(true)
	colorBulletRed   = lipgloss.NewStyle().Foreground(lipgloss.Color("196")).Bold(true)
	colorGray        = lipgloss.NewStyle().Foreground(lipgloss.Color("241"))
	colorBoldWhite   = lipgloss.NewStyle().Foreground(lipgloss.Color("255")).Bold(true)
	
	macRegex = regexp.MustCompile(`(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}`)
	ipRegex  = regexp.MustCompile(`\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b`)
)

func formatLogLine(line string) string {
	line = macRegex.ReplaceAllStringFunc(line, func(m string) string {
		return "\x1b[0m\x1b[1;38;5;255m" + m + "\x1b[0m\x1b[38;5;241m"
	})
	line = ipRegex.ReplaceAllStringFunc(line, func(m string) string {
		return "\x1b[0m\x1b[1;38;5;255m" + m + "\x1b[0m\x1b[38;5;241m"
	})

	if strings.HasPrefix(line, "[*]") {
		return colorBulletBlue.Render("[*]") + colorGray.Render(line[3:])
	} else if strings.HasPrefix(line, "[+]") {
		return colorBulletGreen.Render("[+]") + colorGray.Render(line[3:])
	} else if strings.HasPrefix(line, "[!]") {
		return colorBulletRed.Render("[!]") + colorGray.Render(line[3:])
	} else if strings.HasPrefix(line, "    ") {
		return "    " + colorGray.Render(line[4:])
	}
	return colorGray.Render("• " + line)
}

func (m DashboardModel) renderFooter() string {
	parts := []string{
		keyHint("Esc", "back"),
		keyHint("q", "quit & teardown"),
	}
	return styleFooter.Width(m.width - 4).Render("  " + strings.Join(parts, "   "))
}
