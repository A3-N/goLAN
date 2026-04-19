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
		bState := bridge.BridgeStateDown
		if m.bridge != nil {
			bState = m.bridge.State()
		}

		switch msg.String() {
		case "up", "k":
			m.logScroll++
		case "down", "j":
			m.logScroll--

		// Continue from paused state.
		case "c", "C":
			if m.bridge != nil && bState == bridge.BridgeStatePaused {
				m.bridge.Continue()
			}

		// Action modes — only available when bridge is Ready.
		case "a", "A":
			if m.bridge != nil && bState == bridge.BridgeStateReady && m.bridge.GatewayKnown() {
				logFunc := m.bridgeLogFunc()
				go m.bridge.RunAutoMode(logFunc)
			}
		case "e", "E", "l", "L":
			if m.bridge != nil && (bState == bridge.BridgeStateReady || bState == bridge.BridgeStateEAPOLListening) {
				logFunc := m.bridgeLogFunc()
				go m.bridge.RunListenEAPOL(logFunc)
			}
		case "r", "R":
			if m.bridge != nil && (bState == bridge.BridgeStateReady || bState == bridge.BridgeStateEAPOLDetected) {
				logFunc := m.bridgeLogFunc()
				go m.bridge.RunEAPOLRelay(logFunc)
			}
		case "n", "N":
			if m.bridge != nil && (bState == bridge.BridgeStateReady || bState == bridge.BridgeStateEAPOLAuthenticated) && m.bridge.GatewayKnown() {
				logFunc := m.bridgeLogFunc()
				go m.bridge.RunNATProxy(logFunc)
			}
		case "s", "S":
			if m.bridge != nil && bState == bridge.BridgeStateReady {
				logFunc := m.bridgeLogFunc()
				go m.bridge.RunInjectEAPOL(logFunc)
			}

		// Toggle: MACsec Downgrade
		case "m", "M":
			if m.bridge != nil {
				current := m.bridge.MACsecDowngrade()
				m.bridge.SetMACsecDowngrade(!current)
			}
		}

		maxVis := m.reconMaxVis()
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

	// ── Two-Column Layout: Left (Traffic + Throughput) | Right (Recon) ──
	sb.WriteString(m.renderMainContent(contentWidth))
	sb.WriteString("\n")

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

	// Derive status for the header based on bridge state.
	bridgeUp := bState == bridge.BridgeStateUp ||
		bState == bridge.BridgeStateStealthActive ||
		bState == bridge.BridgeStateEAPOLAuthenticated ||
		bState == bridge.BridgeStateEAPOLRelaying

	mediaDisrupt := m.hasStats &&
		(!m.latestStats.IfaceA.Stats.MediaActive || !m.latestStats.IfaceB.Stats.MediaActive)

	switch {
	case bState == bridge.BridgeStatePaused:
		stateStr = styleError.Render("⚠ PAUSED")
	case bState == bridge.BridgeStateReady:
		stateStr = lipgloss.NewStyle().Foreground(colorReady).Bold(true).Render("◉ READY")
	case bridgeUp && mediaDisrupt:
		stateStr = styleError.Render("⚠ DISRUPT")
	case bridgeUp:
		stateStr = styleUp.Render("● ACTIVE")
	default:
		stateStr = styleWarning.Render("○ STOPPED")
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

	// Build the middle card FIRST so we can match its height.
	middleContent := lipgloss.NewStyle().Foreground(colorGreen).Bold(true).Render("● goLAN Engine") + "\n" +
		styleDim.Render("Middle Man Proxy") + "\n"
	
	bState := bridge.BridgeStateDown
	if m.bridge != nil {
		bState = m.bridge.State()
	}

	if m.bridge != nil {
		switch bState {
		case bridge.BridgeStatePaused:
			middleContent += lipgloss.NewStyle().Foreground(colorRed).Bold(true).Render("⚠ PAUSED") + "\n" +
				styleDim.Render("Press [C] to continue")
		case bridge.BridgeStateReady:
			middleContent += lipgloss.NewStyle().Foreground(colorReady).Bold(true).Render("Ready") + "\n" +
				styleDim.Render("Awaiting action...")
		case bridge.BridgeStateStealthActive:
			middleContent += styleDim.Render("Bridged (Spoofed)") + "\n" +
				lipgloss.NewStyle().Foreground(colorGreen).Render("NAT Masqueraded")
		case bridge.BridgeStateSniffing:
			middleContent += lipgloss.NewStyle().Foreground(colorYellow).Render("Reconnaissance...") + "\n" +
				styleDim.Render("Air-gapped (Secure)")
		case bridge.BridgeStateEAPOLDetected:
			middleContent += lipgloss.NewStyle().Foreground(color802dot1X).Bold(true).Render("802.1X Detected") + "\n" +
				styleDim.Render("EAPOL Relay Pending")
		case bridge.BridgeStateEAPOLRelaying:
			status := m.bridge.Status()
			methodStr := "Negotiating..."
			if status.EAPMethod != "" && status.EAPMethod != "Unknown" {
				methodStr = status.EAPMethod
			}
			middleContent += lipgloss.NewStyle().Foreground(color802dot1X).Bold(true).Render("EAPOL Relay Active") + "\n" +
				styleDim.Render("Method: "+methodStr)
		case bridge.BridgeStateEAPOLAuthenticated:
			status := m.bridge.Status()
			middleContent += lipgloss.NewStyle().Foreground(colorGreen).Bold(true).Render("802.1X Authenticated") + "\n" +
				styleDim.Render("Method: "+status.EAPMethod)
		case bridge.BridgeStateEAPOLFailed:
			middleContent += lipgloss.NewStyle().Foreground(colorRed).Bold(true).Render("802.1X FAILED") + "\n" +
				styleDim.Render("Auth Rejected")
		case bridge.BridgeStateDowngrading:
			middleContent += lipgloss.NewStyle().Foreground(colorYellow).Bold(true).Render("MACsec Downgrade") + "\n" +
				styleDim.Render("Stripping MKA...")
		default:
			middleContent += styleDim.Render("Transparent") + "\n" +
				styleDim.Render("L2 Passthrough")
		}
	} else {
		middleContent += "\n\n"
	}

	middleManBox := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(colorGreen).
		Padding(0, 1).
		Width(cardWidth).
		Render(middleContent)

	// Measure the green card height and force side cards to match.
	targetHeight := lipgloss.Height(middleManBox)

	// Left card = Device (orange).
	cardA := styleIfaceCardDevice.Width(cardWidth).Height(targetHeight - 2).Render(
		styleIfaceNameDevice.Render("● "+m.ifaceA.Name) + "\n" +
			styleDim.Render("Device Port") + "\n" +
			styleDim.Render("MAC: "+macA) + "\n" +
			styleDim.Render(fmt.Sprintf("MTU: %d", m.ifaceA.MTU)),
	)

	// Right card = Switch (magenta).
	cardB := styleIfaceCardSwitch.Width(cardWidth).Height(targetHeight - 2).Render(
		styleIfaceNameSwitch.Render("● "+m.ifaceB.Name) + "\n" +
			styleDim.Render("Switch Port") + "\n" +
			styleDim.Render("MAC: "+macB) + "\n" +
			styleDim.Render(fmt.Sprintf("MTU: %d", m.ifaceB.MTU)),
	)

	// Connection wires
	wireStr := " ═══❌═══ "
	wireColor := colorRed

	var status bridge.BridgeStatus
	if m.bridge != nil {
		status = m.bridge.Status()
	}
	isNAT := bState == bridge.BridgeStateStealthActive
	isAuth := bState == bridge.BridgeStateEAPOLAuthenticated || status.EAPOLAuthenticated

	if isNAT && isAuth {
		wireStr = " ══🌐🔑══ "
		wireColor = colorGreen
	} else if isNAT {
		wireStr = " ═══🌐═══ "
		wireColor = colorGreen
	} else if isAuth {
		wireStr = " ═══🔑═══ "
		wireColor = colorGreen
	} else if bState == bridge.BridgeStateReady || bState == bridge.BridgeStateEAPOLDetected || bState == bridge.BridgeStateEAPOLRelaying || bState == bridge.BridgeStateEAPOLListening || bState == bridge.BridgeStateUp {
		wireStr = " ═══🔗═══ "
		wireColor = colorYellow
	}

	wireStrA := wireStr
	wireStrB := wireStr
	wireStyleA := lipgloss.NewStyle().Foreground(wireColor).Bold(true)
	wireStyleB := lipgloss.NewStyle().Foreground(wireColor).Bold(true)

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

	// Center the diagram horizontally within the full content width.
	return lipgloss.Place(contentWidth, lipgloss.Height(diagram), lipgloss.Center, lipgloss.Top, diagram)
}

// reconMaxVis computes the maximum visible recon log lines based on terminal height.
func (m DashboardModel) reconMaxVis() int {
	// Estimate overhead: header(2) + diagram(8) + footer(3) + margins(3) = ~16 lines
	maxVis := m.height - 16
	if maxVis < 6 {
		maxVis = 6
	}
	return maxVis
}

// renderMainContent renders the two-column layout below the bridge diagram:
// Left column = Traffic Statistics + Throughput sparklines
// Right column = Reconnaissance Log (fills the full height)
func (m DashboardModel) renderMainContent(width int) string {
	leftWidth := (width - 6) / 3
	if leftWidth < 38 {
		leftWidth = 38
	}
	rightWidth := width - leftWidth - 6
	if rightWidth < 38 {
		rightWidth = 38
	}

	// ── Left Column: Traffic Stats + Throughput Sparklines ──────
	leftColumn := m.renderLeftColumn(leftWidth)

	// ── Right Column: Reconnaissance Log ────────────────────────
	leftHeight := lipgloss.Height(leftColumn)
	rightColumn := m.renderReconPanel(rightWidth, leftHeight)

	return lipgloss.NewStyle().MarginLeft(2).Render(
		lipgloss.JoinHorizontal(lipgloss.Top, leftColumn, "  ", rightColumn),
	)
}

// renderLeftColumn renders Traffic Statistics (stacked) and Throughput sparklines.
func (m DashboardModel) renderLeftColumn(width int) string {
	var sb strings.Builder

	// Traffic Statistics.
	sb.WriteString(m.renderTrafficStats(width))
	sb.WriteString("\n")

	// Throughput sparklines.
	if m.collector != nil {
		sb.WriteString(m.renderThroughput(width))
	}

	return sb.String()
}

func (m DashboardModel) renderTrafficStats(width int) string {
	var s stats.StatsUpdate
	if m.hasStats {
		s = m.latestStats
	}

	renderIface := func(label string, d stats.InterfaceDelta, nameStyle lipgloss.Style) string {
		var sb strings.Builder
		sb.WriteString(nameStyle.Render(label) + "\n")
		sb.WriteString(renderKeyValue("Total",
			styleUp.Render("▼")+styleVal.Render(" "+stats.HumanizeBytes(d.Stats.RxBytes))+"  "+
				styleKey.Render("▲")+styleVal.Render(" "+stats.HumanizeBytes(d.Stats.TxBytes))) + "\n")
		sb.WriteString(renderKeyValue("Rate",
			styleUp.Render("▼")+styleVal.Render(" "+stats.HumanizeThroughput(d.RxBytesPerSec))+"  "+
				styleKey.Render("▲")+styleVal.Render(" "+stats.HumanizeThroughput(d.TxBytesPerSec))) + "\n")
		sb.WriteString(renderKeyValue("Packets",
			styleUp.Render("▼")+styleVal.Render(" "+humanizePacketRate(d.RxPktPerSec))+"  "+
				styleKey.Render("▲")+styleVal.Render(" "+humanizePacketRate(d.TxPktPerSec))) + "\n")
		sb.WriteString(renderKeyValue("Errors", fmt.Sprintf("RX:%d TX:%d", d.Stats.RxErrors, d.Stats.TxErrors)) + "\n")
		return sb.String()
	}

	// Device (orange) on top, Switch (magenta) below — stacked vertically.
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

	cardWidth := width - 4
	if cardWidth < 30 {
		cardWidth = 30
	}

	boxA := styleStatsBox.Width(cardWidth).Render(statsA)
	boxB := styleStatsBox.Width(cardWidth).Render(statsB)

	return boxA + "\n" + boxB
}

// renderThroughput renders sparkline graphs for both interfaces.
func (m DashboardModel) renderThroughput(width int) string {
	sparkWidth := width - 8
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

	return graphA + "\n" + graphB
}

// renderReconPanel renders the Reconnaissance Log panel for the right column.
// targetHeight is the left column height so the panel stretches to match.
func (m DashboardModel) renderReconPanel(width int, targetHeight int) string {
	if m.bridge == nil {
		return ""
	}

	status := m.bridge.Status()
	// Only render if we have logs or are actively sniffing.
	if len(status.ReconLogs) == 0 && status.State != bridge.BridgeStateSniffing && status.State != bridge.BridgeStateStealthActive {
		return ""
	}

	var sb strings.Builder
	sb.WriteString(styleLabel.Render("Reconnaissance Log") + styleDim.Render("  (↑↓/jk scroll)") + "\n")

	sep := strings.Repeat("─", width-4)
	sb.WriteString(lipgloss.NewStyle().Foreground(colorBorder).Render(sep) + "\n")

	logs := []string{"[*] Waiting for sniffer to initialize..."}
	if len(status.ReconLogs) > 0 {
		logs = status.ReconLogs
	}

	// Dynamic maxVis — fill the available height (minus header/sep/border).
	maxVis := targetHeight - 6
	if maxVis < 6 {
		maxVis = 6
	}

	logsLen := len(logs)
	start := logsLen - maxVis - m.logScroll
	if start < 0 {
		start = 0
	}
	end := start + maxVis
	if end > logsLen {
		end = logsLen
	}

	for _, log := range logs[start:end] {
		sb.WriteString(formatLogLine(log) + "\n")
	}

	// Wrap in a bordered box that stretches to the target height.
	content := sb.String()
	panelHeight := targetHeight - 2
	if panelHeight < 8 {
		panelHeight = 8
	}

	return lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(colorBorder).
		Padding(0, 1).
		Width(width).
		Height(panelHeight).
		Render(content)
}

var (
	colorBulletBlue  = lipgloss.NewStyle().Foreground(lipgloss.Color("39")).Bold(true)
	colorBulletGreen = lipgloss.NewStyle().Foreground(lipgloss.Color("42")).Bold(true)
	colorBulletRed   = lipgloss.NewStyle().Foreground(lipgloss.Color("196")).Bold(true)
	colorBulletPurple = lipgloss.NewStyle().Foreground(color802dot1X).Bold(true)
	colorGray        = lipgloss.NewStyle().Foreground(lipgloss.Color("241"))
	
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

	if strings.HasPrefix(line, "[+][802.1X]") {
		return colorBulletGreen.Render("[+]") + colorBulletPurple.Render("[802.1X]") + colorGray.Render(line[11:])
	} else if strings.HasPrefix(line, "[!][802.1X]") {
		return colorBulletRed.Render("[!]") + colorBulletPurple.Render("[802.1X]") + colorGray.Render(line[11:])
	} else if strings.HasPrefix(line, "[+][MACSEC]") {
		return colorBulletGreen.Render("[+]") + colorBulletPurple.Render("[MACSEC]") + colorGray.Render(line[11:])
	} else if strings.HasPrefix(line, "[!][MACSEC]") {
		return colorBulletRed.Render("[!]") + colorBulletPurple.Render("[MACSEC]") + colorGray.Render(line[11:])
	} else if strings.HasPrefix(line, "[+][RELAY]") {
		return colorBulletGreen.Render("[+]") + colorBulletPurple.Render("[RELAY]") + colorGray.Render(line[10:])
	} else if strings.HasPrefix(line, "[!][RELAY]") {
		return colorBulletRed.Render("[!]") + colorBulletPurple.Render("[RELAY]") + colorGray.Render(line[10:])
	} else if strings.HasPrefix(line, "[*]") {
		return colorBulletBlue.Render("[*]") + colorGray.Render(line[3:])
	} else if strings.HasPrefix(line, "[+]") {
		return colorBulletGreen.Render("[+]") + colorGray.Render(line[3:])
	} else if strings.HasPrefix(line, "[!]") {
		return colorBulletRed.Render("[!]") + colorGray.Render(line[3:])
	} else if strings.HasPrefix(line, "[802.1X]") {
		return colorBulletPurple.Render("[802.1X]") + colorGray.Render(line[8:])
	} else if strings.HasPrefix(line, "[RELAY]") {
		return colorBulletPurple.Render("[RELAY]") + colorGray.Render(line[7:])
	} else if strings.HasPrefix(line, "[MACSEC]") {
		return colorBulletPurple.Render("[MACSEC]") + colorGray.Render(line[8:])
	} else if strings.HasPrefix(line, "    ") {
		return "    " + colorGray.Render(line[4:])
	}
	return colorBulletBlue.Render("[*]") + colorGray.Render(" " + line)
}

func (m DashboardModel) renderFooter() string {
	bState := bridge.BridgeStateDown
	if m.bridge != nil {
		bState = m.bridge.State()
	}

	// Helper: pick active/disabled based on condition.
	hint := func(enabled bool, key, desc string) string {
		if enabled {
			return keyHint(key, desc)
		}
		return keyHintDisabled(key, desc)
	}

	// Determine which actions are available in the current state.
	ready := bState == bridge.BridgeStateReady
	listening := bState == bridge.BridgeStateEAPOLListening
	eapolDetected := bState == bridge.BridgeStateEAPOLDetected
	authenticated := bState == bridge.BridgeStateEAPOLAuthenticated

	// Toggle values.
	macsecStr := "DWNGRD"
	if m.bridge != nil && !m.bridge.MACsecDowngrade() {
		macsecStr = "IGNORE"
	}

	hasBridge := m.bridge != nil
	gatewayKnown := hasBridge && m.bridge.GatewayKnown()

	// Navigation first (left side), then actions (right side).
	parts := []string{
		keyHint("Esc", "back"),
		keyHint("q", "quit"),
	}

	// Action shortcuts — always visible, greyed when unavailable.
	parts = append(parts,
		hint(ready && gatewayKnown, "A", "auto"),
		hint(ready || listening, "E", "802.1X listen"),
		hint(ready, "S", "802.1X send"),
		hint(ready || eapolDetected, "R", "relay"),
		hint((ready || authenticated) && gatewayKnown, "N", "NAT proxy"),
		hint(hasBridge, "M", "MACsec:"+macsecStr),
	)

	return styleFooter.Width(m.width - 4).Render("  " + strings.Join(parts, "   "))
}

// bridgeLogFunc returns a log function that appends to the bridge's recon logs.
func (m DashboardModel) bridgeLogFunc() func(string) {
	return func(msg string) {
		if m.bridge != nil {
			m.bridge.AppendLog(msg)
		}
	}
}
