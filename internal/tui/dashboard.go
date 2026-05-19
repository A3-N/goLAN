package tui

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"
	"github.com/mcrn/goLAN/internal/bridge"
	"github.com/mcrn/goLAN/internal/stats"
	"github.com/mcrn/goLAN/internal/stealth"

	tea "github.com/charmbracelet/bubbletea"
)

type dashboardPage int

const (
	pageOverview dashboardPage = iota
	pageAuthMap
)

// DashboardModel is the main bridge monitoring dashboard.
type DashboardModel struct {
	bridge    *bridge.Bridge
	collector *stats.Collector
	cancel    context.CancelFunc
	statsCh   <-chan stats.StatsUpdate

	ifaceA   bridge.NetInterface // Device port (from selector LAN 1)
	ifaceB   bridge.NetInterface // Switch port (from selector LAN 2)
	restoreA bridge.InterfaceRestoreState
	restoreB bridge.InterfaceRestoreState

	latestStats stats.StatsUpdate
	hasStats    bool

	width     int
	height    int
	err       error
	logScroll int
	page      dashboardPage
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
		ifaceA:   ifA, // Device port
		ifaceB:   ifB, // Switch port
		restoreA: bridge.CaptureInterfaceRestoreState(ifA.Name, ifA.HardwarePort),
		restoreB: bridge.CaptureInterfaceRestoreState(ifB.Name, ifB.HardwarePort),
	}
}

func (m DashboardModel) createBridgeCmd(ifA, ifB string, ignoreMAC string) tea.Cmd {
	return func() tea.Msg {
		br, err := bridge.NewBridge(ifA, ifB, ignoreMAC,
			m.ifaceA.CurrentMAC,
			m.ifaceA.PermanentMAC,
			m.ifaceB.CurrentMAC,
			m.ifaceB.PermanentMAC,
		)
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
	// in the TUI thread. Errors are non-fatal but logged for debugging.
	if err := bridge.LockdownInterface(m.ifaceA.Name, m.ifaceA.HardwarePort); err != nil {
		fmt.Fprintf(os.Stderr, "[lockdown] %s: %v\n", m.ifaceA.Name, err)
	}
	if err := bridge.LockdownInterface(m.ifaceB.Name, m.ifaceB.HardwarePort); err != nil {
		fmt.Fprintf(os.Stderr, "[lockdown] %s: %v\n", m.ifaceB.Name, err)
	}

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
		case "tab":
			if m.page == pageOverview {
				m.page = pageAuthMap
			} else {
				m.page = pageOverview
			}
		case "1":
			m.page = pageOverview
		case "2":
			m.page = pageAuthMap

		case "up", "k":
			m.logScroll++
		case "down", "j":
			m.logScroll--

		// Continue from paused state.
		case "c", "C":
			if m.bridge != nil && bState == bridge.BridgeStatePaused {
				m.bridge.Continue()
			}

		// Optional action modes for the active Layer 2 bridge.
		case "e", "E", "l", "L":
			if m.bridge != nil && (bState == bridge.BridgeStateReady || bState == bridge.BridgeStateEAPOLListening) {
				logFunc := m.bridgeLogFunc()
				go m.bridge.RunListenEAPOL(logFunc)
			}
		case "r", "R":
			if m.bridge != nil {
				if bState == bridge.BridgeStateEAPOLRelaying || bState == bridge.BridgeStateEAPOLAuthenticated {
					logFunc := m.bridgeLogFunc()
					go m.bridge.StopEAPOLRelay(logFunc)
				} else if bState == bridge.BridgeStateReady || bState == bridge.BridgeStateEAPOLDetected {
					logFunc := m.bridgeLogFunc()
					go m.bridge.RunEAPOLRelay(logFunc)
				}
			}
		case "n", "N":
			if m.bridge != nil {
				// If NAT is already active, hitting N acts as Disable (toggle off).
				if m.bridge.IsNATActive() {
					logFunc := m.bridgeLogFunc()
					go m.bridge.DisableNATProxy(logFunc)
				} else if (bState == bridge.BridgeStateReady ||
					bState == bridge.BridgeStateEAPOLDetected ||
					bState == bridge.BridgeStateEAPOLListening ||
					bState == bridge.BridgeStateEAPOLRelaying ||
					bState == bridge.BridgeStateEAPOLAuthenticated) && m.bridge.GatewayKnown() {
					// Otherwise, if conditions permit, spin NAT up.
					logFunc := m.bridgeLogFunc()
					go m.bridge.RunNATProxy(logFunc)
				}
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

		if m.logScroll > logsLen-maxVis {
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
	var errs []string
	runStep := func(name string, timeout time.Duration, fn func() error) {
		done := make(chan error, 1)
		go func() {
			done <- fn()
		}()
		select {
		case err := <-done:
			if err != nil {
				errs = append(errs, err.Error())
			}
		case <-time.After(timeout):
			errs = append(errs, fmt.Sprintf("%s timed out after %s", name, timeout))
		}
	}
	if m.bridge != nil {
		runStep("bridge destroy", 8*time.Second, m.bridge.Destroy)
	}
	runStep("device interface restore", 5*time.Second, func() error { return bridge.RestoreInterfaceState(m.restoreA) })
	runStep("switch interface restore", 5*time.Second, func() error { return bridge.RestoreInterfaceState(m.restoreB) })
	if len(errs) > 0 {
		return errors.New(strings.Join(errs, " | "))
	}
	return nil
}

func (m DashboardModel) View() string {
	if m.width == 0 {
		return ""
	}

	var sb strings.Builder
	contentWidth := m.width
	if contentWidth < 1 {
		contentWidth = 1
	}

	// ── Header with Status ──────────────────────────────────────
	sb.WriteString(m.renderHeader(contentWidth))
	sb.WriteString("\n")

	// ── Error State ─────────────────────────────────────────────
	if m.err != nil {
		sb.WriteString(m.renderError())
		return m.fitViewport(sb.String())
	}

	// ── Loading State ───────────────────────────────────────────
	if m.bridge == nil {
		sb.WriteString("\n")
		sb.WriteString(styleDim.Render("  ⟳ Creating bridge between " + m.ifaceA.Name + " and " + m.ifaceB.Name + "..."))
		return m.fitViewport(sb.String())
	}

	if m.page == pageAuthMap {
		sb.WriteString(m.renderAuthMapContent(contentWidth))
	} else {
		// ── Bridge Diagram ──────────────────────────────────────────
		sb.WriteString(m.renderBridgeDiagram(contentWidth))
		sb.WriteString("\n")

		// ── Two-Column Layout: Left (Traffic + Throughput) | Right (Recon) ──
		sb.WriteString(m.renderMainContent(contentWidth))
	}
	sb.WriteString("\n")

	// ── Footer ──────────────────────────────────────────────────
	sb.WriteString(m.renderFooter())

	return m.fitViewport(sb.String())
}

func (m DashboardModel) fitViewport(content string) string {
	if m.width <= 0 || m.height <= 0 {
		return content
	}
	return lipgloss.NewStyle().
		Width(m.width).
		Height(m.height).
		MaxWidth(m.width).
		MaxHeight(m.height).
		Render(content)
}

func safeWidth(width int) int {
	if width < 1 {
		return 1
	}
	return width
}

func pageContentArea(width int) (int, int) {
	margin := 0
	if width >= 50 {
		margin = 1
	}
	inner := width - margin
	if inner < 1 {
		inner = 1
		margin = 0
	}
	return inner, margin
}

func renderCard(width int, content string) string {
	w := safeWidth(width)
	return styleStatsBox.Width(w).MaxWidth(w).Render(content)
}

func (m DashboardModel) renderHeader(width int) string {
	var stateStr string
	bState := bridge.BridgeStateDown
	eapolPassthrough := false
	if m.bridge != nil {
		status := m.bridge.Status()
		bState = status.State
		eapolPassthrough = status.EAPOLPassthrough
	}

	// Derive status for the header based on bridge state.
	bridgeUp := bState == bridge.BridgeStateUp ||
		bState == bridge.BridgeStateReady ||
		bState == bridge.BridgeStateEAPOLDetected ||
		bState == bridge.BridgeStateEAPOLListening ||
		bState == bridge.BridgeStateEAPOLAuthenticated ||
		bState == bridge.BridgeStateEAPOLRelaying ||
		(m.bridge != nil && m.bridge.IsNATActive())

	mediaDisrupt := m.hasStats &&
		(!m.latestStats.IfaceA.Stats.MediaActive || !m.latestStats.IfaceB.Stats.MediaActive)

	switch {
	case bState == bridge.BridgeStatePaused:
		stateStr = styleError.Render("⚠ PAUSED")
	case bState == bridge.BridgeStateReady:
		stateStr = lipgloss.NewStyle().Foreground(colorReady).Bold(true).Render("◉ READY")
	case bridgeUp && mediaDisrupt:
		stateStr = styleError.Render("⚠ DISRUPT")
	case bState == bridge.BridgeStateEAPOLRelaying && eapolPassthrough:
		stateStr = lipgloss.NewStyle().Foreground(color802dot1X).Bold(true).Render("◉ L2+EAPOL")
	case bState == bridge.BridgeStateEAPOLRelaying:
		stateStr = lipgloss.NewStyle().Foreground(color802dot1X).Bold(true).Render("◉ RELAY")
	case bState == bridge.BridgeStateEAPOLDetected:
		stateStr = lipgloss.NewStyle().Foreground(color802dot1X).Bold(true).Render("◉ AUTH FLOW")
	case m.bridge != nil && m.bridge.IsNATActive():
		stateStr = lipgloss.NewStyle().Foreground(colorYellow).Bold(true).Render("PROXY ACTIVE")
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
	const wireToken = " ==L2= "
	wireWidth := lipgloss.Width(wireToken)
	cardWidth := (contentWidth - (wireWidth * 2)) / 3
	if cardWidth > 30 {
		cardWidth = 30
	}
	if cardWidth < 24 {
		return m.renderBridgeDiagramCompact(contentWidth)
	}

	macA := m.ifaceA.CurrentMAC
	if macA == "" {
		macA = "N/A"
	}
	macB := m.ifaceB.CurrentMAC
	if macB == "" {
		macB = "N/A"
	}

	// Build the middle card FIRST so we can match its height.
	middleContent := lipgloss.NewStyle().Foreground(colorGreen).Bold(true).Render("● goLAN Engine") + "\n" +
		styleDim.Render("Middle Man Proxy") + "\n"

	bState := bridge.BridgeStateDown
	var status bridge.BridgeStatus
	targetMAC := ""
	if m.bridge != nil {
		status = m.bridge.Status()
		bState = status.State
		if status.TargetID != nil && len(status.TargetID.MAC) > 0 {
			targetMAC = status.TargetID.MAC.String()
		}
	}

	if m.bridge != nil {
		switch bState {
		case bridge.BridgeStatePaused:
			middleContent += lipgloss.NewStyle().Foreground(colorRed).Bold(true).Render("⚠ PAUSED") + "\n" +
				styleDim.Render("Press [C] to continue")
		case bridge.BridgeStateReady:
			middleContent += lipgloss.NewStyle().Foreground(colorReady).Bold(true).Render("Ready") + "\n" +
				styleDim.Render("L2 Forwarding")
		case bridge.BridgeStateStealthActive:
			middleContent += styleDim.Render("Bridged (Spoofed)") + "\n" +
				lipgloss.NewStyle().Foreground(colorGreen).Render("NAT Masqueraded")
		case bridge.BridgeStateSniffing:
			middleContent += lipgloss.NewStyle().Foreground(colorYellow).Render("Reconnaissance...") + "\n" +
				styleDim.Render("Air-gapped (Secure)")
		case bridge.BridgeStateEAPOLDetected:
			middleContent += lipgloss.NewStyle().Foreground(color802dot1X).Bold(true).Render("802.1X Observed") + "\n" +
				styleDim.Render("L2 Forwarding")
		case bridge.BridgeStateEAPOLRelaying:
			methodStr := "Negotiating..."
			if status.EAPMethod != "" && status.EAPMethod != "Unknown" {
				methodStr = status.EAPMethod
			}
			title := "EAPOL Relay Active"
			if status.EAPOLPassthrough {
				title = "EAPOL Passthrough"
			}
			middleContent += lipgloss.NewStyle().Foreground(color802dot1X).Bold(true).Render(title) + "\n" +
				styleDim.Render("Method: "+methodStr)
		case bridge.BridgeStateEAPOLAuthenticated:
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
	deviceMACLine := "Adapter: " + macA
	if targetMAC != "" {
		deviceMACLine = "Target: " + targetMAC
	}
	cardA := styleIfaceCardDevice.Width(cardWidth).Height(targetHeight - 2).Render(
		styleIfaceNameDevice.Render("● "+m.ifaceA.Name) + "\n" +
			styleDim.Render("Device Port") + "\n" +
			styleDim.Render(trunc(deviceMACLine, cardWidth-4)) + "\n" +
			styleDim.Render(fmt.Sprintf("MTU: %d", m.ifaceA.MTU)),
	)

	// Right card = Switch (magenta).
	switchMACLine := "Adapter: " + macB
	if targetMAC != "" {
		switchMACLine = "Effective: " + targetMAC
	}
	cardB := styleIfaceCardSwitch.Width(cardWidth).Height(targetHeight - 2).Render(
		styleIfaceNameSwitch.Render("● "+m.ifaceB.Name) + "\n" +
			styleDim.Render("Switch Port") + "\n" +
			styleDim.Render(trunc(switchMACLine, cardWidth-4)) + "\n" +
			styleDim.Render(fmt.Sprintf("MTU: %d", m.ifaceB.MTU)),
	)

	// Connection wires
	wireStr := " ==X== "
	wireColor := colorRed

	isNAT := bState == bridge.BridgeStateStealthActive
	isAuth := bState == bridge.BridgeStateEAPOLAuthenticated || status.EAPOLAuthenticated

	if isNAT && isAuth {
		wireStr = " ==OK= "
		wireColor = colorGreen
	} else if isNAT {
		wireStr = " ==N== "
		wireColor = colorGreen
	} else if isAuth {
		wireStr = " ==A== "
		wireColor = colorGreen
	} else if bState == bridge.BridgeStateReady || bState == bridge.BridgeStateEAPOLDetected || bState == bridge.BridgeStateEAPOLRelaying || bState == bridge.BridgeStateEAPOLListening || bState == bridge.BridgeStateUp {
		wireStr = wireToken
		wireColor = colorYellow
	}

	wireStrA := wireStr
	wireStrB := wireStr
	wireStyleA := lipgloss.NewStyle().Foreground(wireColor).Bold(true)
	wireStyleB := lipgloss.NewStyle().Foreground(wireColor).Bold(true)

	// Physical overrides: If media is physically inactive (cable unplugged), force the X.
	if m.hasStats {
		if !m.latestStats.IfaceA.Stats.MediaActive {
			wireStrA = " ==X== "
			wireStyleA = lipgloss.NewStyle().Foreground(colorRed).Bold(true)
		}
		if !m.latestStats.IfaceB.Stats.MediaActive {
			wireStrB = " ==X== "
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

func (m DashboardModel) renderBridgeDiagramCompact(contentWidth int) string {
	width, margin := pageContentArea(contentWidth)

	state := "starting"
	targetMAC := "unknown"
	method := "unknown"
	if m.bridge != nil {
		status := m.bridge.Status()
		state = status.State.String()
		if status.EAPOLPassthrough {
			state = "EAPOL Passthrough"
		}
		if status.TargetID != nil && len(status.TargetID.MAC) > 0 {
			targetMAC = status.TargetID.MAC.String()
		}
		if status.EAPMethod != "" && status.EAPMethod != "Unknown" {
			method = status.EAPMethod
		}
	}

	var sb strings.Builder
	sb.WriteString(styleIfaceNameDevice.Render(m.ifaceA.Name+" device") + styleDim.Render(" -> ") +
		styleSuccess.Render("goLAN") + styleDim.Render(" -> ") +
		styleIfaceNameSwitch.Render(m.ifaceB.Name+" switch") + "\n")
	sb.WriteString(renderKeyValue("State", trunc(state, width-18)) + "\n")
	sb.WriteString(renderKeyValue("Target", trunc(targetMAC, width-18)) + "\n")
	if method != "unknown" {
		sb.WriteString(renderKeyValue("EAP", trunc(method, width-18)) + "\n")
	}

	return lipgloss.NewStyle().MarginLeft(margin).Width(width).MaxWidth(width).Render(
		renderCard(width, sb.String()),
	)
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
	usable, margin := pageContentArea(width)
	if usable < 90 {
		leftColumn := m.renderLeftColumn(usable)
		reconHeight := m.height - lipgloss.Height(leftColumn) - 10
		if reconHeight < 8 {
			reconHeight = 8
		}
		recon := m.renderReconPanel(usable, reconHeight)
		content := leftColumn
		if recon != "" {
			content += "\n" + recon
		}
		return lipgloss.NewStyle().MarginLeft(margin).Width(usable).MaxWidth(usable).Render(content)
	}

	gap := 2
	leftWidth := usable / 3
	rightWidth := usable - leftWidth - gap

	// ── Left Column: Traffic Stats + Throughput Sparklines ──────
	leftColumn := m.renderLeftColumn(leftWidth)

	// ── Right Column: Reconnaissance Log ────────────────────────
	leftHeight := lipgloss.Height(leftColumn)
	rightColumn := m.renderReconPanel(rightWidth, leftHeight)

	return lipgloss.NewStyle().MarginLeft(margin).Width(usable).MaxWidth(usable).Render(
		lipgloss.JoinHorizontal(lipgloss.Top, leftColumn, "  ", rightColumn),
	)
}

func (m DashboardModel) renderAuthMapContent(width int) string {
	status, snap, ok := m.authSnapshot()
	usable, margin := pageContentArea(width)
	if !ok {
		content := styleDim.Render("Passive topology map waiting for bridge observer...")
		return lipgloss.NewStyle().MarginLeft(margin).Width(usable).MaxWidth(usable).Render(
			renderCard(usable, content),
		)
	}

	if usable < 96 {
		sections := []string{
			m.renderTopologyBox(status, snap, usable),
			m.renderVisibilityBox(status, snap, usable),
			m.renderCredentialExposureBox(status, snap, usable),
			m.renderConversationsBox(status, snap, usable),
			m.renderSignalsBox(snap, usable),
			m.renderRecentEventsBox(snap, usable),
		}
		return lipgloss.NewStyle().MarginLeft(margin).Width(usable).MaxWidth(usable).Render(strings.Join(sections, "\n"))
	}

	gap := 2
	leftWidth := (usable - gap) / 2
	rightWidth := usable - leftWidth - gap

	left := strings.Builder{}
	left.WriteString(m.renderTopologyBox(status, snap, leftWidth))
	left.WriteString("\n")
	left.WriteString(m.renderConversationsBox(status, snap, leftWidth))
	left.WriteString("\n")
	left.WriteString(m.renderHostsBox(snap, leftWidth))

	right := strings.Builder{}
	right.WriteString(m.renderVisibilityBox(status, snap, rightWidth))
	right.WriteString("\n")
	right.WriteString(m.renderCredentialExposureBox(status, snap, rightWidth))
	right.WriteString("\n")
	right.WriteString(m.renderSignalsBox(snap, rightWidth))
	right.WriteString("\n")
	right.WriteString(m.renderRecentEventsBox(snap, rightWidth))

	return lipgloss.NewStyle().MarginLeft(margin).Width(usable).MaxWidth(usable).Render(
		lipgloss.JoinHorizontal(lipgloss.Top, left.String(), "  ", right.String()),
	)
}

func (m DashboardModel) authSnapshot() (bridge.BridgeStatus, stealth.NetworkMapSnapshot, bool) {
	if m.bridge == nil {
		return bridge.BridgeStatus{}, stealth.NetworkMapSnapshot{}, false
	}
	status := m.bridge.Status()
	if status.TargetID == nil || status.TargetID.NetworkMap == nil {
		return status, stealth.NetworkMapSnapshot{}, false
	}
	return status, status.TargetID.NetworkMap.Snapshot(), true
}

func (m DashboardModel) renderTopologyBox(status bridge.BridgeStatus, snap stealth.NetworkMapSnapshot, width int) string {
	targetMAC := "unknown"
	targetIP := "unknown"
	if status.TargetID != nil {
		targetMAC = formatMAC(status.TargetID.MAC)
		targetIP = formatIP(firstIP(status.TargetID.IP, snap.DHCP.ACKIP, snap.DHCP.OfferedIP))
	}
	bridgeName := emptyText(status.Name)
	if bridgeName == "unknown" {
		bridgeName = "bridge"
	}

	port := formatPortState(snap.Port)
	evidence := trunc(emptyText(snap.Port.Reason), width-16)
	if evidence == "unknown" {
		evidence = "waiting for traffic evidence"
	}

	var sb strings.Builder
	sb.WriteString(styleLabel.Render("Where We Are") + "\n")
	sb.WriteString(styleIfaceNameDevice.Render(trunc("PC / supplicant", width-4)) + "\n")
	sb.WriteString(styleDim.Render("  "+trunc(targetIP+"  "+targetMAC, width-4)) + "\n")
	sb.WriteString(styleDim.Render(trunc("        | "+status.IfaceA+" device-side", width-4)) + "\n")
	sb.WriteString(styleSuccess.Render(trunc("goLAN inline bridge  "+bridgeName, width-4)) + "\n")
	sb.WriteString(styleDim.Render(trunc("        | "+status.IfaceB+" switch-side", width-4)) + "\n")
	sb.WriteString(styleIfaceNameSwitch.Render(trunc("Switch / network", width-4)) + "\n")
	sb.WriteString(renderKeyValue("Port", port) + "\n")
	sb.WriteString(renderKeyValue("Evidence", evidence) + "\n")
	return renderCard(width, sb.String())
}

func (m DashboardModel) renderVisibilityBox(status bridge.BridgeStatus, snap stealth.NetworkMapSnapshot, width int) string {
	vlanText := formatVLANs(snap.VLANIDs, snap.RADIUS.AssignedVLAN)
	gateway := "unknown"
	if snap.Gateway.Confirmed {
		gateway = formatIP(snap.Gateway.IP)
	} else if len(snap.DHCP.RouterIP) > 0 {
		gateway = formatIP(snap.DHCP.RouterIP)
	}
	radius := "not visible"
	if snap.RADIUS.Seen {
		radius = formatIP(firstIP(snap.RADIUS.ServerIP, snap.RADIUS.ClientIP))
	}
	dhcp := "not visible"
	if snap.DHCP.Seen {
		dhcp = firstString(formatIP(snap.DHCP.ServerIP), snap.DHCP.LastType)
		if dhcp == "unknown" {
			dhcp = emptyText(snap.DHCP.LastType)
		}
	}

	var sb strings.Builder
	sb.WriteString(styleLabel.Render("Visibility") + "\n")
	sb.WriteString(renderKeyValue("VLANs", trunc(vlanText, width-18)) + "\n")
	sb.WriteString(renderKeyValue("Gateway", trunc(gateway, width-18)) + "\n")
	sb.WriteString(renderKeyValue("RADIUS", trunc(radius, width-18)) + "\n")
	sb.WriteString(renderKeyValue("DHCP", trunc(dhcp, width-18)) + "\n")
	sb.WriteString(renderKeyValue("Hosts", fmt.Sprintf("%d", snap.HostCount)) + "\n")
	sb.WriteString(renderKeyValue("Flows", fmt.Sprintf("%d recent", len(snap.Conversations))) + "\n")
	if len(snap.CredentialExposures) > 0 {
		sb.WriteString(renderKeyValue("Cleartext", styleWarning.Render(fmt.Sprintf("%d", len(snap.CredentialExposures)))) + "\n")
	} else {
		sb.WriteString(renderKeyValue("Cleartext", styleDim.Render("none")) + "\n")
	}
	if status.EAPOLPassthrough {
		sb.WriteString(renderKeyValue("802.1X", styleUp.Render("passthrough")) + "\n")
	} else {
		sb.WriteString(renderKeyValue("802.1X", boolText(snap.EAPOL.Detected)) + "\n")
	}
	return renderCard(width, sb.String())
}

func (m DashboardModel) renderCredentialExposureBox(status bridge.BridgeStatus, snap stealth.NetworkMapSnapshot, width int) string {
	var sb strings.Builder
	sb.WriteString(styleWarning.Render("Cleartext Exposure") + "\n")
	if len(snap.CredentialExposures) == 0 {
		sb.WriteString(styleDim.Render("No cleartext credential patterns observed.") + "\n")
		return renderCard(width, sb.String())
	}

	limit := 6
	if width < 64 {
		limit = 4
	}
	for i, finding := range snap.CredentialExposures {
		if i >= limit {
			break
		}
		sb.WriteString(m.renderCredentialExposureLine(status, snap, finding, width))
	}
	return renderCard(width, sb.String())
}

func (m DashboardModel) renderCredentialExposureLine(status bridge.BridgeStatus, snap stealth.NetworkMapSnapshot, finding stealth.CredentialExposureSummary, width int) string {
	service := credentialServiceLabel(finding)
	user := finding.Username
	if strings.TrimSpace(user) == "" {
		user = "unknown"
	}
	detail := finding.Evidence
	if detail == "" {
		detail = finding.SecretKind
	}
	if finding.Path != "" {
		detail += " " + finding.Path
	}
	line := fmt.Sprintf("%s %-7s %s user=%s %s",
		ageString(finding.LastSeen), finding.Service, service, user, credentialSecretLabel(finding))
	if finding.Count > 1 {
		line += fmt.Sprintf(" x%d", finding.Count)
	}
	if detail != "" {
		line += "  " + detail
	}
	return styleWarning.Render(trunc(line, width-4)) + "\n"
}

func (m DashboardModel) renderSignalsBox(snap stealth.NetworkMapSnapshot, width int) string {
	e := snap.EAPOL
	eapLast := "not observed"
	if e.Detected {
		method := emptyText(e.LastMethod)
		eapLast = strings.TrimSpace(e.LastCode + " " + method)
		if !e.LastSeen.IsZero() {
			eapLast += "  " + ageString(e.LastSeen)
		}
	}
	dhcpLast := "not observed"
	if snap.DHCP.Seen {
		dhcpLast = emptyText(snap.DHCP.LastType)
		if !snap.DHCP.LastSeen.IsZero() {
			dhcpLast += "  " + ageString(snap.DHCP.LastSeen)
		}
	}
	radiusLast := "not visible"
	if snap.RADIUS.Seen {
		radiusLast = emptyText(snap.RADIUS.LastCode)
		if snap.RADIUS.AccessRequests > 0 && snap.RADIUS.AccessAccepts == 0 && snap.RADIUS.AccessRejects == 0 && snap.RADIUS.AccessChallenges == 0 {
			radiusLast += "  no response"
		}
	}

	var sb strings.Builder
	sb.WriteString(styleLabel.Render("Control Plane") + "\n")
	sb.WriteString(renderKeyValue("EAPOL", trunc(eapLast, width-18)) + "\n")
	sb.WriteString(renderKeyValue("EAP S/F", fmt.Sprintf("%d/%d", e.Successes, e.Failures)) + "\n")
	sb.WriteString(renderKeyValue("DHCP", trunc(dhcpLast, width-18)) + "\n")
	sb.WriteString(renderKeyValue("RADIUS", trunc(radiusLast, width-18)) + "\n")
	sb.WriteString(renderKeyValue("Req/Resp", fmt.Sprintf("%d/%d", snap.RADIUS.AccessRequests, snap.RADIUS.AccessAccepts+snap.RADIUS.AccessRejects+snap.RADIUS.AccessChallenges)) + "\n")
	return renderCard(width, sb.String())
}

func (m DashboardModel) renderConversationsBox(status bridge.BridgeStatus, snap stealth.NetworkMapSnapshot, width int) string {
	var sb strings.Builder
	sb.WriteString(styleLabel.Render("Visible Conversations") + "\n")
	if len(snap.Conversations) == 0 {
		sb.WriteString(styleDim.Render("No IP conversations observed yet.") + "\n")
		return renderCard(width, sb.String())
	}
	limit := 10
	if width < 64 {
		limit = 7
	}
	for i, conv := range snap.Conversations {
		if i >= limit {
			break
		}
		sb.WriteString(m.renderConversationLine(status, snap, conv, width))
	}
	return renderCard(width, sb.String())
}

func (m DashboardModel) renderConversationLine(status bridge.BridgeStatus, snap stealth.NetworkMapSnapshot, conv stealth.ConversationSummary, width int) string {
	prefix := conv.Protocol
	if conv.VLANID != 0 {
		prefix += fmt.Sprintf("/%d", conv.VLANID)
	}
	age := ageString(conv.LastSeen)
	src := m.endpointLabel(status, snap, conv.SrcIP, conv.SrcMAC)
	dst := m.endpointLabel(status, snap, conv.DstIP, conv.DstMAC)
	src += portSuffix(conv.Protocol, conv.SrcPort)
	dst += portSuffix(conv.Protocol, conv.DstPort)
	line := fmt.Sprintf("%s %-10s %s -> %s  %d pkt", age, prefix, src, dst, conv.Packets)
	return styleDim.Render(trunc(line, width-4)) + "\n"
}

func (m DashboardModel) endpointLabel(status bridge.BridgeStatus, snap stealth.NetworkMapSnapshot, ip net.IP, mac net.HardwareAddr) string {
	if status.TargetID != nil {
		if len(status.TargetID.MAC) > 0 && macEqualUI(mac, status.TargetID.MAC) {
			return "target"
		}
		if len(status.TargetID.IP) > 0 && ip.Equal(status.TargetID.IP) {
			return "target"
		}
	}
	if len(snap.Gateway.IP) > 0 && ip.Equal(snap.Gateway.IP) {
		return "gateway"
	}
	if len(snap.Gateway.MAC) > 0 && macEqualUI(mac, snap.Gateway.MAC) {
		return "gateway"
	}
	if len(snap.RADIUS.ServerIP) > 0 && ip.Equal(snap.RADIUS.ServerIP) {
		return "radius"
	}
	if len(snap.DHCP.ServerIP) > 0 && ip.Equal(snap.DHCP.ServerIP) {
		return "dhcp"
	}
	if len(snap.DHCP.RouterIP) > 0 && ip.Equal(snap.DHCP.RouterIP) {
		return "gateway"
	}
	if len(ip) > 0 {
		return ip.String()
	}
	if len(mac) > 0 {
		return mac.String()
	}
	return "unknown"
}

func (m DashboardModel) renderAuthFlowBox(status bridge.BridgeStatus, snap stealth.NetworkMapSnapshot, width int) string {
	targetMAC := "unknown"
	targetIP := "unknown"
	if status.TargetID != nil {
		targetMAC = formatMAC(status.TargetID.MAC)
		targetIP = formatIP(status.TargetID.IP)
	}
	if targetIP == "unknown" && len(snap.DHCP.ACKIP) > 0 {
		targetIP = snap.DHCP.ACKIP.String()
	}

	portState := formatPortState(snap.Port)

	radius := "not visible"
	if snap.RADIUS.Seen {
		radius = formatIP(snap.RADIUS.ServerIP)
	}

	var sb strings.Builder
	sb.WriteString(styleLabel.Render("Passive NAC Map") + "\n")
	sb.WriteString(renderKeyValue("Device", targetMAC+"  "+targetIP) + "\n")
	sb.WriteString(renderKeyValue("Supplicant", formatMAC(snap.EAPOL.SupplicantMAC)) + "\n")
	sb.WriteString(renderKeyValue("Authenticator", formatMAC(snap.EAPOL.AuthenticatorMAC)) + "\n")
	sb.WriteString(renderKeyValue("RADIUS", radius) + "\n")
	sb.WriteString(renderKeyValue("Port", portState) + "\n")
	sb.WriteString(renderKeyValue("Evidence", trunc(emptyText(snap.Port.Reason), width-18)) + "\n")
	sb.WriteString(renderKeyValue("VLANs", formatVLANs(snap.VLANIDs, snap.RADIUS.AssignedVLAN)) + "\n")
	return renderCard(width, sb.String())
}

func (m DashboardModel) renderEAPOLBox(snap stealth.NetworkMapSnapshot, width int) string {
	e := snap.EAPOL
	method := e.LastMethod
	if method == "" {
		method = "unknown"
	}
	last := "never"
	if !e.LastSeen.IsZero() {
		last = ageString(e.LastSeen)
	}

	var sb strings.Builder
	sb.WriteString(styleLabel.Render("802.1X / EAPOL") + "\n")
	sb.WriteString(renderKeyValue("Detected", boolText(e.Detected)) + "\n")
	sb.WriteString(renderKeyValue("Last", e.LastCode+" "+method+"  "+last) + "\n")
	sb.WriteString(renderKeyValue("Requests", fmt.Sprintf("%d", e.Requests)) + "\n")
	sb.WriteString(renderKeyValue("Responses", fmt.Sprintf("%d", e.Responses)) + "\n")
	sb.WriteString(renderKeyValue("Success/Fail", fmt.Sprintf("%d / %d", e.Successes, e.Failures)) + "\n")
	sb.WriteString(renderKeyValue("Start/Logoff", fmt.Sprintf("%d / %d", e.Starts, e.Logoffs)) + "\n")
	sb.WriteString(renderKeyValue("MKA/Key", fmt.Sprintf("%d / %d", e.MKAFrames, e.KeyFrames)) + "\n")
	return renderCard(width, sb.String())
}

func (m DashboardModel) renderDHCPBox(snap stealth.NetworkMapSnapshot, width int) string {
	d := snap.DHCP
	last := "never"
	if !d.LastSeen.IsZero() {
		last = ageString(d.LastSeen)
	}
	lease := "unknown"
	if d.LeaseSeconds > 0 {
		lease = stats.HumanizeDuration(time.Duration(d.LeaseSeconds) * time.Second)
	}

	var sb strings.Builder
	sb.WriteString(styleLabel.Render("DHCP / VLAN") + "\n")
	sb.WriteString(renderKeyValue("Seen", boolText(d.Seen)) + "\n")
	sb.WriteString(renderKeyValue("Last", d.LastType+"  "+last) + "\n")
	sb.WriteString(renderKeyValue("D/O/R/A/N", fmt.Sprintf("%d/%d/%d/%d/%d", d.Discovers, d.Offers, d.Requests, d.ACKs, d.NAKs)) + "\n")
	sb.WriteString(renderKeyValue("Address", formatIP(firstIP(d.ACKIP, d.OfferedIP))) + "\n")
	sb.WriteString(renderKeyValue("Server", formatIP(d.ServerIP)) + "\n")
	sb.WriteString(renderKeyValue("Router", formatIP(d.RouterIP)) + "\n")
	sb.WriteString(renderKeyValue("Hostname", emptyText(d.Hostname)) + "\n")
	sb.WriteString(renderKeyValue("Lease", lease) + "\n")
	return renderCard(width, sb.String())
}

func (m DashboardModel) renderRADIUSBox(snap stealth.NetworkMapSnapshot, width int) string {
	r := snap.RADIUS
	last := "never"
	if !r.LastSeen.IsZero() {
		last = ageString(r.LastSeen)
	}

	var sb strings.Builder
	sb.WriteString(styleLabel.Render("RADIUS") + "\n")
	if !r.Seen {
		sb.WriteString(styleDim.Render("RADIUS traffic is not visible on this inline path unless it traverses the bridge or a mirror feed.") + "\n")
		return renderCard(width, sb.String())
	}
	sb.WriteString(renderKeyValue("Server", formatIP(r.ServerIP)) + "\n")
	sb.WriteString(renderKeyValue("NAS", formatIP(r.NASIPAddress)) + "\n")
	sb.WriteString(renderKeyValue("Last", r.LastCode+"  "+last) + "\n")
	sb.WriteString(renderKeyValue("Req/Chal", fmt.Sprintf("%d / %d", r.AccessRequests, r.AccessChallenges)) + "\n")
	sb.WriteString(renderKeyValue("Accept/Reject", fmt.Sprintf("%d / %d", r.AccessAccepts, r.AccessRejects)) + "\n")
	sb.WriteString(renderKeyValue("Acct", fmt.Sprintf("%d / %d", r.AccountingRequests, r.AccountingResponses)) + "\n")
	if r.AccessRequests > 0 && r.AccessAccepts == 0 && r.AccessRejects == 0 && r.AccessChallenges == 0 {
		path := "no response seen"
		if !r.LastRequestSeen.IsZero() {
			path += " " + ageString(r.LastRequestSeen)
		}
		sb.WriteString(renderKeyValue("Path", styleWarning.Render(path)) + "\n")
	}
	sb.WriteString(renderKeyValue("Calling", emptyText(r.CallingStationID)) + "\n")
	sb.WriteString(renderKeyValue("Called", emptyText(r.CalledStationID)) + "\n")
	sb.WriteString(renderKeyValue("Policy", emptyText(firstString(r.FilterID, r.ReplyMessage))) + "\n")
	sb.WriteString(renderKeyValue("VLAN", emptyText(r.AssignedVLAN)) + "\n")
	return renderCard(width, sb.String())
}

func (m DashboardModel) renderRecentEventsBox(snap stealth.NetworkMapSnapshot, width int) string {
	var sb strings.Builder
	sb.WriteString(styleLabel.Render("Auth Events") + "\n")
	if len(snap.RecentEvents) == 0 {
		sb.WriteString(styleDim.Render("No control-plane events observed yet.") + "\n")
		return renderCard(width, sb.String())
	}
	start := 0
	if len(snap.RecentEvents) > 8 {
		start = len(snap.RecentEvents) - 8
	}
	for _, ev := range snap.RecentEvents[start:] {
		prefix := ev.Kind
		if ev.VLANID != 0 {
			prefix += fmt.Sprintf("/%d", ev.VLANID)
		}
		if ev.Interface != "" {
			prefix += "@" + ev.Interface
		}
		sb.WriteString(styleKeyDesc.Render(ageString(ev.Timestamp)) + " " +
			styleKey.Render(prefix) + " " +
			styleVal.Render(trunc(ev.Summary, width-18)) + "\n")
	}
	return renderCard(width, sb.String())
}

func (m DashboardModel) renderHostsBox(snap stealth.NetworkMapSnapshot, width int) string {
	var sb strings.Builder
	sb.WriteString(styleLabel.Render("Observed Network") + "\n")
	sb.WriteString(renderKeyValue("Hosts", fmt.Sprintf("%d", snap.HostCount)) + "\n")
	if snap.Gateway.Confirmed {
		sb.WriteString(renderKeyValue("Gateway", formatIP(snap.Gateway.IP)+"  "+formatMAC(snap.Gateway.MAC)) + "\n")
	}
	for _, host := range snap.Hosts {
		line := formatMAC(host.MAC) + "  " + formatIPs(host.IPs)
		sb.WriteString(styleDim.Render(trunc(line, width-4)) + "\n")
	}
	if len(snap.DNSLog) > 0 {
		sb.WriteString(styleLabel.Render("DNS") + "\n")
		for _, q := range snap.DNSLog {
			sb.WriteString(styleDim.Render(trunc(q.Name+" "+q.Type, width-4)) + "\n")
		}
	}
	return renderCard(width, sb.String())
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

	cardWidth := safeWidth(width)

	boxA := renderCard(cardWidth, statsA)
	boxB := renderCard(cardWidth, statsB)

	return boxA + "\n" + boxB
}

// renderThroughput renders sparkline graphs for both interfaces.
func (m DashboardModel) renderThroughput(width int) string {
	sparkWidth := width - 8
	if sparkWidth < 4 {
		sparkWidth = 4
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

	outerWidth := safeWidth(width)
	innerWidth := outerWidth - 4 // border + left/right padding
	if innerWidth < 1 {
		innerWidth = 1
	}

	outerHeight := targetHeight
	if outerHeight < 6 {
		outerHeight = 6
	}
	contentHeight := outerHeight - 2 // border only; padding is horizontal
	if contentHeight < 1 {
		contentHeight = 1
	}

	var sb strings.Builder
	sb.WriteString(styleLabel.Render(trunc("Reconnaissance Log", innerWidth)) + styleDim.Render(trunc("  (↑↓/jk scroll)", innerWidth-18)) + "\n")

	sepLen := innerWidth
	sep := strings.Repeat("─", sepLen)
	sb.WriteString(lipgloss.NewStyle().Foreground(colorBorder).Render(sep) + "\n")

	logs := []string{"[*] Waiting for sniffer to initialize..."}
	if len(status.ReconLogs) > 0 {
		logs = status.ReconLogs
	}

	// Dynamic maxVis: content height minus title and separator.
	maxVis := contentHeight - 2
	if maxVis < 0 {
		maxVis = 0
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
		sb.WriteString(formatLogLine(trunc(log, innerWidth)) + "\n")
	}

	return lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(colorBorder).
		Padding(0, 1).
		Width(innerWidth).
		MaxWidth(innerWidth).
		Height(contentHeight).
		MaxHeight(contentHeight).
		Render(sb.String())
}

var (
	colorBulletBlue   = lipgloss.NewStyle().Foreground(lipgloss.Color("39")).Bold(true)
	colorBulletGreen  = lipgloss.NewStyle().Foreground(lipgloss.Color("42")).Bold(true)
	colorBulletRed    = lipgloss.NewStyle().Foreground(lipgloss.Color("196")).Bold(true)
	colorBulletOrange = lipgloss.NewStyle().Foreground(lipgloss.Color("#ff9100")).Bold(true)
	colorBulletPurple = lipgloss.NewStyle().Foreground(color802dot1X).Bold(true)
	colorBulletCyan   = lipgloss.NewStyle().Foreground(lipgloss.Color("#00CED1")).Bold(true)
	colorGray         = lipgloss.NewStyle().Foreground(lipgloss.Color("241"))

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
	} else if strings.HasPrefix(line, "[W][802.1X]") {
		return colorBulletOrange.Render("[W]") + colorBulletPurple.Render("[802.1X]") + colorGray.Render(line[11:])
	} else if strings.HasPrefix(line, "[*][802.1X]") {
		return colorBulletBlue.Render("[*]") + colorBulletPurple.Render("[802.1X]") + colorGray.Render(line[11:])
	} else if strings.HasPrefix(line, "[+][MACSEC]") {
		return colorBulletGreen.Render("[+]") + colorBulletPurple.Render("[MACSEC]") + colorGray.Render(line[11:])
	} else if strings.HasPrefix(line, "[!][MACSEC]") {
		return colorBulletRed.Render("[!]") + colorBulletPurple.Render("[MACSEC]") + colorGray.Render(line[11:])
	} else if strings.HasPrefix(line, "[W][MACSEC]") {
		return colorBulletOrange.Render("[W]") + colorBulletPurple.Render("[MACSEC]") + colorGray.Render(line[11:])
	} else if strings.HasPrefix(line, "[*][MACSEC]") {
		return colorBulletBlue.Render("[*]") + colorBulletPurple.Render("[MACSEC]") + colorGray.Render(line[11:])
	} else if strings.HasPrefix(line, "[+][RELAY]") {
		return colorBulletGreen.Render("[+]") + colorBulletPurple.Render("[RELAY]") + colorGray.Render(line[10:])
	} else if strings.HasPrefix(line, "[!][RELAY]") {
		return colorBulletRed.Render("[!]") + colorBulletPurple.Render("[RELAY]") + colorGray.Render(line[10:])
	} else if strings.HasPrefix(line, "[W][RELAY]") {
		return colorBulletOrange.Render("[W]") + colorBulletPurple.Render("[RELAY]") + colorGray.Render(line[10:])
	} else if strings.HasPrefix(line, "[*][RELAY]") {
		return colorBulletBlue.Render("[*]") + colorBulletPurple.Render("[RELAY]") + colorGray.Render(line[10:])
	} else if strings.HasPrefix(line, "[+][RECON]") {
		return colorBulletGreen.Render("[+]") + colorBulletPurple.Render("[RECON]") + colorGray.Render(line[10:])
	} else if strings.HasPrefix(line, "[*][RECON]") {
		return colorBulletBlue.Render("[*]") + colorBulletPurple.Render("[RECON]") + colorGray.Render(line[10:])
	} else if strings.HasPrefix(line, "[!][RECON]") {
		return colorBulletRed.Render("[!]") + colorBulletPurple.Render("[RECON]") + colorGray.Render(line[10:])
	} else if strings.HasPrefix(line, "[W][RECON]") {
		return colorBulletOrange.Render("[W]") + colorBulletPurple.Render("[RECON]") + colorGray.Render(line[10:])
	} else if strings.HasPrefix(line, "[+][VLAN]") {
		return colorBulletGreen.Render("[+]") + colorBulletPurple.Render("[VLAN]") + colorGray.Render(line[9:])
	} else if strings.HasPrefix(line, "[!][VLAN]") {
		return colorBulletRed.Render("[!]") + colorBulletPurple.Render("[VLAN]") + colorGray.Render(line[9:])
	} else if strings.HasPrefix(line, "[W][VLAN]") {
		return colorBulletOrange.Render("[W]") + colorBulletPurple.Render("[VLAN]") + colorGray.Render(line[9:])
	} else if strings.HasPrefix(line, "[+][NET]") {
		return colorBulletGreen.Render("[+]") + colorBulletPurple.Render("[NET]") + colorGray.Render(line[8:])
	} else if strings.HasPrefix(line, "[!][NET]") {
		return colorBulletRed.Render("[!]") + colorBulletPurple.Render("[NET]") + colorGray.Render(line[8:])
	} else if strings.HasPrefix(line, "[W][NET]") {
		return colorBulletOrange.Render("[W]") + colorBulletPurple.Render("[NET]") + colorGray.Render(line[8:])
	} else if strings.HasPrefix(line, "[*][NET]") {
		return colorBulletBlue.Render("[*]") + colorBulletPurple.Render("[NET]") + colorGray.Render(line[8:])
	} else if strings.HasPrefix(line, "[+][AUTH]") {
		return colorBulletGreen.Render("[+]") + colorBulletPurple.Render("[AUTH]") + colorGray.Render(line[9:])
	} else if strings.HasPrefix(line, "[!][AUTH]") {
		return colorBulletRed.Render("[!]") + colorBulletPurple.Render("[AUTH]") + colorGray.Render(line[9:])
	} else if strings.HasPrefix(line, "[W][AUTH]") {
		return colorBulletOrange.Render("[W]") + colorBulletPurple.Render("[AUTH]") + colorGray.Render(line[9:])
	} else if strings.HasPrefix(line, "[*][AUTH]") {
		return colorBulletBlue.Render("[*]") + colorBulletPurple.Render("[AUTH]") + colorGray.Render(line[9:])
	} else if strings.HasPrefix(line, "[W]") {
		return colorBulletOrange.Render("[W]") + colorGray.Render(line[3:])
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
	} else if strings.HasPrefix(line, "[RECON]") {
		return colorBulletPurple.Render("[RECON]") + colorGray.Render(line[7:])
	} else if strings.HasPrefix(line, "[VLAN]") {
		return colorBulletPurple.Render("[VLAN]") + colorGray.Render(line[6:])
	} else if strings.HasPrefix(line, "[NET]") {
		return colorBulletPurple.Render("[NET]") + colorGray.Render(line[5:])
	} else if strings.HasPrefix(line, "[AUTH]") {
		return colorBulletPurple.Render("[AUTH]") + colorGray.Render(line[6:])
	} else if strings.HasPrefix(line, "    ") {
		return "    " + colorGray.Render(line[4:])
	}
	return colorBulletBlue.Render("[*]") + colorGray.Render(" "+line)
}

func formatMAC(mac net.HardwareAddr) string {
	if len(mac) == 0 {
		return "unknown"
	}
	return mac.String()
}

func formatIP(ip net.IP) string {
	if len(ip) == 0 {
		return "unknown"
	}
	return ip.String()
}

func formatIPs(ips []net.IP) string {
	if len(ips) == 0 {
		return "unknown"
	}
	parts := make([]string, 0, len(ips))
	for _, ip := range ips {
		if len(ip) > 0 {
			parts = append(parts, ip.String())
		}
	}
	if len(parts) == 0 {
		return "unknown"
	}
	return strings.Join(parts, ", ")
}

func formatVLANs(vlans []uint16, radiusVLAN string) string {
	parts := make([]string, 0, len(vlans)+1)
	for _, vlan := range vlans {
		parts = append(parts, fmt.Sprintf("%d", vlan))
	}
	if radiusVLAN != "" {
		parts = append(parts, "RADIUS:"+radiusVLAN)
	}
	if len(parts) == 0 {
		return "unknown"
	}
	return strings.Join(parts, ", ")
}

func formatPortState(port stealth.PortTelemetry) string {
	state := port.State
	if state == "" {
		state = stealth.PortStateUnknown
	}
	label := strings.ToUpper(string(state))
	if port.Confidence > 0 {
		label += fmt.Sprintf(" %d%%", port.Confidence)
	}
	switch state {
	case stealth.PortStateOpen:
		return styleUp.Render(label)
	case stealth.PortStateAccepted:
		return styleWarning.Render(label)
	case stealth.PortStateAuthenticating:
		return lipgloss.NewStyle().Foreground(color802dot1X).Bold(true).Render(label)
	case stealth.PortStateRejected, stealth.PortStateClosed:
		return styleError.Render(label)
	default:
		return styleDim.Render(label)
	}
}

func ageString(t time.Time) string {
	if t.IsZero() {
		return "never"
	}
	return stats.HumanizeDuration(time.Since(t)) + " ago"
}

func boolText(v bool) string {
	if v {
		return styleUp.Render("yes")
	}
	return styleDim.Render("no")
}

func emptyText(s string) string {
	if strings.TrimSpace(s) == "" {
		return "unknown"
	}
	return s
}

func firstString(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

func firstIP(values ...net.IP) net.IP {
	for _, v := range values {
		if len(v) > 0 {
			return v
		}
	}
	return nil
}

func portSuffix(proto string, port uint16) string {
	if port == 0 {
		return ""
	}
	switch proto {
	case "ICMP", "IP":
		return ""
	default:
		return fmt.Sprintf(":%d", port)
	}
}

func credentialServiceLabel(finding stealth.CredentialExposureSummary) string {
	ip := formatIP(finding.ServiceIP)
	if finding.Host != "" {
		ip = finding.Host
	}
	if finding.ServicePort == 0 {
		return ip
	}
	return fmt.Sprintf("%s:%d", ip, finding.ServicePort)
}

func credentialSecretLabel(finding stealth.CredentialExposureSummary) string {
	if strings.TrimSpace(finding.SecretValue) != "" {
		return finding.SecretValue
	}
	return finding.SecretPreview
}

func macEqualUI(a, b net.HardwareAddr) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func (m DashboardModel) renderFooter() string {
	bState := bridge.BridgeStateDown
	eapolPassthrough := false
	if m.bridge != nil {
		status := m.bridge.Status()
		bState = status.State
		eapolPassthrough = status.EAPOLPassthrough
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
		keyHint("Tab", map[bool]string{true: "overview", false: "auth map"}[m.page == pageAuthMap]),
		keyHint("1/2", "pages"),
		keyHint("Esc", "back"),
		keyHint("q", "quit"),
	}

	natActive := hasBridge && m.bridge.IsNATActive()

	// Action shortcuts — always visible, greyed when unavailable.
	relayStr := "manual relay"
	if bState == bridge.BridgeStateEAPOLRelaying || bState == bridge.BridgeStateEAPOLAuthenticated {
		relayStr = "stop relay"
		if eapolPassthrough {
			relayStr = "stop eapol"
		}
	}
	parts = append(parts,
		hint(ready || listening, "E", "802.1X listen"),
		hint(ready, "S", "802.1X send"),
		hint(ready || eapolDetected || bState == bridge.BridgeStateEAPOLRelaying || bState == bridge.BridgeStateEAPOLAuthenticated, "R", relayStr),
		hint((ready || eapolDetected || listening || bState == bridge.BridgeStateEAPOLRelaying || authenticated || natActive) && gatewayKnown, "N", "NAT: "+map[bool]string{true: "ON", false: "OFF"}[natActive]),
		hint(hasBridge, "M", "MACsec:"+macsecStr),
	)

	footerWidth := m.width - 2
	if footerWidth < 1 {
		footerWidth = 1
	}
	return styleFooter.Width(footerWidth).MaxWidth(footerWidth).Render("  " + strings.Join(parts, "   "))
}

// bridgeLogFunc returns a log function that appends to the bridge's recon logs.
func (m DashboardModel) bridgeLogFunc() func(string) {
	return func(msg string) {
		if m.bridge != nil {
			m.bridge.AppendLog(msg)
		}
	}
}
