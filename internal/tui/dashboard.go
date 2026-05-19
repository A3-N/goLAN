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
	pageTopology
	pageIntel
	pageNetwork
	pageNodeDetail
)

const pageCount = 4

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

	width      int
	height     int
	err        error
	logScroll  int
	pageScroll int
	page       dashboardPage

	session         *SessionStore
	lastSessionSave time.Time
	selectedNodeKey string
	noteEditing     bool
	noteBuffer      string

	networkShowLAN bool
	networkShowWAN bool
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
func NewDashboardModel(ifA, ifB bridge.NetInterface, session *SessionStore) DashboardModel {
	return DashboardModel{
		ifaceA:         ifA, // Device port
		ifaceB:         ifB, // Switch port
		restoreA:       bridge.CaptureInterfaceRestoreState(ifA.Name, ifA.HardwarePort),
		restoreB:       bridge.CaptureInterfaceRestoreState(ifB.Name, ifB.HardwarePort),
		session:        session,
		networkShowLAN: true,
	}
}

func (m DashboardModel) createBridgeCmd(ifA, ifB string, ignoreMAC string) tea.Cmd {
	return func() tea.Msg {
		captureDir := ""
		if m.session != nil {
			captureDir = m.session.PcapDir()
		}
		br, err := bridge.NewBridge(ifA, ifB, ignoreMAC, captureDir,
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
		m.persistSessionSnapshot(false)
		return m, waitForStats(m.statsCh)

	case tea.KeyMsg:
		if m.noteEditing {
			return m.handleNoteEditKey(msg), nil
		}

		bState := bridge.BridgeStateDown
		if m.bridge != nil {
			bState = m.bridge.State()
		}

		switch msg.String() {
		case "tab":
			if m.page == pageNodeDetail {
				m.page = pageNetwork
			} else {
				m.page = (m.page + 1) % pageCount
			}
			m.pageScroll = 0
		case "1":
			m.page = pageOverview
			m.pageScroll = 0
		case "2":
			m.page = pageTopology
			m.pageScroll = 0
		case "3":
			m.page = pageIntel
			m.pageScroll = 0
		case "4":
			m.page = pageNetwork
			m.pageScroll = 0
		case "w", "W":
			if m.page == pageNetwork {
				m.setNetworkTrafficMode("wan")
			}
		case "l", "L":
			if m.page == pageNetwork {
				m.setNetworkTrafficMode("lan")
			} else if m.bridge != nil && (bState == bridge.BridgeStateReady || bState == bridge.BridgeStateEAPOLListening) {
				logFunc := m.bridgeLogFunc()
				go m.bridge.RunListenEAPOL(logFunc)
			}

		case "up", "k":
			if m.page == pageNetwork {
				m.moveNetworkSelection(-1)
			} else if m.page == pageTopology || m.page == pageIntel || m.page == pageNodeDetail {
				m.pageScroll--
			} else {
				m.logScroll++
			}
		case "down", "j":
			if m.page == pageNetwork {
				m.moveNetworkSelection(1)
			} else if m.page == pageTopology || m.page == pageIntel || m.page == pageNodeDetail {
				m.pageScroll++
			} else {
				m.logScroll--
			}
		case "left", "h":
			if m.page == pageNetwork {
				m.moveNetworkSelection(-5)
			}
		case "right":
			if m.page == pageNetwork {
				m.moveNetworkSelection(5)
			}
		case "enter":
			if m.page == pageNetwork {
				m.ensureNetworkSelection()
				m.page = pageNodeDetail
				m.pageScroll = 0
			}
		case "b", "B", "backspace":
			if m.page == pageNodeDetail {
				m.page = pageNetwork
				m.pageScroll = 0
			}
		// Continue from paused state.
		case "c", "C":
			if m.bridge != nil && bState == bridge.BridgeStatePaused {
				m.bridge.Continue()
			}

		// Optional action modes for the active Layer 2 bridge.
		case "e", "E":
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
			if m.page == pageNodeDetail {
				m.ensureNetworkSelection()
				m.noteBuffer = m.currentNodeNote()
				m.noteEditing = true
			} else if m.bridge != nil {
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
		if m.pageScroll < 0 {
			m.pageScroll = 0
		}
	}

	return m, nil
}

// Shutdown cleans up the bridge and stats collector.
func (m *DashboardModel) Shutdown() error {
	if m.cancel != nil {
		m.cancel()
	}
	m.persistSessionSnapshot(true)
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

	contentWidth := m.width
	if contentWidth < 1 {
		contentWidth = 1
	}

	// ── Header with Status ──────────────────────────────────────
	header := m.renderHeader(contentWidth)
	footer := m.renderFooter()
	bodyBudget := m.bodyHeightBudget(header, footer)

	// ── Error State ─────────────────────────────────────────────
	if m.err != nil {
		body := m.fitBodyHeight(m.renderError(), bodyBudget, 0)
		return m.renderFrame(header, body, footer)
	}

	// ── Loading State ───────────────────────────────────────────
	if m.bridge == nil {
		body := "\n" + styleDim.Render("  ⟳ Creating bridge between "+m.ifaceA.Name+" and "+m.ifaceB.Name+"...")
		body = m.fitBodyHeight(body, bodyBudget, 0)
		return m.renderFrame(header, body, footer)
	}

	var body string
	switch m.page {
	case pageTopology:
		body = m.renderTopologyPageContent(contentWidth, bodyBudget)
	case pageIntel:
		body = m.renderIntelPageContent(contentWidth, bodyBudget)
	case pageNetwork:
		body = m.renderNetworkPageContent(contentWidth, bodyBudget)
	case pageNodeDetail:
		body = m.renderNodeDetailPageContent(contentWidth, bodyBudget)
	default:
		body = m.renderOverviewPageContent(contentWidth, bodyBudget)
	}

	scroll := 0
	if m.page == pageTopology || m.page == pageIntel || m.page == pageNodeDetail {
		scroll = m.pageScroll
	}
	body = m.fitBodyHeight(body, bodyBudget, scroll)

	return m.renderFrame(header, body, footer)
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

func (m DashboardModel) renderFrame(header, body, footer string) string {
	if m.width <= 0 || m.height <= 0 {
		return strings.TrimRight(header+"\n"+body+"\n"+footer, "\n")
	}

	header = strings.TrimRight(header, "\n")
	body = strings.TrimRight(body, "\n")
	footer = strings.TrimRight(footer, "\n")

	headerHeight := lipgloss.Height(header)
	footerHeight := lipgloss.Height(footer)
	bodyHeight := m.height - headerHeight - footerHeight
	if bodyHeight < 0 {
		bodyHeight = 0
	}

	bodyBlock := lipgloss.NewStyle().
		Width(m.width).
		Height(bodyHeight).
		MaxWidth(m.width).
		MaxHeight(bodyHeight).
		Render(body)

	parts := make([]string, 0, 3)
	if header != "" {
		parts = append(parts, header)
	}
	if bodyHeight > 0 {
		parts = append(parts, bodyBlock)
	}
	if footer != "" {
		parts = append(parts, footer)
	}

	return m.fitViewport(strings.Join(parts, "\n"))
}

func (m DashboardModel) bodyHeightBudget(header, footer string) int {
	if m.height <= 0 {
		return 0
	}
	budget := m.height - lipgloss.Height(header)
	if footer != "" {
		budget -= lipgloss.Height(footer)
	}
	if budget < 0 {
		return 0
	}
	return budget
}

func (m DashboardModel) fitBodyHeight(content string, maxHeight int, scroll int) string {
	if maxHeight <= 0 {
		return ""
	}
	content = strings.TrimRight(content, "\n")
	if content == "" || lipgloss.Height(content) <= maxHeight {
		return content
	}

	blocks := splitBodyBlocks(content)
	if len(blocks) > 1 || isFramedContent(content) {
		return m.fitBodyBlocks(blocks, maxHeight, scroll)
	}

	return m.fitBodyLines(content, maxHeight, scroll)
}

func (m DashboardModel) fitBodyLines(content string, maxHeight int, scroll int) string {
	content = strings.TrimRight(content, "\n")
	if maxHeight <= 0 || content == "" {
		return ""
	}
	lines := strings.Split(content, "\n")
	if len(lines) <= maxHeight {
		return content
	}
	if maxHeight == 1 {
		return styleDim.Render(trunc("content clipped; resize terminal", safeWidth(m.width)-4))
	}

	visibleHeight := maxHeight - 1
	maxScroll := len(lines) - visibleHeight
	if maxScroll < 0 {
		maxScroll = 0
	}
	if scroll < 0 {
		scroll = 0
	}
	if scroll > maxScroll {
		scroll = maxScroll
	}
	end := scroll + visibleHeight
	if end > len(lines) {
		end = len(lines)
	}

	visible := append([]string(nil), lines[scroll:end]...)
	marker := fmt.Sprintf("showing %d-%d/%d  ↑↓ scroll", scroll+1, end, len(lines))
	visible = append(visible, styleDim.Render(trunc(marker, safeWidth(m.width)-4)))
	return strings.Join(visible, "\n")
}

func (m DashboardModel) fitBodyBlocks(blocks []string, maxHeight int, scroll int) string {
	if maxHeight <= 0 {
		return ""
	}
	if len(blocks) == 0 {
		return ""
	}
	if maxHeight == 1 {
		return styleDim.Render(trunc("content clipped; resize terminal", safeWidth(m.width)-4))
	}

	visibleHeight := maxHeight - 1
	if scroll < 0 {
		scroll = 0
	}
	if scroll >= len(blocks) {
		scroll = len(blocks) - 1
	}

	selected := make([]string, 0, len(blocks))
	used := 0
	firstTooTall := false
	for i := scroll; i < len(blocks); i++ {
		block := blocks[i]
		blockHeight := lipgloss.Height(block)
		needed := blockHeight
		if len(selected) > 0 {
			needed++
		}
		if used+needed > visibleHeight {
			if len(selected) == 0 {
				firstTooTall = true
			}
			break
		}
		if len(selected) > 0 {
			used++
		}
		selected = append(selected, block)
		used += blockHeight
	}

	if firstTooTall {
		if isFramedContent(blocks[scroll]) {
			return clipFramedBlock(blocks[scroll], maxHeight)
		}
		return m.fitBodyLines(blocks[scroll], maxHeight, 0)
	}
	if len(selected) == 0 {
		selected = append(selected, blocks[scroll])
	}

	endIndex := scroll + len(selected)
	visible := strings.Join(selected, "\n\n")
	marker := fmt.Sprintf("sections %d-%d/%d  ↑↓ scroll", scroll+1, endIndex, len(blocks))
	return visible + "\n" + styleDim.Render(trunc(marker, safeWidth(m.width)-4))
}

func splitBodyBlocks(content string) []string {
	lines := strings.Split(strings.TrimRight(content, "\n"), "\n")
	blocks := make([]string, 0, 4)
	current := make([]string, 0, 8)
	for _, line := range lines {
		if strings.TrimSpace(line) == "" {
			if len(current) > 0 {
				blocks = append(blocks, strings.Join(current, "\n"))
				current = current[:0]
			}
			continue
		}
		current = append(current, line)
	}
	if len(current) > 0 {
		blocks = append(blocks, strings.Join(current, "\n"))
	}
	return blocks
}

func isFramedContent(content string) bool {
	return strings.Contains(content, "╭") && strings.Contains(content, "╰")
}

func clipFramedBlock(content string, maxHeight int) string {
	if maxHeight <= 0 {
		return ""
	}
	lines := strings.Split(strings.TrimRight(content, "\n"), "\n")
	if len(lines) <= maxHeight {
		return strings.Join(lines, "\n")
	}
	if maxHeight == 1 {
		return styleDim.Render("...")
	}
	visible := append([]string(nil), lines[:maxHeight]...)
	visible[maxHeight-1] = lines[len(lines)-1]
	return strings.Join(visible, "\n")
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

func cardContentWidth(width int) int {
	inner := safeWidth(width) - 2 // left/right border
	if inner < 1 {
		return 1
	}
	return inner
}

func renderCard(width int, content string) string {
	outer := safeWidth(width)
	inner := cardContentWidth(width)
	return styleStatsBox.Width(inner).MaxWidth(outer).Render(content)
}

func renderFixedCard(width int, height int, content string) string {
	if height <= 0 {
		return ""
	}
	if height < 3 {
		return lipgloss.NewStyle().
			Width(safeWidth(width)).
			MaxWidth(safeWidth(width)).
			Height(height).
			MaxHeight(height).
			Render(styleDim.Render(trunc("resize terminal", safeWidth(width)-2)))
	}

	contentLines := height - 2 // leave room for top/bottom border
	content = clipCardContent(content, contentLines)
	outer := safeWidth(width)
	inner := cardContentWidth(width)
	return styleStatsBox.
		Width(inner).
		MaxWidth(outer).
		Height(contentLines).
		MaxHeight(height).
		Render(content)
}

func clipCardContent(content string, maxLines int) string {
	if maxLines <= 0 {
		return ""
	}
	lines := strings.Split(strings.TrimRight(content, "\n"), "\n")
	if len(lines) <= maxLines {
		return strings.Join(lines, "\n")
	}
	lines = lines[:maxLines]
	lines[maxLines-1] = styleDim.Render("... clipped; resize terminal")
	return strings.Join(lines, "\n")
}

func renderFixedCardStack(width int, maxHeight int, contents []string) string {
	if maxHeight <= 0 || len(contents) == 0 {
		return ""
	}
	if len(contents) == 1 {
		return renderFixedCard(width, maxHeight, contents[0])
	}

	gapCount := len(contents) - 1
	available := maxHeight - gapCount
	if available < 3 {
		return renderFixedCard(width, maxHeight, contents[0])
	}

	minHeight := 4
	if available < minHeight*len(contents) {
		minHeight = 3
	}
	if available < minHeight*len(contents) {
		return renderFixedCard(width, maxHeight, contents[0])
	}

	heights := make([]int, len(contents))
	total := 0
	for i, content := range contents {
		desired := lipgloss.Height(renderCard(width, content))
		if desired < minHeight {
			desired = minHeight
		}
		heights[i] = desired
		total += desired
	}

	for total > available {
		idx := -1
		tallest := minHeight
		for i, height := range heights {
			if height > tallest {
				tallest = height
				idx = i
			}
		}
		if idx == -1 {
			break
		}
		heights[idx]--
		total--
	}

	if total < available {
		heights[len(heights)-1] += available - total
	}

	parts := make([]string, 0, len(contents))
	for i, content := range contents {
		parts = append(parts, renderFixedCard(width, heights[i], content))
	}
	rendered := strings.Join(parts, "\n")
	if short := maxHeight - lipgloss.Height(rendered); short > 0 {
		heights[len(heights)-1] += short
		parts[len(parts)-1] = renderFixedCard(width, heights[len(heights)-1], contents[len(contents)-1])
		rendered = strings.Join(parts, "\n")
	}
	return rendered
}

func renderScrollableCardStack(width int, maxHeight int, contents []string) string {
	if len(contents) == 0 {
		return ""
	}
	maxCardHeight := maxHeight - 1 // fitBodyBlocks adds a one-line scroll marker.
	if maxCardHeight < 3 {
		maxCardHeight = 3
	}

	parts := make([]string, 0, len(contents))
	for _, content := range contents {
		height := lipgloss.Height(renderCard(width, content))
		if height > maxCardHeight {
			height = maxCardHeight
		}
		if height < 3 {
			height = 3
		}
		parts = append(parts, renderFixedCard(width, height, content))
	}
	return strings.Join(parts, "\n\n")
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
	const wireToken = " ==L2== "
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
		wireStr = " ==OK== "
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

func (m DashboardModel) renderOverviewPageContent(width int, maxHeight int) string {
	if maxHeight <= 0 {
		return ""
	}

	mainMinHeight := 8
	spacingHeight := 2
	diagram := m.renderBridgeDiagram(width)
	if lipgloss.Height(diagram)+spacingHeight+mainMinHeight > maxHeight {
		diagram = m.renderBridgeDiagramCompact(width)
	}

	diagramHeight := lipgloss.Height(diagram)
	remaining := maxHeight - diagramHeight - spacingHeight
	if remaining < mainMinHeight {
		return m.renderMainContentFit(width, maxHeight)
	}

	main := m.renderMainContentFit(width, remaining)
	if strings.TrimSpace(main) == "" {
		return diagram
	}
	return diagram + "\n\n" + main
}

// renderMainContent renders the two-column layout below the bridge diagram:
// Left column = Traffic Statistics + Throughput sparklines
// Right column = Reconnaissance Log (fills the full height)
func (m DashboardModel) renderMainContent(width int) string {
	return m.renderMainContentFit(width, 0)
}

func (m DashboardModel) renderMainContentFit(width int, maxHeight int) string {
	usable, margin := pageContentArea(width)
	if usable < 90 {
		leftColumn := m.renderLeftColumnFit(usable, maxHeight)
		content := leftColumn
		reconHeight := m.height - lipgloss.Height(leftColumn) - 10
		if maxHeight > 0 {
			reconHeight = maxHeight - lipgloss.Height(leftColumn) - 1
		}
		if reconHeight >= 6 || maxHeight <= 0 {
			if reconHeight < 8 {
				reconHeight = 8
			}
			recon := m.renderReconPanel(usable, reconHeight)
			content += "\n" + recon
		}
		return lipgloss.NewStyle().MarginLeft(margin).Width(usable).MaxWidth(usable).Render(content)
	}

	gap := 2
	leftWidth := usable / 3
	rightWidth := usable - leftWidth - gap

	// ── Left Column: Traffic Stats + Throughput Sparklines ──────
	leftColumn := m.renderLeftColumnFit(leftWidth, maxHeight)
	if maxHeight > 0 && maxHeight < 6 {
		return lipgloss.NewStyle().MarginLeft(margin).Width(usable).MaxWidth(usable).Render(leftColumn)
	}

	// ── Right Column: Reconnaissance Log ────────────────────────
	leftHeight := lipgloss.Height(leftColumn)
	if maxHeight > 0 && leftHeight > maxHeight {
		leftHeight = maxHeight
	}
	rightColumn := m.renderReconPanel(rightWidth, leftHeight)

	return lipgloss.NewStyle().MarginLeft(margin).Width(usable).MaxWidth(usable).Render(
		lipgloss.JoinHorizontal(lipgloss.Top, leftColumn, "  ", rightColumn),
	)
}

func (m DashboardModel) renderTopologyPageContent(width int, maxHeight int) string {
	status, snap, ok := m.authSnapshot()
	usable, margin := pageContentArea(width)
	if !ok {
		content := styleDim.Render("Topology waiting for bridge observer...")
		return lipgloss.NewStyle().MarginLeft(margin).Width(usable).MaxWidth(usable).Render(
			renderCard(usable, content),
		)
	}

	if usable >= 96 && maxHeight >= 10 {
		gap := 2
		leftWidth := (usable - gap) / 2
		rightWidth := usable - leftWidth - gap
		rightGap := 1
		layer2Height := (maxHeight - rightGap) / 2
		layer3Height := maxHeight - rightGap - layer2Height

		if layer2Height >= 4 && layer3Height >= 4 {
			left := renderFixedCard(leftWidth, maxHeight, m.topologyBoxContent(status, snap, leftWidth))
			right := renderFixedCard(rightWidth, layer2Height, m.layer2DetailContent(status, snap, rightWidth)) +
				"\n" +
				renderFixedCard(rightWidth, layer3Height, m.layer3DetailContent(status, snap, rightWidth))

			return lipgloss.NewStyle().MarginLeft(margin).Width(usable).MaxWidth(usable).Render(
				lipgloss.JoinHorizontal(lipgloss.Top, left, strings.Repeat(" ", gap), right),
			)
		}
	}

	sections := []string{
		m.renderTopologyBox(status, snap, usable),
		m.renderLayer2DetailBox(status, snap, usable),
		m.renderLayer3DetailBox(status, snap, usable),
	}
	return lipgloss.NewStyle().MarginLeft(margin).Width(usable).MaxWidth(usable).Render(strings.Join(sections, "\n\n"))
}

func (m DashboardModel) renderIntelPageContent(width int, maxHeight int) string {
	status, snap, ok := m.authSnapshot()
	usable, margin := pageContentArea(width)
	if !ok {
		content := styleDim.Render("Passive intelligence waiting for bridge observer...")
		return lipgloss.NewStyle().MarginLeft(margin).Width(usable).MaxWidth(usable).Render(
			renderCard(usable, content),
		)
	}

	allContents := []string{
		m.credentialExposureContent(status, snap, usable),
		m.conversationsContent(status, snap, usable),
		m.signalsContent(snap, usable),
		m.eapolContent(snap, usable),
		m.dhcpContent(snap, usable),
		m.radiusContent(snap, usable),
		m.recentEventsContent(snap, usable),
	}

	if usable < 96 {
		return lipgloss.NewStyle().MarginLeft(margin).Width(usable).MaxWidth(usable).Render(
			renderScrollableCardStack(usable, maxHeight, allContents),
		)
	}

	gap := 2
	leftWidth := (usable - gap) / 2
	rightWidth := usable - leftWidth - gap
	rightMinHeight := (4 * 3) + 3 // four cards, three one-line gaps.
	if maxHeight < rightMinHeight {
		return lipgloss.NewStyle().MarginLeft(margin).Width(usable).MaxWidth(usable).Render(
			renderScrollableCardStack(usable, maxHeight, allContents),
		)
	}

	leftContents := []string{
		m.credentialExposureContent(status, snap, leftWidth),
		m.conversationsContent(status, snap, leftWidth),
		m.recentEventsContent(snap, leftWidth),
	}
	rightContents := []string{
		m.signalsContent(snap, rightWidth),
		m.eapolContent(snap, rightWidth),
		m.dhcpContent(snap, rightWidth),
		m.radiusContent(snap, rightWidth),
	}
	left := renderFixedCardStack(leftWidth, maxHeight, leftContents)
	right := renderFixedCardStack(rightWidth, maxHeight, rightContents)

	return lipgloss.NewStyle().MarginLeft(margin).Width(usable).MaxWidth(usable).Render(
		lipgloss.JoinHorizontal(lipgloss.Top, left, strings.Repeat(" ", gap), right),
	)
}

func (m DashboardModel) authSnapshot() (bridge.BridgeStatus, stealth.NetworkMapSnapshot, bool) {
	if m.bridge == nil {
		return bridge.BridgeStatus{}, stealth.NetworkMapSnapshot{}, false
	}
	status := m.bridge.Status()
	if status.TargetID == nil || status.TargetID.NetworkMap == nil {
		return status, stealth.NetworkMapSnapshot{}, true
	}
	return status, status.TargetID.NetworkMap.Snapshot(), true
}

func (m *DashboardModel) persistSessionSnapshot(force bool) {
	if m == nil || m.session == nil || m.bridge == nil {
		return
	}
	if !force && !m.lastSessionSave.IsZero() && time.Since(m.lastSessionSave) < 5*time.Second {
		return
	}
	status, snap, ok := m.authSnapshot()
	if !ok {
		return
	}
	m.session.Merge(status, snap)
	_ = m.session.Save()
	m.lastSessionSave = time.Now()
}

func (m DashboardModel) handleNoteEditKey(msg tea.KeyMsg) DashboardModel {
	switch msg.String() {
	case "enter":
		if m.session != nil && strings.TrimSpace(m.selectedNodeKey) != "" {
			m.session.SetNote(m.selectedNodeKey, m.noteBuffer)
			_ = m.session.Save()
		}
		m.noteEditing = false
	case "backspace", "ctrl+h":
		runes := []rune(m.noteBuffer)
		if len(runes) > 0 {
			m.noteBuffer = string(runes[:len(runes)-1])
		}
	case "ctrl+u":
		m.noteBuffer = ""
	default:
		if msg.Type == tea.KeyRunes {
			m.noteBuffer += string(msg.Runes)
		} else if msg.String() == " " || msg.String() == "space" {
			m.noteBuffer += " "
		}
	}
	return m
}

func (m *DashboardModel) ensureNetworkSelection() {
	if m == nil {
		return
	}
	status, snap, ok := m.authSnapshot()
	if !ok {
		return
	}
	graph := m.buildNetworkGraph(status, snap)
	if len(graph.Nodes) == 0 {
		return
	}
	for _, node := range graph.Nodes {
		if node.Key == m.selectedNodeKey {
			return
		}
	}
	m.selectedNodeKey = graph.Nodes[graph.Selected].Key
}

func (m *DashboardModel) moveNetworkSelection(delta int) {
	if m == nil {
		return
	}
	status, snap, ok := m.authSnapshot()
	if !ok {
		return
	}
	graph := m.buildNetworkGraph(status, snap)
	if len(graph.Nodes) == 0 {
		return
	}
	next := graph.Selected + delta
	if next < 0 {
		next = 0
	}
	if next >= len(graph.Nodes) {
		next = len(graph.Nodes) - 1
	}
	m.selectedNodeKey = graph.Nodes[next].Key
}

func (m *DashboardModel) setNetworkTrafficMode(mode string) {
	if m == nil {
		return
	}
	switch mode {
	case "wan":
		m.networkShowLAN = false
		m.networkShowWAN = true
	default:
		m.networkShowLAN = true
		m.networkShowWAN = false
	}
	m.pageScroll = 0
	m.ensureNetworkSelection()
}

func (m DashboardModel) currentNodeNote() string {
	if m.session == nil || strings.TrimSpace(m.selectedNodeKey) == "" {
		return ""
	}
	return m.session.Note(m.selectedNodeKey)
}

func (m DashboardModel) renderTopologyBox(status bridge.BridgeStatus, snap stealth.NetworkMapSnapshot, width int) string {
	return renderCard(width, m.topologyBoxContent(status, snap, width))
}

func (m DashboardModel) topologyBoxContent(status bridge.BridgeStatus, snap stealth.NetworkMapSnapshot, width int) string {
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
	sb.WriteString(styleIfaceNameDevice.Render(trunc(status.IfaceA+" adapter", width-4)) + "\n")
	sb.WriteString(renderKeyValue("Hardware", trunc(emptyText(m.ifaceA.HardwarePort), width-18)) + "\n")
	sb.WriteString(renderKeyValue("Adapter MAC", trunc(emptyText(m.ifaceA.CurrentMAC), width-18)) + "\n")
	sb.WriteString(renderKeyValue("Factory MAC", trunc(emptyText(m.ifaceA.PermanentMAC), width-18)) + "\n")
	sb.WriteString(renderKeyValue("MTU/Addrs", trunc(fmt.Sprintf("%d  %s", m.ifaceA.MTU, formatStrings(m.ifaceA.Addrs)), width-18)) + "\n")
	sb.WriteString(styleIfaceNameSwitch.Render(trunc(status.IfaceB+" adapter", width-4)) + "\n")
	sb.WriteString(renderKeyValue("Hardware", trunc(emptyText(m.ifaceB.HardwarePort), width-18)) + "\n")
	sb.WriteString(renderKeyValue("Adapter MAC", trunc(emptyText(m.ifaceB.CurrentMAC), width-18)) + "\n")
	sb.WriteString(renderKeyValue("Factory MAC", trunc(emptyText(m.ifaceB.PermanentMAC), width-18)) + "\n")
	sb.WriteString(renderKeyValue("MTU/Addrs", trunc(fmt.Sprintf("%d  %s", m.ifaceB.MTU, formatStrings(m.ifaceB.Addrs)), width-18)) + "\n")
	sb.WriteString(styleSuccess.Render("Target MAC use") + "\n")
	sb.WriteString(renderKeyValue("Found", trunc(targetMAC, width-18)) + "\n")
	sb.WriteString(renderKeyValue("PC -> Mac", trunc(targetMAC+" observed on "+status.IfaceA, width-18)) + "\n")
	sb.WriteString(renderKeyValue("Bridge", trunc(bridgeName+" mirrors "+targetMAC, width-18)) + "\n")
	sb.WriteString(renderKeyValue("Switch side", trunc(status.IfaceB+" mirrors "+targetMAC+" when supported", width-18)) + "\n")
	sb.WriteString(renderKeyValue("Port", port) + "\n")
	sb.WriteString(renderKeyValue("Evidence", evidence) + "\n")
	return sb.String()
}

func (m DashboardModel) renderLayer2DetailBox(status bridge.BridgeStatus, snap stealth.NetworkMapSnapshot, width int) string {
	return renderCard(width, m.layer2DetailContent(status, snap, width))
}

func (m DashboardModel) layer2DetailContent(status bridge.BridgeStatus, snap stealth.NetworkMapSnapshot, width int) string {
	targetMAC := "unknown"
	if status.TargetID != nil {
		targetMAC = formatMAC(status.TargetID.MAC)
	}
	eap := snap.EAPOL
	eapolLast := "unknown"
	if eap.Detected {
		eapolLast = strings.TrimSpace(firstString(eap.LastCode, "EAPOL") + " " + eap.LastMethod + " " + ageString(eap.LastSeen))
	}
	supplicant := formatMAC(eap.SupplicantMAC)
	if supplicant == "unknown" {
		supplicant = targetMAC
	}

	var sb strings.Builder
	sb.WriteString(styleLabel.Render("Layer 2 Detail") + "\n")
	sb.WriteString(renderKeyValue("Bridge", trunc(emptyText(status.Name), width-18)) + "\n")
	sb.WriteString(renderKeyValue("State", trunc(status.State.String(), width-18)) + "\n")
	sb.WriteString(renderKeyValue("Target MAC", trunc(targetMAC, width-18)) + "\n")
	sb.WriteString(renderKeyValue("Supplicant", trunc(supplicant, width-18)) + "\n")
	sb.WriteString(renderKeyValue("Authenticator", trunc(formatMAC(eap.AuthenticatorMAC), width-18)) + "\n")
	sb.WriteString(renderKeyValue("EAPOL", trunc(eapolLast, width-18)) + "\n")
	sb.WriteString(renderKeyValue("Passthrough", boolText(status.EAPOLPassthrough)) + "\n")
	sb.WriteString(renderKeyValue("Port", formatPortState(snap.Port)) + "\n")
	sb.WriteString(renderKeyValue("Evidence", trunc(emptyText(firstString(snap.Port.Evidence, snap.Port.Reason)), width-18)) + "\n")
	sb.WriteString(renderKeyValue("VLANs", trunc(formatVLANs(snap.VLANIDs, snap.RADIUS.AssignedVLAN), width-18)) + "\n")
	return sb.String()
}

func (m DashboardModel) renderLayer3DetailBox(status bridge.BridgeStatus, snap stealth.NetworkMapSnapshot, width int) string {
	return renderCard(width, m.layer3DetailContent(status, snap, width))
}

func (m DashboardModel) layer3DetailContent(status bridge.BridgeStatus, snap stealth.NetworkMapSnapshot, width int) string {
	targetIPs := targetIPList(status, snap)
	gateway := "unknown"
	if snap.Gateway.Confirmed {
		gateway = formatIP(snap.Gateway.IP) + "  " + formatMAC(snap.Gateway.MAC)
	} else if len(snap.DHCP.RouterIP) > 0 {
		gateway = formatIP(snap.DHCP.RouterIP) + "  DHCP router"
	}

	radius := "not visible"
	if snap.RADIUS.Seen {
		radius = fmt.Sprintf("%s -> %s", formatIP(snap.RADIUS.ClientIP), formatIP(snap.RADIUS.ServerIP))
	}
	natSource := "off"
	if status.NATActive && status.NATHiddenIP != "" {
		natSource = status.NATHiddenIP
		if status.NATHiddenNetmask != "" {
			natSource += "/" + status.NATHiddenNetmask
		}
	}
	natRange := "unknown"
	if status.NATRouteNetwork != "" {
		natRange = status.NATRouteNetwork + "/" + status.NATRouteNetmask
	}

	var sb strings.Builder
	sb.WriteString(styleLabel.Render("Layer 3 Detail") + "\n")
	sb.WriteString(renderKeyValue("Target IPs", trunc(targetIPs, width-18)) + "\n")
	sb.WriteString(renderKeyValue("DHCP Offer", trunc(formatIP(snap.DHCP.OfferedIP), width-18)) + "\n")
	sb.WriteString(renderKeyValue("DHCP ACK", trunc(formatIP(snap.DHCP.ACKIP), width-18)) + "\n")
	sb.WriteString(renderKeyValue("Netmask", trunc(formatMask(snap.DHCP.Netmask), width-18)) + "\n")
	sb.WriteString(renderKeyValue("DHCP Server", trunc(formatIP(snap.DHCP.ServerIP), width-18)) + "\n")
	sb.WriteString(renderKeyValue("Gateway", trunc(gateway, width-18)) + "\n")
	sb.WriteString(renderKeyValue("RADIUS", trunc(radius, width-18)) + "\n")
	sb.WriteString(renderKeyValue("NAT Source", trunc(natSource, width-18)) + "\n")
	sb.WriteString(renderKeyValue("NAT Mode", trunc(firstString(status.NATAnchorMode, "off"), width-18)) + "\n")
	sb.WriteString(renderKeyValue("NAT Range", trunc(natRange, width-18)) + "\n")
	sb.WriteString(renderKeyValue("DNS seen", fmt.Sprintf("%d recent", len(snap.DNSLog))) + "\n")
	return sb.String()
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
	return renderCard(width, m.credentialExposureContent(status, snap, width))
}

func (m DashboardModel) credentialExposureContent(status bridge.BridgeStatus, snap stealth.NetworkMapSnapshot, width int) string {
	var sb strings.Builder
	sb.WriteString(styleWarning.Render("Cleartext Exposure") + "\n")
	if len(snap.CredentialExposures) == 0 {
		sb.WriteString(styleDim.Render("No cleartext credential patterns observed.") + "\n")
		return sb.String()
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
	return sb.String()
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
	return renderCard(width, m.signalsContent(snap, width))
}

func (m DashboardModel) signalsContent(snap stealth.NetworkMapSnapshot, width int) string {
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
	return sb.String()
}

func (m DashboardModel) renderConversationsBox(status bridge.BridgeStatus, snap stealth.NetworkMapSnapshot, width int) string {
	return renderCard(width, m.conversationsContent(status, snap, width))
}

func (m DashboardModel) conversationsContent(status bridge.BridgeStatus, snap stealth.NetworkMapSnapshot, width int) string {
	var sb strings.Builder
	sb.WriteString(styleLabel.Render("Visible Conversations") + "\n")
	if len(snap.Conversations) == 0 {
		sb.WriteString(styleDim.Render("No IP conversations observed yet.") + "\n")
		return sb.String()
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
	return sb.String()
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
	return renderCard(width, m.eapolContent(snap, width))
}

func (m DashboardModel) eapolContent(snap stealth.NetworkMapSnapshot, width int) string {
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
	return sb.String()
}

func (m DashboardModel) renderDHCPBox(snap stealth.NetworkMapSnapshot, width int) string {
	return renderCard(width, m.dhcpContent(snap, width))
}

func (m DashboardModel) dhcpContent(snap stealth.NetworkMapSnapshot, width int) string {
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
	return sb.String()
}

func (m DashboardModel) renderRADIUSBox(snap stealth.NetworkMapSnapshot, width int) string {
	return renderCard(width, m.radiusContent(snap, width))
}

func (m DashboardModel) radiusContent(snap stealth.NetworkMapSnapshot, width int) string {
	r := snap.RADIUS
	last := "never"
	if !r.LastSeen.IsZero() {
		last = ageString(r.LastSeen)
	}

	var sb strings.Builder
	sb.WriteString(styleLabel.Render("RADIUS") + "\n")
	if !r.Seen {
		sb.WriteString(styleDim.Render("RADIUS traffic is not visible on this inline path unless it traverses the bridge or a mirror feed.") + "\n")
		return sb.String()
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
	return sb.String()
}

func (m DashboardModel) renderRecentEventsBox(snap stealth.NetworkMapSnapshot, width int) string {
	return renderCard(width, m.recentEventsContent(snap, width))
}

func (m DashboardModel) recentEventsContent(snap stealth.NetworkMapSnapshot, width int) string {
	var sb strings.Builder
	sb.WriteString(styleLabel.Render("Auth Events") + "\n")
	if len(snap.RecentEvents) == 0 {
		sb.WriteString(styleDim.Render("No control-plane events observed yet.") + "\n")
		return sb.String()
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
	return sb.String()
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
	return m.renderLeftColumnFit(width, 0)
}

func (m DashboardModel) renderLeftColumnFit(width int, maxHeight int) string {
	var sb strings.Builder

	// Traffic Statistics.
	sb.WriteString(m.renderTrafficStats(width))
	sb.WriteString("\n")

	// Throughput sparklines.
	if m.collector != nil {
		sb.WriteString(m.renderThroughput(width))
	}

	full := sb.String()
	if maxHeight <= 0 || lipgloss.Height(full) <= maxHeight {
		return full
	}

	traffic := m.renderTrafficStats(width)
	if lipgloss.Height(traffic) <= maxHeight {
		return traffic
	}

	compact := m.renderTrafficStatsCompact(width)
	if m.collector != nil {
		throughput := m.renderThroughput(width)
		if lipgloss.Height(compact)+1+lipgloss.Height(throughput) <= maxHeight {
			return compact + "\n" + throughput
		}
	}
	return compact
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

func (m DashboardModel) renderTrafficStatsCompact(width int) string {
	var s stats.StatsUpdate
	if m.hasStats {
		s = m.latestStats
	}

	renderIface := func(label string, d stats.InterfaceDelta, nameStyle lipgloss.Style) string {
		raw := fmt.Sprintf("%s  RX %s  TX %s  err %d/%d",
			label,
			stats.HumanizeThroughput(d.RxBytesPerSec),
			stats.HumanizeThroughput(d.TxBytesPerSec),
			d.Stats.RxErrors,
			d.Stats.TxErrors,
		)
		return nameStyle.Render(trunc(raw, width-4))
	}

	var sb strings.Builder
	sb.WriteString(styleLabel.Render("Traffic Statistics") + "\n")
	sb.WriteString(renderIface(m.ifaceA.Name+" device", s.IfaceA, styleIfaceNameDevice) + "\n")
	sb.WriteString(renderIface(m.ifaceB.Name+" switch", s.IfaceB, styleIfaceNameSwitch) + "\n")
	return renderCard(width, sb.String())
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
		MaxWidth(outerWidth).
		Height(contentHeight).
		MaxHeight(outerHeight).
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

func formatStrings(values []string) string {
	parts := make([]string, 0, len(values))
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			parts = append(parts, value)
		}
	}
	if len(parts) == 0 {
		return "unknown"
	}
	return strings.Join(parts, ", ")
}

func targetIPList(status bridge.BridgeStatus, snap stealth.NetworkMapSnapshot) string {
	var targetMAC net.HardwareAddr
	if status.TargetID != nil {
		targetMAC = status.TargetID.MAC
	}
	seen := make(map[string]bool)
	ips := make([]net.IP, 0, 4)
	add := func(ip net.IP) {
		if len(ip) == 0 {
			return
		}
		key := ip.String()
		if key == "" || key == "<nil>" || seen[key] {
			return
		}
		seen[key] = true
		ips = append(ips, ip)
	}
	if status.TargetID != nil {
		add(status.TargetID.IP)
	}
	add(snap.DHCP.ACKIP)
	add(snap.DHCP.OfferedIP)
	for _, host := range snap.Hosts {
		if len(targetMAC) > 0 && macEqualUI(host.MAC, targetMAC) {
			for _, ip := range host.IPs {
				add(ip)
			}
		}
	}
	return formatIPs(ips)
}

func formatMask(mask net.IPMask) string {
	if len(mask) == 0 {
		return "unknown"
	}
	return net.IP(mask).String()
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
		styleKey.Render("[Tab/1/2/3/4]"),
		keyHint("Esc", "back"),
		keyHint("q", "quit"),
	}

	switch {
	case m.noteEditing:
		parts = append(parts,
			keyHint("Enter", "save note"),
			keyHint("Backspace", "delete"),
			keyHint("Ctrl+U", "clear"),
		)
	case m.page == pageNetwork:
		parts = append(parts,
			keyHint("↑↓", "select node"),
			keyHint("←→", "jump"),
			keyHint("Enter", "node detail"),
			keyHint("L", "LAN:"+onOff(m.networkShowLAN)),
			keyHint("W", "WAN:"+onOff(m.networkShowWAN)),
		)
	case m.page == pageNodeDetail:
		parts = append(parts,
			keyHint("B", "map"),
			keyHint("N", "edit note"),
		)
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
	if !m.noteEditing && m.page != pageNodeDetail {
		parts = append(parts,
			hint(ready || listening, "E", "802.1X listen"),
			hint(ready, "S", "802.1X send"),
			hint(ready || eapolDetected || bState == bridge.BridgeStateEAPOLRelaying || bState == bridge.BridgeStateEAPOLAuthenticated, "R", relayStr),
			hint((ready || eapolDetected || listening || bState == bridge.BridgeStateEAPOLRelaying || authenticated || natActive) && gatewayKnown, "N", "NAT: "+map[bool]string{true: "ON", false: "OFF"}[natActive]),
			hint(hasBridge, "M", "MACsec:"+macsecStr),
		)
	}

	footerWidth := m.width
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
