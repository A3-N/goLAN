package tui

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

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
	pageNetwork
	pageNodeDetail
)

const pageCount = 3

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

	pcapRun         *PcapRun
	selectedNodeKey string

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
func NewDashboardModel(ifA, ifB bridge.NetInterface, pcapRun *PcapRun) DashboardModel {
	return DashboardModel{
		ifaceA:         ifA, // Device port
		ifaceB:         ifB, // Switch port
		restoreA:       bridge.CaptureInterfaceRestoreState(ifA.Name, ifA.HardwarePort),
		restoreB:       bridge.CaptureInterfaceRestoreState(ifB.Name, ifB.HardwarePort),
		pcapRun:        pcapRun,
		networkShowLAN: true,
	}
}

func (m DashboardModel) createBridgeCmd(ifA, ifB string, ignoreMAC string) tea.Cmd {
	return func() tea.Msg {
		captureDir := ""
		if m.pcapRun != nil {
			captureDir = m.pcapRun.PcapDir()
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
		return m, waitForStats(m.statsCh)

	case tea.KeyMsg:
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
			} else if m.page == pageTopology || m.page == pageNodeDetail {
				m.pageScroll--
			} else {
				m.logScroll++
			}
		case "down", "j":
			if m.page == pageNetwork {
				m.moveNetworkSelection(1)
			} else if m.page == pageTopology || m.page == pageNodeDetail {
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

func (m DashboardModel) CaptureFiles() []string {
	if m.bridge == nil {
		return nil
	}
	return m.bridge.Status().CaptureFiles
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
	case pageNetwork:
		body = m.renderNetworkPageContent(contentWidth, bodyBudget)
	case pageNodeDetail:
		body = m.renderNodeDetailPageContent(contentWidth, bodyBudget)
	default:
		body = m.renderOverviewPageContent(contentWidth, bodyBudget)
	}

	scroll := 0
	if m.page == pageTopology || m.page == pageNodeDetail {
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
		content := styleDim.Render("Passive intelligence waiting for bridge observer...")
		return lipgloss.NewStyle().MarginLeft(margin).Width(usable).MaxWidth(usable).Render(
			renderCard(usable, content),
		)
	}

	contents := []string{
		m.credentialExposureContent(status, snap, usable),
		m.conversationsContent(status, snap, usable),
		m.layer2DetailContent(status, snap, usable),
		m.layer3DetailContent(status, snap, usable),
		m.hostsMapContent(snap, usable),
	}

	if usable < 96 || maxHeight < 10 {
		return lipgloss.NewStyle().MarginLeft(margin).Width(usable).MaxWidth(usable).Render(
			renderScrollableCardStack(usable, maxHeight, contents),
		)
	}

	gap := 2
	leftWidth := (usable - gap) / 2
	rightWidth := usable - leftWidth - gap
	leftContents := []string{
		m.credentialExposureContent(status, snap, leftWidth),
		m.conversationsContent(status, snap, leftWidth),
		m.hostsMapContent(snap, leftWidth),
	}
	rightContents := []string{
		m.layer2DetailContent(status, snap, rightWidth),
		m.layer3DetailContent(status, snap, rightWidth),
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
	sb.WriteString(renderKeyValue("EAP R/R", fmt.Sprintf("%d/%d", eap.Requests, eap.Responses)) + "\n")
	sb.WriteString(renderKeyValue("EAP S/F", fmt.Sprintf("%d/%d", eap.Successes, eap.Failures)) + "\n")
	sb.WriteString(renderKeyValue("Start/Logoff", fmt.Sprintf("%d/%d", eap.Starts, eap.Logoffs)) + "\n")
	sb.WriteString(renderKeyValue("Passthrough", boolText(status.EAPOLPassthrough)) + "\n")
	sb.WriteString(renderKeyValue("Port", formatPortState(snap.Port)) + "\n")
	sb.WriteString(renderKeyValue("Evidence", trunc(emptyText(firstString(snap.Port.Evidence, snap.Port.Reason)), width-18)) + "\n")
	sb.WriteString(renderKeyValue("VLANs", trunc(formatVLANs(snap.VLANIDs, snap.RADIUS.AssignedVLAN), width-18)) + "\n")
	return sb.String()
}

func (m DashboardModel) layer3DetailContent(status bridge.BridgeStatus, snap stealth.NetworkMapSnapshot, width int) string {
	targetIPs := targetIPList(status, snap)

	var sb strings.Builder
	sb.WriteString(styleLabel.Render("Layer 3 Detail") + "\n")
	sb.WriteString(renderKeyValue("Target IPs", trunc(targetIPs, width-18)) + "\n")
	sb.WriteString(renderKeyValue("IP Evidence", trunc(layer3IPEvidence(status, snap), width-18)) + "\n")
	sb.WriteString(renderKeyValue("Gateway", trunc(formatGatewayEvidence(status, snap), width-18)) + "\n")
	sb.WriteString(renderKeyValue("DNS Servers", trunc(formatDNSServers(snap), width-18)) + "\n")
	sb.WriteString(renderKeyValue("Netmask", trunc(formatNetmaskEvidence(status, snap), width-18)) + "\n")
	sb.WriteString(renderKeyValue("DHCP Lease", trunc(formatDHCPLease(snap), width-18)) + "\n")
	sb.WriteString(renderKeyValue("Observed LAN", trunc(formatObservedLAN(status, snap), width-18)) + "\n")
	sb.WriteString(renderKeyValue("External Seen", formatExternalSeen(snap)) + "\n")
	return sb.String()
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
		for _, targetIP := range targetIPCandidates(status, snap) {
			if ip.Equal(targetIP) {
				return "target"
			}
		}
	}
	if roles := endpointInfraRoles(snap, ip, mac); len(roles) > 0 {
		return strings.Join(roles, "+")
	}
	if len(ip) > 0 {
		return ip.String()
	}
	if len(mac) > 0 {
		return mac.String()
	}
	return "unknown"
}

func endpointInfraRoles(snap stealth.NetworkMapSnapshot, ip net.IP, mac net.HardwareAddr) []string {
	roles := make([]string, 0, 4)
	add := func(role string) {
		if role == "" {
			return
		}
		for _, existing := range roles {
			if existing == role {
				return
			}
		}
		roles = append(roles, role)
	}
	if len(snap.Gateway.IP) > 0 && ip.Equal(snap.Gateway.IP) {
		add("gateway")
	}
	if len(snap.Gateway.MAC) > 0 && macEqualUI(mac, snap.Gateway.MAC) {
		add("gateway")
	}
	if len(snap.DHCP.RouterIP) > 0 && ip.Equal(snap.DHCP.RouterIP) {
		add("gateway")
	}
	if len(snap.DHCP.ServerIP) > 0 && ip.Equal(snap.DHCP.ServerIP) {
		add("dhcp")
	}
	if len(snap.RADIUS.ServerIP) > 0 && ip.Equal(snap.RADIUS.ServerIP) {
		add("radius")
	}
	if len(snap.RADIUS.ClientIP) > 0 && ip.Equal(snap.RADIUS.ClientIP) {
		add("nas")
	}
	if len(snap.RADIUS.NASIPAddress) > 0 && ip.Equal(snap.RADIUS.NASIPAddress) {
		add("nas")
	}
	for _, dnsIP := range dnsServerCandidates(snap) {
		if len(dnsIP) > 0 && ip.Equal(dnsIP) {
			add("dns")
		}
	}
	return roles
}

func (m DashboardModel) hostsMapContent(snap stealth.NetworkMapSnapshot, width int) string {
	var sb strings.Builder
	sb.WriteString(styleLabel.Render("Hosts Map") + "\n")

	entries := dnsHostMapEntries(snap)
	if len(entries) == 0 {
		sb.WriteString(styleDim.Render("No DNS host mappings observed yet.") + "\n")
		return sb.String()
	}

	limit := 10
	if width < 64 {
		limit = 6
	}
	for i, entry := range entries {
		if i >= limit {
			sb.WriteString(styleDim.Render(fmt.Sprintf("+%d more DNS names", len(entries)-i)) + "\n")
			break
		}
		target := strings.Join(entry.IPs, ", ")
		meta := emptyText(strings.Join(entry.Types, ","))
		if !entry.LastSeen.IsZero() {
			meta += " " + ageString(entry.LastSeen)
		}
		line := fmt.Sprintf("%s -> %s  %s", entry.Name, target, meta)
		sb.WriteString(styleDim.Render(trunc(line, width-4)) + "\n")
	}
	return sb.String()
}

type dnsHostMapEntry struct {
	Name     string
	IPs      []string
	Types    []string
	LastSeen time.Time
}

func dnsHostMapEntries(snap stealth.NetworkMapSnapshot) []dnsHostMapEntry {
	byName := make(map[string]*dnsHostMapEntry)
	for _, query := range snap.DNSLog {
		name := normalizeDNSName(query.Name)
		if name == "" {
			continue
		}
		entry := byName[name]
		if entry == nil {
			entry = &dnsHostMapEntry{Name: name}
			byName[name] = entry
		}
		entry.Types = appendUniqueString(entry.Types, emptyText(query.Type))
		entry.LastSeen = maxTime(entry.LastSeen, query.Timestamp)
		for _, response := range query.Response {
			response = strings.TrimSpace(response)
			if response == "" {
				continue
			}
			if ip := net.ParseIP(response); ip != nil {
				if !ipLooksLAN(ip) {
					continue
				}
				entry.IPs = appendUniqueString(entry.IPs, ip.String())
			}
		}
		if len(entry.IPs) == 0 {
			delete(byName, name)
		}
	}

	entries := make([]dnsHostMapEntry, 0, len(byName))
	for _, entry := range byName {
		if len(entry.IPs) == 0 {
			continue
		}
		entries = append(entries, *entry)
	}
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].Name == entries[j].Name {
			return entries[i].LastSeen.After(entries[j].LastSeen)
		}
		return entries[i].Name < entries[j].Name
	})
	return entries
}

func ipLooksLAN(ip net.IP) bool {
	if ip == nil || ip.IsLinkLocalUnicast() || ip.IsLoopback() || ip.IsMulticast() || ip.IsUnspecified() {
		return false
	}
	return ip.IsPrivate()
}

func normalizeDNSName(name string) string {
	name = strings.TrimSpace(name)
	name = strings.TrimSuffix(name, ".")
	return name
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

	logs := []string{"[*] Waiting for sniffer to initialize..."}
	if len(status.ReconLogs) > 0 {
		logs = status.ReconLogs
	}

	for _, log := range visibleReconLogLines(logs, innerWidth, contentHeight-1, m.logScroll) {
		sb.WriteString(formatLogLine(log) + "\n")
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

func visibleReconLogLines(logs []string, width int, maxLines int, scroll int) []string {
	if maxLines <= 0 || len(logs) == 0 {
		return nil
	}
	if scroll < 0 {
		scroll = 0
	}
	end := len(logs) - scroll
	if end < 0 {
		end = 0
	}
	if end > len(logs) {
		end = len(logs)
	}

	lines := make([]string, 0, maxLines)
	for i := end - 1; i >= 0 && len(lines) < maxLines; i-- {
		wrapped := wrapReconLogLine(logs[i], width)
		for j := len(wrapped) - 1; j >= 0 && len(lines) < maxLines; j-- {
			lines = append(lines, wrapped[j])
		}
	}
	for i, j := 0, len(lines)-1; i < j; i, j = i+1, j-1 {
		lines[i], lines[j] = lines[j], lines[i]
	}
	return lines
}

func wrapReconLogLine(line string, width int) []string {
	line = strings.TrimRight(line, " \t")
	if width <= 0 {
		return nil
	}
	if line == "" || lipgloss.Width(line) <= width {
		return []string{line}
	}

	const continuation = "    "
	var out []string
	prefix := ""
	for line != "" {
		available := width - lipgloss.Width(prefix)
		if available < 1 {
			prefix = ""
			available = width
		}
		cut := reconWrapCut(line, available)
		if cut <= 0 {
			break
		}
		part := strings.TrimRight(line[:cut], " \t")
		if part != "" {
			out = append(out, prefix+part)
		}
		line = strings.TrimLeft(line[cut:], " \t")
		if line == "" {
			break
		}
		if width > lipgloss.Width(continuation)+1 {
			prefix = continuation
		} else {
			prefix = ""
		}
	}
	if len(out) == 0 {
		return []string{""}
	}
	return out
}

func reconWrapCut(line string, width int) int {
	if lipgloss.Width(line) <= width {
		return len(line)
	}
	lastSpace := -1
	for idx, r := range line {
		next := idx + utf8.RuneLen(r)
		if lipgloss.Width(line[:next]) > width {
			if unicode.IsSpace(r) && idx > 0 {
				return idx
			}
			if lastSpace > 0 {
				return lastSpace
			}
			if idx > 0 {
				return idx
			}
			return next
		}
		if unicode.IsSpace(r) {
			lastSpace = next
		}
	}
	return len(line)
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
	return formatIPs(targetIPCandidates(status, snap))
}

func targetIPCandidates(status bridge.BridgeStatus, snap stealth.NetworkMapSnapshot) []net.IP {
	var targetMAC net.HardwareAddr
	if status.TargetID != nil {
		targetMAC = status.TargetID.MAC
	}
	seen := make(map[string]bool)
	ips := make([]net.IP, 0, 4)
	add := func(ip net.IP) {
		ip4 := ip.To4()
		if ip4 == nil || ip4.IsUnspecified() || ip4.IsMulticast() {
			return
		}
		key := ip4.String()
		if key == "" || key == "<nil>" || seen[key] {
			return
		}
		seen[key] = true
		ips = append(ips, append(net.IP(nil), ip4...))
	}
	if status.TargetID != nil {
		add(status.TargetID.IP)
	}
	if len(targetMAC) == 0 || macEqualUI(snap.DHCP.ClientMAC, targetMAC) {
		add(snap.DHCP.ACKIP)
		add(snap.DHCP.OfferedIP)
	}
	for _, host := range snap.Hosts {
		if len(targetMAC) > 0 && macEqualUI(host.MAC, targetMAC) {
			for _, ip := range host.IPs {
				add(ip)
			}
		}
	}
	for _, conv := range snap.Conversations {
		if len(targetMAC) > 0 && macEqualUI(conv.SrcMAC, targetMAC) {
			add(conv.SrcIP)
		}
		if len(targetMAC) > 0 && macEqualUI(conv.DstMAC, targetMAC) {
			add(conv.DstIP)
		}
	}
	if len(targetMAC) > 0 && macEqualUI(snap.Port.SrcMAC, targetMAC) {
		add(snap.Port.SrcIP)
	}
	if len(targetMAC) > 0 && macEqualUI(snap.Port.DstMAC, targetMAC) {
		add(snap.Port.DstIP)
	}
	return ips
}

func layer3IPEvidence(status bridge.BridgeStatus, snap stealth.NetworkMapSnapshot) string {
	targets := targetIPCandidates(status, snap)
	if len(targets) == 0 {
		return "unknown"
	}

	var targetMAC net.HardwareAddr
	if status.TargetID != nil {
		targetMAC = status.TargetID.MAC
	}
	evidence := make([]string, 0, 5)
	add := func(label string) {
		evidence = appendUniqueString(evidence, label)
	}

	if status.TargetID != nil && ipInList(status.TargetID.IP, targets) {
		add("initial passive")
	}
	if ipInList(snap.DHCP.ACKIP, targets) {
		add("DHCP ACK")
	}
	if ipInList(snap.DHCP.OfferedIP, targets) {
		add("DHCP offer")
	}
	for _, host := range snap.Hosts {
		if len(targetMAC) > 0 && macEqualUI(host.MAC, targetMAC) {
			for _, ip := range host.IPs {
				if ipInList(ip, targets) {
					add("host traffic")
					break
				}
			}
		}
	}
	for _, conv := range snap.Conversations {
		switch {
		case len(targetMAC) > 0 && (macEqualUI(conv.SrcMAC, targetMAC) || macEqualUI(conv.DstMAC, targetMAC)):
			add("passive traffic")
		case ipInList(conv.SrcIP, targets) || ipInList(conv.DstIP, targets):
			add("passive traffic")
		}
	}
	if ipInList(snap.Port.SrcIP, targets) || ipInList(snap.Port.DstIP, targets) {
		add("port telemetry")
	}

	if len(evidence) == 0 {
		return "passive IP"
	}
	return strings.Join(evidence, ", ")
}

func formatGatewayEvidence(status bridge.BridgeStatus, snap stealth.NetworkMapSnapshot) string {
	evidence := make(map[string][]string)
	addEvidence := func(ip net.IP, label string) {
		ip4 := ip.To4()
		if ip4 == nil || ip4.IsUnspecified() || ip4.IsMulticast() {
			return
		}
		key := ip4.String()
		evidence[key] = appendUniqueString(evidence[key], label)
	}

	addEvidence(snap.DHCP.RouterIP, "DHCP option 3")
	if snap.Gateway.Confirmed {
		addEvidence(snap.Gateway.IP, "traffic analysis")
	}
	if status.TargetID != nil {
		addEvidence(status.TargetID.Gateway, "passive ARP/DHCP")
	}

	for _, ip := range []net.IP{snap.DHCP.RouterIP, snap.Gateway.IP} {
		ip4 := ip.To4()
		if ip4 == nil {
			continue
		}
		label := ip4.String()
		if snap.Gateway.Confirmed && snap.Gateway.IP.Equal(ip4) && len(snap.Gateway.MAC) > 0 {
			label += "  " + formatMAC(snap.Gateway.MAC)
		}
		if tags := evidence[ip4.String()]; len(tags) > 0 {
			label += " (" + strings.Join(tags, ", ") + ")"
		}
		return label
	}
	if status.TargetID != nil {
		if ip4 := status.TargetID.Gateway.To4(); ip4 != nil {
			label := ip4.String()
			if tags := evidence[ip4.String()]; len(tags) > 0 {
				label += " (" + strings.Join(tags, ", ") + ")"
			}
			return label
		}
	}
	return "unknown"
}

func formatNetmaskEvidence(status bridge.BridgeStatus, snap stealth.NetworkMapSnapshot) string {
	if len(snap.DHCP.Netmask) > 0 {
		return formatMask(snap.DHCP.Netmask) + " (DHCP option 1)"
	}
	if status.TargetID != nil && status.TargetID.NetmaskObserved && len(status.TargetID.Netmask) > 0 {
		return formatMask(status.TargetID.Netmask) + " (passive)"
	}
	return "unknown"
}

func formatDHCPLease(snap stealth.NetworkMapSnapshot) string {
	d := snap.DHCP
	leaseIP := firstIP(d.ACKIP, d.OfferedIP)
	if len(leaseIP) == 0 {
		if d.Seen {
			return "pending (" + emptyText(d.LastType) + ")"
		}
		return "not observed"
	}

	parts := []string{formatIP(leaseIP)}
	if len(d.ServerIP) > 0 {
		parts = append(parts, "from "+formatIP(d.ServerIP))
	}
	if d.LeaseSeconds > 0 {
		parts = append(parts, stats.HumanizeDuration(time.Duration(d.LeaseSeconds)*time.Second))
	}
	if strings.TrimSpace(d.LastType) != "" {
		parts = append(parts, d.LastType)
	}
	return strings.Join(parts, "  ")
}

func formatObservedLAN(status bridge.BridgeStatus, snap stealth.NetworkMapSnapshot) string {
	ip := firstIPFromSlice(targetIPCandidates(status, snap))
	if len(ip) == 0 {
		ip = firstIP(snap.DHCP.ACKIP, snap.DHCP.OfferedIP, snap.Gateway.IP)
	}

	mask := snap.DHCP.Netmask
	evidence := "DHCP option 1"
	if len(mask) == 0 && status.TargetID != nil && status.TargetID.NetmaskObserved {
		mask = status.TargetID.Netmask
		evidence = "passive"
	}

	ip4 := ip.To4()
	if ip4 == nil || len(mask) == 0 {
		return "unknown"
	}
	ones, bits := mask.Size()
	if bits == 0 {
		return "unknown"
	}
	return fmt.Sprintf("%s/%d (%s)", ip4.Mask(mask).String(), ones, evidence)
}

func formatExternalSeen(snap stealth.NetworkMapSnapshot) string {
	count := 0
	for _, conv := range snap.Conversations {
		if ipIsExternal(conv.SrcIP) || ipIsExternal(conv.DstIP) {
			count++
		}
	}
	if count == 0 {
		return "no"
	}
	if count == 1 {
		return "yes (1 flow)"
	}
	return fmt.Sprintf("yes (%d flows)", count)
}

func ipInList(ip net.IP, values []net.IP) bool {
	ip4 := ip.To4()
	if ip4 == nil {
		return false
	}
	for _, value := range values {
		if ip4.Equal(value.To4()) {
			return true
		}
	}
	return false
}

func firstIPFromSlice(values []net.IP) net.IP {
	for _, value := range values {
		if value.To4() != nil {
			return value
		}
	}
	return nil
}

func ipIsExternal(ip net.IP) bool {
	if len(ip) == 0 || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLoopback() || ip.IsMulticast() || ip.IsUnspecified() {
		return false
	}
	return ip.IsGlobalUnicast()
}

func ipStringCandidates(ips []net.IP) []string {
	out := make([]string, 0, len(ips))
	for _, ip := range ips {
		out = appendUniqueString(out, formatIP(ip))
	}
	return out
}

func dnsServerCandidates(snap stealth.NetworkMapSnapshot) []net.IP {
	evidence := dnsServerEvidence(snap)
	keys := make([]string, 0, len(evidence))
	for key := range evidence {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	out := make([]net.IP, 0, len(keys))
	for _, key := range keys {
		if ip := net.ParseIP(key); ip != nil {
			out = append(out, ip)
		}
	}
	return out
}

func dnsServerEvidence(snap stealth.NetworkMapSnapshot) map[string][]string {
	evidence := make(map[string][]string)
	add := func(ip net.IP, tags ...string) {
		ip4 := ip.To4()
		if ip4 == nil || ip4.IsUnspecified() || ip4.IsMulticast() {
			return
		}
		key := ip4.String()
		evidence[key] = appendUniqueStrings(evidence[key], tags...)
	}

	for _, ip := range snap.DHCP.DNSServers {
		add(ip, "dhcp-option-6")
	}
	for _, query := range snap.DNSLog {
		if len(query.ServerIP) > 0 {
			tags := []string{"dns-packet"}
			if len(query.Response) > 0 {
				tags = append(tags, "dns-response-src")
			} else {
				tags = append(tags, "dns-query-dst")
			}
			if query.VLANID != 0 {
				tags = append(tags, fmt.Sprintf("vlan/%d", query.VLANID))
			}
			add(query.ServerIP, tags...)
		}
	}
	for _, conv := range snap.Conversations {
		proto := strings.ToUpper(strings.TrimSpace(conv.Protocol))
		tags := []string{"dns-port-53"}
		if proto == "DNS" {
			tags = append(tags, "dns-conversation", "dns-packet")
		}
		if conv.DstPort == 53 {
			add(conv.DstIP, append(tags, "dns-query-dst")...)
		}
		if conv.SrcPort == 53 {
			add(conv.SrcIP, append(tags, "dns-response-src")...)
		}
	}
	return evidence
}

func formatDNSServers(snap stealth.NetworkMapSnapshot) string {
	ips := dnsServerCandidates(snap)
	if len(ips) == 0 {
		return "unknown"
	}
	evidence := dnsServerEvidence(snap)
	parts := make([]string, 0, len(ips))
	for _, ip := range ips {
		label := formatIP(ip)
		if tags := limitStrings(evidence[label], 3); len(tags) > 0 {
			label += " (" + strings.Join(tags, ",") + ")"
		}
		parts = append(parts, label)
	}
	return strings.Join(parts, ", ")
}

func dnsServerLastSeen(snap stealth.NetworkMapSnapshot, ip net.IP) time.Time {
	var last time.Time
	if ip == nil {
		return last
	}
	for _, dnsIP := range snap.DHCP.DNSServers {
		if dnsIP.Equal(ip) {
			last = maxTime(last, snap.DHCP.LastSeen)
		}
	}
	for _, query := range snap.DNSLog {
		if len(query.ServerIP) > 0 && query.ServerIP.Equal(ip) {
			last = maxTime(last, query.Timestamp)
		}
	}
	for _, conv := range snap.Conversations {
		if (conv.SrcPort == 53 && conv.SrcIP.Equal(ip)) || (conv.DstPort == 53 && conv.DstIP.Equal(ip)) ||
			(strings.EqualFold(conv.Protocol, "DNS") && (conv.SrcIP.Equal(ip) || conv.DstIP.Equal(ip))) {
			last = maxTime(last, conv.LastSeen)
		}
	}
	return last
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

func formatDHCPParamRequest(params []byte) string {
	if len(params) == 0 {
		return ""
	}
	names := map[byte]string{
		1:   "subnet",
		3:   "router",
		6:   "dns",
		12:  "host",
		15:  "domain",
		42:  "ntp",
		44:  "netbios-ns",
		46:  "netbios-node",
		119: "search",
		121: "routes",
		252: "wpad",
	}
	labels := make([]string, 0, len(params))
	for i, param := range params {
		if i >= 12 {
			labels = append(labels, fmt.Sprintf("+%d", len(params)-i))
			break
		}
		if name := names[param]; name != "" {
			labels = append(labels, fmt.Sprintf("%d/%s", param, name))
		} else {
			labels = append(labels, fmt.Sprintf("%d", param))
		}
	}
	return strings.Join(labels, ",")
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
		styleKey.Render("[Tab/1/2/3]"),
		keyHint("Esc", "back"),
		keyHint("q", "quit"),
	}

	switch {
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
	if m.page != pageNodeDetail {
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
