package tui

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	bridge "golan/internal/bridge"
	"golan/internal/edge"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

type settingsImpact string

const (
	settingsImpactLive        settingsImpact = "LIVE"
	settingsImpactReconfigure settingsImpact = "RECONFIGURE LINK"
	settingsImpactDisrupts    settingsImpact = "DISRUPTS CONNECTIONS"
)

var settingsImpactOrder = []settingsImpact{
	settingsImpactLive,
	settingsImpactReconfigure,
	settingsImpactDisrupts,
}

type settingsRowKind int

const (
	settingsRowEdgeMode settingsRowKind = iota
	settingsRowEdgeUpstream
	settingsRowPortForwardSummary
	settingsRowPortForward
	settingsRowEAPOLLogoff
	settingsRowEAPOLMACsec
	settingsRowRedactSecrets
	settingsRowQueueDepth
	settingsRowOverload
)

type settingsInputKind int

const (
	settingsInputNone settingsInputKind = iota
	settingsInputPortForward
)

type settingsDraft struct {
	edgeMode      string
	edgeUpstream  string
	forwards      []edgeForwardSetting
	eapolLogoff   bool
	eapolMACsec   bool
	redactSecrets bool
	controlled    bridge.ControlledOptions
}

type settingsEditorState struct {
	open       bool
	cursor     int
	returnCard cardFocus
	original   settingsDraft
	draft      settingsDraft
	inputKind  settingsInputKind
	input      string
	err        string
}

type settingsEditorRow struct {
	group    string
	label    string
	before   string
	after    string
	kind     settingsRowKind
	index    int
	changed  bool
	impacts  []settingsImpact
	editable bool
}

func (m Model) settingsSnapshot() settingsDraft {
	return settingsDraft{
		edgeMode:      m.edgeConfiguredMode,
		edgeUpstream:  m.edgeUpstream,
		forwards:      append([]edgeForwardSetting(nil), m.edgeForwards...),
		eapolLogoff:   m.eapolSuppressLogoff,
		eapolMACsec:   m.eapolDowngradeMACsec,
		redactSecrets: m.redactObservedSecrets,
		controlled:    m.bridgeControlledOptions,
	}
}

func (m *Model) openSettingsEditor() {
	if m.settingsEditor.open {
		return
	}
	snapshot := m.settingsSnapshot()
	m.settingsEditor = settingsEditorState{
		open:       true,
		returnCard: m.activeCard,
		original:   cloneSettingsDraft(snapshot),
		draft:      cloneSettingsDraft(snapshot),
	}
}

func cloneSettingsDraft(source settingsDraft) settingsDraft {
	source.forwards = append([]edgeForwardSetting(nil), source.forwards...)
	return source
}

func (m *Model) closeSettingsEditor() {
	if !m.settingsEditor.open {
		return
	}
	m.activeCard = m.settingsEditor.returnCard
	m.settingsEditor = settingsEditorState{}
}

func (m Model) updateSettingsEditor(key tea.KeyMsg) (tea.Model, tea.Cmd) {
	if key.String() == "ctrl+c" {
		return m, tea.Quit
	}
	if m.settingsEditor.inputKind != settingsInputNone {
		m.updateSettingsInventoryInput(key)
		return m, nil
	}
	switch key.String() {
	case "esc":
		m.closeSettingsEditor()
	case "up", "k":
		m.moveSettingsCursor(-1)
	case "down", "j":
		m.moveSettingsCursor(1)
	case "left", "h":
		m.cycleSettingsValue(-1)
	case "right", "l", "enter", " ":
		m.cycleSettingsValue(1)
	case "a":
		m.startSettingsInventoryInput()
	case "d", "delete":
		m.removeSettingsInventoryItem()
	case "ctrl+r":
		m.settingsEditor.draft = cloneSettingsDraft(m.settingsEditor.original)
		m.settingsEditor.err = ""
	case "ctrl+s":
		m.commitSettingsEditor()
	}
	return m, nil
}

func (m *Model) updateSettingsEditorMouse(msg tea.MouseMsg) {
	switch msg.Button {
	case tea.MouseButtonWheelUp:
		m.moveSettingsCursor(-1)
	case tea.MouseButtonWheelDown:
		m.moveSettingsCursor(1)
	}
}

func (m *Model) moveSettingsCursor(delta int) {
	rows := m.settingsRows()
	if len(rows) == 0 {
		m.settingsEditor.cursor = 0
		return
	}
	m.settingsEditor.cursor = (m.settingsEditor.cursor + delta + len(rows)) % len(rows)
	m.settingsEditor.err = ""
}

func (m *Model) cycleSettingsValue(delta int) {
	rows := m.settingsRows()
	if len(rows) == 0 {
		return
	}
	row := rows[clamp(m.settingsEditor.cursor, 0, len(rows)-1)]
	draft := &m.settingsEditor.draft
	switch row.kind {
	case settingsRowEdgeMode:
		draft.edgeMode = cycleSettingString(draft.edgeMode, []string{"observe", "route"}, delta)
	case settingsRowEdgeUpstream:
		values := append([]string{"auto"}, m.adapterNames()...)
		draft.edgeUpstream = cycleSettingString(draft.edgeUpstream, values, delta)
	case settingsRowEAPOLLogoff:
		draft.eapolLogoff = !draft.eapolLogoff
	case settingsRowEAPOLMACsec:
		draft.eapolMACsec = !draft.eapolMACsec
	case settingsRowRedactSecrets:
		draft.redactSecrets = !draft.redactSecrets
	case settingsRowQueueDepth:
		draft.controlled.QueueDepth = cycleSettingInt(draft.controlled.QueueDepth, []int{64, 256, 512, 1024, 2048, 4096}, delta)
	case settingsRowOverload:
		draft.controlled.Overload = bridge.OverloadBehavior(cycleSettingString(string(draft.controlled.Overload), []string{string(bridge.OverloadFailOpen), string(bridge.OverloadFailClosed)}, delta))
	}
	m.settingsEditor.err = ""
}

func cycleSettingString(current string, values []string, delta int) string {
	values = append([]string(nil), values...)
	found := false
	for _, value := range values {
		if value == current {
			found = true
			break
		}
	}
	if !found && current != "" {
		values = append(values, current)
	}
	if len(values) == 0 {
		return current
	}
	index := 0
	for candidate, value := range values {
		if value == current {
			index = candidate
			break
		}
	}
	return values[(index+delta+len(values))%len(values)]
}

func cycleSettingInt(current int, values []int, delta int) int {
	found := false
	for _, value := range values {
		if value == current {
			found = true
			break
		}
	}
	if !found {
		values = append(values, current)
		sort.Ints(values)
	}
	strings := make([]string, len(values))
	for index, value := range values {
		strings[index] = strconv.Itoa(value)
	}
	next, _ := strconv.Atoi(cycleSettingString(strconv.Itoa(current), strings, delta))
	return next
}

func (m *Model) startSettingsInventoryInput() {
	rows := m.settingsRows()
	if len(rows) == 0 {
		return
	}
	row := rows[clamp(m.settingsEditor.cursor, 0, len(rows)-1)]
	switch row.kind {
	case settingsRowPortForwardSummary, settingsRowPortForward:
		m.settingsEditor.inputKind = settingsInputPortForward
	default:
		m.settingsEditor.err = "Select a port-forward inventory row before adding."
		return
	}
	m.settingsEditor.input = ""
	m.settingsEditor.err = ""
}

func (m *Model) updateSettingsInventoryInput(key tea.KeyMsg) {
	switch key.String() {
	case "esc":
		m.settingsEditor.inputKind = settingsInputNone
		m.settingsEditor.input = ""
		m.settingsEditor.err = ""
	case "enter":
		var err error
		switch m.settingsEditor.inputKind {
		case settingsInputPortForward:
			err = m.addSettingsPortForward(m.settingsEditor.input)
		}
		if err != nil {
			m.settingsEditor.err = err.Error()
			return
		}
		m.settingsEditor.inputKind = settingsInputNone
		m.settingsEditor.input = ""
		m.settingsEditor.err = ""
	case "backspace", "ctrl+h":
		m.settingsEditor.input = trimLastRune(m.settingsEditor.input)
		m.settingsEditor.err = ""
	case "ctrl+u":
		m.settingsEditor.input = ""
		m.settingsEditor.err = ""
	default:
		if utf8.RuneCountInString(m.settingsEditor.input) < 256 {
			m.settingsEditor.input = appendInput(m.settingsEditor.input, key)
		}
	}
}

func (m *Model) addSettingsPortForward(input string) error {
	fields := strings.Fields(input)
	if len(fields) != 3 {
		return fmt.Errorf("use: <tcp|udp> <listen-port> <client-port>")
	}
	protocol := strings.ToLower(fields[0])
	listenPort, listenErr := strconv.ParseUint(fields[1], 10, 16)
	targetPort, targetErr := strconv.ParseUint(fields[2], 10, 16)
	if (protocol != "tcp" && protocol != "udp") || listenErr != nil || targetErr != nil || listenPort == 0 || targetPort == 0 {
		return fmt.Errorf("port forward requires TCP/UDP and non-zero ports")
	}
	for _, existing := range m.settingsEditor.draft.forwards {
		if existing.Protocol == protocol && existing.ListenPort == uint16(listenPort) {
			return fmt.Errorf("port forward %s/%d is duplicated", protocol, listenPort)
		}
	}
	m.settingsEditor.draft.forwards = append(m.settingsEditor.draft.forwards, edgeForwardSetting{
		Protocol: protocol, ListenPort: uint16(listenPort), TargetPort: uint16(targetPort),
	})
	return nil
}

func (m *Model) removeSettingsInventoryItem() {
	rows := m.settingsRows()
	if len(rows) == 0 {
		return
	}
	row := rows[clamp(m.settingsEditor.cursor, 0, len(rows)-1)]
	switch row.kind {
	case settingsRowPortForward:
		m.settingsEditor.draft.forwards = append(m.settingsEditor.draft.forwards[:row.index], m.settingsEditor.draft.forwards[row.index+1:]...)
	default:
		m.settingsEditor.err = "Select an inventory item before removing."
		return
	}
	m.settingsEditor.cursor = clamp(m.settingsEditor.cursor, 0, max(0, len(m.settingsRows())-1))
	m.settingsEditor.err = ""
}

func (m *Model) commitSettingsEditor() {
	draft := m.settingsEditor.draft
	if err := m.validateSettingsDraft(draft); err != nil {
		m.settingsEditor.err = err.Error()
		return
	}
	changes, impacts, requiresInactive := settingsDraftSummary(m.settingsEditor.original, draft)
	if changes == 0 {
		m.settingsEditor.err = "No staged changes."
		return
	}
	if requiresInactive {
		if blocker := m.adapterMutationBlocker(); blocker != "" {
			m.settingsEditor.err = "Cannot commit restart/reconfigure settings: " + blocker + "."
			return
		}
	} else if pending := m.pendingRuntimeOperation(); pending != "" {
		m.settingsEditor.err = "Cannot commit live settings while " + pending + "."
		return
	}

	m.edgeConfiguredMode = draft.edgeMode
	m.edgeUpstream = draft.edgeUpstream
	m.edgeForwards = append([]edgeForwardSetting(nil), draft.forwards...)
	m.eapolSuppressLogoff = draft.eapolLogoff
	m.eapolDowngradeMACsec = draft.eapolMACsec
	m.redactObservedSecrets = draft.redactSecrets
	m.bridgeControlledOptions = draft.controlled
	if m.bridge != nil {
		m.bridge.SetEAPOLPolicy(m.eapolPolicy())
	}
	returnCard := m.settingsEditor.returnCard
	m.settingsEditor = settingsEditorState{}
	m.activeCard = returnCard
	m.print(fmt.Sprintf("settings: committed %d changes impacts=%s", changes, strings.Join(settingsImpactStrings(impacts), ",")))
	m.print(fmt.Sprintf("settings: edge=%s upstream=%s forwards=%d controlled-queue=%d redact-secrets=%t", m.edgeConfiguredMode, m.edgeUpstream, len(m.edgeForwards), m.bridgeControlledOptions.QueueDepth, m.redactObservedSecrets))
}

func (m Model) validateSettingsDraft(draft settingsDraft) error {
	if draft.edgeMode != string(edge.ModeObserve) && draft.edgeMode != string(edge.ModeRoute) {
		return fmt.Errorf("edge mode must be observe or route")
	}
	if !strings.EqualFold(draft.edgeUpstream, "auto") {
		adapter, ok := m.findAdapter(draft.edgeUpstream)
		if !ok || adapter.Name == "" {
			return fmt.Errorf("edge upstream adapter is no longer available: %s", draft.edgeUpstream)
		}
	}
	if err := bridge.ValidateControlledOptions(draft.controlled); err != nil {
		return err
	}
	if len(draft.forwards) > 0 && draft.edgeMode == string(edge.ModeObserve) {
		return fmt.Errorf("port forwards require edge route mode")
	}
	seenForwards := make(map[string]bool, len(draft.forwards))
	for _, forward := range draft.forwards {
		key := fmt.Sprintf("%s/%d", forward.Protocol, forward.ListenPort)
		if (forward.Protocol != "tcp" && forward.Protocol != "udp") || forward.ListenPort == 0 || forward.TargetPort == 0 || seenForwards[key] {
			return fmt.Errorf("invalid or duplicate port forward: %s", key)
		}
		seenForwards[key] = true
	}
	return nil
}

func settingsDraftSummary(before, after settingsDraft) (int, []settingsImpact, bool) {
	changes := 0
	impactSet := make(map[settingsImpact]bool)
	requiresInactive := false
	add := func(changed, inactive bool, impacts ...settingsImpact) {
		if !changed {
			return
		}
		changes++
		requiresInactive = requiresInactive || inactive
		for _, impact := range impacts {
			impactSet[impact] = true
		}
	}
	add(before.edgeMode != after.edgeMode, true, settingsImpactReconfigure, settingsImpactDisrupts)
	add(before.edgeUpstream != after.edgeUpstream, true, settingsImpactReconfigure, settingsImpactDisrupts)
	add(!equalEdgeForwards(before.forwards, after.forwards), true, settingsImpactReconfigure, settingsImpactDisrupts)
	add(before.eapolLogoff != after.eapolLogoff, false, settingsImpactLive)
	add(before.eapolMACsec != after.eapolMACsec, false, settingsImpactLive)
	add(before.redactSecrets != after.redactSecrets, false, settingsImpactLive)
	add(before.controlled.QueueDepth != after.controlled.QueueDepth, true, settingsImpactReconfigure)
	add(before.controlled.Overload != after.controlled.Overload, true, settingsImpactReconfigure)
	impacts := make([]settingsImpact, 0, len(impactSet))
	for _, impact := range settingsImpactOrder {
		if impactSet[impact] {
			impacts = append(impacts, impact)
		}
	}
	return changes, impacts, requiresInactive
}

func equalEdgeForwards(left, right []edgeForwardSetting) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func (m Model) settingsRows() []settingsEditorRow {
	before := m.settingsEditor.original
	after := m.settingsEditor.draft
	rows := []settingsEditorRow{
		settingRow("Session", "Edge mode", before.edgeMode, after.edgeMode, settingsRowEdgeMode, settingsImpactReconfigure, settingsImpactDisrupts),
		settingRow("Addressing", "Upstream adapter", before.edgeUpstream, after.edgeUpstream, settingsRowEdgeUpstream, settingsImpactReconfigure, settingsImpactDisrupts),
		settingCountRow("Addressing", "Port forwards", len(before.forwards), len(after.forwards), settingsRowPortForwardSummary, settingsImpactReconfigure, settingsImpactDisrupts),
	}
	for index, forward := range after.forwards {
		value := fmt.Sprintf("%s/%d -> client:%d", forward.Protocol, forward.ListenPort, forward.TargetPort)
		rows = append(rows, settingsInventoryRow("Addressing", "Port forward", value, edgeForwardPresent(before.forwards, forward), settingsRowPortForward, index, settingsImpactReconfigure, settingsImpactDisrupts))
	}
	rows = append(rows,
		settingRow("Policy", "Drop EAPOL logoff", settingOnOff(before.eapolLogoff), settingOnOff(after.eapolLogoff), settingsRowEAPOLLogoff, settingsImpactLive),
		settingRow("Policy", "MACsec downgrade", settingOnOff(before.eapolMACsec), settingOnOff(after.eapolMACsec), settingsRowEAPOLMACsec, settingsImpactLive),
		settingRow("Privacy", "Redact observed secrets", settingOnOff(before.redactSecrets), settingOnOff(after.redactSecrets), settingsRowRedactSecrets, settingsImpactLive),
		settingRow("Performance", "Controlled queue depth", strconv.Itoa(before.controlled.QueueDepth), strconv.Itoa(after.controlled.QueueDepth), settingsRowQueueDepth, settingsImpactReconfigure),
		settingRow("Performance", "Queue overload", string(before.controlled.Overload), string(after.controlled.Overload), settingsRowOverload, settingsImpactReconfigure),
	)
	return rows
}

func settingRow(group, label, before, after string, kind settingsRowKind, impacts ...settingsImpact) settingsEditorRow {
	return settingsEditorRow{group: group, label: label, before: before, after: after, kind: kind, changed: before != after, impacts: impacts, editable: true}
}

func settingCountRow(group, label string, before, after int, kind settingsRowKind, impacts ...settingsImpact) settingsEditorRow {
	return settingsEditorRow{group: group, label: label, before: strconv.Itoa(before), after: strconv.Itoa(after), kind: kind, changed: before != after, impacts: impacts}
}

func settingsInventoryRow(group, label, after string, existed bool, kind settingsRowKind, index int, impacts ...settingsImpact) settingsEditorRow {
	before := after
	if !existed {
		before = "<absent>"
	}
	return settingsEditorRow{group: group, label: label, before: before, after: after, kind: kind, index: index, changed: !existed, impacts: impacts}
}

func edgeForwardPresent(values []edgeForwardSetting, target edgeForwardSetting) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func settingOnOff(value bool) string {
	if value {
		return "on"
	}
	return "off"
}

func settingsImpactStrings(impacts []settingsImpact) []string {
	values := make([]string, len(impacts))
	for index, impact := range impacts {
		values[index] = string(impact)
	}
	return values
}

func (m Model) renderSettingsEditor() string {
	terminalCols := terminalWidth(m.width)
	width := renderWidth(terminalCols)
	height := renderHeight(terminalHeight(m.height))
	margin := horizontalMargin(terminalCols)
	rows, selected := m.settingsEditorDocument(max(1, width-2))
	available := max(1, height-3)
	start := clamp(selected-available/2, 0, max(0, len(rows)-available))
	end := min(len(rows), start+available)
	footer := " ↑/↓ move   ←/→ or Enter change   a add inventory   d remove   Ctrl+R reset   Ctrl+S commit   Esc cancel   F1 help "
	content := box("TRANSACTIONAL SETTINGS", rows[start:end], width, max(4, height-1), true)
	view := lipgloss.JoinVertical(lipgloss.Left, content, styleFooterBar.Render(fit(footer, width)))
	return insetBlock(clampBlock(view, width, height), margin)
}

func (m Model) settingsEditorDocument(rowWidth int) ([]string, int) {
	rows := m.settingsRows()
	changes, impacts, _ := settingsDraftSummary(m.settingsEditor.original, m.settingsEditor.draft)
	document := []string{
		fmt.Sprintf("Staged changes %d · impacts %s", changes, settingImpactSummary(impacts)),
		"All values remain drafts until Ctrl+S validates and commits the complete transaction.",
		"",
	}
	selectedLine := 0
	lastGroup := ""
	for index, row := range rows {
		if row.group != lastGroup {
			if lastGroup != "" {
				document = append(document, "")
			}
			document = append(document, styleHeader.Render(strings.ToUpper(row.group)))
			lastGroup = row.group
		}
		line := "  " + row.label + " = " + row.after
		if row.changed {
			line = "  " + row.label + ": " + row.before + " -> " + row.after
		}
		selected := index == m.settingsEditor.cursor
		if selected {
			line = "> " + strings.TrimLeft(line, " ")
			selectedLine = len(document)
		}
		line = alignSettingsImpacts(line, row.impacts, selected, rowWidth)
		document = append(document, line)
	}
	if m.settingsEditor.inputKind != settingsInputNone {
		prompt := "Port forward: <tcp|udp> <listen-port> <client-port>"
		document = append(document, "", styleHeader.Render("ADD INVENTORY"), prompt, "> "+m.settingsEditor.input+"|")
		selectedLine = len(document) - 1
	}
	if m.settingsEditor.err != "" {
		document = append(document, "", styleError.Render(m.settingsEditor.err))
		selectedLine = len(document) - 1
	}
	return document, selectedLine
}

func renderSettingsImpacts(impacts []settingsImpact, selected bool) string {
	badges := make([]string, len(impacts))
	style := styleContext
	if selected {
		style = styleContextSelected
	}
	for index, impact := range impacts {
		badges[index] = style.Render("[" + string(impact) + "]")
	}
	return strings.Join(badges, " ")
}

func alignSettingsImpacts(left string, impacts []settingsImpact, selected bool, width int) string {
	if len(impacts) == 0 || width <= 0 {
		return left
	}
	right := renderSettingsImpacts(impacts, selected)
	gap := width - lipgloss.Width(left) - lipgloss.Width(right)
	if gap < 2 {
		left = fit(left, max(1, width-lipgloss.Width(right)-1))
		gap = max(1, width-lipgloss.Width(left)-lipgloss.Width(right))
	}
	return left + strings.Repeat(" ", gap) + right
}

func settingImpactSummary(impacts []settingsImpact) string {
	if len(impacts) == 0 {
		return "none"
	}
	return strings.Join(settingsImpactStrings(impacts), ", ")
}
