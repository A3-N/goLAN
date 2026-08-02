package tui

import (
	"context"
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"golan/internal/adapters"
	"golan/internal/configs"
	"golan/internal/profile"
	workproject "golan/internal/project"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

type startupView int

const (
	startupMenu startupView = iota
	startupRecentProjects
	startupConfigs
	startupLiveModes
	startupLivePrimary
	startupLiveSecondary
	startupLiveReview
	startupPrompt
)

type startupPromptKind int

const (
	startupNoPrompt startupPromptKind = iota
	startupNewName
	startupOpenPath
	startupBundlePath
	startupConfigProjectName
)

type startupState struct {
	open        bool
	view        startupView
	cursor      int
	input       string
	prompt      startupPromptKind
	returnView  startupView
	selected    string
	err         string
	configs     []string
	liveMode    string
	livePrimary string
	liveSecond  string
}

type startupChoice struct {
	label       string
	description string
	disabled    bool
}

func (m *Model) openStartupChooser() {
	m.startup = startupState{open: true, view: startupMenu}
	if err := m.reloadRecents(); err != nil {
		m.startup.err = "Recent items unavailable: " + err.Error()
	}
	configNames, err := configs.List()
	if err != nil {
		m.startup.err = joinStartupError(m.startup.err, "Configs unavailable: "+err.Error())
	} else {
		m.startup.configs = configNames
	}
}

func (m Model) startupChoices() []startupChoice {
	return []startupChoice{
		{label: "New Project", description: "Create a blank, unsaved project"},
		{label: "Open Recent Project", description: "Choose a saved project from local history"},
		{label: "Open Project Directory", description: "Open an existing .golan directory"},
		{label: "Import Project Bundle", description: "Import a portable .golanproj bundle"},
		{label: "Start from Config", description: "Snapshot editable config values into a new project"},
		{label: "Quick Live Session", description: "Choose mode and adapters, then review a staged start command", disabled: m.offline},
	}
}

const (
	startupLiveListen           = "listen"
	startupLiveEdgeObserve      = "edge-observe"
	startupLiveEdgeRoute        = "edge-route"
	startupLiveBridgeFast       = "bridge-fast"
	startupLiveBridgeControlled = "bridge-controlled"
)

func startupLiveChoices() []startupChoice {
	return []startupChoice{
		{label: "Passive Listen", description: "Capture one adapter without forwarding"},
		{label: "Edge Observe", description: "Observe one downstream adapter"},
		{label: "Edge Route", description: "Route a downstream client through an upstream adapter"},
		{label: "Fast Bridge", description: "Kernel bridge a host and switch adapter"},
		{label: "Controlled Bridge", description: "Userspace bounded forwarding for enforceable frame rules"},
	}
}

var startupLiveModeOrder = []string{
	startupLiveListen,
	startupLiveEdgeObserve,
	startupLiveEdgeRoute,
	startupLiveBridgeFast,
	startupLiveBridgeControlled,
}

func (m Model) updateStartupChooser(key tea.KeyMsg) (tea.Model, tea.Cmd) {
	name := key.String()
	if name == "ctrl+c" {
		return m, tea.Quit
	}
	if m.startup.view == startupPrompt {
		m.updateStartupPrompt(key)
		return m, nil
	}
	switch name {
	case "?":
		m.openHelp()
	case "esc":
		switch m.startup.view {
		case startupMenu:
			m.closeStartupChooser()
		case startupLiveModes:
			m.startup.view = startupMenu
			m.startup.cursor = len(m.startupChoices()) - 1
		case startupLivePrimary:
			m.startup.view = startupLiveModes
			m.startup.cursor = startupLiveModeIndex(m.startup.liveMode)
		case startupLiveSecondary:
			m.startup.view = startupLivePrimary
			m.startup.cursor = startupAdapterIndex(m.adapters, m.startup.livePrimary, "")
		case startupLiveReview:
			if startupLiveNeedsSecond(m.startup.liveMode) {
				m.startup.view = startupLiveSecondary
				m.startup.cursor = m.startupLiveSecondaryIndex(m.startup.liveSecond)
			} else {
				m.startup.view = startupLivePrimary
				m.startup.cursor = startupAdapterIndex(m.adapters, m.startup.livePrimary, "")
			}
		default:
			m.startup.view = startupMenu
			m.startup.cursor = 0
		}
		m.startup.err = ""
	case "up", "k":
		m.moveStartupCursor(-1)
	case "down", "j":
		m.moveStartupCursor(1)
	case "enter":
		m.selectStartupItem()
	}
	return m, nil
}

func (m *Model) closeStartupChooser() {
	m.startup = startupState{}
	m.activeCard = cardCLI
	m.input = ""
	m.inputMode = modeCommand
	m.completions = nil
	m.resetCompletionCycle()
	m.cursorVisible = true
}

func (m *Model) moveStartupCursor(delta int) {
	count := m.startupItemCount()
	if count == 0 {
		m.startup.cursor = 0
		return
	}
	m.startup.cursor = (clamp(m.startup.cursor, 0, count-1) + delta + count) % count
	m.startup.err = ""
}

func (m Model) startupItemCount() int {
	switch m.startup.view {
	case startupMenu:
		return len(m.startupChoices())
	case startupRecentProjects:
		return len(m.recents.Projects)
	case startupConfigs:
		return len(m.startup.configs)
	case startupLiveModes:
		return len(startupLiveChoices())
	case startupLivePrimary:
		return len(m.adapters)
	case startupLiveSecondary:
		return len(m.startupLiveSecondaryChoices())
	case startupLiveReview:
		return 1
	default:
		return 0
	}
}

func (m *Model) selectStartupItem() {
	m.startup.err = ""
	switch m.startup.view {
	case startupMenu:
		m.selectStartupMenu()
	case startupRecentProjects:
		m.selectStartupRecentProject()
	case startupConfigs:
		if len(m.startup.configs) == 0 {
			m.startup.err = "No saved configs are available."
			return
		}
		index := clamp(m.startup.cursor, 0, len(m.startup.configs)-1)
		m.startup.selected = m.startup.configs[index]
		m.beginStartupPrompt(startupConfigProjectName, startupConfigs, startupDefaultName(m.startup.selected))
	case startupLiveModes:
		m.selectStartupLiveMode()
	case startupLivePrimary:
		m.selectStartupLivePrimary()
	case startupLiveSecondary:
		m.selectStartupLiveSecondary()
	case startupLiveReview:
		m.commitStartupLive()
	}
}

func (m *Model) selectStartupMenu() {
	choices := m.startupChoices()
	index := clamp(m.startup.cursor, 0, len(choices)-1)
	if choices[index].disabled {
		m.startup.err = "Quick Live requires macOS root privileges; project work remains available."
		return
	}
	switch index {
	case 0:
		m.beginStartupPrompt(startupNewName, startupMenu, "")
	case 1:
		m.startup.view = startupRecentProjects
		m.startup.cursor = 0
	case 2:
		m.beginStartupPrompt(startupOpenPath, startupMenu, "")
	case 3:
		m.beginStartupPrompt(startupBundlePath, startupMenu, "")
	case 4:
		m.startup.view = startupConfigs
		m.startup.cursor = 0
	case 5:
		m.startup.view = startupLiveModes
		m.startup.cursor = 0
		m.startup.liveMode = ""
		m.startup.livePrimary = ""
		m.startup.liveSecond = ""
	}
}

func (m *Model) selectStartupLiveMode() {
	if len(m.adapters) == 0 {
		m.startup.err = "No live adapters are available; refresh discovery and try again."
		return
	}
	index := clamp(m.startup.cursor, 0, len(startupLiveModeOrder)-1)
	m.startup.liveMode = startupLiveModeOrder[index]
	m.startup.livePrimary = ""
	m.startup.liveSecond = ""
	m.startup.view = startupLivePrimary
	m.startup.cursor = 0
}

func (m *Model) selectStartupLivePrimary() {
	adapters := startupSortedAdapters(m.adapters, "")
	if len(adapters) == 0 {
		m.startup.err = "No live adapters are available."
		return
	}
	m.startup.livePrimary = adapters[clamp(m.startup.cursor, 0, len(adapters)-1)]
	m.startup.liveSecond = ""
	if startupLiveNeedsSecond(m.startup.liveMode) {
		if len(m.startupLiveSecondaryChoices()) == 0 {
			m.startup.err = "This mode requires a second distinct adapter."
			return
		}
		m.startup.view = startupLiveSecondary
		m.startup.cursor = 0
		return
	}
	m.startup.view = startupLiveReview
	m.startup.cursor = 0
}

func (m *Model) selectStartupLiveSecondary() {
	choices := m.startupLiveSecondaryChoices()
	if len(choices) == 0 {
		m.startup.err = "No compatible second adapter is available."
		return
	}
	m.startup.liveSecond = choices[clamp(m.startup.cursor, 0, len(choices)-1)]
	m.startup.view = startupLiveReview
	m.startup.cursor = 0
}

func startupLiveNeedsSecond(mode string) bool {
	switch mode {
	case startupLiveEdgeRoute, startupLiveBridgeFast, startupLiveBridgeControlled:
		return true
	default:
		return false
	}
}

func startupLiveIsBridge(mode string) bool {
	return mode == startupLiveBridgeFast || mode == startupLiveBridgeControlled
}

func (m Model) startupLiveSecondaryChoices() []string {
	values := startupSortedAdapters(m.adapters, m.startup.livePrimary)
	if !startupLiveIsBridge(m.startup.liveMode) {
		values = append([]string{"auto"}, values...)
	}
	return values
}

func (m Model) startupLiveSecondaryIndex(name string) int {
	for index, candidate := range m.startupLiveSecondaryChoices() {
		if strings.EqualFold(candidate, name) {
			return index
		}
	}
	return 0
}

func startupSortedAdapters(inventory []adapters.Adapter, exclude string) []string {
	values := make([]string, 0, len(inventory))
	for _, adapter := range inventory {
		if adapter.Name != "" && !strings.EqualFold(adapter.Name, exclude) {
			values = append(values, adapter.Name)
		}
	}
	sort.Strings(values)
	return values
}

func startupAdapterIndex(inventory []adapters.Adapter, name, exclude string) int {
	for index, candidate := range startupSortedAdapters(inventory, exclude) {
		if strings.EqualFold(candidate, name) {
			return index
		}
	}
	return 0
}

func startupLiveModeIndex(mode string) int {
	for index, candidate := range startupLiveModeOrder {
		if candidate == mode {
			return index
		}
	}
	return 0
}

func (m *Model) commitStartupLive() {
	if blocker := m.adapterMutationBlocker(); blocker != "" {
		m.startup.err = "Cannot stage live setup: " + blocker
		return
	}
	primary, ok := m.findAdapter(m.startup.livePrimary)
	if !ok {
		m.startup.err = "Primary adapter is no longer available: " + m.startup.livePrimary
		return
	}
	var staged profile.Profile
	if _, err := staged.SetAdapterRole(primary, profile.AdapterRoleHost); err != nil {
		m.startup.err = err.Error()
		return
	}
	if startupLiveIsBridge(m.startup.liveMode) {
		second, ok := m.findAdapter(m.startup.liveSecond)
		if !ok || strings.EqualFold(second.Name, primary.Name) {
			m.startup.err = "Switch adapter is no longer available or distinct."
			return
		}
		if _, err := staged.SetAdapterRole(second, profile.AdapterRoleSwitch); err != nil {
			m.startup.err = err.Error()
			return
		}
	}
	command := startupLiveCommand(m.startup.liveMode)
	m.profile = staged
	m.profileNeedsRehydrate = true
	m.activeAdapter = primary.Name
	switch m.startup.liveMode {
	case startupLiveEdgeObserve:
		m.edgeConfiguredMode = "observe"
	case startupLiveEdgeRoute:
		m.edgeConfiguredMode = "route"
		m.edgeUpstream = m.startup.liveSecond
	case startupLiveBridgeFast, startupLiveBridgeControlled:
		m.activeAdapter = "bridge"
	}
	m.closeStartupChooser()
	m.workspace = workspaceMain
	m.activeCard = cardCLI
	m.input = command
	m.refreshCompletions()
	m.print("quick live: staged mode=" + command + "; no networking started; review the command and press Enter")
}

func startupLiveCommand(mode string) string {
	switch mode {
	case startupLiveEdgeObserve:
		return "start edge observe"
	case startupLiveEdgeRoute:
		return "start edge route"
	case startupLiveBridgeFast:
		return "start bridge fast"
	case startupLiveBridgeControlled:
		return "start bridge controlled"
	default:
		return "start listen"
	}
}

func (m *Model) selectStartupRecentProject() {
	if len(m.recents.Projects) == 0 {
		m.startup.err = "No recent projects are available."
		return
	}
	entry := m.recents.Projects[clamp(m.startup.cursor, 0, len(m.recents.Projects)-1)]
	if !entry.Available {
		m.startup.err = "Project is missing: " + entry.Path
		return
	}
	project, err := workproject.Open(entry.Path)
	if err != nil {
		m.startup.err = "Open project: " + err.Error()
		return
	}
	m.finishStartupProject(project, true)
	m.reportUnindexedProjectArtifacts()
}

func (m *Model) beginStartupPrompt(kind startupPromptKind, returnView startupView, initial string) {
	m.startup.view = startupPrompt
	m.startup.prompt = kind
	m.startup.returnView = returnView
	m.startup.input = initial
	m.startup.err = ""
}

func (m *Model) updateStartupPrompt(key tea.KeyMsg) {
	switch key.String() {
	case "esc":
		m.startup.view = m.startup.returnView
		m.startup.prompt = startupNoPrompt
		m.startup.input = ""
		m.startup.err = ""
	case "enter":
		m.submitStartupPrompt()
	case "backspace", "ctrl+h":
		m.startup.input = trimLastRune(m.startup.input)
		m.startup.err = ""
	case "ctrl+u":
		m.startup.input = ""
		m.startup.err = ""
	default:
		if len(m.startup.input) < 8192 {
			m.startup.input = appendInput(m.startup.input, key)
		}
	}
}

func (m *Model) submitStartupPrompt() {
	value := strings.TrimSpace(m.startup.input)
	if value == "" {
		m.startup.err = "A value is required."
		return
	}
	var err error
	switch m.startup.prompt {
	case startupNewName:
		var project *workproject.Project
		project, err = workproject.NewDefault(value)
		if err == nil {
			m.finishStartupProject(project, false)
		}
	case startupOpenPath:
		var project *workproject.Project
		project, err = workproject.Open(value)
		if err == nil {
			m.finishStartupProject(project, true)
			m.reportUnindexedProjectArtifacts()
		}
	case startupBundlePath:
		err = m.startProjectFromBundle(value)
	case startupConfigProjectName:
		err = m.startProjectFromConfig(m.startup.selected, value)
	default:
		err = fmt.Errorf("unknown startup prompt")
	}
	if err != nil {
		m.startup.err = err.Error()
	}
}

func (m *Model) finishStartupProject(project *workproject.Project, remember bool) {
	m.attachProject(project)
	m.workspace = workspaceMain
	if remember {
		m.rememberRecentProject(project)
	}
	m.closeStartupChooser()
	if project.Dirty() {
		m.print("project: ready " + project.Path() + " (PROJECT*)")
	} else {
		m.print("project: open " + project.Path())
	}
}

func (m *Model) startProjectFromBundle(path string) error {
	root, err := workproject.DefaultRoot()
	if err != nil {
		return fmt.Errorf("import bundle: %w", err)
	}
	name := startupDefaultName(path)
	project, report, err := workproject.ImportBundleWithReport(context.Background(), path, root, name)
	if err != nil {
		return fmt.Errorf("import bundle: %w", err)
	}
	m.finishStartupProject(project, true)
	m.printBundleReport("import", report)
	m.reportUnindexedProjectArtifacts()
	return nil
}

func (m *Model) startProjectFromConfig(configName, projectName string) error {
	snapshot, path, err := configs.Load(configName)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	if err := validateProjectConfigSnapshot(snapshot); err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	project, err := workproject.NewDefault(projectName)
	if err != nil {
		return fmt.Errorf("new project: %w", err)
	}
	if _, err := project.ImportConfig(path); err != nil {
		return err
	}
	m.stageProjectConfigSnapshot(snapshot)
	m.finishStartupProject(project, false)
	m.print("config staged from immutable snapshot: " + path)
	return nil
}

func validateProjectConfigSnapshot(snapshot configs.Snapshot) error {
	return nil
}

func (m *Model) stageProjectConfigSnapshot(snapshot configs.Snapshot) {
	m.profile = snapshot.Profile
	m.profileNeedsRehydrate = true
	m.applySnapshotSettings(snapshot.Settings)
	m.activeAdapter = ""
	if isBridgeContext(snapshot.ActiveAdapter) {
		m.profile.BridgeAdapter()
		m.activeAdapter = "bridge"
	} else if _, ok := m.profile.ByName(snapshot.ActiveAdapter); ok {
		m.activeAdapter = snapshot.ActiveAdapter
	}
}

func startupDefaultName(path string) string {
	name := filepath.Base(strings.TrimSpace(path))
	ext := filepath.Ext(name)
	if ext != "" {
		name = strings.TrimSuffix(name, ext)
	}
	return name
}

func startupPromptLabel(kind startupPromptKind) string {
	switch kind {
	case startupNewName:
		return "Project name"
	case startupOpenPath:
		return "Project directory"
	case startupBundlePath:
		return "Bundle path"
	case startupConfigProjectName:
		return "New project name"
	default:
		return "Value"
	}
}

func (m Model) renderStartupChooser() string {
	terminalCols := terminalWidth(m.width)
	width := renderWidth(terminalCols)
	height := renderHeight(terminalHeight(m.height))
	margin := horizontalMargin(terminalCols)
	title, rows := m.startupRowsForView()
	if m.startup.err != "" {
		rows = append(rows, "", styleError.Render(m.startup.err))
	}
	footer := " ↑/↓ or j/k move   Enter select   Esc back/command mode   F1 help "
	contentHeight := max(4, height-1)
	content := box(title, rows, width, contentHeight, true)
	view := lipgloss.JoinVertical(lipgloss.Left, content, styleFooterBar.Render(fit(footer, width)))
	return insetBlock(clampBlock(view, width, height), margin)
}

func (m Model) startupRowsForView() (string, []string) {
	switch m.startup.view {
	case startupRecentProjects:
		rows := []string{"Saved projects from local history", ""}
		if len(m.recents.Projects) == 0 {
			return "OPEN RECENT PROJECT", append(rows, "No recent projects.")
		}
		for index, entry := range m.recents.Projects {
			label := fmt.Sprintf("%s  %s", entry.Name, entry.Path)
			if !entry.Available {
				label += "  [missing]"
			}
			rows = append(rows, startupCursorRow(index == m.startup.cursor, label, !entry.Available))
		}
		return "OPEN RECENT PROJECT", rows
	case startupConfigs:
		rows := []string{"Choose a saved config to snapshot. Live adapter metadata is not applied yet.", ""}
		if len(m.startup.configs) == 0 {
			return "START FROM CONFIG", append(rows, "No saved configs.")
		}
		for index, name := range m.startup.configs {
			rows = append(rows, startupCursorRow(index == m.startup.cursor, name, false))
		}
		return "START FROM CONFIG", rows
	case startupLiveModes:
		rows := []string{"Choose a live data plane. This wizard only stages configuration.", ""}
		for index, choice := range startupLiveChoices() {
			rows = append(rows, startupCursorRow(index == m.startup.cursor, choice.label+" — "+choice.description, false))
		}
		return "QUICK LIVE — MODE", rows
	case startupLivePrimary:
		label := "downstream"
		if startupLiveIsBridge(m.startup.liveMode) {
			label = "host-side"
		}
		rows := []string{"Choose the " + label + " adapter. Adapter isolation remains deferred until Start.", ""}
		adapterNames := startupSortedAdapters(m.adapters, "")
		if len(adapterNames) == 0 {
			rows = append(rows, "No live adapters are available.")
		}
		for index, name := range adapterNames {
			rows = append(rows, startupCursorRow(index == m.startup.cursor, name, false))
		}
		return "QUICK LIVE — PRIMARY ADAPTER", rows
	case startupLiveSecondary:
		label := "upstream adapter"
		if startupLiveIsBridge(m.startup.liveMode) {
			label = "switch-side adapter"
		}
		rows := []string{"Choose a distinct " + label + ". Auto resolves the IPv4 default route at Start.", ""}
		for index, name := range m.startupLiveSecondaryChoices() {
			rows = append(rows, startupCursorRow(index == m.startup.cursor, name, false))
		}
		return "QUICK LIVE — SECOND ADAPTER", rows
	case startupLiveReview:
		command := startupLiveCommand(m.startup.liveMode)
		rows := []string{
			"Review staged configuration. Enter returns to Setup with the command ready for explicit execution.",
			"",
			"Mode       " + command,
			"Primary    " + m.startup.livePrimary,
		}
		if m.startup.liveSecond != "" {
			rows = append(rows, "Secondary  "+m.startup.liveSecond)
		}
		rows = append(rows,
			"",
			styleWarn.Render("NO NETWORKING HAS STARTED"),
			"Start will refresh adapter metadata, isolate selected interfaces, and require review/retry before activation.",
		)
		return "QUICK LIVE — REVIEW", rows
	case startupPrompt:
		cursor := " "
		if m.cursorVisible {
			cursor = "|"
		}
		rows := []string{startupPromptLabel(m.startup.prompt), "", styleText.Render("> " + m.startup.input + cursor), "", "Enter confirms. Esc returns without changing project state."}
		return "STARTUP INPUT", rows
	default:
		rows := []string{"Choose how to begin. No selection starts networking.", ""}
		for index, choice := range m.startupChoices() {
			label := choice.label + " — " + choice.description
			if choice.disabled {
				label += "  [offline]"
			}
			rows = append(rows, startupCursorRow(index == m.startup.cursor, label, choice.disabled))
		}
		return "GOLAN WORKBENCH START", rows
	}
}

func startupCursorRow(selected bool, label string, disabled bool) string {
	prefix := "  "
	if selected {
		prefix = "> "
	}
	row := prefix + label
	if selected {
		return styleFocus.Render(row)
	}
	if disabled {
		return styleMuted.Render(row)
	}
	return row
}

func joinStartupError(existing, next string) string {
	if existing == "" {
		return next
	}
	return existing + "; " + next
}
