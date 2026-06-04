package tui

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"
	"unicode"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"golan/internal/adapters"
	bridge "golan/internal/bridge"
	"golan/internal/canvas"
	"golan/internal/configs"
	"golan/internal/inspect"
	"golan/internal/listen"
	"golan/internal/profile"
)

// Model owns the command-first initialization TUI state.
type Model struct {
	adapters             []adapters.Adapter
	profile              profile.Profile
	loading              bool
	err                  error
	listener             *listen.Session
	capMode              string
	bridge               *bridge.Session
	natActive            bool
	eapolSuppressLogoff  bool
	eapolDowngradeMACsec bool

	bridgeState  string
	restoreState map[string]bridge.InterfaceRestoreState
	lockPending  map[string]bool

	activeAdapter string
	cursorVisible bool
	activeCard    cardFocus
	outputScroll  int
	miscScroll    int
	output        []string
	outputMuted   []bool
	traffic       []string
	findings      []string
	pcapDirs      []string
	signalSeen    map[string]bool
	canvasMap     *canvas.Map
	canvasEnabled bool
	canvasPath    string
	canvasDirty   bool
	input         string
	inputMode     inputMode
	completions   []string
	cycleContext  string
	cycleIndex    int
	cycleOptions  []string
	history       []string
	historyIndex  int

	width  int
	height int
}

type discoveredMsg struct {
	adapters []adapters.Adapter
	err      error
}

type cursorBlinkMsg struct{}

type listenStartedMsg struct {
	session *listen.Session
	err     error
	mode    string
}

type listenEventMsg struct {
	session *listen.Session
	event   listen.Event
	ok      bool
}

type bridgeStartedMsg struct {
	session *bridge.Session
	err     error
}

type bridgeEventMsg struct {
	session *bridge.Session
	event   bridge.Event
	ok      bool
}

type bridgeStoppedMsg struct {
	session *bridge.Session
	err     error
}

type bridgeNATMsg struct {
	session *bridge.Session
	active  bool
	err     error
}

type eapolSentMsg struct {
	session *bridge.Session
	err     error
}

type adapterStateMsg struct {
	name  string
	state string
	err   error
}

type adapterLockdownMsg struct {
	name  string
	role  string
	state bridge.InterfaceRestoreState
	err   error
}

type adapterRestoreMsg struct {
	name string
	err  error
}

type cardFocus int
type inputMode int

const (
	cardOutput cardFocus = iota
	cardCLI
	cardMisc
)

const (
	modeCommand inputMode = iota
	modeSaveName
)

const (
	cursorBlinkInterval = 500 * time.Millisecond
)

// NewModel creates a new setup model. The output pane intentionally starts
// blank; command output appears only after the user runs a command.
func NewModel() Model {
	return Model{
		loading:              true,
		cursorVisible:        true,
		activeCard:           cardCLI,
		cycleIndex:           -1,
		historyIndex:         -1,
		restoreState:         make(map[string]bridge.InterfaceRestoreState),
		lockPending:          make(map[string]bool),
		signalSeen:           make(map[string]bool),
		canvasMap:            canvas.NewMap(),
		eapolSuppressLogoff:  true,
		eapolDowngradeMACsec: true,
	}
}

func NewModelWithSize(width, height int) Model {
	m := NewModel()
	if width > 0 {
		m.width = width
	}
	if height > 0 {
		m.height = height
	}
	return m
}

func (m Model) Init() tea.Cmd {
	return tea.Batch(discoverAdaptersCmd, blinkCursorCmd())
}

// Shutdown synchronously persists and tears down runtime resources held by a
// returned Bubble Tea model. It is safe to call after normal quits and signal
// interruptions; repeated calls are harmless.
func Shutdown(model tea.Model) error {
	switch model := model.(type) {
	case Model:
		return model.shutdown()
	case *Model:
		return model.shutdown()
	default:
		return nil
	}
}

func PcapDirs(model tea.Model) []string {
	switch model := model.(type) {
	case Model:
		return model.pcapDirsSnapshot()
	case *Model:
		return model.pcapDirsSnapshot()
	default:
		return nil
	}
}

func (m *Model) shutdown() error {
	var errs []error
	m.recordActivePcapDirs()
	if err := m.saveCanvas(); err != nil {
		m.print("canvas err: " + err.Error())
		errs = append(errs, fmt.Errorf("save canvas: %w", err))
	}
	if err := m.stopCapture(); err != nil {
		errs = append(errs, fmt.Errorf("stop listen: %w", err))
	}
	if err := m.stopBridgeNow(); err != nil {
		errs = append(errs, fmt.Errorf("stop bridge: %w", err))
	}
	if err := m.restoreLockedAdaptersNow(); err != nil {
		errs = append(errs, fmt.Errorf("restore adapters: %w", err))
	}
	return errors.Join(errs...)
}

func blinkCursorCmd() tea.Cmd {
	return tea.Tick(cursorBlinkInterval, func(time.Time) tea.Msg {
		return cursorBlinkMsg{}
	})
}

func discoverAdaptersCmd() tea.Msg {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	list, err := adapters.Discover(ctx)
	return discoveredMsg{adapters: list, err: err}
}

func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case discoveredMsg:
		m.loading = false
		m.adapters = msg.adapters
		m.err = msg.err
		m.refreshCompletions()
		return m, nil
	case tea.WindowSizeMsg:
		if m.width == 0 || m.height == 0 {
			m.width = msg.Width
			m.height = msg.Height
			m.trimTraffic()
			m.trimFindings()
		}
		return m, nil
	case cursorBlinkMsg:
		m.cursorVisible = !m.cursorVisible
		return m, blinkCursorCmd()
	case listenStartedMsg:
		if msg.err != nil {
			m.print(msg.mode + " err: " + msg.err.Error())
			return m, nil
		}
		m.listener = msg.session
		m.capMode = msg.mode
		m.print("listen: on")
		m.print("pcap: " + msg.session.Dir)
		m.rememberPcapDir(msg.session.Dir)
		return m, waitListenEventCmd(msg.session)
	case listenEventMsg:
		if m.listener != msg.session {
			return m, nil
		}
		if !msg.ok {
			m.listener = nil
			mode := m.capMode
			m.capMode = ""
			if mode == "" {
				mode = "listen"
			}
			m.print(mode + ": off")
			return m, nil
		}
		cmd := m.handleListenEvent(msg.event)
		return m, cmd
	case bridgeStartedMsg:
		if msg.err != nil {
			m.print("bridge err: " + msg.err.Error())
			return m, nil
		}
		m.bridge = msg.session
		m.bridgeState = "starting"
		m.print("bridge: on")
		m.print("pcap: " + msg.session.Dir)
		m.rememberPcapDir(msg.session.Dir)
		return m, waitBridgeEventCmd(msg.session)
	case bridgeEventMsg:
		if m.bridge != msg.session {
			return m, nil
		}
		if !msg.ok {
			m.bridge = nil
			m.bridgeState = ""
			m.natActive = false
			m.print("bridge: off")
			return m, nil
		}
		return m, m.handleBridgeEvent(msg.session, msg.event)
	case bridgeStoppedMsg:
		wasActive := m.bridge == msg.session
		if wasActive {
			m.bridge = nil
			m.bridgeState = ""
			m.natActive = false
		}
		if msg.err != nil {
			m.print("bridge err: stop " + msg.err.Error())
		} else if wasActive {
			m.print("bridge: off")
		}
		return m, nil
	case bridgeNATMsg:
		if m.bridge != msg.session {
			return m, nil
		}
		if msg.err != nil {
			m.print("nat err: " + msg.err.Error())
			return m, nil
		}
		m.natActive = msg.active
		if msg.active {
			m.print("nat: on")
		} else {
			m.print("nat: off")
		}
		return m, nil
	case eapolSentMsg:
		if m.bridge != msg.session {
			return m, nil
		}
		if msg.err != nil {
			m.print("send err: " + msg.err.Error())
			return m, nil
		}
		m.print("send: eapol start")
		return m, nil
	case adapterStateMsg:
		if msg.err != nil {
			m.print(fmt.Sprintf("adapter state err %s: %v", msg.name, msg.err))
			return m, nil
		}
		if cfg, ok := m.profile.ByName(msg.name); ok {
			_, _ = cfg.Set("state", msg.state)
		}
		m.updateAdapterStatus(msg.name, msg.state == "up")
		m.print(fmt.Sprintf("adapter state: %s %s", msg.name, msg.state))
		return m, nil
	case adapterLockdownMsg:
		if m.restoreState == nil {
			m.restoreState = make(map[string]bridge.InterfaceRestoreState)
		}
		if m.lockPending != nil {
			delete(m.lockPending, msg.name)
		}
		if _, exists := m.restoreState[msg.name]; !exists {
			m.restoreState[msg.name] = msg.state
		}
		m.updateAdapterStatus(msg.name, false)
		if msg.err != nil {
			m.print(fmt.Sprintf("adapter isolate warn %s: %v", msg.name, msg.err))
		} else {
			m.print(fmt.Sprintf("adapter isolated: %s %s", msg.role, msg.name))
		}
		return m, nil
	case adapterRestoreMsg:
		if msg.err != nil {
			m.print(fmt.Sprintf("adapter restore warn %s: %v", msg.name, msg.err))
		} else {
			m.print("adapter restored: " + msg.name)
		}
		return m, nil
	case tea.KeyMsg:
		return m.updateCLI(msg)
	default:
		return m, nil
	}
}

func (m Model) updateCLI(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "ctrl+c":
		_ = m.shutdown()
		return m, tea.Quit
	case "ctrl+s":
		m.startSavePrompt()
	case "left":
		m.moveCardFocus(-1)
	case "right":
		m.moveCardFocus(1)
	case "esc":
		m.activeCard = cardCLI
		m.input = ""
		m.inputMode = modeCommand
		m.completions = nil
		m.resetCompletionCycle()
		m.cursorVisible = true
	case "enter":
		m.activeCard = cardCLI
		raw := strings.TrimSpace(m.input)
		m.input = ""
		m.completions = nil
		m.resetCompletionCycle()
		m.cursorVisible = true
		if m.inputMode == modeSaveName {
			m.inputMode = modeCommand
			if raw == "" {
				m.print("save: cancel")
				return m, nil
			}
			m.saveConfig(raw)
			return m, nil
		}
		if raw == "" {
			return m, nil
		}
		m.history = append(m.history, raw)
		m.historyIndex = -1
		cmd := m.executeCommand(raw)
		return m, cmd
	case "backspace", "ctrl+h":
		m.activeCard = cardCLI
		m.input = trimLastRune(m.input)
		m.resetCompletionCycle()
		m.refreshCompletions()
		m.cursorVisible = true
	case "ctrl+u":
		m.activeCard = cardCLI
		m.input = ""
		m.completions = nil
		m.resetCompletionCycle()
		m.cursorVisible = true
	case "tab":
		m.activeCard = cardCLI
		m.applyCompletion()
		m.cursorVisible = true
	case "up":
		m.handleVerticalMove(-1)
		m.cursorVisible = true
	case "down":
		m.handleVerticalMove(1)
		m.cursorVisible = true
	default:
		m.activeCard = cardCLI
		m.input = appendInput(m.input, msg)
		m.resetCompletionCycle()
		m.refreshCompletions()
		m.cursorVisible = true
	}
	return m, nil
}

func (m *Model) startSavePrompt() {
	m.activeCard = cardCLI
	m.inputMode = modeSaveName
	m.input = ""
	m.completions = nil
	m.resetCompletionCycle()
	m.cursorVisible = true
	m.print("save as:")
}

func (m *Model) moveCardFocus(delta int) {
	next := int(m.activeCard) + delta
	if next < int(cardOutput) {
		next = int(cardMisc)
	}
	if next > int(cardMisc) {
		next = int(cardOutput)
	}
	m.activeCard = cardFocus(next)
}

func (m *Model) handleVerticalMove(delta int) {
	switch m.activeCard {
	case cardOutput:
		m.outputScroll = max(0, m.outputScroll-delta)
	case cardMisc:
		return
	default:
		m.recallHistory(delta)
	}
}

func (m *Model) executeCommand(raw string) tea.Cmd {
	m.print(m.prompt() + raw)
	fields := strings.Fields(raw)
	if len(fields) == 0 {
		return nil
	}

	switch strings.ToLower(fields[0]) {
	case "help", "?":
		m.showHelp()
	case "show":
		m.executeShow(fields[1:])
	case "clear", "cls":
		m.output = nil
		m.outputMuted = nil
		m.traffic = nil
		m.findings = nil
		m.outputScroll = 0
	case "set":
		return m.executeSet(fields[1:])
	case "unset":
		return m.executeUnset(fields[1:])
	case "conf", "config", "configure":
		return m.executeConf(fields[1:])
	case "load":
		m.executeLoad(fields[1:])
	case "enable":
		return m.executeEnable(fields[1:])
	case "disable":
		return m.executeDisable(fields[1:])
	case "start":
		return m.executeStart(fields[1:])
	case "stop":
		return m.executeStop(fields[1:])
	case "send":
		return m.executeSend(fields[1:])
	case "listen", "bridge":
		m.print("use: start " + strings.ToLower(fields[0]) + " | stop " + strings.ToLower(fields[0]))
	case "up":
		return m.executeActiveAdapterState("up")
	case "down":
		return m.executeActiveAdapterState("down")
	case "refresh":
		m.loading = true
		m.err = nil
		m.print("refresh: adapters")
		return discoverAdaptersCmd
	case "quit", "exit":
		_ = m.shutdown()
		return tea.Quit
	default:
		m.print("unknown: " + fields[0])
		m.print("use: help")
	}
	return nil
}

func (m Model) prompt() string {
	if m.inputMode == modeSaveName {
		return "save as > "
	}
	if m.activeAdapter == "" {
		return "> "
	}
	return "> (" + m.activeAdapter + ") "
}

func isBridgeContext(name string) bool {
	return strings.EqualFold(strings.TrimSpace(name), "bridge")
}

func (m *Model) activeConfig() (*profile.AdapterConfig, bool) {
	if isBridgeContext(m.activeAdapter) {
		return m.profile.BridgeAdapter(), true
	}
	return m.profile.ByName(m.activeAdapter)
}

func isAutoValue(value string) bool {
	value = strings.TrimSpace(value)
	return value == "" || strings.EqualFold(value, "auto")
}

func (m *Model) executeShow(args []string) {
	if len(args) == 0 {
		m.print("use: show adapters|config|bridge|secrets")
		return
	}
	switch strings.ToLower(args[0]) {
	case "adapters", "adapter":
		m.showAdapters()
	case "config", "conf":
		m.showConfig()
	case "bridge":
		m.showBridge()
	case "secrets", "secret", "findings":
		m.showSecrets()
	default:
		m.print("use: show adapters|config|bridge|secrets")
	}
}

func (m *Model) executeSet(args []string) tea.Cmd {
	if len(args) == 0 {
		m.print("use: set <adapter> <host|switch> | set <property> <value>")
		return nil
	}

	key := strings.ToLower(args[0])
	if key == "adapter" {
		if len(args) < 2 {
			m.print("use: set adapter <name> [host|switch]")
			return nil
		}
		if len(args) >= 3 {
			return m.stageAdapter(args[1], args[2])
		}
		return m.stageAdapterNext(args[1])
	}

	if _, ok := m.findAdapter(args[0]); ok {
		if len(args) < 2 {
			m.print("use: set <adapter> <host|switch>")
			return nil
		}
		return m.stageAdapter(args[0], args[1])
	}

	if len(args) < 2 {
		m.print("use: set <property> <value>")
		return nil
	}
	if m.activeAdapter == "" {
		m.print("ctx: none; use: conf <adapter>")
		return nil
	}

	cfg, ok := m.activeConfig()
	if !ok {
		m.print("ctx: stale")
		m.activeAdapter = ""
		return nil
	}

	value := strings.Join(args[1:], " ")
	old, err := cfg.Set(key, value)
	if err != nil {
		m.print("set err: " + err.Error())
		return nil
	}
	canonical := profile.CanonicalKey(key)
	next := cfg.Value(canonical)
	autoApplied := false
	if strings.EqualFold(next, "auto") {
		if _, ok := cfg.ApplyFirstDiscovery(canonical); ok {
			next = cfg.Value(canonical)
			autoApplied = true
		}
	}
	if old == next {
		m.print(fmt.Sprintf("%s %s: same %s", cfg.Name, canonical, next))
		return nil
	}
	suffix := ""
	if autoApplied {
		suffix = " auto"
	}
	m.print(fmt.Sprintf("%s %s: %s -> %s%s", cfg.Name, canonical, old, next, suffix))
	m.syncCanvasProfile()
	return nil
}

func (m *Model) stageAdapter(name, roleValue string) tea.Cmd {
	adapter, ok := m.findAdapter(name)
	if !ok {
		m.print("adapter err: " + name)
		return nil
	}
	adapterRole := profile.CanonicalAdapterRole(roleValue)
	if !profile.ValidAdapterRole(adapterRole) {
		m.print("role err: host|switch")
		return nil
	}
	before := append([]profile.AdapterConfig(nil), m.profile.Adapters...)
	cfg, err := m.profile.SetAdapterRole(adapter, adapterRole)
	if err != nil {
		m.print("adapter err: " + err.Error())
		return nil
	}
	if m.activeAdapter != "" && !isBridgeContext(m.activeAdapter) {
		if _, ok := m.profile.ByName(m.activeAdapter); !ok {
			m.activeAdapter = ""
		}
	}
	if strings.EqualFold(m.activeAdapter, cfg.Name) {
		m.activeAdapter = ""
	}
	m.miscScroll = 0
	m.print(fmt.Sprintf("adapter: %s %s", cfg.AdapterRole, cfg.Name))
	m.markLockPending(cfg.Name)
	m.syncCanvasProfile()
	return tea.Batch(append(m.restoreRemovedAdapterCmds(before), lockdownAdapterCmd(cfg))...)
}

func (m *Model) stageAdapterNext(name string) tea.Cmd {
	adapter, ok := m.findAdapter(name)
	if !ok {
		m.print("adapter err: " + name)
		return nil
	}
	cfg, err := m.profile.Add(adapter)
	if err != nil {
		m.print("adapter err: " + err.Error())
		return nil
	}
	m.miscScroll = 0
	m.print(fmt.Sprintf("adapter: %s %s", cfg.AdapterRole, cfg.Name))
	m.markLockPending(cfg.Name)
	m.syncCanvasProfile()
	return lockdownAdapterCmd(cfg)
}

func (m *Model) executeUnset(args []string) tea.Cmd {
	if len(args) == 0 {
		return m.unsetAdapter(m.activeAdapter)
	}
	if strings.EqualFold(args[0], "adapter") {
		if len(args) == 1 {
			return m.unsetAdapter(m.activeAdapter)
		}
		return m.unsetAdapter(args[1])
	}
	m.print("use: unset | unset adapter <name>")
	return nil
}

func (m *Model) unsetAdapter(name string) tea.Cmd {
	if name == "" {
		m.print("ctx: none; use: conf <adapter>")
		return nil
	}
	removed, ok := m.profile.RemoveName(name)
	if !ok {
		m.print("adapter unset: " + name)
		return nil
	}
	if strings.EqualFold(m.activeAdapter, removed.Name) {
		m.activeAdapter = ""
	}
	m.miscScroll = 0
	m.print("adapter off: " + removed.Name)
	if m.lockPending != nil {
		delete(m.lockPending, removed.Name)
	}
	m.syncCanvasProfile()
	return m.restoreAdapterCmd(removed.Name)
}

func (m *Model) markLockPending(name string) {
	if m.lockPending == nil {
		m.lockPending = make(map[string]bool)
	}
	m.lockPending[name] = true
}

func (m *Model) restoreRemovedAdapterCmds(before []profile.AdapterConfig) []tea.Cmd {
	var cmds []tea.Cmd
	for _, cfg := range before {
		if _, ok := m.profile.ByName(cfg.Name); ok {
			continue
		}
		if cmd := m.restoreAdapterCmd(cfg.Name); cmd != nil {
			cmds = append(cmds, cmd)
		}
	}
	return cmds
}

func (m *Model) restoreAdapterCmd(name string) tea.Cmd {
	if m.restoreState == nil {
		return nil
	}
	state, ok := m.restoreState[name]
	if !ok {
		return nil
	}
	delete(m.restoreState, name)
	return func() tea.Msg {
		return adapterRestoreMsg{name: name, err: bridge.RestoreInterfaceState(state)}
	}
}

func lockdownAdapterCmd(cfg profile.AdapterConfig) tea.Cmd {
	return func() tea.Msg {
		state := bridge.CaptureInterfaceRestoreState(cfg.Name, cfg.HardwarePort)
		err := bridge.LockdownInterface(cfg.Name, cfg.HardwarePort)
		return adapterLockdownMsg{name: cfg.Name, role: cfg.AdapterRole, state: state, err: err}
	}
}

func (m *Model) saveConfig(name string) {
	if !m.profile.Ready() {
		m.print("save err: no adapter")
		return
	}
	settings := m.snapshotSettings()
	path, err := configs.Save(name, configs.Snapshot{
		ActiveAdapter: m.activeAdapter,
		Profile:       m.profile,
		Settings:      &settings,
	})
	if err != nil {
		m.print("save err: " + err.Error())
		return
	}
	m.print("saved: " + path)
}

func (m *Model) executeLoad(args []string) {
	if len(args) == 0 {
		m.listConfigs()
		return
	}
	if args[0] == "<>" {
		m.listConfigs()
		return
	}
	snapshot, path, err := configs.Load(args[0])
	if err != nil {
		m.print("load err: " + err.Error())
		return
	}
	m.profile = snapshot.Profile
	m.applySnapshotSettings(snapshot.Settings)
	m.activeAdapter = ""
	if snapshot.ActiveAdapter != "" {
		if isBridgeContext(snapshot.ActiveAdapter) {
			m.profile.BridgeAdapter()
			m.activeAdapter = "bridge"
		} else if _, ok := m.profile.ByName(snapshot.ActiveAdapter); ok {
			m.activeAdapter = snapshot.ActiveAdapter
		}
	}
	m.miscScroll = 0
	m.print("loaded: " + path)
	m.syncCanvasProfile()
}

func (m Model) snapshotSettings() configs.Settings {
	return configs.Settings{
		CanvasEnabled:        m.canvasEnabled,
		CanvasPath:           m.canvasPath,
		EAPOLLogoffDrop:      m.eapolSuppressLogoff,
		EAPOLDowngradeMACsec: m.eapolDowngradeMACsec,
	}
}

func (m *Model) applySnapshotSettings(settings *configs.Settings) {
	next := configs.DefaultSettings()
	if settings != nil {
		next = *settings
	}
	m.canvasEnabled = next.CanvasEnabled
	m.canvasPath = next.CanvasPath
	if m.canvasMap == nil {
		m.canvasMap = canvas.NewMap()
	}
	m.eapolSuppressLogoff = next.EAPOLLogoffDrop
	m.eapolDowngradeMACsec = next.EAPOLDowngradeMACsec
	if m.bridge != nil {
		m.bridge.SetEAPOLPolicy(m.eapolPolicy())
	}
}

func (m *Model) executeStart(args []string) tea.Cmd {
	if len(args) == 0 {
		m.print("use: start listen|bridge|nat")
		return nil
	}

	switch strings.ToLower(args[0]) {
	case "listen":
		if pending := m.pendingLocks(); len(pending) > 0 {
			m.print("listen err: adapter isolate pending " + strings.Join(pending, ","))
			return nil
		}
		if m.natActive {
			m.print("listen err: nat")
			return nil
		}
		if m.bridge != nil {
			m.print("listen err: bridge")
			return nil
		}
		if m.listener != nil {
			if m.capMode == "listen" {
				m.print("listen: on")
			} else {
				m.print("listen err: bridge")
			}
			return nil
		}
		targets := m.listenTargets()
		if len(targets) == 0 {
			m.print("listen err: no adapter")
			return nil
		}
		m.print("listen: start")
		return startListenCmd(targets, "listen")
	case "bridge":
		if pending := m.pendingLocks(); len(pending) > 0 {
			m.print("bridge err: adapter isolate pending " + strings.Join(pending, ","))
			return nil
		}
		if m.bridge != nil {
			m.print("bridge: on")
			return nil
		}
		if m.listener != nil {
			m.print("bridge err: listen")
			return nil
		}
		host, sw, errText := m.bridgeAdapters()
		if errText != "" {
			m.print("bridge err: " + errText)
			return nil
		}
		m.print("bridge: start")
		return startBridgeCmd(host, sw, m.eapolPolicy())
	case "nat":
		if m.bridge == nil {
			m.print("nat err: bridge")
			return nil
		}
		if m.natActive {
			m.print("nat: on")
			return nil
		}
		m.print("nat: start")
		return startNATCmd(m.bridge, m.bridgeTakeoverConfig())
	default:
		m.print("use: start listen|bridge|nat")
		return nil
	}
}

func (m *Model) executeEnable(args []string) tea.Cmd {
	if len(args) == 1 && strings.EqualFold(args[0], "canvas") {
		return m.enableCanvas()
	}
	return m.setEAPOLToggle(true, args)
}

func (m *Model) enableCanvas() tea.Cmd {
	if m.canvasMap == nil {
		m.canvasMap = canvas.NewMap()
	}
	m.syncCanvasProfile()
	if m.canvasPath == "" {
		path, err := canvas.SessionPath()
		if err != nil {
			m.print("canvas err: " + err.Error())
			return nil
		}
		m.canvasPath = path
	}
	m.canvasEnabled = true
	m.canvasDirty = true
	if err := m.saveCanvas(); err != nil {
		m.print("canvas err: " + err.Error())
		return nil
	}
	m.print("canvas: on " + m.canvasPath)
	return nil
}

func (m *Model) executeDisable(args []string) tea.Cmd {
	if len(args) == 1 && strings.EqualFold(args[0], "canvas") {
		return m.disableCanvas()
	}
	return m.setEAPOLToggle(false, args)
}

func (m *Model) disableCanvas() tea.Cmd {
	if !m.canvasEnabled {
		m.print("canvas: off")
		return nil
	}
	if err := m.saveCanvas(); err != nil {
		m.print("canvas err: " + err.Error())
		return nil
	}
	m.canvasEnabled = false
	m.print("canvas: off " + m.canvasPath)
	return nil
}

func (m *Model) setEAPOLToggle(enabled bool, args []string) tea.Cmd {
	action := toggleAction(enabled)
	if len(args) != 2 || !strings.EqualFold(args[0], "eapol") {
		m.print("use: " + action + " canvas|eapol drop-logoff|eapol macsec-downgrade")
		return nil
	}
	switch strings.ToLower(args[1]) {
	case "drop-logoff":
		m.setEAPOLLogoffToggle(enabled)
	case "macsec-downgrade":
		m.setMACsecToggle(enabled)
	default:
		m.print("use: " + action + " eapol drop-logoff|eapol macsec-downgrade")
	}
	return nil
}

func toggleAction(enabled bool) string {
	if enabled {
		return "enable"
	}
	return "disable"
}

func (m *Model) setEAPOLLogoffToggle(enabled bool) {
	m.eapolSuppressLogoff = enabled
	if m.bridge != nil {
		m.bridge.SetEAPOLPolicy(m.eapolPolicy())
	}
	m.print(eapolLogoffStatus(enabled))
}

func (m *Model) setMACsecToggle(enabled bool) {
	m.eapolDowngradeMACsec = enabled
	if m.bridge != nil {
		m.bridge.SetEAPOLPolicy(m.eapolPolicy())
	}
	m.print(macsecStatus(enabled))
}

func (m *Model) executeStop(args []string) tea.Cmd {
	if len(args) == 0 {
		m.print("use: stop listen|bridge|nat")
		return nil
	}

	switch strings.ToLower(args[0]) {
	case "listen":
		if m.listener == nil || m.capMode != "listen" {
			m.print("listen: off")
			return nil
		}
		_ = m.stopCapture()
		m.print("listen: stop")
		return nil
	case "bridge":
		if m.bridge == nil {
			m.print("bridge: off")
			return nil
		}
		if m.natActive {
			m.print("bridge err: nat; use: stop nat")
			return nil
		}
		m.print("bridge: stop")
		return stopBridgeCmd(m.bridge)
	case "nat":
		if m.bridge == nil || !m.natActive {
			m.print("nat: off")
			return nil
		}
		m.print("nat: stop")
		return stopNATCmd(m.bridge)
	default:
		m.print("use: stop listen|bridge|nat")
		return nil
	}
}

func (m *Model) executeSend(args []string) tea.Cmd {
	if len(args) != 2 || !strings.EqualFold(args[0], "eapol") || !strings.EqualFold(args[1], "start") {
		m.print("use: send eapol start")
		return nil
	}
	if m.bridge == nil {
		m.print("send err: bridge")
		return nil
	}
	m.print("send: eapol start")
	return sendEAPOLStartCmd(m.bridge)
}

func (m Model) listenTargets() []listen.Target {
	cfg, ok := m.profile.Role(profile.AdapterRoleHost)
	if !ok {
		return nil
	}
	target := *cfg
	if adapter, ok := m.findAdapter(target.Name); ok {
		target.CurrentMAC = adapter.MAC
		target.HardwarePort = adapter.HardwarePort
	}
	return []listen.Target{{
		Name:         target.Name,
		Role:         target.AdapterRole,
		HardwarePort: target.HardwarePort,
		LocalMAC:     target.CurrentMAC,
	}}
}

func (m Model) bridgeAdapters() (profile.AdapterConfig, profile.AdapterConfig, string) {
	host, okHost := m.profile.Role(profile.AdapterRoleHost)
	sw, okSwitch := m.profile.Role(profile.AdapterRoleSwitch)
	if !okHost || !okSwitch {
		return profile.AdapterConfig{}, profile.AdapterConfig{}, "host+switch"
	}
	hostCfg := *host
	swCfg := *sw
	if adapter, ok := m.findAdapter(host.Name); ok {
		hostCfg.CurrentMAC = adapter.MAC
		hostCfg.HardwarePort = adapter.HardwarePort
		hostCfg.Addrs = append([]string(nil), adapter.Addrs...)
	}
	if adapter, ok := m.findAdapter(sw.Name); ok {
		swCfg.CurrentMAC = adapter.MAC
		swCfg.HardwarePort = adapter.HardwarePort
		swCfg.Addrs = append([]string(nil), adapter.Addrs...)
	}
	return hostCfg, swCfg, ""
}

func (m Model) bridgeTakeoverConfig() bridge.NATConfig {
	cfg := m.profile.BridgeAdapterSnapshot()
	var host profile.AdapterConfig
	if hostCfg, ok := m.profile.Role(profile.AdapterRoleHost); ok {
		host = *hostCfg
	}
	pick := func(key string) string {
		value := cfg.Value(key)
		if !isAutoValue(value) {
			return value
		}
		value = host.Value(key)
		if !isAutoValue(value) {
			return value
		}
		return cfg.Value(key)
	}
	return bridge.NATConfig{
		MAC:     pick("mac"),
		IP:      pick("ip"),
		CIDR:    pick("cidr"),
		Gateway: pick("gateway"),
		DNS:     pick("dns"),
		DHCP:    pick("dhcp"),
	}
}

func (m Model) eapolPolicy() bridge.EAPOLPolicy {
	return bridge.EAPOLPolicy{
		SuppressLogoff:  m.eapolSuppressLogoff,
		DowngradeMACsec: m.eapolDowngradeMACsec,
	}
}

func (m Model) pendingLocks() []string {
	if len(m.lockPending) == 0 {
		return nil
	}
	names := make([]string, 0, len(m.lockPending))
	for name, pending := range m.lockPending {
		if pending {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	return names
}

func startListenCmd(targets []listen.Target, mode string) tea.Cmd {
	return func() tea.Msg {
		for _, target := range targets {
			if err := bringAdapterUp(target.Name); err != nil {
				return listenStartedMsg{err: err, mode: mode}
			}
		}
		session, err := listen.Start(targets)
		return listenStartedMsg{session: session, err: err, mode: mode}
	}
}

func startBridgeCmd(host, sw profile.AdapterConfig, policy bridge.EAPOLPolicy) tea.Cmd {
	return func() tea.Msg {
		session, err := bridge.StartWithPolicy(
			bridge.Adapter{Name: host.Name, Role: host.AdapterRole, HardwarePort: host.HardwarePort, LocalMAC: host.CurrentMAC, TargetMAC: host.MAC},
			bridge.Adapter{Name: sw.Name, Role: sw.AdapterRole, HardwarePort: sw.HardwarePort, LocalMAC: sw.CurrentMAC},
			"",
			policy,
		)
		return bridgeStartedMsg{session: session, err: err}
	}
}

func stopBridgeCmd(session *bridge.Session) tea.Cmd {
	return func() tea.Msg {
		return bridgeStoppedMsg{session: session, err: session.Stop()}
	}
}

func startNATCmd(session *bridge.Session, cfg bridge.NATConfig) tea.Cmd {
	return func() tea.Msg {
		return bridgeNATMsg{session: session, active: true, err: session.StartNAT(cfg)}
	}
}

func stopNATCmd(session *bridge.Session) tea.Cmd {
	return func() tea.Msg {
		return bridgeNATMsg{session: session, active: false, err: session.StopNAT()}
	}
}

func sendEAPOLStartCmd(session *bridge.Session) tea.Cmd {
	return func() tea.Msg {
		return eapolSentMsg{session: session, err: session.SendEAPOLStart()}
	}
}

func waitBridgeEventCmd(session *bridge.Session) tea.Cmd {
	return func() tea.Msg {
		event, ok := <-session.Events
		return bridgeEventMsg{session: session, event: event, ok: ok}
	}
}

func (m *Model) stopCapture() error {
	var err error
	if m.listener != nil {
		if err = m.listener.Stop(); err != nil {
			m.print("listen err: stop " + err.Error())
		}
	}
	m.listener = nil
	m.capMode = ""
	return err
}

func (m *Model) stopBridgeNow() error {
	if m.bridge == nil {
		return nil
	}
	session := m.bridge
	m.bridge = nil
	m.bridgeState = ""
	m.natActive = false
	if err := session.Stop(); err != nil {
		m.print("bridge err: stop " + err.Error())
		return err
	}
	return nil
}

func (m *Model) handleBridgeEvent(session *bridge.Session, event bridge.Event) tea.Cmd {
	switch event.Kind {
	case bridge.KindState:
		if event.State != "" && event.State != m.bridgeState {
			m.bridgeState = event.State
			m.print("bridge state: " + event.State)
		}
	case bridge.KindLog:
		m.printEAPOLLogSignal(event.Message)
	case bridge.KindTraffic:
		m.addTraffic(event.Message)
	case bridge.KindFinding:
		m.addFindingEvent(event.Message, event.Adapter, event.Role)
	case bridge.KindCanvas:
		m.applyCanvasEvent(event.Message)
	case bridge.KindPcap:
		m.print(fmt.Sprintf("pcap %s/%s: %s", event.Role, event.Adapter, event.Path))
		m.rememberPcapPath(event.Path)
	case bridge.KindError:
		if event.Err != nil {
			m.print("bridge err: " + event.Err.Error())
		} else if event.Message != "" {
			m.print("bridge err: " + event.Message)
		}
	case bridge.KindDiscovery:
		m.applyDiscovery(listen.Event{
			Kind:     "discovery",
			Adapter:  event.Adapter,
			Role:     event.Role,
			Field:    event.Field,
			Value:    event.Value,
			Evidence: event.Evidence,
			Packet:   event.Packet,
		})
	case bridge.KindStopped:
		if event.Message != "" {
			m.print("bridge: " + event.Message)
		}
		m.bridge = nil
		m.bridgeState = ""
		m.natActive = false
		m.print("bridge: off")
		return nil
	}
	return waitBridgeEventCmd(session)
}

func setAdapterStateCmd(name, state string) tea.Cmd {
	return func() tea.Msg {
		return adapterStateMsg{name: name, state: state, err: setAdapterState(name, state)}
	}
}

func bringAdapterUp(name string) error {
	return setAdapterState(name, "up")
}

func setAdapterState(name, state string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "ifconfig", name, state)
	out, err := cmd.CombinedOutput()
	if ctx.Err() == context.DeadlineExceeded {
		err = fmt.Errorf("ifconfig %s %s timed out", name, state)
	}
	if err != nil {
		err = fmt.Errorf("%w (%s)", err, strings.TrimSpace(string(out)))
	}
	return err
}

func (m *Model) restoreLockedAdaptersNow() error {
	var errs []error
	for name, state := range m.restoreState {
		if err := bridge.RestoreInterfaceState(state); err != nil {
			m.print(fmt.Sprintf("adapter restore warn %s: %v", name, err))
			errs = append(errs, fmt.Errorf("%s: %w", name, err))
		}
		delete(m.restoreState, name)
	}
	for name := range m.lockPending {
		delete(m.lockPending, name)
	}
	return errors.Join(errs...)
}

func (m *Model) updateAdapterStatus(name string, up bool) {
	for i := range m.adapters {
		if strings.EqualFold(m.adapters[i].Name, name) {
			m.adapters[i].IsUp = up
			return
		}
	}
}

func waitListenEventCmd(session *listen.Session) tea.Cmd {
	return func() tea.Msg {
		event, ok := <-session.Events
		return listenEventMsg{session: session, event: event, ok: ok}
	}
}

func (m *Model) handleListenEvent(event listen.Event) tea.Cmd {
	mode := m.capMode
	if mode == "" {
		mode = "listen"
	}
	switch event.Kind {
	case "pcap":
		m.print(fmt.Sprintf("pcap %s/%s: %s", event.Role, event.Adapter, event.Path))
		m.rememberPcapPath(event.Path)
	case "log":
		m.printEAPOLLogSignal(event.Message)
	case "traffic":
		m.addTraffic(event.Message)
	case "finding":
		m.addFindingEvent(event.Message, event.Adapter, event.Role)
	case canvas.EventKind:
		m.applyCanvasEvent(event.Message)
	case "error":
		m.print(fmt.Sprintf("%s err %s/%s: %v", mode, event.Role, event.Adapter, event.Err))
	case "stopped":
		m.print(fmt.Sprintf("%s off %s/%s", mode, event.Role, event.Adapter))
	case "discovery":
		m.applyDiscovery(event)
	}
	if m.listener == nil {
		return nil
	}
	return waitListenEventCmd(m.listener)
}

func (m *Model) applyDiscovery(event listen.Event) {
	if isBridgeObservation(event) {
		m.profile.AddBridgeObservation(event.Adapter, event.Role, event.Field, event.Value, event.Evidence, event.Packet)
	}
	m.applyBridgeConfigDiscovery(event)
	m.applyCanvasDiscovery(event)
	m.printEAPOLDiscoverySignal(event)
	if !profile.KnownField(event.Field) {
		return
	}

	cfg, ok := m.profile.ByName(event.Adapter)
	if !ok {
		return
	}
	added, applied := cfg.AddDiscovery(event.Field, event.Value, event.Evidence, event.Packet)
	if !added && !applied {
		return
	}
	status := "saved"
	if applied {
		status = "auto"
	}
	m.print(formatDiscoveryOutput(event, status))
	m.refreshCompletions()
}

func (m *Model) applyBridgeConfigDiscovery(event listen.Event) {
	if !profile.KnownField(event.Field) {
		return
	}
	switch profile.CanonicalKey(event.Field) {
	case "mac", "ip", "cidr", "gateway", "dns":
	default:
		return
	}
	if event.Role != profile.AdapterRoleHost && event.Role != "bridge" {
		return
	}
	cfg := m.profile.BridgeAdapter()
	added, applied := cfg.AddDiscovery(event.Field, event.Value, event.Evidence, event.Packet)
	if added || applied {
		m.refreshCompletions()
	}
}

func isBridgeObservation(event listen.Event) bool {
	if !profile.KnownField(event.Field) {
		return true
	}
	switch event.Packet {
	case "ARP", "EAPOL / 802.1X", "VLAN-tagged traffic":
		return true
	default:
		return false
	}
}

func formatDiscoveryOutput(event listen.Event, status string) string {
	return fmt.Sprintf("%s/%s %s=%s %s/%s %s",
		event.Role,
		event.Adapter,
		strings.ToUpper(event.Field),
		event.Value,
		event.Packet,
		event.Evidence,
		status,
	)
}

func (m *Model) listConfigs() {
	names, err := configs.List()
	if err != nil {
		m.print("load err: " + err.Error())
		return
	}
	if len(names) == 0 {
		m.print("configs: none")
		return
	}
	m.print("configs:")
	for _, name := range names {
		m.print("  " + name)
	}
}

func (m *Model) executeConf(args []string) tea.Cmd {
	if len(args) == 0 {
		if m.activeAdapter == "" {
			m.print("ctx: none")
			return nil
		}
		m.print("ctx: " + m.activeAdapter)
		return nil
	}
	if len(args) >= 2 {
		m.print("use: conf <adapter|bridge>")
		return nil
	}
	if isBridgeContext(args[0]) {
		m.profile.BridgeAdapter()
		m.activeAdapter = "bridge"
		m.miscScroll = 0
		m.print("ctx: bridge")
		return nil
	}
	cfg, ok := m.profile.ByName(args[0])
	if !ok {
		m.print("adapter off: " + args[0])
		m.print("use: set " + args[0] + " <host|switch>")
		return nil
	}
	m.activeAdapter = cfg.Name
	m.miscScroll = 0
	m.print("ctx: " + cfg.Name)
	return nil
}

func (m *Model) executeActiveAdapterState(state string) tea.Cmd {
	if m.activeAdapter == "" {
		m.print("ctx: none; use: conf <adapter|bridge>")
		return nil
	}
	if isBridgeContext(m.activeAdapter) {
		cfg := m.profile.BridgeAdapter()
		old, err := cfg.Set("state", state)
		if err != nil {
			m.print("set err: " + err.Error())
			return nil
		}
		m.print(fmt.Sprintf("bridge state: %s -> %s", old, cfg.State))
		return nil
	}
	cfg, ok := m.profile.ByName(m.activeAdapter)
	if !ok {
		m.print("ctx: stale")
		m.activeAdapter = ""
		return nil
	}
	m.print(fmt.Sprintf("adapter state: %s -> %s", cfg.Name, state))
	return setAdapterStateCmd(cfg.Name, state)
}

func (m *Model) showAdapters() {
	if m.loading {
		m.print("adapters: loading")
		return
	}
	if m.err != nil {
		m.print("adapters err: " + m.err.Error())
		return
	}
	if len(m.adapters) == 0 {
		m.print("adapters: none")
		return
	}

	m.print("adapters:")
	m.print("  name       kind          state  mtu    mac               address")
	for _, adapter := range m.adapters {
		marker := " "
		if _, ok := m.profile.SelectedRole(adapter.Name); ok {
			marker = "*"
		}
		m.print(fmt.Sprintf(" %s %-10s %-13s %-5s %-6d %-17s %s",
			marker,
			adapter.Name,
			adapter.Kind,
			adapter.Status(),
			adapter.MTU,
			adapter.MAC,
			adapter.PrimaryAddr(),
		))
	}
}

func (m *Model) showConfig() {
	bridgeCfg := m.profile.BridgeAdapterSnapshot()
	hasBridgeConfig := isBridgeContext(m.activeAdapter) || len(bridgeCfg.Discovered) > 0
	for _, field := range profile.Fields {
		if !isAutoValue(bridgeCfg.Value(field.Key)) {
			hasBridgeConfig = true
			break
		}
	}
	m.showConfigSettings()
	if len(m.profile.Adapters) == 0 && !hasBridgeConfig {
		m.print("staged: none")
		return
	}
	m.print("staged:")
	for _, cfg := range m.profile.Adapters {
		m.print(fmt.Sprintf("  %s %s", cfg.AdapterRole, cfg.Name))
		for _, field := range profile.Fields {
			m.print("    " + styleKey.Render(fmt.Sprintf("%-7s", field.Key)) + " " + styleValue.Render(cfg.Value(field.Key)))
		}
		if len(cfg.Discovered) > 0 {
			m.print("    discovered")
			for _, item := range cfg.Discovered {
				m.print("      " + styleKey.Render(fmt.Sprintf("%-12s", item.Field)) + " " + styleValue.Render(item.Value) + fmt.Sprintf(" %s/%s", item.Packet, item.Evidence))
			}
		}
	}
	if hasBridgeConfig {
		m.print("  bridge bridge")
		for _, field := range profile.Fields {
			m.print("    " + styleKey.Render(fmt.Sprintf("%-7s", field.Key)) + " " + styleValue.Render(bridgeCfg.Value(field.Key)))
		}
		if len(bridgeCfg.Discovered) > 0 {
			m.print("    discovered")
			for _, item := range bridgeCfg.Discovered {
				m.print("      " + styleKey.Render(fmt.Sprintf("%-12s", item.Field)) + " " + styleValue.Render(item.Value) + fmt.Sprintf(" %s/%s", item.Packet, item.Evidence))
			}
		}
	}
}

func (m *Model) showConfigSettings() {
	m.print("settings:")
	m.print("  canvas: " + onOff(m.canvasEnabled))
	if m.canvasPath != "" {
		m.print("  canvas path: " + m.canvasPath)
	}
	m.print("  " + eapolLogoffStatus(m.eapolSuppressLogoff))
	m.print("  " + macsecStatus(m.eapolDowngradeMACsec))
}

func (m *Model) showBridge() {
	state := "off"
	if m.bridge != nil {
		state = "on"
		if m.bridgeState != "" {
			state += " " + m.bridgeState
		}
	}
	m.print("bridge state: " + state)
	if m.natActive {
		m.print("nat: on")
	} else {
		m.print("nat: off")
	}
	m.print(eapolLogoffStatus(m.eapolSuppressLogoff))
	m.print(macsecStatus(m.eapolDowngradeMACsec))
	if len(m.profile.Bridge.Observations) == 0 {
		m.print("bridge observations: none")
		return
	}
	m.print("bridge observations:")
	for _, obs := range m.profile.Bridge.Observations {
		m.print("  " +
			styleKey.Render(fmt.Sprintf("%-12s", obs.Field)) + " " +
			styleValue.Render(obs.Value) +
			fmt.Sprintf(" %s/%s %s/%s x%d", obs.Packet, obs.Evidence, obs.Role, obs.Adapter, obs.Count))
	}
}

func onOff(enabled bool) string {
	if enabled {
		return "on"
	}
	return "off"
}

func enableDisable(enabled bool) string {
	if enabled {
		return "enable"
	}
	return "disable"
}

func eapolLogoffStatus(enabled bool) string {
	return "eapol drop-logoff: " + enableDisable(enabled)
}

func macsecStatus(enabled bool) string {
	return "eapol macsec-downgrade: " + enableDisable(enabled)
}

func (m *Model) showSecrets() {
	if len(m.findings) == 0 {
		m.print("secrets: none")
		return
	}
	m.print("secrets:")
	for _, line := range m.findings {
		m.print("  " + line)
	}
}

func (m *Model) showHelp() {
	lines := []string{
		"cmd:",
		"  show adapters",
		"  show config",
		"  show bridge",
		"  show secrets",
		"  set <adapter> <host|switch>",
		"  conf <name|bridge>",
		"  unset",
		"  load [name]",
		"  enable canvas",
		"  disable canvas",
		"  enable eapol drop-logoff",
		"  disable eapol drop-logoff",
		"  enable eapol macsec-downgrade",
		"  disable eapol macsec-downgrade",
		"  start listen|bridge|nat",
		"  stop listen|bridge|nat",
		"  send eapol start",
		"  set ip <value|auto>",
		"  set mac <value|auto>",
		"  set state up|down|auto",
		"  up | down",
		"  clear",
		"  tab",
	}
	for _, line := range lines {
		m.print(line)
	}
}

func (m *Model) findAdapter(name string) (adapters.Adapter, bool) {
	name = strings.ToLower(strings.TrimSpace(name))
	for _, adapter := range m.adapters {
		if strings.ToLower(adapter.Name) == name || strings.ToLower(adapter.HardwarePort) == name {
			return adapter, true
		}
	}
	return adapters.Adapter{}, false
}

func (m *Model) print(line string) {
	m.appendOutput(line, isCommandLevelOutput(line))
}

func (m *Model) printTraffic(line string) {
	m.appendOutput(line, false)
}

func (m *Model) appendOutput(line string, muted bool) {
	m.output = append(m.output, line)
	m.outputMuted = append(m.outputMuted, muted)
	m.outputScroll = 0
	if len(m.output) > 500 {
		drop := len(m.output) - 500
		m.output = m.output[drop:]
		if len(m.outputMuted) > drop {
			m.outputMuted = m.outputMuted[drop:]
		} else {
			m.outputMuted = nil
		}
	}
}

func (m *Model) rememberPcapDir(dir string) {
	dir = strings.TrimSpace(dir)
	if dir == "" {
		return
	}
	for _, existing := range m.pcapDirs {
		if existing == dir {
			return
		}
	}
	m.pcapDirs = append(m.pcapDirs, dir)
}

func (m *Model) rememberPcapPath(path string) {
	path = strings.TrimSpace(path)
	if path == "" {
		return
	}
	m.rememberPcapDir(filepath.Dir(path))
}

func (m *Model) recordActivePcapDirs() {
	if m.listener != nil {
		m.rememberPcapDir(m.listener.Dir)
	}
	if m.bridge != nil {
		m.rememberPcapDir(m.bridge.Dir)
	}
}

func (m Model) pcapDirsSnapshot() []string {
	return append([]string(nil), m.pcapDirs...)
}

func (m *Model) addTraffic(line string) {
	line = strings.TrimSpace(line)
	if line == "" {
		return
	}
	m.traffic = append(m.traffic, line)
	m.trimTraffic()
}

func (m *Model) trimTraffic() {
	limit := m.trafficCapacity()
	if len(m.traffic) > limit {
		m.traffic = m.traffic[len(m.traffic)-limit:]
	}
}

func (m Model) trafficCapacity() int {
	height := renderHeight(terminalHeight(m.height))
	width := renderWidth(terminalWidth(m.width))
	footerHeight := lipgloss.Height(m.renderFooter(width))
	mainHeight := mainAreaHeight(height, footerHeight)
	_, trafficHeight := rightPaneHeights(mainHeight)
	return max(1, trafficHeight-3)
}

func (m *Model) addFinding(line string) {
	line = strings.TrimSpace(line)
	if line == "" {
		return
	}
	m.findings = append(m.findings, line)
	m.trimFindings()
	m.printSignal("finding\x00"+strings.ToLower(line), line)
}

func (m *Model) addFindingEvent(encoded, adapter, role string) {
	finding, err := inspect.DecodeFinding(encoded)
	if err != nil {
		m.addFinding(encoded)
		return
	}
	line := finding.Display()
	m.addFinding(line)
	m.applyCanvasObservation(canvas.FromFinding(finding, adapter, role))
}

func (m *Model) applyCanvasEvent(encoded string) {
	obs, err := canvas.DecodeObservation(encoded)
	if err != nil {
		return
	}
	m.applyCanvasObservation(obs)
}

func (m *Model) applyCanvasDiscovery(event listen.Event) {
	for _, obs := range canvas.FromDiscovery(event.Adapter, event.Role, event.Field, event.Value, event.Evidence, event.Packet) {
		m.applyCanvasObservation(obs)
	}
}

func (m *Model) applyCanvasObservation(obs canvas.Observation) {
	if m.canvasMap == nil {
		m.canvasMap = canvas.NewMap()
	}
	changed := m.canvasMap.Apply(obs)
	m.canvasDirty = true
	if changed && m.canvasEnabled {
		if err := m.saveCanvas(); err != nil {
			m.print("canvas err: " + err.Error())
		}
	}
}

func (m *Model) syncCanvasProfile() {
	if m.canvasMap == nil {
		m.canvasMap = canvas.NewMap()
	}
	if m.canvasMap.ApplyProfile(m.profile) {
		m.canvasDirty = true
		if m.canvasEnabled {
			if err := m.saveCanvas(); err != nil {
				m.print("canvas err: " + err.Error())
			}
		}
	}
}

func (m *Model) saveCanvas() error {
	if !m.canvasEnabled {
		return nil
	}
	if m.canvasMap == nil {
		m.canvasMap = canvas.NewMap()
	}
	if m.canvasPath == "" {
		path, err := canvas.SessionPath()
		if err != nil {
			return err
		}
		m.canvasPath = path
	}
	if err := m.canvasMap.WriteFile(m.canvasPath); err != nil {
		return err
	}
	m.canvasDirty = false
	return nil
}

func (m *Model) trimFindings() {
	limit := m.findingsCapacity()
	if len(m.findings) > limit {
		m.findings = m.findings[len(m.findings)-limit:]
	}
}

func (m Model) findingsCapacity() int {
	height := renderHeight(terminalHeight(m.height))
	width := renderWidth(terminalWidth(m.width))
	footerHeight := lipgloss.Height(m.renderFooter(width))
	mainHeight := mainAreaHeight(height, footerHeight)
	findingsHeight, _ := rightPaneHeights(mainHeight)
	return max(1, findingsHeight-3)
}

func (m *Model) printSignal(key, line string) {
	key = strings.TrimSpace(strings.ToLower(key))
	line = strings.TrimSpace(line)
	if key == "" || line == "" {
		return
	}
	if m.signalSeen == nil {
		m.signalSeen = make(map[string]bool)
	}
	if m.signalSeen[key] {
		return
	}
	m.signalSeen[key] = true
	m.printTraffic(line)
}

func (m *Model) printEAPOLDiscoverySignal(event listen.Event) {
	key, label, ok := eapolDiscoverySignal(event)
	if !ok {
		return
	}
	location := strings.Trim(strings.Join([]string{event.Role, event.Adapter}, "/"), "/")
	if location != "" {
		label += " " + location
	}
	m.printSignal(key+"\x00"+location, label)
}

func (m *Model) printEAPOLLogSignal(message string) {
	_, label, ok := eapolLogSignal(message)
	if ok {
		m.printTraffic(label)
	}
}

func eapolDiscoverySignal(event listen.Event) (string, string, bool) {
	if event.Packet == "MACsec" {
		return "macsec-0x88e5", "MACsec 0x88e5 detected", true
	}
	if event.Packet != "EAPOL / 802.1X" {
		return "", "", false
	}
	value := strings.ToLower(event.Value)
	switch event.Field {
	case "eapol":
		switch {
		case strings.Contains(value, "start"):
			return "eapol-start", "EAPOL start", true
		case strings.Contains(value, "logoff"):
			return "eapol-logoff", "EAPOL-Logoff", true
		case strings.Contains(value, "mka") || strings.Contains(value, "type 5") || value == "5":
			return "macsec-mka", "MACsec MKA detected", true
		}
	case "eapol_type":
		if value == "5" {
			return "macsec-mka", "MACsec MKA detected", true
		}
	case "eap_code":
		switch value {
		case "request":
			return "eap-request", "EAP request", true
		case "response":
			return "eap-response", "EAP response", true
		case "success":
			return "eap-success", "EAPOL success", true
		case "failure":
			return "eap-failure", "EAPOL failure", true
		}
	case "eap_type":
		if value != "" && value != "none" && value != "unknown" {
			return "eap-type-" + signalKeyToken(value), "EAP " + event.Value, true
		}
	}
	return "", "", false
}

func eapolLogSignal(message string) (string, string, bool) {
	lower := strings.ToLower(message)
	switch {
	case strings.Contains(lower, "drop-logoff enabled"):
		return "eapol-drop-logoff-enable", "EAPOL drop-logoff enable", true
	case strings.Contains(lower, "drop-logoff disabled"):
		return "eapol-drop-logoff-disable", "EAPOL drop-logoff disable", true
	case strings.Contains(lower, "eapol-logoff"):
		if strings.Contains(lower, "forwarding") {
			return "eapol-logoff-forwarded", "EAPOL-Logoff forwarded", true
		}
		return "eapol-logoff-dropped", "EAPOL-Logoff dropped", true
	case strings.Contains(lower, "eapol-start") && strings.Contains(lower, "failed"):
		return "eapol-start-failed", "EAPOL start failed", true
	case strings.Contains(lower, "injected") && strings.Contains(lower, "eapol-start"):
		return "eapol-start-injected", "EAPOL start injected", true
	case strings.Contains(lower, "eapol-start"):
		return "eapol-start", "EAPOL start", true
	case strings.Contains(lower, "eapol-key"):
		return "eapol-key", "EAPOL key forwarded", true
	case strings.Contains(lower, "eapol-eap frame"):
		return "eapol-eap", "EAPOL-EAP frame", true
	case strings.Contains(lower, "unknown eapol type"):
		return "eapol-unknown", compactEAPOLLog(message), true
	case strings.Contains(lower, "eap-request"):
		method := relayLogValue(message, "Type=")
		if method == "" {
			return "eap-request", appendLogID("EAP request", message), true
		}
		return "eap-request-" + signalKeyToken(method), appendLogID("EAP request "+method, message), true
	case strings.Contains(lower, "eap-response"):
		method := relayLogValue(message, "Type=")
		identity := relayLogValue(message, "Identity=")
		if strings.EqualFold(method, "identity") && identity != "" {
			return "eap-response-identity-" + signalKeyToken(identity), appendLogID("EAP response identity: "+identity, message), true
		}
		if method == "" {
			return "eap-response", appendLogID("EAP response", message), true
		}
		return "eap-response-" + signalKeyToken(method), appendLogID("EAP response "+method, message), true
	case strings.Contains(lower, "eap-success") || strings.Contains(lower, "port authorized"):
		return "eap-success", appendLogID("EAPOL success", message), true
	case strings.Contains(lower, "eap-failure") || strings.Contains(lower, "authentication rejected"):
		return "eap-failure", appendLogID("EAPOL failure", message), true
	case strings.Contains(lower, "re-authentication"):
		return "eap-reauth", compactEAPOLLog(message), true
	case strings.Contains(lower, "macsec") && strings.Contains(lower, "dropping"):
		return "macsec-drop", "MACsec drop", true
	case strings.Contains(lower, "macsec") && strings.Contains(lower, "macsec-downgrade enabled"):
		return "eapol-macsec-downgrade-enable", "EAPOL macsec-downgrade enable", true
	case strings.Contains(lower, "macsec") && strings.Contains(lower, "macsec-downgrade disabled"):
		return "eapol-macsec-downgrade-disable", "EAPOL macsec-downgrade disable", true
	case strings.Contains(lower, "macsec") && (strings.Contains(lower, "type 5") || strings.Contains(lower, "mka")):
		return "macsec-mka", "MACsec MKA detected", true
	case strings.Contains(lower, "eap method negotiated"):
		return "eap-method", compactEAPOLLog(message), true
	default:
		return "", "", false
	}
}

func relayLogValue(message, marker string) string {
	lower := strings.ToLower(message)
	idx := strings.Index(lower, strings.ToLower(marker))
	if idx < 0 {
		return ""
	}
	value := message[idx+len(marker):]
	if cut := strings.IndexAny(value, " \t\r\n"); cut >= 0 {
		value = value[:cut]
	}
	return strings.Trim(value, " ,;()")
}

func appendLogID(label, message string) string {
	id := relayLogValue(message, "ID=")
	if id == "" {
		return label
	}
	return label + " ID=" + id
}

func signalKeyToken(value string) string {
	value = strings.TrimSpace(strings.ToLower(value))
	var out strings.Builder
	lastDash := false
	for _, r := range value {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			out.WriteRune(r)
			lastDash = false
			continue
		}
		if !lastDash {
			out.WriteByte('-')
			lastDash = true
		}
	}
	token := strings.Trim(out.String(), "-")
	if token == "" {
		return "unknown"
	}
	return token
}

func compactEAPOLLog(message string) string {
	message = strings.TrimSpace(message)
	if message == "" {
		return "EAPOL"
	}
	if idx := strings.LastIndex(message, ":"); idx >= 0 && idx+1 < len(message) {
		message = strings.TrimSpace(message[idx+1:])
	}
	return "EAPOL " + message
}

func (c cardFocus) String() string {
	switch c {
	case cardOutput:
		return "output"
	case cardMisc:
		return "right"
	default:
		return "cli"
	}
}

func (m *Model) recallHistory(delta int) {
	if len(m.history) == 0 {
		return
	}
	if m.historyIndex == -1 {
		if delta < 0 {
			m.historyIndex = len(m.history) - 1
		} else {
			return
		}
	} else {
		m.historyIndex += delta
	}
	if m.historyIndex < 0 {
		m.historyIndex = 0
	}
	if m.historyIndex >= len(m.history) {
		m.historyIndex = -1
		m.input = ""
		m.refreshCompletions()
		return
	}
	m.input = m.history[m.historyIndex]
	m.refreshCompletions()
}

func (m *Model) applyCompletion() {
	candidates := m.completionCandidates(m.input)
	if len(candidates) == 0 {
		candidates = m.allCompletionCandidates(m.input)
	}
	candidates = dedupe(candidates)
	if len(candidates) == 0 {
		m.completions = nil
		m.resetCompletionCycle()
		return
	}

	context := completionContext(m.input)
	current := currentCompletionToken(m.input)
	if m.canContinueCompletionCycle(context, current) {
		m.cycleIndex = (m.cycleIndex + 1) % len(m.cycleOptions)
		m.completions = m.cycleOptions
		m.input = replaceCurrentToken(m.input, m.cycleOptions[m.cycleIndex])
		return
	}

	m.completions = candidates
	m.cycleContext = context
	m.cycleOptions = candidates
	m.cycleIndex = 0
	m.input = replaceCurrentToken(m.input, candidates[0])
	if len(candidates) == 1 {
		m.resetCompletionCycle()
		if shouldAppendSpace(m.input) {
			m.input += " "
		}
		m.refreshCompletions()
	}
}

func (m *Model) resetCompletionCycle() {
	m.cycleContext = ""
	m.cycleIndex = -1
	m.cycleOptions = nil
}

func (m Model) canContinueCompletionCycle(context, current string) bool {
	if m.cycleIndex < 0 || len(m.cycleOptions) < 2 {
		return false
	}
	if m.cycleContext != context || m.cycleIndex >= len(m.cycleOptions) {
		return false
	}
	return strings.EqualFold(current, m.cycleOptions[m.cycleIndex])
}

func (m *Model) refreshCompletions() {
	if m.inputMode == modeSaveName {
		m.completions = filterPrefix(m.configNames(), strings.ToLower(strings.TrimSpace(m.input)))
		return
	}
	m.completions = m.completionCandidates(m.input)
}

func (m Model) completionCandidates(input string) []string {
	candidates, current := m.completionCandidateSet(input)
	return filterPrefix(candidates, current)
}

func (m Model) allCompletionCandidates(input string) []string {
	candidates, _ := m.completionCandidateSet(input)
	return dedupe(candidates)
}

func (m Model) completionCandidateSet(input string) ([]string, string) {
	tokens, trailingSpace := commandTokens(input)
	if len(tokens) == 0 {
		return topLevelCommands(), ""
	}

	lower := lowerTokens(tokens)
	current := ""
	if !trailingSpace {
		current = lower[len(lower)-1]
	}

	var candidates []string
	switch {
	case len(lower) == 1 && !trailingSpace:
		candidates = topLevelCommands()
	case lower[0] == "show":
		if len(lower) <= 2 {
			candidates = []string{"adapters", "bridge", "config", "secrets"}
		}
	case lower[0] == "set":
		candidates = m.setCompletions(lower, trailingSpace)
	case lower[0] == "unset":
		candidates = m.unsetCompletions(lower, trailingSpace)
	case lower[0] == "load":
		if len(lower) <= 2 {
			candidates = m.configNames()
		}
	case lower[0] == "enable", lower[0] == "disable":
		if len(lower) <= 2 {
			candidates = []string{"canvas", "eapol"}
		} else if len(lower) <= 3 && lower[1] == "eapol" {
			candidates = []string{"drop-logoff", "macsec-downgrade"}
		}
	case lower[0] == "start":
		if len(lower) <= 2 {
			candidates = []string{"bridge", "listen", "nat"}
		}
	case lower[0] == "stop":
		if len(lower) <= 2 {
			candidates = []string{"bridge", "listen", "nat"}
		}
	case lower[0] == "send":
		if len(lower) <= 2 {
			candidates = []string{"eapol"}
		} else if len(lower) <= 3 && lower[1] == "eapol" {
			candidates = []string{"start"}
		}
	case isConfCommand(lower[0]):
		if len(lower) <= 2 {
			candidates = append(m.selectedAdapterNames(), "bridge")
		}
	default:
		candidates = topLevelCommands()
	}

	return candidates, current
}

func (m Model) setCompletions(tokens []string, trailingSpace bool) []string {
	if len(tokens) == 1 && !trailingSpace {
		return []string{"set"}
	}
	if len(tokens) == 1 || (len(tokens) == 2 && !trailingSpace) {
		return append(m.adapterNames(), propertyKeys()...)
	}

	target := tokens[1]
	if target == "adapter" {
		if len(tokens) >= 3 && trailingSpace {
			return profile.AdapterRoles()
		}
		if len(tokens) >= 4 && !trailingSpace {
			return profile.AdapterRoles()
		}
		return m.adapterNames()
	}
	if _, ok := m.findAdapter(target); ok {
		return profile.AdapterRoles()
	}

	if len(tokens) == 2 && trailingSpace {
		return m.valueCompletions(target)
	}
	if len(tokens) == 3 && !trailingSpace {
		return m.valueCompletions(target)
	}
	return nil
}

func topLevelCommands() []string {
	return []string{"show", "set", "unset", "conf", "load", "enable", "disable", "start", "stop", "send", "clear", "refresh", "help", "up", "down", "quit"}
}

func (m Model) unsetCompletions(tokens []string, trailingSpace bool) []string {
	if len(tokens) == 1 && !trailingSpace {
		return []string{"unset"}
	}
	if len(tokens) == 1 || (len(tokens) == 2 && !trailingSpace) {
		return []string{"adapter"}
	}
	if tokens[1] == "adapter" {
		return m.selectedAdapterNames()
	}
	return nil
}

func propertyKeys() []string {
	out := make([]string, 0, len(profile.Fields))
	for _, field := range profile.Fields {
		out = append(out, field.Key)
	}
	return out
}

func (m Model) valueCompletions(key string) []string {
	values := baseValueCompletions(key)
	if isBridgeContext(m.activeAdapter) {
		cfg := m.profile.BridgeAdapterSnapshot()
		values = append(values, cfg.Values(key)...)
	} else if cfg, ok := m.profile.ByName(m.activeAdapter); ok {
		values = append(values, cfg.Values(key)...)
	}
	return dedupe(values)
}

func baseValueCompletions(key string) []string {
	switch profile.CanonicalKey(key) {
	case "state":
		return []string{"auto", "up", "down"}
	case "dhcp":
		return []string{"auto", "manual", "off"}
	case "role":
		return []string{"auto", "client", "uplink", "mirror", "spare"}
	default:
		return []string{"auto"}
	}
}

func (m Model) adapterNames() []string {
	out := make([]string, 0, len(m.adapters))
	for _, adapter := range m.adapters {
		out = append(out, adapter.Name)
	}
	sort.Strings(out)
	return out
}

func (m Model) selectedAdapterNames() []string {
	out := make([]string, 0, len(m.profile.Adapters))
	for _, adapter := range m.profile.Adapters {
		out = append(out, adapter.Name)
	}
	sort.Strings(out)
	return out
}

func (m Model) configNames() []string {
	names, err := configs.List()
	if err != nil {
		return nil
	}
	return names
}

func filterPrefix(values []string, prefix string) []string {
	if prefix == "" {
		return dedupe(values)
	}
	var out []string
	for _, value := range values {
		if strings.HasPrefix(strings.ToLower(value), prefix) {
			out = append(out, value)
		}
	}
	return dedupe(out)
}

func dedupe(values []string) []string {
	seen := make(map[string]bool, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func commandTokens(input string) ([]string, bool) {
	runes := []rune(input)
	trailingSpace := len(runes) > 0 && unicode.IsSpace(runes[len(runes)-1])
	return strings.Fields(input), trailingSpace
}

func lowerTokens(tokens []string) []string {
	out := make([]string, len(tokens))
	for i, token := range tokens {
		out[i] = strings.ToLower(token)
	}
	return out
}

func isConfCommand(value string) bool {
	switch value {
	case "conf", "config", "configure":
		return true
	default:
		return false
	}
}

func completionContext(input string) string {
	runes := []rune(input)
	if len(runes) == 0 {
		return ""
	}
	if unicode.IsSpace(runes[len(runes)-1]) {
		return input
	}
	start := len(runes)
	for start > 0 && !unicode.IsSpace(runes[start-1]) {
		start--
	}
	return string(runes[:start])
}

func currentCompletionToken(input string) string {
	runes := []rune(input)
	end := len(runes)
	for end > 0 && unicode.IsSpace(runes[end-1]) {
		return ""
	}
	start := end
	for start > 0 && !unicode.IsSpace(runes[start-1]) {
		start--
	}
	return string(runes[start:end])
}

func replaceCurrentToken(input, value string) string {
	runes := []rune(input)
	if len(runes) > 0 && unicode.IsSpace(runes[len(runes)-1]) {
		return input + value
	}
	end := len(runes)
	for end > 0 && unicode.IsSpace(runes[end-1]) {
		end--
	}
	start := end
	for start > 0 && !unicode.IsSpace(runes[start-1]) {
		start--
	}
	return string(runes[:start]) + value + string(runes[end:])
}

func shouldAppendSpace(input string) bool {
	runes := []rune(input)
	return len(runes) > 0 && !unicode.IsSpace(runes[len(runes)-1])
}

func appendInput(input string, msg tea.KeyMsg) string {
	switch msg.Type {
	case tea.KeyRunes:
		return input + string(msg.Runes)
	case tea.KeySpace:
		return input + " "
	default:
		return input
	}
}

func trimLastRune(value string) string {
	runes := []rune(value)
	if len(runes) == 0 {
		return value
	}
	return string(runes[:len(runes)-1])
}
