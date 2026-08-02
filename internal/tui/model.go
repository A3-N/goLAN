package tui

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"golan/internal/adapters"
	bridge "golan/internal/bridge"
	"golan/internal/canvas"
	"golan/internal/edge"
	"golan/internal/listen"
	networkobs "golan/internal/network"
	"golan/internal/policy"
	"golan/internal/profile"
	workproject "golan/internal/project"

	tea "github.com/charmbracelet/bubbletea"
)

// Model owns the command-first initialization TUI state.
type Model struct {
	adapters                []adapters.Adapter
	profile                 profile.Profile
	profileNeedsRehydrate   bool
	loading                 bool
	err                     error
	listener                *listen.Session
	listenerStopReported    *listen.Session
	listenInterfaces        []string
	listenStopPending       bool
	capMode                 string
	bridge                  *bridge.Session
	natActive               bool
	runtimeOperation        string
	adapterStatePending     string
	refreshPending          bool
	eapolSuppressLogoff     bool
	eapolDowngradeMACsec    bool
	redactObservedSecrets   bool
	workspace               workspace
	inspectorVisible        bool
	maximized               bool
	help                    helpState
	commandPalette          commandPaletteState
	settingsEditor          settingsEditorState
	startup                 startupState
	ruleEditor              ruleEditorState
	project                 *workproject.Project
	projectSessions         []workproject.AssociatedSession
	projectSessionErr       string
	bundleExport            bundleExportState
	saveAsCancel            context.CancelFunc
	recents                 workproject.RecentState
	recentErr               string
	recentEpoch             uint64
	doctorEpoch             uint64
	rulePreviewEpoch        uint64
	policyStore             *policy.Store
	offline                 bool
	bridgeMode              string
	bridgeControlledOptions bridge.ControlledOptions
	edgeMode                string
	edgeUpstream            string
	edgeConfiguredMode      string
	edgeSession             *edge.Session
	edgeForwards            []edgeForwardSetting

	bridgeState    string
	effects        *effectTracker
	restoreState   map[string]bridge.InterfaceRestoreState
	lockPending    map[string]bool
	lockFailed     map[string]bool
	restorePending map[string]bool

	activeAdapter           string
	cursorVisible           bool
	activeCard              cardFocus
	outputScroll            int
	output                  []string
	outputMuted             []bool
	outputLiteral           []bool
	liveEvidence            []liveEvidenceRecord
	liveEvidenceBytes       int
	networkTracker          *networkobs.Tracker
	observedSecrets         map[string]string
	networkFilter           networkobs.Category
	networkSearch           string
	selectedNetworkDevice   string
	networkSection          int
	networkExpanded         map[networkobs.Category]bool
	networkSessionPersisted string
	selectedRuleID          string
	artifacts               *artifactRegistry
	canvasMap               *canvas.Map
	canvasDirty             bool
	input                   string
	inputMode               inputMode
	completions             []string
	cycleContext            string
	cycleIndex              int
	cycleOptions            []string
	history                 []string
	historyIndex            int

	width  int
	height int
}

type discoveredMsg struct {
	adapters []adapters.Adapter
	err      error
}

type cursorBlinkMsg struct{}

type recentsLoadedMsg struct {
	epoch uint64
	state workproject.RecentState
	err   error
}

type edgeForwardSetting struct {
	Protocol   string
	ListenPort uint16
	TargetPort uint16
}

type listenStartedMsg struct {
	session        *listen.Session
	interfaces     []string
	cleanupPending []string
	err            error
	mode           string
}

type listenEventMsg struct {
	session *listen.Session
	event   listen.Event
	ok      bool
}

type listenStoppedMsg struct {
	session        *listen.Session
	artifactDir    string
	interfaces     []string
	cleanupPending []string
	sessionPending bool
	cleanupErr     error
	err            error
}

type bridgeStartedMsg struct {
	session *bridge.Session
	mode    bridge.Mode
	err     error
}

type bridgeEventMsg struct {
	session *bridge.Session
	event   bridge.Event
	ok      bool
}

type bridgeStoppedMsg struct {
	session        *bridge.Session
	artifactDir    string
	cleanupPending bool
	err            error
}

type bridgeNATMsg struct {
	session *bridge.Session
	active  bool
	err     error
}

type edgeStartedMsg struct {
	session *edge.Session
	mode    edge.Mode
	err     error
}

type edgeEventMsg struct {
	session *edge.Session
	event   edge.Event
	ok      bool
}

type edgeStoppedMsg struct {
	session        *edge.Session
	artifactDir    string
	cleanupPending bool
	err            error
}

type projectCapturesIndexedMsg struct {
	project   *workproject.Project
	directory string
	results   []workproject.SessionCaptureImport
	err       error
}

type bundleExportMsg struct {
	project     *workproject.Project
	destination string
	report      workproject.BundleReport
	showReport  bool
	err         error
}

type projectSaveAsMsg struct {
	source      *workproject.Project
	next        *workproject.Project
	destination string
	err         error
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
	name  string
	state bridge.InterfaceRestoreState
	err   error
}

type cardFocus int
type inputMode int
type workspace string

const (
	workspaceMain    workspace = "Main"
	workspaceNetwork workspace = "Network"
	workspaceRules   workspace = "Rules"
)

var workspaces = []workspace{workspaceMain, workspaceNetwork, workspaceRules}

const cardNone cardFocus = -1

const (
	cardOutput cardFocus = iota
	cardCLI
	cardInspector
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
	eapolDefaults := bridge.DefaultEAPOLPolicy()
	return Model{
		loading:                 true,
		workspace:               workspaceMain,
		inspectorVisible:        true,
		cursorVisible:           true,
		activeCard:              cardCLI,
		cycleIndex:              -1,
		historyIndex:            -1,
		restoreState:            make(map[string]bridge.InterfaceRestoreState),
		effects:                 newEffectTracker(),
		lockPending:             make(map[string]bool),
		lockFailed:              make(map[string]bool),
		restorePending:          make(map[string]bool),
		artifacts:               newArtifactRegistry(),
		canvasMap:               canvas.NewMap(),
		networkExpanded:         map[networkobs.Category]bool{networkobs.CategoryAddressing: true},
		policyStore:             &policy.Store{},
		eapolSuppressLogoff:     eapolDefaults.SuppressLogoff,
		eapolDowngradeMACsec:    eapolDefaults.DowngradeMACsec,
		redactObservedSecrets:   true,
		observedSecrets:         make(map[string]string),
		edgeUpstream:            "auto",
		edgeConfiguredMode:      "observe",
		bridgeControlledOptions: bridge.DefaultControlledOptions(),
	}
}

// NewModelWithSize returns a model with an explicit initial terminal size.
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

// NewStartupModelWithSize creates a Workbench model with the keyboard-driven
// project chooser open. Choosing an item only stages local project state; it
// never starts a listener, bridge, edge session, or adapter mutation.
func NewStartupModelWithSize(width, height int, offline bool) Model {
	m := NewModelWithSize(width, height)
	m.offline = offline
	m.openStartupChooser()
	return m
}

// NewProjectModel creates a Workbench model for a working project. Offline
// models skip adapter discovery and never start networking implicitly.
func NewProjectModel(project *workproject.Project, offline bool, width, height int) Model {
	m := NewModelWithSize(width, height)
	m.offline = offline
	m.attachProject(project)
	if project != nil {
		manifest := project.Manifest()
		for _, candidate := range workspaces {
			if strings.EqualFold(string(candidate), manifest.Preferences.Workspace) {
				m.workspace = candidate
				break
			}
		}
		m.reportUnindexedProjectArtifacts()
	}
	return m
}

// Init starts adapter discovery and cursor timing.
func (m Model) Init() tea.Cmd {
	if m.offline {
		return tea.Batch(loadRecentsCmd(m.recentEpoch), blinkCursorCmd())
	}
	return tea.Batch(discoverAdaptersCmd, loadRecentsCmd(m.recentEpoch), blinkCursorCmd())
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

// PcapDirs returns an immutable snapshot of artifact directories owned by model.
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
	if m.saveAsCancel != nil {
		m.saveAsCancel()
		m.saveAsCancel = nil
	}
	m.finishPendingEffects()
	m.clearRuntimeOperation(projectSaveAsOperation)
	m.recordActivePcapDirs()
	if err := m.stopCapture(); err != nil {
		errs = append(errs, fmt.Errorf("stop listen: %w", err))
	}
	if err := m.stopEdgeNow(); err != nil {
		errs = append(errs, fmt.Errorf("stop edge: %w", err))
	}
	if err := m.stopBridgeNow(); err != nil {
		errs = append(errs, fmt.Errorf("stop bridge: %w", err))
	}
	m.finishNetworkSession()
	if err := m.restoreLockedAdaptersNow(); err != nil {
		errs = append(errs, fmt.Errorf("restore adapters: %w", err))
	}
	m.indexRememberedProjectCapturesNow()
	return errors.Join(errs...)
}

func (m *Model) indexRememberedProjectCapturesNow() {
	if m.project == nil {
		return
	}
	for _, directory := range m.pcapDirsSnapshot() {
		// A tracked indexing command may have been returned to Bubble Tea but
		// not started before shutdown. Clear only that pending marker; a
		// completed marker remains intact.
		m.finishProjectCaptureIndex(m.project.Path(), directory, false)
		cmd := m.startProjectCaptureIndex(directory)
		if cmd == nil {
			continue
		}
		next, _ := m.Update(cmd())
		switch next := next.(type) {
		case Model:
			*m = next
		case *Model:
			*m = *next
		}
	}
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

// Update applies one Bubble Tea message and schedules any follow-up effect.
func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	if key, ok := msg.(tea.KeyMsg); ok {
		if m.help.open {
			m.updateHelpKey(key.String())
			return m, nil
		}
		if key.String() == "f1" || (key.String() == "?" && m.input == "" && m.activeCard != cardCLI && m.cardVisible(m.activeCard) && !m.commandPalette.open && !m.startup.open && !m.bundleExport.open) {
			m.openHelp()
			return m, nil
		}
		if m.commandPalette.open {
			return m.updateCommandPalette(key)
		}
		if m.settingsEditor.open {
			return m.updateSettingsEditor(key)
		}
		if m.startup.open {
			return m.updateStartupChooser(key)
		}
		if m.bundleExport.open {
			return m.updateBundleExport(key)
		}
		if m.ruleEditor.open {
			return m.updateRuleEditor(key)
		}
	}
	if mouse, ok := msg.(tea.MouseMsg); ok {
		switch {
		case m.help.open:
			m.updateHelpMouse(mouse)
		case m.commandPalette.open:
			m.updateCommandPaletteMouse(mouse)
		case m.settingsEditor.open:
			m.updateSettingsEditorMouse(mouse)
		case m.startup.open,
			m.bundleExport.open,
			m.ruleEditor.open:
			// Modal views own the screen; do not activate Workbench controls
			// that are hidden underneath them.
		default:
			return m, m.updateWorkbenchMouse(mouse)
		}
		return m, nil
	}
	switch msg := msg.(type) {
	case effectResultMsg:
		m.effects.acknowledge(msg.id)
		return m.Update(msg.msg)
	case discoveredMsg:
		m.loading = false
		m.refreshPending = false
		m.adapters = msg.adapters
		m.err = msg.err
		m.refreshCompletions()
		return m, nil
	case recentsLoadedMsg:
		if msg.epoch != m.recentEpoch {
			return m, nil
		}
		if msg.err != nil {
			m.recentErr = msg.err.Error()
		} else {
			m.recents = msg.state
			m.recentErr = ""
		}
		m.refreshCompletions()
		return m, nil
	case doctorMsg:
		if msg.epoch != m.doctorEpoch {
			return m, nil
		}
		m.print("doctor:")
		for _, line := range msg.report.Lines() {
			m.print("  " + line)
		}
		return m, nil
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		return m, nil
	case rulePreviewMsg:
		if !m.ruleEditor.open || msg.epoch != m.ruleEditor.previewEpoch {
			return m, nil
		}
		if msg.source != "" {
			m.ruleEditor.previewSource = msg.source
		}
		m.ruleEditor.evidence = nil
		if msg.err != nil {
			m.ruleEditor.preview = "preview error: " + msg.err.Error()
		} else {
			m.ruleEditor.preview = fmt.Sprintf("%d packets tested · %d match · 0 errors", msg.packets, msg.matches)
			switch {
			case msg.matches == 0:
				m.ruleEditor.evidence = []string{"no matching packet sample"}
			case msg.sample != nil:
				m.ruleEditor.evidence = formatFrameTransformationPreview(*msg.sample)
			case msg.sampleErr != nil:
				m.ruleEditor.evidence = []string{
					fmt.Sprintf("sample packet=%s · transformation evidence error: %s", msg.samplePacketID, msg.sampleErr),
				}
			}
		}
		return m, nil
	case cursorBlinkMsg:
		m.cursorVisible = !m.cursorVisible
		return m, blinkCursorCmd()
	case listenStartedMsg:
		m.clearRuntimeOperation("listen start")
		if msg.err != nil {
			m.updateListenInterfaceStates(msg.interfaces, msg.cleanupPending)
			m.listenInterfaces = append([]string(nil), msg.cleanupPending...)
			m.print(msg.mode + " err: " + msg.err.Error())
			if len(msg.cleanupPending) > 0 {
				m.print("listen: cleanup pending; use: stop listen")
			}
			return m, nil
		}
		m.listener = msg.session
		m.listenerStopReported = nil
		m.listenInterfaces = append([]string(nil), msg.interfaces...)
		m.listenStopPending = false
		m.updateListenInterfaceStates(msg.interfaces, msg.interfaces)
		m.capMode = msg.mode
		if strings.HasPrefix(msg.mode, "edge-") {
			m.edgeMode = strings.TrimPrefix(msg.mode, "edge-")
			m.print("edge: on " + m.edgeMode)
		} else {
			m.print("listen: on")
		}
		m.print("pcap: " + msg.session.Dir)
		m.rememberPcapDir(msg.session.Dir)
		m.associateProjectSession(msg.session.Dir)
		m.startNetworkSession(msg.mode, msg.session.Dir)
		return m, waitListenEventCmd(msg.session)
	case listenEventMsg:
		if m.listener != msg.session {
			return m, nil
		}
		if !msg.ok {
			artifactDir := msg.session.Dir
			interfaces := append([]string(nil), m.listenInterfaces...)
			stopPending := m.listenStopPending
			m.listener = nil
			mode := m.capMode
			m.capMode = ""
			m.edgeMode = ""
			m.finishNetworkSession()
			if mode == "" {
				mode = "listen"
			}
			if stopPending {
				return m, nil
			}
			if len(interfaces) > 0 {
				m.listenStopPending = true
				m.beginRuntimeOperation("listen stop")
				return m, m.trackEffect(stopListenCleanupCmd(interfaces, artifactDir))
			}
			m.print(mode + ": off")
			return m, m.startProjectCaptureIndex(artifactDir)
		}
		cmd := m.handleListenEvent(msg.event)
		return m, cmd
	case listenStoppedMsg:
		m.clearRuntimeOperation("listen stop")
		wasActive := msg.session != nil && m.listener == msg.session
		cleanupRetry := msg.session == nil
		alreadyReported := msg.session != nil && m.listenerStopReported == msg.session
		if wasActive && !msg.sessionPending {
			m.listener = nil
			m.capMode = ""
			m.edgeMode = ""
		}
		m.listenStopPending = false
		m.updateListenInterfaceStates(msg.interfaces, msg.cleanupPending)
		m.listenInterfaces = append([]string(nil), msg.cleanupPending...)
		if msg.err != nil && !alreadyReported {
			m.print("listen err: stop " + msg.err.Error())
		} else if alreadyReported && msg.cleanupErr != nil {
			m.print("listen err: stop " + msg.cleanupErr.Error())
		} else if (wasActive || cleanupRetry) && !alreadyReported && len(msg.cleanupPending) == 0 && !msg.sessionPending {
			m.print("listen: off")
		}
		if len(msg.cleanupPending) > 0 || msg.sessionPending {
			m.print("listen: cleanup pending; use: stop listen")
		}
		m.listenerStopReported = nil
		if !msg.sessionPending {
			m.finishNetworkSession()
			return m, m.startProjectCaptureIndex(msg.artifactDir)
		}
		return m, nil
	case edgeStartedMsg:
		m.clearRuntimeOperation("edge start")
		if msg.err != nil {
			m.print("edge err: " + msg.err.Error())
			return m, nil
		}
		m.edgeSession = msg.session
		m.edgeMode = string(msg.mode)
		m.print("edge: on " + string(msg.mode))
		m.print("pcap: " + msg.session.Dir)
		m.rememberPcapDir(msg.session.Dir)
		m.associateProjectSession(msg.session.Dir)
		m.startNetworkSession("edge-"+string(msg.mode), msg.session.Dir)
		return m, waitEdgeEventCmd(msg.session)
	case edgeEventMsg:
		if m.edgeSession != msg.session {
			return m, nil
		}
		if !msg.ok {
			m.edgeSession = nil
			m.edgeMode = ""
			m.finishNetworkSession()
			m.print("edge: off")
			return m, nil
		}
		return m, m.handleEdgeEvent(msg.session, msg.event)
	case edgeStoppedMsg:
		m.clearRuntimeOperation("edge stop")
		if m.edgeSession != msg.session {
			return m, nil
		}
		if msg.err != nil {
			m.print("edge err: stop " + msg.err.Error())
		}
		if msg.cleanupPending {
			m.print("edge: cleanup pending; use: stop edge")
		} else {
			m.edgeSession = nil
			m.edgeMode = ""
			m.print("edge: off")
		}
		m.finishNetworkSession()
		return m, m.startProjectCaptureIndex(msg.artifactDir)
	case bridgeStartedMsg:
		m.clearRuntimeOperation("bridge start")
		if msg.err != nil {
			m.print("bridge err: " + msg.err.Error())
			return m, nil
		}
		m.bridge = msg.session
		m.bridgeMode = string(msg.mode)
		m.bridgeState = "starting"
		m.print("bridge: on")
		m.print("pcap: " + msg.session.Dir)
		m.rememberPcapDir(msg.session.Dir)
		m.associateProjectSession(msg.session.Dir)
		m.startNetworkSession("bridge-"+string(msg.mode), msg.session.Dir)
		return m, waitBridgeEventCmd(msg.session)
	case bridgeEventMsg:
		if m.bridge != msg.session {
			return m, nil
		}
		if !msg.ok {
			m.bridge = nil
			m.bridgeState = ""
			m.bridgeMode = ""
			m.natActive = false
			m.finishNetworkSession()
			m.print("bridge: off")
			return m, nil
		}
		return m, m.handleBridgeEvent(msg.session, msg.event)
	case bridgeStoppedMsg:
		m.clearRuntimeOperation("bridge stop")
		wasActive := m.bridge == msg.session
		alreadyPending := wasActive && m.bridgeState == "cleanup-pending"
		if wasActive && !msg.cleanupPending {
			m.bridge = nil
			m.bridgeState = ""
			m.bridgeMode = ""
			m.natActive = false
		}
		if msg.err != nil && !alreadyPending {
			m.print("bridge err: stop " + msg.err.Error())
		}
		if wasActive && msg.cleanupPending {
			m.bridgeState = "cleanup-pending"
			if !alreadyPending {
				m.print("bridge: cleanup pending; use: stop bridge")
			}
		} else if wasActive && msg.err == nil {
			m.print("bridge: off")
		}
		m.finishNetworkSession()
		return m, m.startProjectCaptureIndex(msg.artifactDir)
	case projectCapturesIndexedMsg:
		m.applyProjectCaptureIndex(msg)
		return m, nil
	case bundleExportMsg:
		m.applyBundleExport(msg)
		return m, nil
	case projectSaveAsMsg:
		m.applyProjectSaveAs(msg)
		return m, nil
	case bridgeNATMsg:
		if msg.active {
			m.clearRuntimeOperation("takeover start")
		} else {
			m.clearRuntimeOperation("takeover stop")
		}
		if m.bridge != msg.session {
			return m, nil
		}
		if msg.err != nil {
			snapshot := msg.session.TakeoverSnapshot()
			m.natActive = snapshot.Active || snapshot.CleanupPending
			m.print("takeover err: " + msg.err.Error())
			if snapshot.CleanupPending {
				m.print("takeover: cleanup pending; use: stop takeover")
			}
			return m, nil
		}
		m.natActive = msg.active
		if msg.active {
			m.print("takeover: on")
		} else {
			m.print("takeover: off")
		}
		return m, nil
	case eapolSentMsg:
		m.clearRuntimeOperation("eapol send")
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
		if m.adapterStatePending == msg.name {
			m.adapterStatePending = ""
		}
		if msg.err != nil {
			m.print(fmt.Sprintf("adapter state err %s: %v", msg.name, msg.err))
			return m, nil
		}
		if cfg, ok := m.profile.ByName(msg.name); ok {
			if _, err := cfg.Set("state", msg.state); err != nil {
				m.print(fmt.Sprintf("adapter state err %s: %v", msg.name, err))
				return m, nil
			}
		}
		m.updateAdapterStatus(msg.name, msg.state == "up")
		m.print(fmt.Sprintf("adapter state: %s %s", msg.name, msg.state))
		return m, nil
	case adapterLockdownMsg:
		if m.restoreState == nil {
			m.restoreState = make(map[string]bridge.InterfaceRestoreState)
		}
		if _, exists := m.restoreState[msg.name]; !exists {
			m.restoreState[msg.name] = msg.state
		}
		if msg.err != nil {
			if m.lockPending != nil {
				delete(m.lockPending, msg.name)
			}
			if m.lockFailed == nil {
				m.lockFailed = make(map[string]bool)
			}
			m.lockFailed[msg.name] = true
			m.updateAdapterStatus(msg.name, msg.state.InterfaceUp)
			m.print(fmt.Sprintf("adapter isolate err %s: %v", msg.name, msg.err))
			return m, nil
		}
		if m.lockPending != nil {
			delete(m.lockPending, msg.name)
		}
		if m.lockFailed != nil {
			delete(m.lockFailed, msg.name)
		}
		m.updateAdapterStatus(msg.name, false)
		m.print(fmt.Sprintf("adapter isolated: %s %s", msg.role, msg.name))
		return m, nil
	case adapterRestoreMsg:
		if m.restorePending != nil {
			delete(m.restorePending, msg.name)
		}
		if msg.err != nil {
			m.print(fmt.Sprintf("adapter restore warn %s: %v", msg.name, msg.err))
		} else {
			if current, ok := m.restoreState[msg.name]; ok && current == msg.state {
				delete(m.restoreState, msg.name)
			}
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
	if m.runtimeOperation == projectSaveAsOperation {
		switch msg.String() {
		case "esc":
			if m.saveAsCancel != nil {
				m.saveAsCancel()
				m.saveAsCancel = nil
				m.print("project: canceling save-as; source project remains active")
			}
			return m, nil
		case "ctrl+c":
			if m.saveAsCancel != nil {
				m.saveAsCancel()
				m.saveAsCancel = nil
			}
			return m, tea.Quit
		default:
			return m, nil
		}
	}
	if shortcut, ok := workbenchShortcutForKey(msg.String()); ok {
		var command tea.Cmd
		switch shortcut {
		case shortcutPanePrevious:
			m.moveCardFocus(-1)
		case shortcutPaneNext:
			m.moveCardFocus(1)
		case shortcutWorkspacePrevious:
			m.moveWorkspace(-1)
		case shortcutWorkspaceNext:
			m.moveWorkspace(1)
		case shortcutPaneMaximize:
			m.toggleMaximized()
		case shortcutInspectorToggle:
			m.toggleInspector()
		case shortcutCommandPalette:
			m.openCommandPalette()
		}
		return m, command
	}
	if target, ok := workspaceShortcutForKey(msg.String()); ok {
		m.selectWorkspace(target)
		return m, nil
	}
	if m.input == "" && m.activeCard != cardCLI && m.activeCard != cardNone {
		switch msg.String() {
		case "s":
			if m.workspace == workspaceMain {
				m.openSettingsEditor()
				return m, nil
			}
		case "r":
			if m.workspace == workspaceRules {
				m.openRuleEditor(false)
				return m, nil
			}
		case "M":
			if m.workspace == workspaceRules {
				m.openRuleEditor(true)
				return m, nil
			}
		case "enter":
			if m.workspace == workspaceNetwork && m.activeCard == cardInspector {
				m.toggleNetworkSection()
				return m, nil
			}
		}
	}
	// Printable keys that are not actions for the focused pane stay in that
	// pane. This prevents macOS modifier composition (for example ß)
	// and ordinary typos from unexpectedly opening and editing the CLI.
	if msg.Type == tea.KeyRunes && m.activeCard != cardCLI && m.activeCard != cardNone {
		return m, nil
	}
	switch msg.String() {
	case "ctrl+c":
		if m.saveAsCancel != nil {
			m.saveAsCancel()
		}
		return m, tea.Quit
	case "ctrl+s":
		if m.project != nil {
			if err := m.project.Save(); err != nil {
				m.print("project err: save " + err.Error())
			} else {
				m.rememberRecentProject(m.project)
				m.print("project: saved " + m.project.Path())
			}
		} else {
			m.startSavePrompt()
		}
	case "left", "right":
		// Horizontal pane navigation uses Shift+Left/Right. Keeping plain
		// arrows inert in the CLI avoids surprising focus changes and leaves
		// room for cursor editing.
	case "esc":
		if m.inputMode != modeCommand {
			m.input = ""
			m.inputMode = modeCommand
			m.completions = nil
			m.resetCompletionCycle()
		}
		m.showAllPanes()
	case "enter":
		if m.workspace != workspaceMain {
			return m, nil
		}
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
			if m.project == nil && m.workspace == workspaceMain {
				m.openStartupChooser()
			}
			return m, nil
		}
		m.history = append(m.history, raw)
		m.historyIndex = -1
		cmd := m.executeCommand(raw)
		return m, cmd
	case "backspace", "ctrl+h":
		if m.workspace != workspaceMain {
			return m, nil
		}
		m.activeCard = cardCLI
		m.input = trimLastRune(m.input)
		m.resetCompletionCycle()
		m.refreshCompletions()
		m.cursorVisible = true
	case "ctrl+u":
		if m.workspace != workspaceMain {
			return m, nil
		}
		m.activeCard = cardCLI
		m.input = ""
		m.completions = nil
		m.resetCompletionCycle()
		m.cursorVisible = true
	case "tab":
		if m.workspace != workspaceMain {
			return m, nil
		}
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
		if m.workspace != workspaceMain {
			return m, nil
		}
		m.activeCard = cardCLI
		m.input = appendInput(m.input, msg)
		m.resetCompletionCycle()
		m.refreshCompletions()
		m.cursorVisible = true
	}
	return m, nil
}

func (m *Model) moveWorkspace(delta int) {
	index := 0
	for i, value := range workspaces {
		if value == m.workspace {
			index = i
			break
		}
	}
	index = (index + delta + len(workspaces)) % len(workspaces)
	m.selectWorkspace(workspaces[index])
}

func (m *Model) selectWorkspace(next workspace) {
	m.workspace = next
	m.maximized = false
	if m.activeCard != cardNone && !m.cardVisible(m.activeCard) {
		m.activeCard = cardOutput
	}
	if m.project != nil {
		m.project.SetWorkspace(string(m.workspace))
	}
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
	cards := m.visibleCards()
	if len(cards) == 0 {
		m.activeCard = cardNone
		return
	}
	index := -1
	for i, card := range cards {
		if card == m.activeCard {
			index = i
			break
		}
	}
	if index == -1 {
		if delta < 0 {
			m.activeCard = cards[len(cards)-1]
		} else {
			m.activeCard = cards[0]
		}
		return
	}
	index = (index + delta + len(cards)) % len(cards)
	m.activeCard = cards[index]
}

func (m *Model) showAllPanes() {
	if m.activeCard == cardNone {
		return
	}
	m.activeCard = cardNone
	m.maximized = false
	m.cursorVisible = false
}

func (m Model) visibleCards() []cardFocus {
	if m.workspace == workspaceMain {
		return []cardFocus{cardOutput, cardCLI}
	}
	if m.workspaceInspectorVisible() {
		return []cardFocus{cardOutput, cardInspector}
	}
	return []cardFocus{cardOutput}
}

func (m *Model) toggleMaximized() {
	if m.activeCard == cardNone {
		return
	}
	if !m.cardVisible(m.activeCard) {
		m.activeCard = cardOutput
	}
	m.maximized = !m.maximized
}

func (m *Model) toggleInspector() {
	if !m.workspaceSupportsInspector() {
		m.print("layout: this workspace has no inspector")
		return
	}
	m.inspectorVisible = !m.inspectorVisible
	if !m.inspectorVisible && m.activeCard == cardInspector {
		m.activeCard = cardOutput
		m.maximized = false
	}
}

func (m Model) cardVisible(card cardFocus) bool {
	switch card {
	case cardOutput:
		return true
	case cardCLI:
		return m.workspace == workspaceMain
	case cardInspector:
		return m.workspaceInspectorVisible()
	default:
		return false
	}
}

func (m Model) workspaceSupportsInspector() bool {
	switch m.workspace {
	case workspaceNetwork, workspaceRules:
		return true
	default:
		return false
	}
}

func (m Model) workspaceInspectorVisible() bool {
	return m.inspectorVisible && m.workspaceSupportsInspector()
}

func (m *Model) handleVerticalMove(delta int) {
	if m.workspace == workspaceNetwork &&
		(m.activeCard == cardOutput || m.activeCard == cardInspector) {
		if m.activeCard == cardInspector {
			m.moveNetworkSection(delta)
		} else {
			m.moveNetworkSelection(delta)
		}
		return
	}
	if m.workspace == workspaceRules &&
		(m.activeCard == cardOutput || m.activeCard == cardInspector) {
		m.moveRuleSelection(delta)
		return
	}
	switch m.activeCard {
	case cardOutput:
		m.outputScroll = max(0, m.outputScroll-delta)
		return
	case cardCLI:
		m.recallHistory(delta)
	default:
		// No pane owns navigation while the Workbench is in its overview state.
	}
}
