package tui

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"time"

	bridge "golan/internal/bridge"
	"golan/internal/dataplane"
	"golan/internal/edge"
	"golan/internal/listen"
	networkobs "golan/internal/network"
	"golan/internal/policy"
	"golan/internal/profile"

	tea "github.com/charmbracelet/bubbletea"
)

func (m Model) listenTargets() []listen.Target {
	cfg, ok := m.profile.Role(profile.AdapterRoleHost)
	if !ok {
		return nil
	}
	target := *cfg
	if adapter, ok := m.findAdapter(target.Name); ok {
		target.CurrentMAC = adapter.MAC
		target.HardwarePort = adapter.HardwarePort
		target.NetworkService = adapter.NetworkService
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
		hostCfg.NetworkService = adapter.NetworkService
		hostCfg.Addrs = append([]string(nil), adapter.Addrs...)
	}
	if adapter, ok := m.findAdapter(sw.Name); ok {
		swCfg.CurrentMAC = adapter.MAC
		swCfg.HardwarePort = adapter.HardwarePort
		swCfg.NetworkService = adapter.NetworkService
		swCfg.Addrs = append([]string(nil), adapter.Addrs...)
	}
	return hostCfg, swCfg, ""
}

func (m Model) compatibilityForCapabilities(rule policy.Rule, capabilities dataplane.Capabilities) (dataplane.Status, dataplane.Capability, string) {
	return policy.Compatibility(rule, capabilities)
}

func (m Model) bridgeTakeoverConfig() bridge.TakeoverConfig {
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
	return bridge.TakeoverConfig{
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
	if len(m.lockPending) == 0 && len(m.lockFailed) == 0 {
		return nil
	}
	seen := make(map[string]bool, len(m.lockPending)+len(m.lockFailed))
	names := make([]string, 0, len(m.lockPending)+len(m.lockFailed))
	for name, pending := range m.lockPending {
		if pending && !seen[name] {
			seen[name] = true
			names = append(names, name)
		}
	}
	for name, failed := range m.lockFailed {
		if failed && !seen[name] {
			seen[name] = true
			names = append(names, name)
		}
	}
	sort.Strings(names)
	return names
}

const projectCaptureIndexOperation = "project capture indexing"

func (m *Model) startProjectCaptureIndex(directory string) tea.Cmd {
	directory = strings.TrimSpace(directory)
	if m.project == nil || directory == "" {
		return nil
	}
	if !m.beginProjectCaptureIndex(m.project.Path(), directory) {
		return nil
	}
	project := m.project
	m.beginRuntimeOperation(projectCaptureIndexOperation)
	return m.trackEffect(func() tea.Msg {
		results, captureErr := project.ImportSessionCaptures(context.Background(), directory)
		return projectCapturesIndexedMsg{
			project: project, directory: directory, results: results, err: captureErr,
		}
	})
}

func (m *Model) associateProjectSession(directory string) {
	if m.project == nil || strings.TrimSpace(directory) == "" {
		return
	}
	if err := m.project.AssociateSession(directory); err != nil {
		m.print("project warn: associate live session: " + err.Error())
		return
	}
	m.refreshAssociatedSessions()
}

func (m *Model) applyProjectCaptureIndex(msg projectCapturesIndexedMsg) {
	m.clearRuntimeOperation(projectCaptureIndexOperation)
	complete := msg.err == nil && len(msg.results) > 0
	imported := 0
	duplicates := 0
	failed := 0
	captureJournalImported := 0
	captureJournalDuplicates := 0
	captureJournalFailed := 0
	for _, result := range msg.results {
		if result.Err != nil {
			complete = false
			failed++
			m.print("project warn: session capture " + filepath.Base(result.Source) + ": " + result.Err.Error())
			continue
		}
		if result.Duplicate {
			duplicates++
		} else {
			imported++
		}
		if result.Pair != nil {
			state := "indexed"
			if result.PairDuplicate {
				state = "already indexed"
			}
			m.print(fmt.Sprintf(
				"project: capture pair %s id=%s records=%d complete=%t",
				state,
				result.Pair.ID,
				result.Pair.JournalRecords,
				result.Pair.JournalComplete,
			))
		}
		if result.JournalErr != nil {
			complete = false
			failed++
			captureJournalFailed++
			m.print("project warn: capture journal " + filepath.Base(result.Source) + ": " + result.JournalErr.Error())
			continue
		}
		if result.Journal != nil {
			state := "indexed"
			if result.JournalDuplicate {
				state = "already indexed"
				captureJournalDuplicates++
			} else {
				captureJournalImported++
			}
			m.print(fmt.Sprintf(
				"project: capture journal %s id=%s mode=%s records=%d complete=%t",
				state, result.Journal.ID, result.Journal.Mode, result.Journal.Records, result.Journal.Complete,
			))
		}
	}
	projectPath := ""
	if msg.project != nil {
		projectPath = msg.project.Path()
	}
	if complete && msg.project != nil {
		if err := msg.project.CompleteSessionAssociation(msg.directory); err != nil {
			complete = false
			m.print("project warn: complete session recovery marker: " + err.Error())
		}
	}
	if msg.project == m.project {
		m.refreshAssociatedSessions()
	}
	m.finishProjectCaptureIndex(projectPath, msg.directory, complete)
	if msg.err != nil {
		m.print("project warn: index session captures: " + msg.err.Error())
		return
	}
	if len(msg.results) == 0 {
		m.print("project: session contains no finalized captures: " + msg.directory)
		return
	}
	suffix := ""
	if msg.project == m.project {
		if msg.project.Dirty() {
			suffix = " (PROJECT*)"
		} else {
			suffix = " (project unchanged)"
		}
	} else if projectPath != "" {
		suffix = " project=" + projectPath
	}
	m.print(fmt.Sprintf("project: session captures indexed imported=%d deduplicated=%d failed=%d%s", imported, duplicates, failed, suffix))
	if captureJournalImported+captureJournalDuplicates+captureJournalFailed > 0 {
		m.print(fmt.Sprintf(
			"project: session capture journals indexed imported=%d deduplicated=%d failed=%d%s",
			captureJournalImported, captureJournalDuplicates, captureJournalFailed, suffix,
		))
	}
}

func (m Model) inFlightLocks() []string {
	var names []string
	for name, pending := range m.lockPending {
		if pending {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	return names
}

func startListenPolicyCmd(targets []listen.Target, mode string, dataMode dataplane.Mode, revision string, rules []policy.Rule) tea.Cmd {
	return startListenPolicyCmdWithState(targets, mode, dataMode, revision, rules, bridge.SetInterfaceState)
}

func startListenPolicyCmdWithState(targets []listen.Target, mode string, dataMode dataplane.Mode, revision string, rules []policy.Rule, setState func(string, string) error) tea.Cmd {
	return startListenWithState(targets, mode, setState, func(targets []listen.Target) (*listen.Session, error) {
		return listen.StartWithPolicy(targets, dataMode, revision, rules)
	})
}

func startListenWithState(targets []listen.Target, mode string, setState func(string, string) error, start func([]listen.Target) (*listen.Session, error)) tea.Cmd {
	return func() tea.Msg {
		interfaces := make([]string, 0, len(targets))
		for _, target := range targets {
			if err := setState(target.Name, "up"); err != nil {
				pending, rollbackErr := lowerInterfaces(interfaces, setState)
				return listenStartedMsg{
					interfaces:     interfaces,
					cleanupPending: pending,
					err:            errors.Join(err, rollbackErr),
					mode:           mode,
				}
			}
			interfaces = append(interfaces, target.Name)
		}
		session, err := start(targets)
		if err != nil {
			pending, rollbackErr := lowerInterfaces(interfaces, setState)
			return listenStartedMsg{
				interfaces:     interfaces,
				cleanupPending: pending,
				err:            errors.Join(err, rollbackErr),
				mode:           mode,
			}
		}
		return listenStartedMsg{session: session, interfaces: interfaces, mode: mode}
	}
}

func stopListenCmd(session *listen.Session, interfaces []string) tea.Cmd {
	return stopListenCmdWithState(session, interfaces, bridge.SetInterfaceState)
}

func startEdgeCmd(downstream, upstream string, mode edge.Mode, revision string, rules []policy.Rule, forwards []edgeForwardSetting) tea.Cmd {
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		config, err := edge.AutoConfig(ctx, downstream, upstream, mode)
		if err != nil {
			return edgeStartedMsg{mode: mode, err: err}
		}
		lease, err := edge.LeaseForSubnet(config.Subnet, config.DNS)
		if err != nil {
			return edgeStartedMsg{mode: mode, err: err}
		}
		for _, forward := range forwards {
			config.PortForwards = append(config.PortForwards, edge.PortForward{Protocol: forward.Protocol, ListenPort: forward.ListenPort, TargetIP: lease.ClientIP, TargetPort: forward.TargetPort})
		}
		session, err := edge.Start(config, revision, rules)
		return edgeStartedMsg{session: session, mode: mode, err: err}
	}
}

func stopEdgeCmd(session *edge.Session) tea.Cmd {
	return func() tea.Msg {
		err := session.Stop()
		return edgeStoppedMsg{session: session, artifactDir: session.Dir, cleanupPending: session.CleanupPending(), err: err}
	}
}

func waitEdgeEventCmd(session *edge.Session) tea.Cmd {
	return func() tea.Msg {
		event, ok := <-session.Events
		return edgeEventMsg{session: session, event: event, ok: ok}
	}
}

func (m *Model) handleEdgeEvent(session *edge.Session, event edge.Event) tea.Cmd {
	switch event.Kind {
	case edge.KindState:
		if event.Message != "" {
			m.print("edge: " + event.Message)
		}
	case edge.KindLog:
		m.print(event.Message)
	case edge.KindPcap:
		m.print(fmt.Sprintf("pcap %s: %s", event.Message, event.Path))
		m.rememberPcapPath(event.Path)
		m.addNetworkCapture(event.Path)
	case edge.KindEvidence:
		m.addLiveEvidenceDecision(event.Frame, event.Flow, event.Mode, event.Decision)
	case edge.KindError:
		if event.Err != nil {
			m.print("edge err: " + event.Err.Error())
		}
	case edge.KindStopped:
		if event.Err != nil {
			m.print("edge err: stop " + event.Err.Error())
		}
		if event.State == "cleanup-pending" {
			m.print("edge: cleanup pending; use: stop edge")
			return m.startProjectCaptureIndex(session.Dir)
		}
		m.edgeSession = nil
		m.edgeMode = ""
		m.print("edge: off")
		return m.startProjectCaptureIndex(session.Dir)
	}
	if m.edgeSession == nil {
		return nil
	}
	return waitEdgeEventCmd(session)
}

func stopListenCmdWithState(session *listen.Session, interfaces []string, setState func(string, string) error) tea.Cmd {
	artifactDir := ""
	if session != nil {
		artifactDir = session.Dir
	}
	return stopListenCmdWithStateAndArtifact(session, interfaces, artifactDir, setState)
}

func stopListenCleanupCmd(interfaces []string, artifactDir string) tea.Cmd {
	return stopListenCmdWithStateAndArtifact(nil, interfaces, artifactDir, bridge.SetInterfaceState)
}

func stopListenCmdWithStateAndArtifact(session *listen.Session, interfaces []string, artifactDir string, setState func(string, string) error) tea.Cmd {
	interfaces = append([]string(nil), interfaces...)
	return func() tea.Msg {
		var stopErr error
		if session != nil {
			stopErr = session.Stop()
		}
		pending, restoreErr := lowerInterfaces(interfaces, setState)
		return listenStoppedMsg{
			session:        session,
			artifactDir:    artifactDir,
			interfaces:     interfaces,
			cleanupPending: pending,
			sessionPending: session != nil && !session.Stopped(),
			cleanupErr:     restoreErr,
			err:            errors.Join(stopErr, restoreErr),
		}
	}
}

func lowerInterfaces(interfaces []string, setState func(string, string) error) ([]string, error) {
	var pending []string
	var errs []error
	for i := len(interfaces) - 1; i >= 0; i-- {
		name := interfaces[i]
		if err := setState(name, "down"); err != nil {
			pending = append(pending, name)
			errs = append(errs, fmt.Errorf("restore %s isolation: %w", name, err))
		}
	}
	sort.Strings(pending)
	return pending, errors.Join(errs...)
}

func (m *Model) updateListenInterfaceStates(interfaces, stillUp []string) {
	pending := make(map[string]bool, len(stillUp))
	for _, name := range stillUp {
		pending[name] = true
	}
	for _, name := range interfaces {
		up := pending[name]
		m.updateAdapterStatus(name, up)
	}
}

func startBridgeCmd(host, sw profile.AdapterConfig, eapolPolicy bridge.EAPOLPolicy, mode bridge.Mode, revision string, rules []policy.Rule, controlledOptions bridge.ControlledOptions) tea.Cmd {
	return startBridgeCmdWithStart(host, sw, eapolPolicy, mode, revision, rules, controlledOptions, bridge.StartModeWithPolicyOptions)
}

func startBridgeCmdWithStart(host, sw profile.AdapterConfig, eapolPolicy bridge.EAPOLPolicy, mode bridge.Mode, revision string, rules []policy.Rule, controlledOptions bridge.ControlledOptions, start func(bridge.Adapter, bridge.Adapter, string, bridge.Mode, bridge.EAPOLPolicy, string, []policy.Rule, bridge.ControlledOptions) (*bridge.Session, error)) tea.Cmd {
	return func() tea.Msg {
		session, err := start(
			bridge.Adapter{Name: host.Name, Role: host.AdapterRole, HardwarePort: host.HardwarePort, NetworkService: adapterNetworkService(host), LocalMAC: host.CurrentMAC, TargetMAC: host.MAC},
			bridge.Adapter{Name: sw.Name, Role: sw.AdapterRole, HardwarePort: sw.HardwarePort, NetworkService: adapterNetworkService(sw), LocalMAC: sw.CurrentMAC},
			"",
			mode,
			eapolPolicy,
			revision,
			rules,
			controlledOptions,
		)
		return bridgeStartedMsg{session: session, mode: mode, err: err}
	}
}

func adapterNetworkService(config profile.AdapterConfig) string {
	return strings.TrimSpace(config.NetworkService)
}

func stopBridgeCmd(session *bridge.Session) tea.Cmd {
	return func() tea.Msg {
		err := session.Stop()
		return bridgeStoppedMsg{session: session, artifactDir: session.Dir, cleanupPending: session.CleanupPending(), err: err}
	}
}

func startNATCmd(session *bridge.Session, cfg bridge.TakeoverConfig) tea.Cmd {
	return func() tea.Msg {
		return bridgeNATMsg{session: session, active: true, err: session.StartTakeover(cfg)}
	}
}

func stopNATCmd(session *bridge.Session) tea.Cmd {
	return func() tea.Msg {
		return bridgeNATMsg{session: session, active: false, err: session.StopTakeover()}
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
	var stopErr error
	sessionPending := false
	if m.listener != nil {
		if stopErr = m.listener.Stop(); stopErr != nil {
			m.print("listen err: stop " + stopErr.Error())
		}
		sessionPending = !m.listener.Stopped()
	}
	pending, restoreErr := lowerInterfaces(m.listenInterfaces, bridge.SetInterfaceState)
	if restoreErr != nil {
		m.print("listen err: stop " + restoreErr.Error())
	}
	m.listenInterfaces = pending
	m.listenStopPending = false
	if !sessionPending {
		m.listener = nil
		m.capMode = ""
		m.edgeMode = ""
	}
	return errors.Join(stopErr, restoreErr)
}

func (m *Model) stopBridgeNow() error {
	if m.bridge == nil {
		return nil
	}
	session := m.bridge
	m.natActive = false
	err := session.Stop()
	if session.CleanupPending() {
		m.bridgeState = "cleanup-pending"
	} else {
		m.bridge = nil
		m.bridgeState = ""
		m.bridgeMode = ""
	}
	if err != nil {
		m.print("bridge err: stop " + err.Error())
		return err
	}
	return nil
}

func (m *Model) stopEdgeNow() error {
	if m.edgeSession == nil {
		return nil
	}
	session := m.edgeSession
	err := session.Stop()
	if !session.CleanupPending() {
		m.edgeSession = nil
		m.edgeMode = ""
	}
	if err != nil {
		m.print("edge err: stop " + err.Error())
	}
	return err
}

func (m *Model) handleBridgeEvent(session *bridge.Session, event bridge.Event) tea.Cmd {
	switch event.Kind {
	case bridge.KindState:
		if event.State != "" && event.State != m.bridgeState {
			m.bridgeState = event.State
			m.print("bridge state: " + event.State)
		}
	case bridge.KindEvidence:
		m.addLiveEvidenceDecision(event.Frame, event.Flow, event.Mode, event.Decision)
	case bridge.KindSignal:
		m.addSensitiveSignalEvent(event.Message, event.Adapter, event.Role)
	case bridge.KindPcap:
		m.print(fmt.Sprintf("pcap %s/%s: %s", event.Role, event.Adapter, event.Path))
		m.rememberPcapPath(event.Path)
		m.addNetworkCapture(event.Path)
	case bridge.KindError:
		if event.Err != nil {
			m.print("bridge err: " + event.Err.Error())
		} else if event.Message != "" {
			m.print("bridge err: " + event.Message)
		}
	case bridge.KindDiscovery:
		m.applyDiscovery(listen.Event{
			Kind:      listen.KindDiscovery,
			Adapter:   event.Adapter,
			Role:      event.Role,
			Field:     event.Field,
			Value:     event.Value,
			Evidence:  event.Evidence,
			Packet:    event.Packet,
			DeviceMAC: event.DeviceMAC,
		})
	case bridge.KindStopped:
		alreadyPending := m.bridgeState == "cleanup-pending"
		if event.Err != nil && !alreadyPending {
			m.print("bridge err: stop " + event.Err.Error())
		}
		if event.State == "cleanup-pending" {
			m.bridgeState = event.State
			m.natActive = false
			if !alreadyPending {
				m.print("bridge: cleanup pending; use: stop bridge")
			}
			return m.startProjectCaptureIndex(session.Dir)
		}
		if event.Message != "" {
			m.print("bridge: " + event.Message)
		}
		m.bridge = nil
		m.bridgeState = ""
		m.bridgeMode = ""
		m.natActive = false
		m.print("bridge: off")
		return m.startProjectCaptureIndex(session.Dir)
	}
	return waitBridgeEventCmd(session)
}

func setAdapterStateCmd(name, state string) tea.Cmd {
	return func() tea.Msg {
		return adapterStateMsg{name: name, state: state, err: bridge.SetInterfaceState(name, state)}
	}
}

func (m *Model) restoreLockedAdaptersNow() error {
	var errs []error
	names := make([]string, 0, len(m.restoreState))
	for name := range m.restoreState {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		state := m.restoreState[name]
		if err := bridge.RestoreInterfaceState(state); err != nil {
			m.print(fmt.Sprintf("adapter restore warn %s: %v", name, err))
			errs = append(errs, fmt.Errorf("%s: %w", name, err))
			continue
		}
		delete(m.restoreState, name)
	}
	for name := range m.lockPending {
		delete(m.lockPending, name)
	}
	for name := range m.lockFailed {
		delete(m.lockFailed, name)
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
	case listen.KindPcap:
		m.print(fmt.Sprintf("pcap %s/%s: %s", event.Role, event.Adapter, event.Path))
		m.rememberPcapPath(event.Path)
		m.addNetworkCapture(event.Path)
	case listen.KindEvidence:
		m.addLiveEvidenceDecision(event.Frame, event.Flow, event.Mode, event.Decision)
	case listen.KindSignal:
		m.addSensitiveSignalEvent(event.Message, event.Adapter, event.Role)
	case listen.KindError:
		m.print(fmt.Sprintf("%s err %s/%s: %v", mode, event.Role, event.Adapter, event.Err))
	case listen.KindStopped:
		m.listenerStopReported = m.listener
		if event.Err != nil {
			m.print(fmt.Sprintf("%s err %s/%s: %v", mode, event.Role, event.Adapter, event.Err))
		}
		m.print(fmt.Sprintf("%s off %s/%s", mode, event.Role, event.Adapter))
	case listen.KindDiscovery:
		m.applyDiscovery(event)
	}
	if m.listener == nil {
		return nil
	}
	return waitListenEventCmd(m.listener)
}

func (m *Model) applyDiscovery(event listen.Event) {
	if m.networkTracker == nil {
		m.networkTracker = networkobs.NewTracker("current", m.capMode, time.Now().UTC())
	}
	m.networkTracker.ObserveDiscovery(networkobs.Discovery{
		Adapter: event.Adapter, Role: event.Role, DeviceMAC: event.DeviceMAC,
		Field: event.Field, Value: event.Value, Evidence: event.Evidence, Packet: event.Packet,
	})
	m.ensureNetworkSelection()
	if isBridgeObservation(event) {
		m.profile.AddBridgeObservation(event.Adapter, event.Role, event.Field, event.Value, event.Evidence, event.Packet)
	}
	m.applyBridgeConfigDiscovery(event)
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
