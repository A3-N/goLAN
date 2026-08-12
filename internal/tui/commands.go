package tui

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"

	"golan/internal/adapters"
	bridge "golan/internal/bridge"
	"golan/internal/configs"
	"golan/internal/dataplane"
	"golan/internal/edge"
	"golan/internal/profile"
	workproject "golan/internal/project"

	tea "github.com/charmbracelet/bubbletea"
)

func (m *Model) executeCommand(raw string) tea.Cmd {
	m.print(m.prompt() + privateCommandEcho(raw))
	fields := strings.Fields(raw)
	if len(fields) == 0 {
		return nil
	}

	switch strings.ToLower(fields[0]) {
	case "help":
		m.showHelp()
	case "doctor":
		return m.startDoctor(fields[1:])
	case "settings":
		m.openSettingsEditor()
	case "show":
		m.executeShow(fields[1:])
	case "project":
		return m.executeProject(fields[1:])
	case "policy":
		return m.executePolicy(fields[1:])
	case "canvas":
		return m.executeCanvas(fields[1:])
	case "network":
		return m.executeNetwork(fields[1:])
	case "delete":
		return m.executeDelete(fields[1:])
	case "clear":
		m.output = nil
		m.outputMuted = nil
		m.outputLiteral = nil
		m.clearLiveEvidence()
		m.outputScroll = 0
	case "cleanup":
		return m.executeCleanup(fields[1:])
	case "set":
		return m.executeSet(fields[1:])
	case "unset":
		return m.executeUnset(fields[1:])
	case "conf":
		return m.executeConf(fields[1:])
	case "load":
		return m.executeLoad(fields[1:])
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
	case "up":
		return m.executeActiveAdapterState("up")
	case "down":
		return m.executeActiveAdapterState("down")
	case "refresh":
		if pending := m.inFlightLocks(); len(pending) > 0 {
			m.print("refresh err: adapter isolate pending " + strings.Join(pending, ","))
			return nil
		}
		if blocker := m.adapterMutationBlocker(); blocker != "" {
			m.print("refresh err: " + blocker)
			return nil
		}
		m.loading = true
		m.refreshPending = true
		m.err = nil
		m.print("refresh: adapters")
		return discoverAdaptersCmd
	case "quit":
		return tea.Quit
	default:
		m.print("unknown: " + fields[0])
		m.print("use: help")
	}
	return nil
}

func privateCommandEcho(raw string) string {
	return raw
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
	if len(args) < 1 || len(args) > 2 || len(args) == 2 && !strings.EqualFold(args[0], "captures") {
		m.print("use: show adapters|config|bridge|nat|edge|project|rules|health|captures")
		return
	}
	switch strings.ToLower(args[0]) {
	case "adapters":
		m.showAdapters()
	case "config":
		m.showConfig()
	case "bridge":
		m.showBridge()
	case "nat":
		m.showNAT()
	case "project":
		m.showProject()
	case "rules":
		m.showRules()
	case "edge":
		m.showEdge()
	case "health":
		m.showHealth()
	case "captures":
		m.showNetworkCaptures(args[1:])
	default:
		m.print("use: show adapters|config|bridge|nat|edge|project|rules|health|captures")
	}
}

func (m *Model) showHealth() {
	runtime := "offline"
	switch {
	case m.bridge != nil:
		runtime = "bridge " + m.bridgeMode + " " + m.bridgeState
	case m.edgeSession != nil:
		runtime = "edge " + m.edgeMode
	case m.listener != nil:
		runtime = "listen " + m.capMode
	}
	m.print(fmt.Sprintf("health: adapters=%d runtime=%s operation=%s", len(m.adapters), runtime, emptyHealthValue(m.runtimeOperation)))
	m.print(fmt.Sprintf(
		"  restoration snapshots=%d isolate-pending=%d restore-pending=%d failed=%d",
		len(m.restoreState), len(m.inFlightLocks()), countPendingStates(m.restorePending), countPendingStates(m.lockFailed),
	))
	if m.edgeSession != nil {
		health := m.edgeSession.Health()
		m.print(fmt.Sprintf("  edge path=%s>%s subnet=%s egress=%s mtu=%d", health.Downstream, health.Upstream, health.Subnet, health.Egress, health.EgressMTU))
		if len(health.VPNDestinations) > 0 {
			m.print("  edge VPN route-address=" + health.VPNRouteAddress + " destinations=" + strings.Join(health.VPNDestinations, ","))
		}
		m.print(fmt.Sprintf("  dhcp server=%s endpoint=%s gateway=%s replies=%d", health.LeaseServer, health.LeaseClient, health.LeaseGateway, health.Stats.DHCPReplies))
		m.print(fmt.Sprintf("  dns advertised=%s upstreams=%s relay=%t", strings.Join(health.DNS, ","), strings.Join(health.DNSUpstreams, ","), health.DNSRelay))
		m.print(fmt.Sprintf("  pf anchor=%s loaded=%t enable-token-owned=%t", health.PF.Anchor, health.PF.Loaded, health.PF.EnableTokenOwned))
		m.print(fmt.Sprintf("  edge packets original=%d forwarded=%d blocked=%d", health.Stats.OriginalPackets, health.Stats.ForwardedPackets, health.Stats.BlockedPackets))
		if m.edgeSession.CleanupPending() {
			m.print("  edge cleanup=pending")
		}
	}
	if m.bridge != nil {
		m.print(fmt.Sprintf("  bridge mode=%s cleanup-pending=%t", m.bridgeMode, m.bridge.CleanupPending()))
		if m.bridgeMode == string(bridge.ModeControlled) {
			stats := m.bridge.ControlledStats()
			options := m.bridge.ControlledOptions()
			m.print(fmt.Sprintf("  bridge queue high-water=%d/%d overload=%d", stats.QueueHighWater, options.QueueDepth, stats.OverloadPackets))
			m.print(fmt.Sprintf("  bridge packets original=%d forwarded=%d blocked=%d", stats.OriginalPackets, stats.ForwardedPackets, stats.BlockedPackets))
		}
	}
	if m.project != nil {
		m.print(fmt.Sprintf("  project sessions recoverable=%d stale=%d", countSessions(m.projectSessions, true), countSessions(m.projectSessions, false)))
	}
}

func emptyHealthValue(value string) string {
	if strings.TrimSpace(value) == "" {
		return "idle"
	}
	return value
}

func countSessions(sessions []workproject.AssociatedSession, recoverable bool) int {
	count := 0
	for _, session := range sessions {
		if session.Recoverable == recoverable {
			count++
		}
	}
	return count
}

func countPendingStates(states map[string]bool) int {
	count := 0
	for _, pending := range states {
		if pending {
			count++
		}
	}
	return count
}

func (m *Model) executeSet(args []string) tea.Cmd {
	if len(args) == 0 {
		m.print("use: set adapter <name> <host|switch> | set <property> <value>")
		return nil
	}
	if blocker := m.adapterMutationBlocker(); blocker != "" {
		m.print("set err: " + blocker)
		return nil
	}

	key := strings.ToLower(args[0])
	if key == "bridge" {
		if len(args) != 3 {
			m.print("use: set bridge queue-depth|overload <value>")
			return nil
		}
		next := m.bridgeControlledOptions
		switch strings.ToLower(args[1]) {
		case "queue-depth":
			value, err := strconv.Atoi(args[2])
			if err != nil {
				m.print(fmt.Sprintf("bridge err: queue-depth must be between %d and %d", bridge.MinControlledQueueDepth, bridge.MaxControlledQueueDepth))
				return nil
			}
			next.QueueDepth = value
		case "overload":
			next.Overload = bridge.OverloadBehavior(strings.ToLower(args[2]))
		default:
			m.print("use: set bridge queue-depth|overload <value>")
			return nil
		}
		if err := bridge.ValidateControlledOptions(next); err != nil {
			m.print("bridge err: " + err.Error())
			return nil
		}
		m.bridgeControlledOptions = next
		m.print(fmt.Sprintf("bridge %s: %s (applies to next controlled session)", strings.ToLower(args[1]), args[2]))
		return nil
	}
	if key == "edge" {
		if len(args) < 2 {
			m.print("use: set edge mode|egress|upstream|vpn-destination|dns|port-forward ...")
			return nil
		}
		switch strings.ToLower(args[1]) {
		case "mode":
			if len(args) != 3 {
				m.print("use: set edge mode <observe|route>")
				return nil
			}
			mode := strings.ToLower(args[2])
			if mode != string(edge.ModeObserve) && mode != string(edge.ModeRoute) {
				m.print("use: set edge mode <observe|route>")
				return nil
			}
			if mode == string(edge.ModeObserve) && m.edgeEgress == string(edge.EgressVPN) {
				m.print("edge err: switch egress to system before selecting observe mode")
				return nil
			}
			m.edgeConfiguredMode = mode
			m.print("edge mode: " + mode + " (applies to next session)")
		case "upstream":
			if len(args) != 3 {
				m.print("use: set edge upstream <auto|adapter>")
				return nil
			}
			value := strings.TrimSpace(args[2])
			if !strings.EqualFold(value, "auto") {
				adapter, ok := m.findAdapter(value)
				if !ok || adapter.Name == "" {
					m.print("edge err: upstream adapter not found: " + value)
					return nil
				}
			}
			m.edgeUpstream = value
			m.edgeEgress = string(edge.EgressSystem)
			m.edgeVPNDestinations = nil
			m.print("edge upstream: " + value + " (applies to next session)")
		case "egress":
			if len(args) != 4 {
				m.print("use: set edge egress system <auto|adapter> | vpn <tunnel-interface>")
				return nil
			}
			mode := strings.ToLower(strings.TrimSpace(args[2]))
			value := strings.TrimSpace(args[3])
			switch mode {
			case string(edge.EgressSystem):
				if !strings.EqualFold(value, "auto") {
					adapter, ok := m.findAdapter(value)
					if !ok || adapter.Name == "" {
						m.print("edge err: upstream adapter not found: " + value)
						return nil
					}
				}
				m.edgeEgress = mode
				m.edgeUpstream = value
				m.edgeVPNDestinations = nil
				m.print("edge egress: system upstream=" + value + " (applies to next session)")
			case string(edge.EgressVPN):
				if strings.EqualFold(value, "auto") || !edge.ValidInterfaceName(value) {
					m.print("edge err: vpn egress requires an explicit valid tunnel interface")
					return nil
				}
				m.edgeEgress = mode
				m.edgeUpstream = value
				m.edgeConfiguredMode = string(edge.ModeRoute)
				m.print("edge egress: vpn tunnel=" + value + " fail-closed (applies to next session)")
			default:
				m.print("use: set edge egress system <auto|adapter> | vpn <tunnel-interface>")
			}
		case "vpn-destination":
			m.setEdgeVPNDestination(args[2:])
		case "dns":
			m.setEdgeDNS(args[2:])
		case "port-forward":
			if len(args) == 3 && strings.EqualFold(args[2], "list") {
				if len(m.edgeForwards) == 0 {
					m.print("edge port-forwards: none")
					return nil
				}
				m.print(fmt.Sprintf("edge port-forwards: %d", len(m.edgeForwards)))
				for _, forward := range m.edgeForwards {
					m.print(fmt.Sprintf("  %s/%d -> client:%d", forward.Protocol, forward.ListenPort, forward.TargetPort))
				}
				return nil
			}
			if len(args) == 3 && strings.EqualFold(args[2], "clear") {
				m.edgeForwards = nil
				m.print("edge port-forwards: cleared (applies to next session)")
				return nil
			}
			if len(args) == 5 && strings.EqualFold(args[2], "remove") {
				protocol := strings.ToLower(args[3])
				listenPort, err := strconv.ParseUint(args[4], 10, 16)
				if (protocol != "tcp" && protocol != "udp") || err != nil || listenPort == 0 {
					m.print("edge err: port-forward remove requires TCP/UDP and a non-zero listen port")
					return nil
				}
				for index, existing := range m.edgeForwards {
					if existing.Protocol != protocol || existing.ListenPort != uint16(listenPort) {
						continue
					}
					m.edgeForwards = append(m.edgeForwards[:index], m.edgeForwards[index+1:]...)
					m.print(fmt.Sprintf("edge port-forward: removed %s/%d (applies to next session)", protocol, listenPort))
					return nil
				}
				m.print(fmt.Sprintf("edge err: port-forward not found: %s/%d", protocol, listenPort))
				return nil
			}
			if len(args) != 5 {
				m.print("use: set edge port-forward list | <tcp|udp> <listen-port> <client-port> | remove <tcp|udp> <listen-port> | clear")
				return nil
			}
			protocol := strings.ToLower(args[2])
			listenPort, listenErr := strconv.ParseUint(args[3], 10, 16)
			targetPort, targetErr := strconv.ParseUint(args[4], 10, 16)
			if (protocol != "tcp" && protocol != "udp") || listenErr != nil || targetErr != nil || listenPort == 0 || targetPort == 0 {
				m.print("edge err: port-forward requires TCP/UDP and non-zero ports")
				return nil
			}
			setting := edgeForwardSetting{Protocol: protocol, ListenPort: uint16(listenPort), TargetPort: uint16(targetPort)}
			for _, existing := range m.edgeForwards {
				if existing.Protocol == setting.Protocol && existing.ListenPort == setting.ListenPort {
					m.print("edge err: port-forward is duplicated")
					return nil
				}
			}
			m.edgeForwards = append(m.edgeForwards, setting)
			m.print(fmt.Sprintf("edge port-forward: %s/%d -> client:%d (applies to next session)", protocol, listenPort, targetPort))
		default:
			m.print("use: set edge mode|egress|upstream|vpn-destination|dns|port-forward ...")
		}
		return nil
	}
	if key == "adapter" {
		if len(args) != 3 {
			m.print("use: set adapter <name> <host|switch>")
			return nil
		}
		return m.stageAdapter(args[1], args[2])
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
	return nil
}

func (m *Model) setEdgeVPNDestination(args []string) {
	usage := "use: set edge vpn-destination <cidr|all|list|clear|remove cidr>"
	if len(args) == 1 && strings.EqualFold(args[0], "list") {
		if len(m.edgeVPNDestinations) == 0 {
			m.print("edge VPN destinations: none")
			return
		}
		m.print(fmt.Sprintf("edge VPN destinations: %d", len(m.edgeVPNDestinations)))
		for _, destination := range m.edgeVPNDestinations {
			m.print("  " + vpnDestinationLabel(destination))
		}
		return
	}
	if len(args) == 1 && strings.EqualFold(args[0], "clear") {
		m.edgeVPNDestinations = nil
		m.print("edge VPN destinations: cleared (applies to next session)")
		return
	}
	if len(args) == 2 && strings.EqualFold(args[0], "remove") {
		target, err := parseVPNDestination(args[1])
		if err != nil {
			m.print("edge err: " + err.Error())
			return
		}
		for index, existing := range m.edgeVPNDestinations {
			if existing != target {
				continue
			}
			m.edgeVPNDestinations = append(m.edgeVPNDestinations[:index], m.edgeVPNDestinations[index+1:]...)
			m.print("edge VPN destination: removed " + vpnDestinationLabel(target) + " (applies to next session)")
			return
		}
		m.print("edge err: VPN destination not found: " + vpnDestinationLabel(target))
		return
	}
	if len(args) != 1 {
		m.print(usage)
		return
	}
	destination, err := parseVPNDestination(args[0])
	if err != nil {
		m.print("edge err: " + err.Error())
		return
	}
	if destination == "0.0.0.0/0" {
		m.edgeVPNDestinations = []string{destination}
		m.print("edge VPN destination: all (applies to next session)")
		return
	}
	for _, existing := range m.edgeVPNDestinations {
		if existing == "0.0.0.0/0" {
			m.print("edge err: VPN destination all must be cleared before adding a prefix")
			return
		}
		if existing == destination {
			m.print("edge err: VPN destination is duplicated")
			return
		}
	}
	m.edgeVPNDestinations = append(m.edgeVPNDestinations, destination)
	m.print("edge VPN destination: " + destination + " (applies to next session)")
}

func parseVPNDestination(raw string) (string, error) {
	if strings.EqualFold(strings.TrimSpace(raw), "all") {
		return "0.0.0.0/0", nil
	}
	destination, err := netip.ParsePrefix(strings.TrimSpace(raw))
	if err != nil || !destination.Addr().Is4() {
		return "", fmt.Errorf("VPN destination must be an IPv4 CIDR or all")
	}
	return destination.Masked().String(), nil
}

func vpnDestinationLabel(value string) string {
	if value == "0.0.0.0/0" {
		return "all"
	}
	return value
}

func (m *Model) setEdgeDNS(args []string) {
	usage := "use: set edge dns <ipv4|list|clear|remove ipv4>"
	if len(args) == 1 && strings.EqualFold(args[0], "list") {
		if len(m.edgeDNS) == 0 {
			m.print("edge DNS: automatic")
			return
		}
		m.print(fmt.Sprintf("edge DNS: %d", len(m.edgeDNS)))
		for _, address := range m.edgeDNS {
			m.print("  " + address)
		}
		return
	}
	if len(args) == 1 && strings.EqualFold(args[0], "clear") {
		m.edgeDNS = nil
		m.print("edge DNS: automatic (applies to next session)")
		return
	}
	if len(args) == 2 && strings.EqualFold(args[0], "remove") {
		address, err := parseEdgeDNS(args[1])
		if err != nil {
			m.print("edge err: " + err.Error())
			return
		}
		for index, existing := range m.edgeDNS {
			if existing != address {
				continue
			}
			m.edgeDNS = append(m.edgeDNS[:index], m.edgeDNS[index+1:]...)
			m.print("edge DNS: removed " + address + " (applies to next session)")
			return
		}
		m.print("edge err: DNS address not found: " + address)
		return
	}
	if len(args) != 1 {
		m.print(usage)
		return
	}
	address, err := parseEdgeDNS(args[0])
	if err != nil {
		m.print("edge err: " + err.Error())
		return
	}
	for _, existing := range m.edgeDNS {
		if existing == address {
			m.print("edge err: DNS address is duplicated")
			return
		}
	}
	m.edgeDNS = append(m.edgeDNS, address)
	m.print("edge DNS: " + address + " (applies to next session)")
}

func parseEdgeDNS(raw string) (string, error) {
	address, err := netip.ParseAddr(strings.TrimSpace(raw))
	if err != nil || !address.Is4() || address.IsUnspecified() || address.IsMulticast() {
		return "", fmt.Errorf("DNS address must be usable IPv4")
	}
	return address.String(), nil
}

func (m *Model) stageAdapter(name, roleValue string) tea.Cmd {
	if blocker := m.adapterMutationBlocker(); blocker != "" {
		m.print("adapter err: " + blocker)
		return nil
	}
	if pending := m.inFlightLocks(); len(pending) > 0 {
		m.print("adapter err: isolate pending " + strings.Join(pending, ","))
		return nil
	}
	if m.adapterRestorationPending(name) {
		m.print("adapter err: restore pending " + name)
		return nil
	}
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
	m.print(fmt.Sprintf("adapter: %s %s", cfg.AdapterRole, cfg.Name))
	cmds := m.restoreRemovedAdapterCmds(before)
	if m.adapterNeedsIsolation(cfg.Name) {
		m.markLockPending(cfg.Name)
		cmds = append(cmds, m.trackEffect(lockdownAdapterCmd(cfg)))
	}
	return tea.Batch(cmds...)
}

func (m *Model) executeUnset(args []string) tea.Cmd {
	if len(args) == 2 && strings.EqualFold(args[0], "adapter") {
		return m.unsetAdapter(args[1])
	}
	m.print("use: unset adapter <name>")
	return nil
}

func (m *Model) unsetAdapter(name string) tea.Cmd {
	if pending := m.inFlightLocks(); len(pending) > 0 {
		m.print("adapter err: isolate pending " + strings.Join(pending, ","))
		return nil
	}
	if blocker := m.adapterMutationBlocker(); blocker != "" {
		m.print("adapter err: " + blocker)
		return nil
	}
	if name == "" {
		m.print("ctx: none; use: conf <adapter>")
		return nil
	}
	removed, ok := m.profile.RemoveName(name)
	if !ok {
		if m.restorePending != nil && m.restorePending[name] {
			m.print("adapter restore pending: " + name)
			return nil
		}
		if cmd := m.restoreAdapterCmd(name); cmd != nil {
			m.print("adapter restore retry: " + name)
			return cmd
		}
		m.print("adapter unset: " + name)
		return nil
	}
	if strings.EqualFold(m.activeAdapter, removed.Name) {
		m.activeAdapter = ""
	}
	m.print("adapter off: " + removed.Name)
	if m.lockPending != nil {
		delete(m.lockPending, removed.Name)
	}
	if m.lockFailed != nil {
		delete(m.lockFailed, removed.Name)
	}
	return m.restoreAdapterCmd(removed.Name)
}

func (m *Model) markLockPending(name string) {
	if m.lockPending == nil {
		m.lockPending = make(map[string]bool)
	}
	m.lockPending[name] = true
	if m.lockFailed != nil {
		delete(m.lockFailed, name)
	}
}

func (m Model) adapterNeedsIsolation(name string) bool {
	if m.lockFailed != nil && m.lockFailed[name] {
		return true
	}
	_, isolated := m.restoreState[name]
	return !isolated
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
	if m.restorePending == nil {
		m.restorePending = make(map[string]bool)
	}
	if m.restorePending[name] {
		return nil
	}
	m.restorePending[name] = true
	return m.trackEffect(func() tea.Msg {
		return adapterRestoreMsg{name: name, state: state, err: bridge.RestoreInterfaceState(state)}
	})
}

func (m Model) adapterRestorationPending(name string) bool {
	if m.restorePending != nil && m.restorePending[name] {
		return true
	}
	if _, selected := m.profile.ByName(name); selected {
		return false
	}
	_, unrestored := m.restoreState[name]
	return unrestored
}

func (m Model) adapterMutationBlocker() string {
	switch {
	case m.refreshPending:
		return "adapter refresh pending"
	case m.runtimeOperation != "":
		return "operation pending: " + m.runtimeOperation
	case m.adapterStatePending != "":
		return "adapter state pending: " + m.adapterStatePending
	case anyPending(m.restorePending):
		return "adapter restore pending"
	case m.natActive:
		return "nat active"
	case m.bridge != nil:
		return "bridge active"
	case m.edgeSession != nil:
		return "edge active"
	case m.listener != nil:
		return "listen active"
	case len(m.listenInterfaces) > 0:
		return "listen cleanup pending"
	default:
		return ""
	}
}

func anyPending(states map[string]bool) bool {
	return countPendingStates(states) > 0
}

func (m *Model) beginRuntimeOperation(operation string) {
	m.runtimeOperation = operation
}

func (m *Model) clearRuntimeOperation(operation string) {
	if m.runtimeOperation == operation {
		m.runtimeOperation = ""
	}
}

func (m Model) pendingRuntimeOperation() string {
	if m.runtimeOperation != "" {
		return m.runtimeOperation
	}
	if m.refreshPending {
		return "adapter refresh"
	}
	if m.adapterStatePending != "" {
		return "adapter state " + m.adapterStatePending
	}
	if anyPending(m.restorePending) {
		return "adapter restore"
	}
	return ""
}

func lockdownAdapterCmd(cfg profile.AdapterConfig) tea.Cmd {
	return func() tea.Msg {
		state, err := bridge.LockdownInterface(cfg.Name, adapterNetworkService(cfg))
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

func (m *Model) executeLoad(args []string) tea.Cmd {
	if len(args) == 0 {
		m.listConfigs()
		return nil
	}
	if len(args) != 1 {
		m.print("use: load [name]")
		return nil
	}
	if blocker := m.adapterMutationBlocker(); blocker != "" {
		m.print("load err: " + blocker)
		return nil
	}
	if pending := m.pendingLocks(); len(pending) > 0 {
		m.print("load err: adapter isolate pending " + strings.Join(pending, ","))
		return nil
	}
	snapshot, path, err := configs.Load(args[0])
	if err != nil {
		m.print("load err: " + err.Error())
		return nil
	}
	rehydrated, err := profile.Rehydrate(snapshot.Profile, m.adapters)
	if err != nil {
		m.print("load err: " + err.Error())
		return nil
	}
	before := append([]profile.AdapterConfig(nil), m.profile.Adapters...)
	m.profile = rehydrated
	m.profileNeedsRehydrate = false
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
	m.print("loaded: " + path)

	cmds := m.restoreRemovedAdapterCmds(before)
	for _, cfg := range m.profile.Adapters {
		if m.restoreState != nil {
			if _, alreadyLocked := m.restoreState[cfg.Name]; alreadyLocked {
				continue
			}
		}
		if m.lockPending != nil && m.lockPending[cfg.Name] {
			continue
		}
		m.markLockPending(cfg.Name)
		cmds = append(cmds, m.trackEffect(lockdownAdapterCmd(cfg)))
	}
	return tea.Batch(cmds...)
}

func (m Model) snapshotSettings() configs.Settings {
	runtime := configs.RuntimeSettings{
		EdgeMode:             m.edgeConfiguredMode,
		EdgeUpstream:         m.edgeUpstream,
		EdgeEgress:           m.edgeEgress,
		EdgeVPNDestinations:  append([]string(nil), m.edgeVPNDestinations...),
		EdgeDNS:              append([]string(nil), m.edgeDNS...),
		ControlledQueueDepth: m.bridgeControlledOptions.QueueDepth,
		ControlledOverload:   string(m.bridgeControlledOptions.Overload),
	}
	for _, forward := range m.edgeForwards {
		runtime.EdgePortForwards = append(runtime.EdgePortForwards, configs.PortForward{
			Protocol: forward.Protocol, ListenPort: forward.ListenPort, TargetPort: forward.TargetPort,
		})
	}
	return configs.Settings{
		EAPOLLogoffDrop:      m.eapolSuppressLogoff,
		EAPOLDowngradeMACsec: m.eapolDowngradeMACsec,
		RedactSecrets:        boolPointer(m.redactObservedSecrets),
		Runtime:              &runtime,
	}
}

func boolPointer(value bool) *bool { return &value }

func (m *Model) applySnapshotSettings(settings *configs.Settings) {
	next := configs.DefaultSettings()
	if settings != nil {
		next = *settings
	}
	m.eapolSuppressLogoff = next.EAPOLLogoffDrop
	m.eapolDowngradeMACsec = next.EAPOLDowngradeMACsec
	m.redactObservedSecrets = next.SecretsRedacted()
	if runtime := next.Runtime; runtime != nil {
		m.edgeConfiguredMode = runtime.EdgeMode
		if m.edgeConfiguredMode == "intercept" {
			m.edgeConfiguredMode = "route"
			m.print("load warn: legacy edge intercept settings are retired; staged as route")
		}
		m.edgeUpstream = runtime.EdgeUpstream
		m.edgeEgress = runtime.EdgeEgress
		if m.edgeEgress == "" {
			m.edgeEgress = string(edge.EgressSystem)
		}
		m.edgeVPNDestinations = append([]string(nil), runtime.EdgeVPNDestinations...)
		m.edgeDNS = append([]string(nil), runtime.EdgeDNS...)
		m.edgeForwards = make([]edgeForwardSetting, 0, len(runtime.EdgePortForwards))
		for _, forward := range runtime.EdgePortForwards {
			m.edgeForwards = append(m.edgeForwards, edgeForwardSetting{
				Protocol: forward.Protocol, ListenPort: forward.ListenPort, TargetPort: forward.TargetPort,
			})
		}
		controlled := bridge.ControlledOptions{
			QueueDepth: runtime.ControlledQueueDepth,
			Overload:   bridge.OverloadBehavior(runtime.ControlledOverload),
		}
		if bridge.ValidateControlledOptions(controlled) == nil {
			m.bridgeControlledOptions = controlled
		}
	}
	if m.bridge != nil {
		m.bridge.SetEAPOLPolicy(m.eapolPolicy())
	}
}

func (m *Model) executeStart(args []string) tea.Cmd {
	if m.offline {
		m.print("live err: macOS root privileges are required; offline project, Rules, and saved Network observations remain available")
		return nil
	}
	if len(args) < 1 || len(args) > 2 {
		m.print("use: start listen | start bridge <fast|controlled> | start nat | start edge <observe|route>")
		return nil
	}
	operation := strings.ToLower(args[0])
	if operation == "listen" || operation == "nat" {
		if len(args) != 1 {
			m.print("use: start " + operation)
			return nil
		}
	} else if operation == "bridge" || operation == "edge" {
		if len(args) != 2 {
			if operation == "bridge" {
				m.print("use: start bridge <fast|controlled>")
			} else {
				m.print("use: start edge <observe|route>")
			}
			return nil
		}
	} else {
		m.print("use: start listen | start bridge <fast|controlled> | start nat | start edge <observe|route>")
		return nil
	}
	if m.profileNeedsRehydrate {
		return m.prepareStagedConfigForLive()
	}

	switch operation {
	case "listen":
		if pending := m.pendingRuntimeOperation(); pending != "" {
			m.print("listen err: operation pending: " + pending)
			return nil
		}
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
		if m.edgeSession != nil {
			m.print("listen err: edge")
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
		if len(m.listenInterfaces) > 0 {
			m.print("listen err: cleanup pending; use: stop listen")
			return nil
		}
		targets := m.listenTargets()
		if len(targets) == 0 {
			m.print("listen err: no adapter")
			return nil
		}
		revision, rules := m.activeBridgeRules()
		m.print("listen: start")
		m.beginRuntimeOperation("listen start")
		return m.trackEffect(startListenPolicyCmd(targets, "listen", dataplane.ModeListen, revision, rules))
	case "bridge":
		mode := bridge.Mode(strings.ToLower(args[1]))
		if mode != bridge.ModeFast && mode != bridge.ModeControlled {
			m.print("use: start bridge <fast|controlled>")
			return nil
		}
		if pending := m.pendingRuntimeOperation(); pending != "" {
			m.print("bridge err: operation pending: " + pending)
			return nil
		}
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
		if m.edgeSession != nil {
			m.print("bridge err: edge")
			return nil
		}
		host, sw, errText := m.bridgeAdapters()
		if errText != "" {
			m.print("bridge err: " + errText)
			return nil
		}
		revision, rules := m.activeBridgeRules()
		m.print("bridge: start " + string(mode))
		m.beginRuntimeOperation("bridge start")
		return m.trackEffect(startBridgeCmd(host, sw, m.eapolPolicy(), mode, revision, rules, m.bridgeControlledOptions))
	case "edge":
		mode := strings.ToLower(args[1])
		if mode != "observe" && mode != "route" {
			m.print("use: start edge <observe|route>")
			return nil
		}
		if pending := m.pendingRuntimeOperation(); pending != "" {
			m.print("edge err: operation pending: " + pending)
			return nil
		}
		if m.bridge != nil || m.listener != nil || m.edgeSession != nil {
			m.print("edge err: another live session is active")
			return nil
		}
		targets := m.listenTargets()
		if len(targets) == 0 {
			m.print("edge err: no downstream adapter")
			return nil
		}
		revision, rules := m.activeBridgeRules()
		if mode == "observe" {
			m.print("edge: start observe")
			m.beginRuntimeOperation("listen start")
			return m.trackEffect(startListenPolicyCmd(targets, "edge-observe", dataplane.ModeEdgeObserve, revision, rules))
		}
		m.print("edge: start " + mode + " egress=" + m.edgeEgress + " upstream=" + m.edgeUpstream)
		m.beginRuntimeOperation("edge start")
		return m.trackEffect(startEdgeCmd(
			targets[0].Name, m.edgeUpstream, edge.Mode(mode), edge.EgressMode(m.edgeEgress),
			m.edgeVPNDestinations, m.edgeDNS, revision, rules, m.edgeForwards,
		))
	case "nat":
		if pending := m.pendingRuntimeOperation(); pending != "" {
			m.print("nat err: operation pending: " + pending)
			return nil
		}
		if m.bridge == nil {
			m.print("nat err: bridge")
			return nil
		}
		if m.bridgeMode == string(bridge.ModeControlled) {
			m.print("nat err: fast bridge is required")
			return nil
		}
		if m.natActive {
			snapshot := m.bridge.NATSnapshot()
			if snapshot.CleanupPending {
				m.print("nat err: cleanup pending; use: stop nat")
			} else {
				m.print("nat: on")
			}
			return nil
		}
		m.print("nat: start")
		m.beginRuntimeOperation("nat start")
		return m.trackEffect(startNATCmd(m.bridge, m.bridgeNATConfig()))
	}
	return nil
}

// prepareStagedConfigForLive refreshes platform-owned adapter metadata only at
// the live-start boundary. Isolation remains asynchronous, so the requested
// session is not started until the operator retries after isolation completes.
func (m *Model) prepareStagedConfigForLive() tea.Cmd {
	rehydrated, err := profile.Rehydrate(m.profile, m.adapters)
	if err != nil {
		m.print("start err: staged config: " + err.Error())
		return nil
	}
	m.profile = rehydrated
	m.profileNeedsRehydrate = false
	if m.activeAdapter != "" && !isBridgeContext(m.activeAdapter) {
		if _, ok := m.profile.ByName(m.activeAdapter); !ok {
			m.activeAdapter = ""
		}
	}
	var cmds []tea.Cmd
	for _, cfg := range m.profile.Adapters {
		if _, alreadyLocked := m.restoreState[cfg.Name]; alreadyLocked || m.lockPending[cfg.Name] {
			continue
		}
		m.markLockPending(cfg.Name)
		cmds = append(cmds, m.trackEffect(lockdownAdapterCmd(cfg)))
	}
	m.print("start: staged config adapter metadata refreshed; isolation pending, retry start when complete")
	return tea.Batch(cmds...)
}

func (m *Model) executeEnable(args []string) tea.Cmd {
	if len(args) == 2 && strings.EqualFold(args[0], "rule") {
		return m.mutateRule(args[1], "enable")
	}
	return m.setEAPOLToggle(true, args)
}

func (m *Model) executeDisable(args []string) tea.Cmd {
	if len(args) == 2 && strings.EqualFold(args[0], "rule") {
		return m.mutateRule(args[1], "disable")
	}
	return m.setEAPOLToggle(false, args)
}

func (m *Model) setEAPOLToggle(enabled bool, args []string) tea.Cmd {
	action := toggleAction(enabled)
	if len(args) != 2 || !strings.EqualFold(args[0], "eapol") {
		m.print("use: " + action + " rule <id>|eapol drop-logoff|eapol macsec-downgrade")
		return nil
	}
	if pending := m.pendingRuntimeOperation(); pending != "" {
		m.print("eapol err: operation pending: " + pending)
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
	if len(args) != 1 {
		m.print("use: stop listen|bridge|nat|edge")
		return nil
	}
	if m.runtimeOperation != "" {
		m.print("stop err: operation pending: " + m.runtimeOperation)
		return nil
	}

	switch strings.ToLower(args[0]) {
	case "listen":
		if m.listener == nil && len(m.listenInterfaces) == 0 {
			m.print("listen: off")
			return nil
		}
		if m.listener != nil && m.capMode != "listen" {
			m.print("listen: off")
			return nil
		}
		m.print("listen: stop")
		m.listenStopPending = true
		m.beginRuntimeOperation("listen stop")
		return m.trackEffect(stopListenCmd(m.listener, m.listenInterfaces))
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
		m.beginRuntimeOperation("bridge stop")
		return m.trackEffect(stopBridgeCmd(m.bridge))
	case "edge":
		if m.edgeSession != nil {
			m.print("edge: stop")
			m.beginRuntimeOperation("edge stop")
			return m.trackEffect(stopEdgeCmd(m.edgeSession))
		}
		if m.listener == nil || !strings.HasPrefix(m.capMode, "edge-") {
			m.print("edge: off")
			return nil
		}
		m.print("edge: stop")
		m.listenStopPending = true
		m.beginRuntimeOperation("listen stop")
		return m.trackEffect(stopListenCmd(m.listener, m.listenInterfaces))
	case "nat":
		if m.bridge == nil || !m.natActive {
			m.print("nat: off")
			return nil
		}
		m.print("nat: stop")
		m.beginRuntimeOperation("nat stop")
		return m.trackEffect(stopNATCmd(m.bridge))
	default:
		m.print("use: stop listen|bridge|nat|edge")
		return nil
	}
}

func (m *Model) executeCleanup(args []string) tea.Cmd {
	if len(args) != 0 {
		m.print("use: cleanup")
		return nil
	}
	if m.runtimeOperation != "" {
		m.print("cleanup err: operation pending: " + m.runtimeOperation)
		return nil
	}
	if m.refreshPending {
		m.print("cleanup err: adapter refresh pending")
		return nil
	}
	if m.adapterStatePending != "" {
		m.print("cleanup err: adapter state pending: " + m.adapterStatePending)
		return nil
	}
	if pending := m.inFlightLocks(); len(pending) > 0 {
		m.print("cleanup err: adapter isolation pending: " + strings.Join(pending, ","))
		return nil
	}
	if anyPending(m.restorePending) {
		m.print("cleanup err: adapter restoration is already pending")
		return nil
	}

	states := make(map[string]bridge.InterfaceRestoreState, len(m.restoreState))
	for name, state := range m.restoreState {
		states[name] = state
	}
	if m.listener != nil || len(m.listenInterfaces) > 0 {
		m.listenStopPending = true
	}
	m.beginRuntimeOperation(cleanupOperation)
	m.print("cleanup: stopping owned runtimes and restoring original adapter state")
	return m.trackEffect(cleanupOwnedStateCmd(
		m.listener,
		m.listenInterfaces,
		m.edgeSession,
		m.bridge,
		states,
	))
}

func (m *Model) executeSend(args []string) tea.Cmd {
	if len(args) != 2 || !strings.EqualFold(args[0], "eapol") || !strings.EqualFold(args[1], "start") {
		m.print("use: send eapol start")
		return nil
	}
	if pending := m.pendingRuntimeOperation(); pending != "" {
		m.print("send err: operation pending: " + pending)
		return nil
	}
	if m.bridge == nil {
		m.print("send err: bridge")
		return nil
	}
	m.print("send: eapol start")
	m.beginRuntimeOperation("eapol send")
	return m.trackEffect(sendEAPOLStartCmd(m.bridge))
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
		m.print("ctx: bridge")
		return nil
	}
	cfg, ok := m.profile.ByName(args[0])
	if !ok {
		m.print("adapter off: " + args[0])
		m.print("use: set adapter " + args[0] + " <host|switch>")
		return nil
	}
	m.activeAdapter = cfg.Name
	m.print("ctx: " + cfg.Name)
	return nil
}

func (m *Model) executeActiveAdapterState(state string) tea.Cmd {
	if m.activeAdapter == "" {
		m.print("ctx: none; use: conf <adapter|bridge>")
		return nil
	}
	if pending := m.inFlightLocks(); len(pending) > 0 {
		m.print("adapter state err: isolate pending " + strings.Join(pending, ","))
		return nil
	}
	if blocker := m.adapterMutationBlocker(); blocker != "" {
		m.print("adapter state err: " + blocker)
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
	m.adapterStatePending = cfg.Name
	return m.trackEffect(setAdapterStateCmd(cfg.Name, state))
}

func (m *Model) showAdapters() {
	if m.loading {
		m.print("adapters: loading")
		return
	}
	if m.err != nil {
		m.print("adapters warn: " + m.err.Error())
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
	for _, field := range profile.Fields() {
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
		for _, field := range profile.Fields() {
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
		for _, field := range profile.Fields() {
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
	m.print(fmt.Sprintf("  edge mode=%s egress=%s upstream=%s VPN-destinations=%d dns=%d", m.edgeConfiguredMode, m.edgeEgress, m.edgeUpstream, len(m.edgeVPNDestinations), len(m.edgeDNS)))
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
	next := m.bridgeControlledOptions
	m.print(fmt.Sprintf("controlled next queue-depth=%d overload=%s", next.QueueDepth, next.Overload))
	natState := "off"
	if m.bridge != nil {
		snapshot := m.bridge.NATSnapshot()
		if snapshot.Active {
			natState = "on"
		} else if snapshot.CleanupPending {
			natState = "cleanup-pending"
		}
	}
	m.print("nat: " + natState)
	m.print(eapolLogoffStatus(m.eapolSuppressLogoff))
	m.print(macsecStatus(m.eapolDowngradeMACsec))
	if m.bridge != nil && m.bridgeMode == string(bridge.ModeControlled) {
		active := m.bridge.ControlledOptions()
		m.print(fmt.Sprintf("controlled active queue-depth=%d overload=%s", active.QueueDepth, active.Overload))
	}
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

func (m *Model) showHelp() {
	for _, line := range commandHelpLines() {
		m.printHelp(line)
	}
}

func (m *Model) findAdapter(name string) (adapters.Adapter, bool) {
	name = strings.ToLower(strings.TrimSpace(name))
	for _, adapter := range m.adapters {
		if strings.ToLower(adapter.Name) == name || strings.ToLower(adapter.HardwarePort) == name || strings.ToLower(adapter.NetworkService) == name {
			return adapter, true
		}
	}
	return adapters.Adapter{}, false
}
