package tui

import (
	"fmt"
	"path/filepath"
	"strings"

	networkobs "golan/internal/network"

	tea "github.com/charmbracelet/bubbletea"
)

func (m *Model) executeNetwork(args []string) tea.Cmd {
	usage := "use: network show|infrastructure|services | network identity|explain|access|fate <device> | network filter <all|addressing|dns|http|access|risks|actions> | network search <term|clear> | network reset | network session <list|show> | network baseline <show|set|clear> | network compare <baseline|session> | network passport <save|verify|compare> | network probe <plan|run> | network rule draft <device>"
	if len(args) == 0 {
		m.print(usage)
		return nil
	}
	switch strings.ToLower(args[0]) {
	case "show":
		if len(args) != 1 {
			m.print(usage)
			return nil
		}
		devices := m.networkDevices()
		observations := 0
		services := 0
		accessEvents := 0
		for _, device := range devices {
			observations += len(device.Observations)
			services += len(device.Services)
			accessEvents += len(device.AccessEvents)
		}
		fates := 0
		if m.networkTracker != nil {
			fates = len(m.networkTracker.Snapshot().PacketFates)
		}
		m.print(fmt.Sprintf("network: devices=%d observations=%d services=%d access-events=%d fates=%d filter=%s search=%s", len(devices), observations, services, accessEvents, fates, networkFilterLabel(m.networkFilter), emptyNetworkValue(m.networkSearch)))
	case "infrastructure":
		m.showNetworkInfrastructure(args[1:])
	case "services":
		m.showNetworkServices(args[1:])
	case "identity", "explain", "access", "fate":
		m.showNetworkDeviceIntelligence(strings.ToLower(args[0]), args[1:])
	case "filter":
		if len(args) != 2 {
			m.print(usage)
			return nil
		}
		value := strings.ToLower(args[1])
		switch value {
		case "all":
			m.networkFilter = ""
		case "addressing":
			m.networkFilter = networkobs.CategoryAddressing
		case "dns":
			m.networkFilter = networkobs.CategoryDNS
		case "http":
			m.networkFilter = networkobs.CategoryHTTP
		case "access":
			m.networkFilter = networkobs.CategoryAccess
		case "risks":
			m.networkFilter = networkobs.CategoryRisk
		case "actions":
			m.networkFilter = networkobs.CategoryAction
		default:
			m.print(usage)
			return nil
		}
		m.ensureNetworkSelection()
		m.print("network filter: " + networkFilterLabel(m.networkFilter))
	case "search":
		if len(args) < 2 {
			m.print(usage)
			return nil
		}
		value := strings.TrimSpace(strings.Join(args[1:], " "))
		if strings.EqualFold(value, "clear") {
			value = ""
		}
		if len([]rune(value)) > 128 {
			m.print("network search err: term is limited to 128 characters")
			return nil
		}
		m.networkSearch = value
		m.ensureNetworkSelection()
		m.print("network search: " + emptyNetworkValue(value))
	case "reset":
		if len(args) != 1 {
			m.print(usage)
			return nil
		}
		m.networkFilter = ""
		m.networkSearch = ""
		m.ensureNetworkSelection()
		m.print("network view: reset")
	case "session":
		m.executeNetworkSession(args[1:])
	case "baseline":
		m.executeNetworkBaseline(args[1:])
	case "compare":
		m.executeNetworkCompare(args[1:])
	case "passport":
		m.executeNetworkPassport(args[1:])
	case "probe":
		return m.executeNetworkProbe(args[1:])
	case "rule":
		m.executeNetworkRule(args[1:])
	default:
		m.print(usage)
	}
	return nil
}

func (m *Model) executeNetworkSession(args []string) {
	usage := "use: network session list | network session show <id>"
	if m.project == nil {
		m.print("network session err: open a project first")
		return
	}
	if len(args) == 1 && strings.EqualFold(args[0], "list") {
		references := m.project.Manifest().NetworkSessions
		m.print(fmt.Sprintf("network sessions: %d", len(references)))
		for _, session := range references {
			m.print(fmt.Sprintf("  %s mode=%s devices=%d observations=%d started=%s", session.ID, session.Mode, session.Devices, session.Observations, session.StartedAt.UTC().Format("2006-01-02T15:04:05Z")))
		}
		return
	}
	if len(args) == 2 && strings.EqualFold(args[0], "show") {
		session, _, err := m.project.ReadNetworkSession(args[1])
		if err != nil {
			m.print("network session err: " + err.Error())
			return
		}
		m.clearObservedSecrets()
		m.networkTracker = networkobs.LoadTracker(session)
		m.networkSessionPersisted = session.ID
		m.ensureNetworkSelection()
		m.workspace = workspaceNetwork
		m.print("network session: " + session.ID)
		return
	}
	m.print(usage)
}

func (m *Model) showNetworkCaptures(args []string) {
	if len(args) > 1 {
		m.print("use: show captures [session-id]")
		return
	}
	if len(args) == 1 {
		if m.project == nil {
			m.print("captures err: open a project first")
			return
		}
		session, _, err := m.project.ReadNetworkSession(args[0])
		if err != nil {
			m.print("captures err: " + err.Error())
			return
		}
		m.print(fmt.Sprintf("captures: %d session=%s", len(session.CapturePaths), session.ID))
		for _, path := range session.CapturePaths {
			m.print("  " + path)
		}
		return
	}
	if m.networkTracker != nil {
		session := m.networkTracker.Snapshot()
		if len(session.CapturePaths) > 0 {
			m.print(fmt.Sprintf("captures: %d session=%s", len(session.CapturePaths), session.ID))
			for _, path := range session.CapturePaths {
				m.print("  " + path)
			}
			return
		}
	}
	if m.project == nil || len(m.project.Manifest().Captures) == 0 {
		m.print("captures: none")
		return
	}
	captures := m.project.Manifest().Captures
	m.print(fmt.Sprintf("captures: %d", len(captures)))
	for _, capture := range captures {
		path := capture.Path
		if capture.Mode == "copy" {
			path = filepath.Join(m.project.Path(), filepath.FromSlash(capture.Path))
		}
		m.print("  " + path)
	}
}

func networkFilterLabel(category networkobs.Category) string {
	if category == "" {
		return "all"
	}
	return string(category)
}

func (m Model) projectNetworkSessionIDs() []string {
	if m.project == nil {
		return nil
	}
	references := m.project.Manifest().NetworkSessions
	ids := make([]string, 0, len(references))
	for _, reference := range references {
		ids = append(ids, reference.ID)
	}
	return ids
}
