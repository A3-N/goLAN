package tui

import (
	"path/filepath"
	"strings"
	"time"

	networkobs "golan/internal/network"
)

func (m *Model) startNetworkSession(mode, directory string) {
	id := filepath.Base(filepath.Clean(directory))
	if id == "." || id == string(filepath.Separator) || strings.TrimSpace(id) == "" {
		id = time.Now().UTC().Format("20060102T150405.000000000Z")
	}
	m.clearObservedSecrets()
	m.networkTracker = networkobs.NewTracker(id, mode, time.Now().UTC())
	m.networkSessionPersisted = ""
	m.selectedNetworkDevice = ""
	m.networkSection = 0
	m.networkExpanded = map[networkobs.Category]bool{networkobs.CategoryAddressing: true}
}

func (m *Model) addNetworkCapture(path string) {
	if m.networkTracker != nil {
		m.networkTracker.AddCapture(path)
	}
}

func (m *Model) finishNetworkSession() {
	if m.networkTracker == nil {
		return
	}
	m.networkTracker.Finish(time.Now().UTC())
	session := m.networkTracker.Snapshot()
	if session.ID == "" || session.ID == m.networkSessionPersisted ||
		len(session.Devices) == 0 && len(session.CapturePaths) == 0 {
		return
	}
	if m.project == nil {
		m.networkSessionPersisted = session.ID
		return
	}
	record, err := m.project.SaveNetworkSession(session)
	if err != nil {
		m.print("network session err: " + err.Error())
		return
	}
	m.networkSessionPersisted = session.ID
	m.print("network session: saved " + record.ID + " (PROJECT*)")
}

func (m *Model) restoreLatestNetworkSession() {
	if m.project == nil {
		return
	}
	references := m.project.Manifest().NetworkSessions
	if len(references) == 0 {
		return
	}
	latest := references[0]
	for _, candidate := range references[1:] {
		if candidate.StartedAt.After(latest.StartedAt) {
			latest = candidate
		}
	}
	session, _, err := m.project.ReadNetworkSession(latest.ID)
	if err != nil {
		m.print("project warn: restore network session: " + err.Error())
		return
	}
	m.clearObservedSecrets()
	m.networkTracker = networkobs.LoadTracker(session)
	m.networkSessionPersisted = session.ID
	m.ensureNetworkSelection()
}
