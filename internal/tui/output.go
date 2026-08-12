package tui

import (
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golan/internal/inspect"
	networkobs "golan/internal/network"
)

const (
	maxObservedSecrets = 8192
	maxOutputLines     = 2048
)

type artifactRegistry struct {
	mu              sync.Mutex
	pcapDirs        []string
	projectIndexing map[string]bool
	projectIndexed  map[string]bool
}

func newArtifactRegistry() *artifactRegistry {
	return &artifactRegistry{projectIndexing: make(map[string]bool), projectIndexed: make(map[string]bool)}
}

func (m *Model) print(line string) {
	m.appendOutput(line, isCommandLevelOutput(line), false)
}

// printHelp appends literal manual text. It deliberately bypasses the Output
// token classifier so command names cannot inherit runtime status colors.
func (m *Model) printHelp(line string) {
	m.appendOutput(line, false, true)
}

func (m *Model) appendOutput(line string, muted, literal bool) {
	m.output = append(m.output, line)
	m.outputMuted = append(m.outputMuted, muted)
	m.outputLiteral = append(m.outputLiteral, literal)
	m.outputScroll = 0
	if len(m.output) > maxOutputLines {
		drop := len(m.output) - maxOutputLines
		m.output = m.output[drop:]
		if len(m.outputMuted) > drop {
			m.outputMuted = m.outputMuted[drop:]
		} else {
			m.outputMuted = nil
		}
		if len(m.outputLiteral) > drop {
			m.outputLiteral = m.outputLiteral[drop:]
		} else {
			m.outputLiteral = nil
		}
	}
}

func (m *Model) rememberPcapDir(dir string) {
	dir = strings.TrimSpace(dir)
	if dir == "" {
		return
	}
	if m.artifacts == nil {
		m.artifacts = newArtifactRegistry()
	}
	m.artifacts.mu.Lock()
	defer m.artifacts.mu.Unlock()
	for _, existing := range m.artifacts.pcapDirs {
		if existing == dir {
			return
		}
	}
	m.artifacts.pcapDirs = append(m.artifacts.pcapDirs, dir)
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
	if m.edgeSession != nil {
		m.rememberPcapDir(m.edgeSession.Dir)
	}
}

func (m Model) pcapDirsSnapshot() []string {
	if m.artifacts == nil {
		return nil
	}
	m.artifacts.mu.Lock()
	defer m.artifacts.mu.Unlock()
	return append([]string(nil), m.artifacts.pcapDirs...)
}

func (m *Model) beginProjectCaptureIndex(projectPath, directory string) bool {
	if m.artifacts == nil {
		m.artifacts = newArtifactRegistry()
	}
	key := projectCaptureIndexKey(projectPath, directory)
	m.artifacts.mu.Lock()
	defer m.artifacts.mu.Unlock()
	if m.artifacts.projectIndexing[key] || m.artifacts.projectIndexed[key] {
		return false
	}
	m.artifacts.projectIndexing[key] = true
	return true
}

func (m *Model) finishProjectCaptureIndex(projectPath, directory string, complete bool) {
	if m.artifacts == nil {
		return
	}
	key := projectCaptureIndexKey(projectPath, directory)
	m.artifacts.mu.Lock()
	defer m.artifacts.mu.Unlock()
	delete(m.artifacts.projectIndexing, key)
	if complete {
		m.artifacts.projectIndexed[key] = true
	}
}

func projectCaptureIndexKey(projectPath, directory string) string {
	return strings.TrimSpace(projectPath) + "\x00" + strings.TrimSpace(directory)
}

func (m *Model) addSensitiveSignalEvent(encoded, adapter, role string) {
	signal, err := inspect.DecodeSignal(encoded)
	if err != nil {
		return
	}
	if m.networkTracker == nil {
		m.clearObservedSecrets()
		m.networkTracker = networkobs.NewTracker("current", "observe", time.Now().UTC())
	}
	if signal.Secret != "" && signal.DeviceMAC != "" {
		if m.observedSecrets == nil {
			m.observedSecrets = make(map[string]string)
		}
		key := observedSecretKey(adapter, signal.DeviceMAC, signal.Protocol, signal.Kind)
		if _, exists := m.observedSecrets[key]; exists || len(m.observedSecrets) < maxObservedSecrets {
			m.observedSecrets[key] = signal.Secret
		}
	}
	m.networkTracker.ObserveRisk(networkobs.Risk{
		Adapter: adapter, Role: role, DeviceMAC: signal.DeviceMAC,
		Protocol: signal.Protocol, Kind: signal.Kind,
	})
	m.ensureNetworkSelection()
}

func (m *Model) clearObservedSecrets() {
	m.observedSecrets = make(map[string]string)
}

func observedSecretKey(adapter, mac, protocol, kind string) string {
	return strings.ToLower(strings.TrimSpace(adapter)) + "/" +
		strings.ToLower(strings.TrimSpace(mac)) + "\x00" +
		strings.ToLower(strings.TrimSpace(protocol)) + "\x00" +
		strings.ToLower(strings.TrimSpace(kind))
}
