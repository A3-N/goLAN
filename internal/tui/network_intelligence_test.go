package tui

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	networkobs "golan/internal/network"

	tea "github.com/charmbracelet/bubbletea"
)

func TestNetworkIntelligenceCommandsAndInspectorRemainDeviceFocused(t *testing.T) {
	now := time.Unix(400, 0).UTC()
	device := networkobs.Device{
		Number: 1, Key: "en0/02:00:00:00:00:01", MAC: "02:00:00:00:00:01", Adapter: "en0",
		IPs: []string{"192.0.2.10"}, Hostnames: []string{"client.local"}, VLANs: []uint16{12},
		Services:     []networkobs.Service{{Type: "_ssh._tcp", Name: "client", Target: "client.local", Port: 22, Protocol: "mDNS", Count: 1}},
		AccessEvents: []networkobs.AccessEvent{{Kind: "eap_code", Label: "EAP Success", Protocol: "EAPOL", Severity: networkobs.SeverityInfo, ObservedAt: now}},
		Observations: []networkobs.Observation{{
			Kind: "query", Summary: "DNS A example.test", Protocol: "DNS", Category: networkobs.CategoryDNS,
			Severity: networkobs.SeverityInfo, FirstSeen: now, LastSeen: now, Count: 1,
		}},
	}
	session := networkobs.Session{Version: networkobs.CurrentVersion, ID: "ui-intelligence", Mode: "listen", StartedAt: now, Devices: []networkobs.Device{device}}
	m := NewModelWithSize(160, 40)
	m.workspace, m.activeCard = workspaceNetwork, cardInspector
	m.networkTracker = networkobs.LoadTracker(session)
	m.ensureNetworkSelection()

	view := m.renderNetworkInspector(100, 32)
	for _, expected := range []string{"O Overview", "E Explain", "A Access", "F Fate", "R Rule", "confidence HIGH", "services 1"} {
		if !strings.Contains(view, expected) {
			t.Fatalf("inspector missing %q:\n%s", expected, view)
		}
	}
	next, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'e'}})
	m = next.(Model)
	if m.networkInsight != "explain" || !strings.Contains(m.renderNetworkInspector(100, 32), "CONNECTION EXPLAINER") {
		t.Fatalf("explain insight not opened: %#v", m.networkInsight)
	}

	for _, command := range []string{"network identity 1", "network services", "network explain 1", "network access 1", "network fate 1", "network infrastructure"} {
		m.executeCommand(command)
	}
	for _, expected := range []string{"network identity:", "network services:", "network explain:", "network access:", "network fate:", "network infrastructure:"} {
		if !containsOutput(m.output, expected) {
			t.Errorf("output missing %q: %v", expected, m.output)
		}
	}

	m.executeCommand("network rule draft 1")
	if !m.ruleEditor.open || m.workspace != workspaceRules || len(m.ruleEditor.draft.conditions) < 2 || m.ruleEditor.draft.action != "block" {
		t.Fatalf("rule draft=%#v workspace=%s", m.ruleEditor, m.workspace)
	}
}

func TestNetworkPassportProbeAndCompletions(t *testing.T) {
	now := time.Unix(500, 0).UTC()
	session := networkobs.Session{Version: networkobs.CurrentVersion, ID: "portable", Mode: "listen", StartedAt: now, Devices: []networkobs.Device{{
		Number: 1, Key: "en0/02:00:00:00:00:01", MAC: "02:00:00:00:00:01", Adapter: "en0", IPs: []string{"192.0.2.10"},
	}}}
	m := NewModel()
	m.networkTracker = networkobs.LoadTracker(session)
	m.ensureNetworkSelection()

	destination := filepath.Join(t.TempDir(), "portable.golanpass")
	m.executeCommand("network passport save " + destination)
	m.executeCommand("network passport verify " + destination)
	if !containsOutput(m.output, "network passport: saved") || !containsOutput(m.output, "network passport [PASS]") {
		t.Fatalf("passport output=%v", m.output)
	}
	m.executeCommand("network probe plan device 192.0.2.10 443")
	if m.pendingNetworkProbe == nil || m.pendingNetworkProbe.Port != 443 {
		t.Fatalf("probe plan=%#v", m.pendingNetworkProbe)
	}
	if cmd := m.executeCommand("network probe run"); cmd == nil || !m.networkProbeRunning {
		t.Fatal("planned probe did not return an asynchronous command")
	}

	for input, expected := range map[string]string{
		"network ":            "infrastructure",
		"network baseline ":   "set",
		"network compare ":    "baseline",
		"network probe plan ": "device",
		"network rule draft ": "1",
		"network passport ":   "verify",
		"network identity ":   "02:00:00:00:00:01",
	} {
		if !hasCompletion(m.allCompletionCandidates(input), expected) {
			t.Errorf("completion %q missing %q: %v", input, expected, m.allCompletionCandidates(input))
		}
	}
}

func hasCompletion(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}
