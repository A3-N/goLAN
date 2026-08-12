package tui

import (
	"archive/zip"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golan/internal/inspect"
	networkobs "golan/internal/network"
	workproject "golan/internal/project"
)

func TestObservedSecretsAreRedactedByDefaultTransientAndRevealable(t *testing.T) {
	m := NewModelWithSize(160, 40)
	m.workspace = workspaceNetwork
	m.activeCard = cardInspector
	signal := inspect.Signal{
		Protocol: "HTTP", Kind: "Basic authentication", DeviceMAC: "02:00:00:00:00:11",
		Secret: "alice:synthetic-secret",
	}
	m.addSensitiveSignalEvent(signal.Encode(), "en0", "host")
	if len(m.output) != 0 {
		t.Fatalf("transient secret leaked into Main Output: %v", m.output)
	}
	m.networkExpanded = map[networkobs.Category]bool{networkobs.CategoryRisk: true}
	m.ensureNetworkSelection()

	view := m.renderNetworkInspector(150, 30)
	if !strings.Contains(view, "observed [REDACTED]") || strings.Contains(view, "synthetic-secret") {
		t.Fatalf("default secret rendering is unsafe:\n%s", view)
	}
	m.redactObservedSecrets = false
	view = m.renderNetworkInspector(150, 30)
	if !strings.Contains(view, "observed [alice:synthetic-secret]") {
		t.Fatalf("revealed secret is missing:\n%s", view)
	}

	persisted, err := json.Marshal(m.networkTracker.Snapshot())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(persisted), "synthetic-secret") || strings.Contains(string(persisted), "alice") {
		t.Fatalf("transient secret entered Network persistence: %s", persisted)
	}
	m.startNetworkSession("listen", filepath.Join(t.TempDir(), "next-session"))
	if len(m.observedSecrets) != 0 {
		t.Fatalf("session replacement retained transient secrets: %#v", m.observedSecrets)
	}
}

func TestObservedSecretNeverEntersProjectCanvasOrBundle(t *testing.T) {
	project, err := workproject.New(t.TempDir(), "SecretBoundary")
	if err != nil {
		t.Fatal(err)
	}
	m := NewProjectModel(project, true, 120, 36)
	m.startNetworkSession("listen", filepath.Join(t.TempDir(), "secret-session"))
	secret := "never-persist-this-secret"
	m.addSensitiveSignalEvent(inspect.Signal{
		Protocol: "FTP", Kind: "plaintext authentication", DeviceMAC: "02:00:00:00:00:21", Secret: secret,
	}.Encode(), "en0", "host")
	m.finishNetworkSession()
	m.buildNetworkCanvas(nil)

	canvasJSON, err := json.Marshal(m.canvasMap.JSONCanvas())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(canvasJSON), secret) {
		t.Fatalf("transient secret entered Canvas: %s", canvasJSON)
	}
	if err := project.Save(); err != nil {
		t.Fatal(err)
	}
	if err := filepath.WalkDir(project.Path(), func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil || entry.IsDir() {
			return walkErr
		}
		content, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		if strings.Contains(string(content), secret) {
			t.Fatalf("transient secret entered project artifact %s", path)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	bundle := filepath.Join(t.TempDir(), "secret-boundary.golanproj")
	if err := project.ExportBundle(context.Background(), bundle, workproject.BundleFull); err != nil {
		t.Fatal(err)
	}
	reader, err := zip.OpenReader(bundle)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	for _, file := range reader.File {
		handle, openErr := file.Open()
		if openErr != nil {
			t.Fatal(openErr)
		}
		content, readErr := io.ReadAll(handle)
		closeErr := handle.Close()
		if readErr != nil || closeErr != nil {
			t.Fatalf("read bundle entry %s: read=%v close=%v", file.Name, readErr, closeErr)
		}
		if strings.Contains(string(content), secret) {
			t.Fatalf("transient secret entered bundle entry %s", file.Name)
		}
	}
}

func TestLiveLifecyclePersistsAndRestoresNetworkSession(t *testing.T) {
	project, err := workproject.New(t.TempDir(), "NetworkLifecycle")
	if err != nil {
		t.Fatal(err)
	}
	m := NewProjectModel(project, true, 120, 36)
	directory := filepath.Join(t.TempDir(), "session-one")
	m.startNetworkSession("listen", directory)
	m.networkTracker.ObserveDiscovery(networkobs.Discovery{
		Adapter: "en0", Role: "host", DeviceMAC: "02:00:00:00:00:01",
		Field: "ip", Value: "192.0.2.10", Packet: "DHCP",
	})
	m.addNetworkCapture(filepath.Join(directory, "host-en0.pcap"))
	m.finishNetworkSession()

	manifest := project.Manifest()
	if len(manifest.NetworkSessions) != 1 || manifest.NetworkSessions[0].ID != "session-one" || !project.Dirty() {
		t.Fatalf("manifest=%#v dirty=%t", manifest.NetworkSessions, project.Dirty())
	}
	if err := project.Save(); err != nil {
		t.Fatal(err)
	}
	opened, err := workproject.Open(project.Path())
	if err != nil {
		t.Fatal(err)
	}
	restored := NewProjectModel(opened, true, 120, 36)
	if restored.networkTracker == nil || restored.networkTracker.Snapshot().ID != "session-one" || len(restored.networkDevices()) != 1 {
		t.Fatalf("restored tracker=%#v devices=%#v", restored.networkTracker, restored.networkDevices())
	}
}

func TestNetworkWorkspaceIsDeviceCentricAndUsesGuidedSections(t *testing.T) {
	m := NewModelWithSize(160, 40)
	m.workspace = workspaceNetwork
	m.activeCard = cardInspector
	m.networkTracker = networkobs.LoadTracker(networkobs.Session{
		Version: networkobs.CurrentVersion, ID: "readable", Mode: "listen", StartedAt: time.Unix(1, 0),
		CapturePaths: []string{"/var/tmp/golan/readable/original.pcap"},
		Devices: []networkobs.Device{{
			Key: "en0/02:00:00:00:00:01", MAC: "02:00:00:00:00:01", Adapter: "en0", Role: "host",
			IPs: []string{"192.0.2.10"}, Protocols: []string{"DNS", "HTTP"},
			FirstSeen: time.Unix(2, 0), LastSeen: time.Unix(3, 0),
			Observations: []networkobs.Observation{
				{Category: networkobs.CategoryAddressing, Kind: "address", Summary: "address 192.0.2.10 via DHCP", Severity: networkobs.SeverityInfo, Count: 1},
				{Category: networkobs.CategoryDNS, Kind: "query", Summary: "DNS A example.test", Severity: networkobs.SeverityInfo, Count: 2},
				{Category: networkobs.CategoryHTTP, Kind: "request", Summary: "HTTP GET example.test/login", Severity: networkobs.SeverityWarn, Count: 1},
			},
		}},
	})
	m.ensureNetworkSelection()

	view := m.View()
	for _, want := range []string{"network devices", "device inspector", "DISCOVERY #1", "02:00:00:00:00:01", "192.0.2.10", "[-] ADDRESSING", "[+] DNS", "[+] HTTP", "CAPTURES (1)"} {
		if !strings.Contains(view, want) {
			t.Fatalf("Network view missing %q:\n%s", want, view)
		}
	}
	if strings.Contains(view, "DNS A example.test") || strings.Contains(view, "HTTP GET example.test/login") {
		t.Fatalf("collapsed observations leaked into the initial overview:\n%s", view)
	}

	m.networkSection = 3
	m.toggleNetworkSection()
	view = m.View()
	if !strings.Contains(view, "[-] HTTP") || !strings.Contains(view, "HTTP GET example.test/login") ||
		!strings.Contains(view, "[+] ADDRESSING") || strings.Contains(view, "address 192.0.2.10 via DHCP") {
		t.Fatalf("accordion disclosure is not focused:\n%s", view)
	}
}

func TestNetworkRowsAndSelectionStayPutWhenOlderDeviceIsActive(t *testing.T) {
	m := NewModelWithSize(120, 30)
	m.workspace = workspaceNetwork
	m.activeCard = cardOutput
	m.networkTracker = networkobs.LoadTracker(networkobs.Session{
		Version: networkobs.CurrentVersion, ID: "stable-rows", Mode: "listen", StartedAt: time.Unix(1, 0),
		Devices: []networkobs.Device{
			{Key: "en0/02:00:00:00:00:01", MAC: "02:00:00:00:00:01", Adapter: "en0", FirstSeen: time.Unix(2, 0), LastSeen: time.Unix(2, 0)},
			{Key: "en0/02:00:00:00:00:02", MAC: "02:00:00:00:00:02", Adapter: "en0", FirstSeen: time.Unix(3, 0), LastSeen: time.Unix(3, 0)},
		},
	})
	m.ensureNetworkSelection()
	m.moveNetworkSelection(1)
	selected := m.selectedNetworkDevice

	m.networkTracker.ObserveDiscovery(networkobs.Discovery{
		Adapter: "en0", Role: "host", DeviceMAC: "02:00:00:00:00:01",
		Field: "ip", Value: "192.0.2.10", Packet: "DHCP",
	})
	m.ensureNetworkSelection()
	devices := m.networkDevices()
	if len(devices) != 2 || devices[0].Number != 2 || devices[1].Number != 1 ||
		devices[0].MAC != "02:00:00:00:00:02" || devices[1].MAC != "02:00:00:00:00:01" {
		t.Fatalf("activity reordered rows: %#v", devices)
	}
	if m.selectedNetworkDevice != selected || selected != devices[1].Key {
		t.Fatalf("selection moved: selected=%q want=%q", m.selectedNetworkDevice, selected)
	}
	view := m.renderNetworkDevices(118, 20)
	newer := strings.Index(view, "02:00:00:00:00:02")
	older := strings.Index(view, "02:00:00:00:00:01")
	if newer < 0 || older < 0 || newer >= older {
		t.Fatalf("highest discovery number is not rendered first:\n%s", view)
	}
	if row := networkDeviceRow("> ", devices[1], 118); !strings.HasPrefix(row, "> 1") {
		t.Fatalf("selected row does not retain discovery number: %q", row)
	}
	m.networkFilter = networkobs.CategoryAddressing
	filtered := m.networkDevices()
	if len(filtered) != 1 || filtered[0].Key != selected || filtered[0].Number != 1 {
		t.Fatalf("filter renumbered the selected device: %#v", filtered)
	}
	m.networkFilter = ""
	m.networkTracker.ObserveDiscovery(networkobs.Discovery{
		Adapter: "en0", Role: "host", DeviceMAC: "02:00:00:00:00:03",
		Field: "ip", Value: "192.0.2.30", Packet: "DHCP",
	})
	m.ensureNetworkSelection()
	devices = m.networkDevices()
	if len(devices) != 3 || devices[0].Number != 3 || devices[1].Number != 2 || devices[2].Number != 1 {
		t.Fatalf("new discovery is not ordered highest to lowest: %#v", devices)
	}
	if m.selectedNetworkDevice != selected {
		t.Fatalf("new discovery stole selection: selected=%q want=%q", m.selectedNetworkDevice, selected)
	}
}

func TestNetworkCommandsFilterSearchAndNeverOfferPacketReplay(t *testing.T) {
	m := NewModel()
	m.networkTracker = networkobs.LoadTracker(networkobs.Session{
		Version: networkobs.CurrentVersion, ID: "commands", Mode: "listen", StartedAt: time.Unix(1, 0),
		Devices: []networkobs.Device{
			{Key: "en0/02:00:00:00:00:01", MAC: "02:00:00:00:00:01", Adapter: "en0", FirstSeen: time.Unix(1, 0), LastSeen: time.Unix(1, 0), Observations: []networkobs.Observation{{Category: networkobs.CategoryDNS, Kind: "query", Summary: "DNS A alpha.test", Severity: networkobs.SeverityInfo, Count: 1}}},
			{Key: "en0/02:00:00:00:00:02", MAC: "02:00:00:00:00:02", Adapter: "en0", FirstSeen: time.Unix(2, 0), LastSeen: time.Unix(2, 0), Observations: []networkobs.Observation{{Category: networkobs.CategoryRisk, Kind: "ntlm", Summary: "NTLM authentication observed", Severity: networkobs.SeverityWarn, Count: 1}}},
		},
	})
	m.executeCommand("network filter dns")
	if devices := m.networkDevices(); len(devices) != 1 || !strings.Contains(devices[0].Observations[0].Summary, "alpha.test") {
		t.Fatalf("DNS filter devices=%#v", devices)
	}
	m.executeCommand("network search alpha")
	if len(m.networkDevices()) != 1 {
		t.Fatalf("search devices=%#v", m.networkDevices())
	}
	m.executeCommand("network reset")
	if len(m.networkDevices()) != 2 || m.networkFilter != "" || m.networkSearch != "" {
		t.Fatalf("reset filter=%q search=%q devices=%d", m.networkFilter, m.networkSearch, len(m.networkDevices()))
	}

	m.input = ""
	m.refreshCompletions()
	for _, retired := range []string{"live", "pcap", "replay", "analyze"} {
		if containsString(m.completions, retired) {
			t.Fatalf("top-level completion retained %q: %v", retired, m.completions)
		}
	}
}

func TestCanvasBuildUsesNetworkObservations(t *testing.T) {
	m := NewModel()
	m.networkTracker = networkobs.LoadTracker(networkobs.Session{
		Version: networkobs.CurrentVersion, ID: "canvas-network", Mode: "listen", StartedAt: time.Unix(1, 0),
		Devices: []networkobs.Device{{
			Key: "en0/02:00:00:00:00:01", MAC: "02:00:00:00:00:01", Adapter: "en0", Role: "host",
			IPs: []string{"192.0.2.10"}, FirstSeen: time.Unix(1, 0), LastSeen: time.Unix(2, 0),
			Observations: []networkobs.Observation{{
				Category: networkobs.CategoryDNS, Kind: "query", Summary: "DNS A example.test", Protocol: "DNS",
				Source: "192.0.2.10", Destination: "192.0.2.53", Severity: networkobs.SeverityInfo, Count: 1,
			}},
		}},
	})
	m.executeCommand("canvas build")
	if m.canvasMap == nil || len(m.canvasMap.Hosts) == 0 || len(m.canvasMap.Conversations) != 1 || !m.canvasDirty {
		t.Fatalf("canvas=%#v dirty=%t output=%v", m.canvasMap, m.canvasDirty, m.output)
	}
	output := strings.Join(m.output, "\n")
	if !strings.Contains(output, "built from network session=canvas-network") {
		t.Fatalf("canvas output=%q", output)
	}
}
