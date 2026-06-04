package tui

import (
	"os"
	"strings"
	"testing"

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

func TestExecuteCommandSelectSetAndConfirm(t *testing.T) {
	m := NewModel()
	m.adapters = []adapters.Adapter{{Name: "en0", Kind: "ethernet"}}

	m.executeCommand("set en0 host")
	if len(m.profile.Adapters) != 1 {
		t.Fatalf("selected adapters = %d", len(m.profile.Adapters))
	}
	if m.activeAdapter != "" {
		t.Fatalf("active adapter = %q", m.activeAdapter)
	}

	m.executeCommand("conf en0")
	m.executeCommand("set role uplink")
	if got := m.profile.Adapters[0].Role; got != "uplink" {
		t.Fatalf("role = %q", got)
	}

	if !containsOutput(m.output, "en0 role: auto -> uplink") {
		t.Fatalf("set output missing: %v", m.output)
	}
}

func TestCommandRejectsThirdAdapter(t *testing.T) {
	m := NewModel()
	m.adapters = []adapters.Adapter{{Name: "en0"}, {Name: "en1"}, {Name: "en2"}}

	m.executeCommand("set en0 host")
	m.executeCommand("set en1 switch")
	m.executeCommand("set adapter en2")

	if len(m.profile.Adapters) != 2 {
		t.Fatalf("selected adapters = %d", len(m.profile.Adapters))
	}
	if !containsOutput(m.output, "maximum of 2 adapters") {
		t.Fatalf("max adapter output missing: %v", m.output)
	}
}

func TestUpdateCLIExecutesCommand(t *testing.T) {
	m := NewModel()
	m.adapters = []adapters.Adapter{{Name: "en0"}}
	m.input = "set en0 host"

	next, _ := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	got := next.(Model)
	if len(got.profile.Adapters) != 1 {
		t.Fatalf("selected adapters = %d", len(got.profile.Adapters))
	}
}

func TestClearClearsOutput(t *testing.T) {
	m := NewModel()
	m.executeCommand("help")
	m.addTraffic("packet")
	m.addFinding("HTTP Basic user=alice secret=secret")
	if len(m.output) == 0 {
		t.Fatal("expected help output")
	}
	m.executeCommand("clear")
	if len(m.output) != 0 || len(m.traffic) != 0 || len(m.findings) != 0 {
		t.Fatalf("output=%v traffic=%v findings=%v", m.output, m.traffic, m.findings)
	}
}

func TestSetAdapterStagesRoleWithoutContext(t *testing.T) {
	m := NewModel()
	m.adapters = []adapters.Adapter{{Name: "en11"}}

	m.executeCommand("set en11 host")
	if got := m.profile.Adapters[0].AdapterRole; got != profile.AdapterRoleHost {
		t.Fatalf("adapter role = %q", got)
	}
	if m.activeAdapter != "" {
		t.Fatalf("active adapter = %q", m.activeAdapter)
	}
	m.executeCommand("conf en11")
	if m.activeAdapter != "en11" {
		t.Fatalf("active adapter after conf = %q", m.activeAdapter)
	}
}

func TestActiveAdapterStateReturnsCommand(t *testing.T) {
	m := NewModel()
	m.adapters = []adapters.Adapter{{Name: "en11"}}
	m.executeCommand("set en11 host")
	m.executeCommand("conf en11")

	cmd := m.executeCommand("up")
	if cmd == nil {
		t.Fatal("expected adapter state command")
	}
	if !containsOutput(m.output, "adapter state: en11 -> up") {
		t.Fatalf("output = %v", m.output)
	}
}

func TestAutocompleteAdapterName(t *testing.T) {
	m := NewModel()
	m.profile.Adapters = append(m.profile.Adapters, adaptersToConfig("en11", profile.AdapterRoleHost))
	m.input = "conf en"
	m.refreshCompletions()
	m.applyCompletion()
	if m.input != "conf en11 " {
		t.Fatalf("input = %q", m.input)
	}
}

func TestAutocompleteSetAdapterRole(t *testing.T) {
	m := NewModel()
	m.adapters = []adapters.Adapter{{Name: "en11"}}
	m.input = "set en11 "
	m.refreshCompletions()
	m.applyCompletion()
	if m.input != "set en11 host" {
		t.Fatalf("input = %q", m.input)
	}
	if !containsString(m.completions, "host") || !containsString(m.completions, "switch") {
		t.Fatalf("completions = %v", m.completions)
	}
	m.applyCompletion()
	if m.input != "set en11 switch" {
		t.Fatalf("cycled input = %q", m.input)
	}
}

func TestUnsetDeselectsActiveAdapter(t *testing.T) {
	m := NewModel()
	m.adapters = []adapters.Adapter{{Name: "en11"}}
	m.executeCommand("set en11 host")
	m.executeCommand("conf en11")
	m.executeCommand("unset")
	if m.activeAdapter != "" {
		t.Fatalf("active adapter = %q", m.activeAdapter)
	}
	if len(m.profile.Adapters) != 0 {
		t.Fatalf("adapters = %+v", m.profile.Adapters)
	}
}

func TestSaveAndLoadConfig(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("GOLAN_CONFIG_DIR", dir)
	m := NewModel()
	m.adapters = []adapters.Adapter{{Name: "en11"}}
	m.executeCommand("set en11 host")
	m.executeCommand("conf en11")
	m.executeCommand("set ip 192.0.2.10")
	m.canvasEnabled = true
	m.canvasPath = dir + "/lab.canvas"
	m.eapolSuppressLogoff = false
	m.eapolDowngradeMACsec = true
	m.saveConfig("lab")

	loaded := NewModel()
	loaded.executeCommand("load")
	if !containsOutput(loaded.output, "lab.json") {
		t.Fatalf("load list missing config: %v", loaded.output)
	}
	loaded.executeCommand("load lab")
	if loaded.activeAdapter != "en11" {
		t.Fatalf("active adapter = %q", loaded.activeAdapter)
	}
	cfg, ok := loaded.profile.ByName("en11")
	if !ok || cfg.IP != "192.0.2.10" {
		t.Fatalf("loaded config = %+v ok=%v", cfg, ok)
	}
	if !loaded.canvasEnabled || loaded.canvasPath != dir+"/lab.canvas" || loaded.eapolSuppressLogoff || !loaded.eapolDowngradeMACsec {
		t.Fatalf("loaded settings canvas=%v path=%q logoff=%v downgrade=%v", loaded.canvasEnabled, loaded.canvasPath, loaded.eapolSuppressLogoff, loaded.eapolDowngradeMACsec)
	}
}

func TestRemovedCommandsAreNotSuggested(t *testing.T) {
	commands := topLevelCommands()
	for _, removed := range []string{"reset", "confirm", "save", "listen", "bridge"} {
		if containsString(commands, removed) {
			t.Fatalf("removed command %q was suggested: %v", removed, commands)
		}
	}
}

func TestStartCommandAutocomplete(t *testing.T) {
	m := NewModel()
	m.input = "start "
	m.refreshCompletions()
	if !containsString(m.completions, "listen") || !containsString(m.completions, "bridge") {
		t.Fatalf("start completions = %v", m.completions)
	}
}

func TestListenTargetsHostOnly(t *testing.T) {
	m := NewModel()
	m.profile.Adapters = append(m.profile.Adapters,
		adaptersToConfig("en11", profile.AdapterRoleHost),
		adaptersToConfig("en12", profile.AdapterRoleSwitch),
	)

	targets := m.listenTargets()
	if len(targets) != 1 || targets[0].Name != "en11" || targets[0].Role != profile.AdapterRoleHost {
		t.Fatalf("listen targets = %+v", targets)
	}
}

func TestStopCommandAutocomplete(t *testing.T) {
	m := NewModel()
	m.input = "stop "
	m.refreshCompletions()
	if !containsString(m.completions, "listen") || !containsString(m.completions, "bridge") {
		t.Fatalf("stop completions = %v", m.completions)
	}
}

func TestEAPOLToggleCommands(t *testing.T) {
	m := NewModel()
	if !m.eapolSuppressLogoff || !m.eapolDowngradeMACsec {
		t.Fatalf("defaults = logoff:%v downgrade:%v", m.eapolSuppressLogoff, m.eapolDowngradeMACsec)
	}

	m.executeCommand("disable eapol drop-logoff")
	if m.eapolSuppressLogoff {
		t.Fatal("expected logoff drop disabled")
	}
	if !containsOutput(m.output, "eapol drop-logoff: disable") {
		t.Fatalf("output = %v", m.output)
	}

	m.executeCommand("disable eapol macsec-downgrade")
	if m.eapolDowngradeMACsec {
		t.Fatal("expected downgrade disabled")
	}
	if !containsOutput(m.output, "eapol macsec-downgrade: disable") {
		t.Fatalf("output = %v", m.output)
	}
	m.executeCommand("enable eapol macsec-downgrade")
	if !m.eapolDowngradeMACsec {
		t.Fatal("expected downgrade enabled")
	}
}

func TestEAPOLToggleAliasesAreRejected(t *testing.T) {
	for _, command := range []string{
		"disable eapol logoff",
		"disable macsec",
		"disable eapol downgrade",
		"disable eapol downgarde",
	} {
		m := NewModel()
		m.executeCommand(command)
		if !m.eapolSuppressLogoff || !m.eapolDowngradeMACsec {
			t.Fatalf("%q changed toggles: logoff=%v downgrade=%v", command, m.eapolSuppressLogoff, m.eapolDowngradeMACsec)
		}
		if !containsOutput(m.output, "use: disable eapol drop-logoff|eapol macsec-downgrade") &&
			!containsOutput(m.output, "use: disable canvas|eapol drop-logoff|eapol macsec-downgrade") {
			t.Fatalf("%q did not print strict usage: %v", command, m.output)
		}
	}
}

func TestShowConfigPrintsSettings(t *testing.T) {
	m := NewModel()
	m.canvasEnabled = true
	m.canvasPath = "/tmp/lab.canvas"
	m.eapolSuppressLogoff = false
	m.eapolDowngradeMACsec = true

	m.executeCommand("show config")
	for _, want := range []string{
		"settings:",
		"canvas: on",
		"canvas path: /tmp/lab.canvas",
		"eapol drop-logoff: disable",
		"eapol macsec-downgrade: enable",
	} {
		if !containsOutput(m.output, want) {
			t.Fatalf("show config missing %q: %v", want, m.output)
		}
	}
}

func TestConfBridgeSetsBridgeConfigContext(t *testing.T) {
	m := NewModel()
	m.executeCommand("conf bridge")
	m.executeCommand("set ip 192.0.2.145")
	m.executeCommand("set cidr 24")
	m.executeCommand("set gateway 192.0.2.1")

	cfg := m.profile.BridgeAdapterSnapshot()
	if m.activeAdapter != "bridge" || cfg.IP != "192.0.2.145" || cfg.CIDR != "24" || cfg.Gateway != "192.0.2.1" {
		t.Fatalf("active=%q bridge cfg=%+v", m.activeAdapter, cfg)
	}
}

func TestTabCyclesOptionsWhenNothingIsListed(t *testing.T) {
	m := NewModel()
	m.input = "zz"
	m.refreshCompletions()
	if len(m.completions) != 0 {
		t.Fatalf("expected no visible completions, got %v", m.completions)
	}

	all := dedupe(topLevelCommands())
	m.applyCompletion()
	if m.input != all[0] {
		t.Fatalf("input = %q want %q", m.input, all[0])
	}
	m.applyCompletion()
	if m.input != all[1] {
		t.Fatalf("cycled input = %q want %q", m.input, all[1])
	}
}

func TestTabCyclesValueOptionsWhenPrefixHasNoMatches(t *testing.T) {
	m := NewModel()
	m.input = "set state z"
	m.refreshCompletions()
	if len(m.completions) != 0 {
		t.Fatalf("expected no visible completions, got %v", m.completions)
	}

	m.applyCompletion()
	if m.input != "set state auto" {
		t.Fatalf("input = %q", m.input)
	}
	m.applyCompletion()
	if m.input != "set state down" {
		t.Fatalf("cycled input = %q", m.input)
	}
}

func TestDiscoveryAppliesAutoAndFeedsAutocomplete(t *testing.T) {
	m := NewModel()
	m.profile.Adapters = append(m.profile.Adapters, adaptersToConfig("en11", profile.AdapterRoleHost))
	m.activeAdapter = "en11"

	m.applyDiscovery(listen.Event{
		Kind:     "discovery",
		Adapter:  "en11",
		Role:     profile.AdapterRoleHost,
		Field:    "ip",
		Value:    "192.0.2.10",
		Evidence: "ipv4 source",
		Packet:   "IPv4",
	})
	cfg, _ := m.profile.ByName("en11")
	if cfg.IP != "192.0.2.10" {
		t.Fatalf("IP = %q", cfg.IP)
	}

	m.applyDiscovery(listen.Event{
		Kind:     "discovery",
		Adapter:  "en11",
		Role:     profile.AdapterRoleHost,
		Field:    "ip",
		Value:    "192.0.2.11",
		Evidence: "arp sender ip",
		Packet:   "ARP",
	})
	cfg, _ = m.profile.ByName("en11")
	if cfg.IP != "192.0.2.10" {
		t.Fatalf("IP changed unexpectedly to %q", cfg.IP)
	}

	m.input = "set ip "
	m.refreshCompletions()
	if !containsString(m.completions, "192.0.2.10") || !containsString(m.completions, "192.0.2.11") {
		t.Fatalf("ip completions = %v", m.completions)
	}
	if !containsOutput(m.output, "auto") {
		t.Fatalf("discovery output missing auto marker: %v", m.output)
	}

	m.executeCommand("set ip 198.51.100.7")
	m.executeCommand("set ip auto")
	cfg, _ = m.profile.ByName("en11")
	if cfg.IP != "192.0.2.10" {
		t.Fatalf("saved discovery was not reapplied, IP = %q", cfg.IP)
	}
}

func TestBridgeStoresNonAdapterObservations(t *testing.T) {
	m := NewModel()
	m.profile.Adapters = append(m.profile.Adapters, adaptersToConfig("en11", profile.AdapterRoleHost))
	m.applyDiscovery(listen.Event{
		Kind:     "discovery",
		Adapter:  "en11",
		Role:     profile.AdapterRoleHost,
		Field:    "arp_who_has",
		Value:    "192.0.2.1",
		Evidence: "who-has target ip",
		Packet:   "ARP",
	})

	cfg, _ := m.profile.ByName("en11")
	if len(cfg.Discovered) != 0 {
		t.Fatalf("adapter discoveries = %+v", cfg.Discovered)
	}
	if len(m.profile.Bridge.Observations) != 1 {
		t.Fatalf("bridge observations = %+v", m.profile.Bridge.Observations)
	}

	m.executeCommand("show bridge")
	if !containsOutput(m.output, "arp_who_has") || !containsOutput(m.output, "192.0.2.1") {
		t.Fatalf("bridge output = %v", m.output)
	}
}

func TestTrafficEventsUseBoundedTrafficPane(t *testing.T) {
	m := NewModel()
	m.height = 18
	m.handleListenEvent(listen.Event{
		Kind:    "traffic",
		Adapter: "en11",
		Role:    profile.AdapterRoleHost,
		Message: "#1 host/en11 IPv4 00:00:11>00:00:22 192.0.2.10>192.0.2.1 TCP",
	})

	if len(m.output) != 0 {
		t.Fatalf("traffic leaked into main output: %v", m.output)
	}
	if len(m.traffic) != 1 || !strings.Contains(m.traffic[0], "IPv4") {
		t.Fatalf("traffic pane = %v", m.traffic)
	}

	limit := m.trafficCapacity()
	for i := 0; i < limit+5; i++ {
		m.addTraffic("packet")
	}
	if len(m.traffic) != limit {
		t.Fatalf("traffic retained %d lines, want %d", len(m.traffic), limit)
	}
}

func TestFindingEventsUseBoundedFindingsPane(t *testing.T) {
	m := NewModel()
	m.height = 18
	m.handleListenEvent(listen.Event{
		Kind:    "finding",
		Adapter: "en11",
		Role:    profile.AdapterRoleHost,
		Message: "HTTP Basic user=alice secret=secret",
	})

	if len(m.findings) != 1 || !strings.Contains(m.findings[0], "secret=secret") {
		t.Fatalf("findings pane = %v", m.findings)
	}
	if !containsOutput(m.output, "HTTP Basic") {
		t.Fatalf("finding signal missing from output: %v", m.output)
	}

	limit := m.findingsCapacity()
	for i := 0; i < limit+5; i++ {
		m.addFinding("FTP PASS user=alice secret=secret")
	}
	if len(m.findings) != limit {
		t.Fatalf("findings retained %d lines, want %d", len(m.findings), limit)
	}
}

func TestShowSecretsPrintsFindingsToOutput(t *testing.T) {
	m := NewModel()
	m.executeCommand("show secrets")
	if !containsOutput(m.output, "secrets: none") {
		t.Fatalf("empty secrets output = %v", m.output)
	}

	m.output = nil
	m.outputMuted = nil
	m.addFinding("HTTP Basic user=alice secret=secret")
	m.executeCommand("show secrets")
	if !containsOutput(m.output, "secrets:") || !containsOutput(m.output, "HTTP Basic user=alice secret=secret") {
		t.Fatalf("secrets output = %v", m.output)
	}
}

func TestFindingEventFeedsCanvasSecretContext(t *testing.T) {
	m := NewModel()
	finding := inspect.Finding{
		Protocol: "HTTP",
		Kind:     "Basic",
		User:     "alice",
		Secret:   "secret123",
		Src:      "192.168.1.10",
		Sport:    49152,
		Dst:      "192.168.1.20",
		Dport:    80,
	}

	m.handleListenEvent(listen.Event{
		Kind:    "finding",
		Adapter: "en11",
		Role:    profile.AdapterRoleHost,
		Message: finding.Encode(),
	})

	server := m.canvasMap.Hosts["ip:192.168.1.20"]
	if server == nil {
		t.Fatalf("server missing: %+v", m.canvasMap.Hosts)
	}
	var found bool
	for _, service := range server.Services {
		if service.Secrets[finding.Display()] {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("secret not tied to destination service: %+v", server.Services)
	}
}

func TestWindowSizeLocksAfterInitialDetection(t *testing.T) {
	m := NewModel()
	next, _ := m.Update(tea.WindowSizeMsg{Width: 80, Height: 24})
	m = next.(Model)
	next, _ = m.Update(tea.WindowSizeMsg{Width: 200, Height: 60})
	m = next.(Model)

	if m.width != 80 || m.height != 24 {
		t.Fatalf("size = %dx%d, want 80x24", m.width, m.height)
	}
}

func TestSeededWindowSizeLocksBeforeFirstMessage(t *testing.T) {
	m := NewModelWithSize(90, 26)
	next, _ := m.Update(tea.WindowSizeMsg{Width: 200, Height: 80})
	m = next.(Model)

	if m.width != 90 || m.height != 26 {
		t.Fatalf("size = %dx%d, want 90x26", m.width, m.height)
	}
}

func TestDiscoveryOnlyPrintsFoundAndEAPOLSignals(t *testing.T) {
	m := NewModel()
	m.profile.Adapters = append(m.profile.Adapters, adaptersToConfig("en11", profile.AdapterRoleHost))

	m.applyDiscovery(listen.Event{
		Kind:     "discovery",
		Adapter:  "en11",
		Role:     profile.AdapterRoleHost,
		Field:    "arp_who_has",
		Value:    "192.0.2.1",
		Evidence: "who-has target ip",
		Packet:   "ARP",
	})
	if len(m.output) != 0 {
		t.Fatalf("bridge-only observation printed: %v", m.output)
	}

	m.applyDiscovery(listen.Event{
		Kind:     "discovery",
		Adapter:  "en11",
		Role:     profile.AdapterRoleHost,
		Field:    "eapol",
		Value:    "Start",
		Evidence: "type",
		Packet:   "EAPOL / 802.1X",
	})
	m.applyDiscovery(listen.Event{
		Kind:     "discovery",
		Adapter:  "en11",
		Role:     profile.AdapterRoleHost,
		Field:    "eapol",
		Value:    "Start",
		Evidence: "type",
		Packet:   "EAPOL / 802.1X",
	})
	m.applyDiscovery(listen.Event{
		Kind:     "discovery",
		Adapter:  "en11",
		Role:     profile.AdapterRoleHost,
		Field:    "eap_code",
		Value:    "success",
		Evidence: "code",
		Packet:   "EAPOL / 802.1X",
	})

	if countOutput(m.output, "EAPOL start") != 1 {
		t.Fatalf("EAPOL start output = %v", m.output)
	}
	if !containsOutput(m.output, "EAPOL success") {
		t.Fatalf("EAPOL success missing: %v", m.output)
	}
}

func TestEAPOLDiscoverySignalsIncludeMACsec(t *testing.T) {
	m := NewModel()
	m.applyDiscovery(listen.Event{
		Kind:     "discovery",
		Adapter:  "en12",
		Role:     profile.AdapterRoleSwitch,
		Field:    "macsec",
		Value:    "0x88e5",
		Evidence: "ether type",
		Packet:   "MACsec",
	})

	if !containsOutput(m.output, "MACsec 0x88e5 detected") {
		t.Fatalf("MACsec signal missing: %v", m.output)
	}

	m.applyDiscovery(listen.Event{
		Kind:     "discovery",
		Adapter:  "en12",
		Role:     profile.AdapterRoleSwitch,
		Field:    "eapol_type",
		Value:    "5",
		Evidence: "type number",
		Packet:   "EAPOL / 802.1X",
	})
	if !containsOutput(m.output, "MACsec MKA detected") {
		t.Fatalf("MKA signal missing: %v", m.output)
	}
}

func TestEAPOLLogSignalsAreDistinct(t *testing.T) {
	cases := []struct {
		message string
		key     string
		label   string
	}{
		{"[RELAY] device->switch: EAPOL-Start from 02:00:00:00:00:01", "eapol-start", "EAPOL start"},
		{"[EAPOL] drop-logoff enabled: EAPOL-Logoff frames will be dropped.", "eapol-drop-logoff-enable", "EAPOL drop-logoff enable"},
		{"[!][RELAY] device->switch: EAPOL-Logoff received from 02:00:00:00:00:01", "eapol-logoff-dropped", "EAPOL-Logoff dropped"},
		{"[RELAY] switch->device: EAP-Request Type=Identity ID=7 from 02:00:00:00:00:02", "eap-request-identity", "EAP request Identity ID=7"},
		{"[RELAY] device->switch: EAP-Response Type=Identity ID=8 Identity=test from 02:00:00:00:00:01", "eap-response-identity-test", "EAP response identity: test ID=8"},
		{"[+][802.1X] EAP-Success received (ID=7) port AUTHORIZED", "eap-success", "EAPOL success ID=7"},
		{"[!][802.1X] EAP-Failure received (ID=8) - authentication REJECTED", "eap-failure", "EAPOL failure ID=8"},
		{"[!][MACSEC] device->switch: MACsec (EAPOL Type 5) discovered. DROPPING PACKET to force downgrade", "macsec-drop", "MACsec drop"},
		{"[MACSEC] macsec-downgrade enabled: EAPOL-MKA type 5 frames will be dropped.", "eapol-macsec-downgrade-enable", "EAPOL macsec-downgrade enable"},
	}
	for _, tc := range cases {
		key, label, ok := eapolLogSignal(tc.message)
		if !ok || key != tc.key || label != tc.label {
			t.Fatalf("eapolLogSignal(%q) = %q, %q, %v; want %q, %q, true", tc.message, key, label, ok, tc.key, tc.label)
		}
	}
}

func TestEAPOLLogSignalsAreAlwaysPrinted(t *testing.T) {
	m := NewModel()
	message := "[+][802.1X] EAP-Success received (ID=7) port AUTHORIZED"
	m.printEAPOLLogSignal(message)
	m.printEAPOLLogSignal(message)
	if len(m.output) != 2 {
		t.Fatalf("output entries = %d: %v", len(m.output), m.output)
	}
	for i, line := range m.output {
		if line != "EAPOL success ID=7" {
			t.Fatalf("line %d = %q", i, line)
		}
		if m.outputMuted[i] {
			t.Fatalf("line %d was muted: %v", i, m.outputMuted)
		}
	}
}

func TestEAPOLSetupLogsAreNotPrintedAsTraffic(t *testing.T) {
	m := NewModel()
	for _, message := range []string{
		"warn: native EAPOL suppression degraded: ifconfig: bad value)",
		"EAPOL passthrough active: en11 <-> en12",
		"802.1X EAPOL passthrough relay active",
		"           DROPPING PACKET to keep session alive",
	} {
		m.printEAPOLLogSignal(message)
	}
	if len(m.output) != 0 {
		t.Fatalf("setup logs were printed as traffic: %v", m.output)
	}
}

func TestEAPOLKeyAndMalformedEAPFramesAreLogged(t *testing.T) {
	m := NewModel()
	m.printEAPOLLogSignal("[RELAY] device->switch: EAPOL-Key frame from 02:00:00:00:00:01 - forwarding")
	m.printEAPOLLogSignal("[RELAY] switch->device: EAPOL-EAP frame (no EAP layer parsed) from 02:00:00:00:00:02")
	for _, want := range []string{"EAPOL key forwarded", "EAPOL-EAP frame"} {
		if !containsOutput(m.output, want) {
			t.Fatalf("missing %q: %v", want, m.output)
		}
	}
}

func TestBridgeStartRequiresHostAndSwitch(t *testing.T) {
	m := NewModel()
	cmd := m.executeCommand("start bridge")
	if cmd != nil {
		t.Fatal("expected no command without host+switch")
	}
	if !containsOutput(m.output, "bridge err: host+switch") {
		t.Fatalf("output = %v", m.output)
	}
}

func TestBridgeStartReturnsBridgeCommandForStagedAdapters(t *testing.T) {
	m := NewModel()
	host := adaptersToConfig("en11", profile.AdapterRoleHost)
	host.MAC = "02:00:00:00:00:11"
	m.profile.Adapters = append(m.profile.Adapters,
		host,
		adaptersToConfig("en12", profile.AdapterRoleSwitch),
	)
	cmd := m.executeCommand("start bridge")
	if cmd == nil {
		t.Fatal("expected bridge capture command")
	}
	if !containsOutput(m.output, "bridge: start") {
		t.Fatalf("output = %v", m.output)
	}
	host, sw, errText := m.bridgeAdapters()
	if errText != "" || host.Name != "en11" || sw.Name != "en12" {
		t.Fatalf("host = %+v switch = %+v err=%q", host, sw, errText)
	}
}

func TestBridgeStartAllowsAutoHostMAC(t *testing.T) {
	m := NewModel()
	m.profile.Adapters = append(m.profile.Adapters,
		adaptersToConfig("en11", profile.AdapterRoleHost),
		adaptersToConfig("en12", profile.AdapterRoleSwitch),
	)

	cmd := m.executeCommand("start bridge")
	if cmd == nil {
		t.Fatal("expected bridge command with auto host mac")
	}
	if !containsOutput(m.output, "bridge: start") {
		t.Fatalf("output = %v", m.output)
	}
}

func TestBridgeStartIgnoresAdapterAddresses(t *testing.T) {
	m := NewModel()
	host := adaptersToConfig("testhost0", profile.AdapterRoleHost)
	host.MAC = "02:00:00:00:00:11"
	host.Addrs = []string{"192.0.2.20/24"}
	sw := adaptersToConfig("testswitch0", profile.AdapterRoleSwitch)
	sw.Addrs = []string{"fe80::1/64", "169.254.10.20/16"}
	m.profile.Adapters = append(m.profile.Adapters, host, sw)

	cmd := m.executeCommand("start bridge")
	if cmd == nil {
		t.Fatal("expected bridge command despite adapter addresses")
	}
	if containsOutput(m.output, "bridge err: host addr") || containsOutput(m.output, "bridge err: switch addr") {
		t.Fatalf("output = %v", m.output)
	}
}

func TestBridgeStartRefusesActiveListen(t *testing.T) {
	m := NewModel()
	m.listener = &listen.Session{}
	m.capMode = "listen"
	cmd := m.executeCommand("start bridge")
	if cmd != nil {
		t.Fatal("expected no bridge command while listen active")
	}
	if !containsOutput(m.output, "bridge err: listen") {
		t.Fatalf("output = %v", m.output)
	}
}

func TestStartNATRequiresActiveBridge(t *testing.T) {
	m := NewModel()
	if cmd := m.executeCommand("start nat"); cmd != nil {
		t.Fatal("expected no command without active bridge")
	}
	if !containsOutput(m.output, "nat err: bridge") {
		t.Fatalf("output = %v", m.output)
	}

	m.bridge = &bridge.Session{}
	if cmd := m.executeCommand("start nat"); cmd == nil {
		t.Fatal("expected nat command with active bridge")
	}
}

func TestStopBridgeRefusesActiveNAT(t *testing.T) {
	m := NewModel()
	m.bridge = &bridge.Session{}
	m.natActive = true

	if cmd := m.executeCommand("stop bridge"); cmd != nil {
		t.Fatal("expected no bridge stop command while nat active")
	}
	if !containsOutput(m.output, "bridge err: nat; use: stop nat") {
		t.Fatalf("output = %v", m.output)
	}
}

func TestListenStartRefusesActiveBridge(t *testing.T) {
	m := NewModel()
	m.bridge = &bridge.Session{}
	cmd := m.executeCommand("start listen")
	if cmd != nil {
		t.Fatal("expected no listen command while bridge active")
	}
	if !containsOutput(m.output, "listen err: bridge") {
		t.Fatalf("output = %v", m.output)
	}
}

func TestListenStartRefusesActiveNAT(t *testing.T) {
	m := NewModel()
	m.bridge = &bridge.Session{}
	m.natActive = true

	if cmd := m.executeCommand("start listen"); cmd != nil {
		t.Fatal("expected no listen command while nat active")
	}
	if !containsOutput(m.output, "listen err: nat") {
		t.Fatalf("output = %v", m.output)
	}
}

func TestCtrlCStopsActiveCapture(t *testing.T) {
	m := NewModel()
	m.listener = &listen.Session{Dir: "/tmp/golan-pcaps/listen"}
	m.capMode = "bridge"
	next, _ := m.Update(tea.KeyMsg{Type: tea.KeyCtrlC})
	got := next.(Model)
	if got.listener != nil || got.capMode != "" {
		t.Fatalf("capture state = listener:%v mode:%q", got.listener, got.capMode)
	}
	if dirs := PcapDirs(got); len(dirs) != 1 || dirs[0] != "/tmp/golan-pcaps/listen" {
		t.Fatalf("pcap dirs = %v", dirs)
	}
}

func TestCtrlCStopsActiveBridge(t *testing.T) {
	m := NewModel()
	m.bridge = &bridge.Session{Dir: "/tmp/golan-pcaps/bridge"}
	next, _ := m.Update(tea.KeyMsg{Type: tea.KeyCtrlC})
	got := next.(Model)
	if got.bridge != nil || got.bridgeState != "" {
		t.Fatalf("bridge state = bridge:%v state:%q", got.bridge, got.bridgeState)
	}
	if dirs := PcapDirs(got); len(dirs) != 1 || dirs[0] != "/tmp/golan-pcaps/bridge" {
		t.Fatalf("pcap dirs = %v", dirs)
	}
}

func TestShutdownStopsReturnedBridgeModel(t *testing.T) {
	m := NewModel()
	m.bridge = &bridge.Session{}
	if err := Shutdown(m); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
}

func TestPcapDirsDedupSessionAndFilePaths(t *testing.T) {
	m := NewModel()
	m.rememberPcapDir("/tmp/golan-pcaps/run")
	m.rememberPcapPath("/tmp/golan-pcaps/run/host-en11.pcap")
	m.rememberPcapDir("/tmp/golan-pcaps/other")

	dirs := PcapDirs(m)
	if len(dirs) != 2 || dirs[0] != "/tmp/golan-pcaps/run" || dirs[1] != "/tmp/golan-pcaps/other" {
		t.Fatalf("pcap dirs = %v", dirs)
	}
}

func TestARPKnownFieldsAlsoGoToBridge(t *testing.T) {
	m := NewModel()
	m.profile.Adapters = append(m.profile.Adapters, adaptersToConfig("en11", profile.AdapterRoleHost))
	m.applyDiscovery(listen.Event{
		Kind:     "discovery",
		Adapter:  "en11",
		Role:     profile.AdapterRoleHost,
		Field:    "ip",
		Value:    "192.0.2.20",
		Evidence: "arp sender ip",
		Packet:   "ARP",
	})

	cfg, _ := m.profile.ByName("en11")
	if cfg.IP != "192.0.2.20" {
		t.Fatalf("IP = %q", cfg.IP)
	}
	if len(m.profile.Bridge.Observations) != 1 {
		t.Fatalf("bridge observations = %+v", m.profile.Bridge.Observations)
	}
}

func TestCtrlSPromptsForFilename(t *testing.T) {
	t.Setenv("GOLAN_CONFIG_DIR", t.TempDir())
	m := NewModel()
	m.profile.Adapters = append(m.profile.Adapters, adaptersToConfig("en11", profile.AdapterRoleHost))
	next, _ := m.Update(tea.KeyMsg{Type: tea.KeyCtrlS})
	got := next.(Model)
	if got.inputMode != modeSaveName {
		t.Fatalf("input mode = %v", got.inputMode)
	}
	got.input = "from-ctrl-s"
	next, _ = got.Update(tea.KeyMsg{Type: tea.KeyEnter})
	got = next.(Model)
	if got.inputMode != modeCommand {
		t.Fatalf("input mode after save = %v", got.inputMode)
	}
	names, err := configs.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(names) != 1 || names[0] != "from-ctrl-s.json" {
		t.Fatalf("names = %v", names)
	}
}

func TestCanvasEnableWritesSessionCanvas(t *testing.T) {
	t.Setenv("GOLAN_CONFIG_DIR", t.TempDir())
	m := NewModel()
	m.profile.Adapters = append(m.profile.Adapters, adaptersToConfig("en11", profile.AdapterRoleHost))
	m.profile.Adapters[0].IP = "192.168.1.10"
	m.profile.Adapters[0].MAC = "02:00:00:00:00:10"

	cmd := m.executeCommand("enable canvas")
	if cmd != nil {
		t.Fatal("expected synchronous canvas enable")
	}
	if !m.canvasEnabled || m.canvasPath == "" {
		t.Fatalf("canvas state enabled=%v path=%q", m.canvasEnabled, m.canvasPath)
	}
	if _, err := os.Stat(m.canvasPath); err != nil {
		t.Fatalf("canvas file missing: %v", err)
	}

	m.applyCanvasObservation(canvas.Observation{Kind: "host", IP: "192.168.1.1", Tag: "gateway"})
	if _, ok := m.canvasMap.Hosts["ip:192.168.1.1"]; !ok {
		t.Fatalf("gateway not mapped: %+v", m.canvasMap.Hosts)
	}
	m.executeCommand("disable canvas")
	if m.canvasEnabled {
		t.Fatal("canvas still enabled")
	}
}

func TestViewUsesContextPromptAndRealBorders(t *testing.T) {
	m := NewModel()
	m.width = 90
	m.height = 24
	m.cursorVisible = true
	m.activeAdapter = "en11"
	m.input = "set ip auto"
	m.completions = []string{"auto"}

	view := m.View()
	if !strings.Contains(view, "> (en11) set ip auto|") {
		t.Fatalf("context prompt missing:\n%s", view)
	}
	if !strings.Contains(view, "╭") {
		t.Fatalf("rounded border missing:\n%s", view)
	}
	if strings.Contains(view, "try:") || strings.Contains(view, "complete:") {
		t.Fatalf("old completion labels still present:\n%s", view)
	}
	if strings.Contains(view, "golan init") {
		t.Fatalf("right top pane is not blank:\n%s", view)
	}
	if !strings.Contains(view, "findings") {
		t.Fatalf("findings pane missing:\n%s", view)
	}
	if !strings.Contains(view, "traffic") {
		t.Fatalf("traffic pane missing:\n%s", view)
	}
	for _, want := range []string{"left/right card", "up/down scroll/history", "ctrl+s save", "ctrl+c quit"} {
		if !strings.Contains(view, want) {
			t.Fatalf("footer hint %q missing:\n%s", want, view)
		}
	}
	for _, removed := range []string{"card cli", "tab autocomplete", "enter run"} {
		if strings.Contains(view, removed) {
			t.Fatalf("removed footer hint %q still present:\n%s", removed, view)
		}
	}
	if got := lipgloss.Height(view); got > m.height {
		t.Fatalf("view height = %d, terminal height = %d\n%s", got, m.height, view)
	}
	assertViewWidth(t, view, m.width)
	assertViewHorizontalInset(t, view, m.width)
	assertViewHeightWithin(t, view, m.height)
}

func TestAutocompleteLineUsesMutedStyle(t *testing.T) {
	line := "auto  192.0.2.10"
	styled := styleAutocompleteLine(line)
	if styled != styleMuted.Render(line) {
		t.Fatalf("autocomplete style = %q, want muted %q", styled, styleMuted.Render(line))
	}
	if got := lipgloss.Width(styled); got != lipgloss.Width(line) {
		t.Fatalf("styled width = %d, want %d", got, lipgloss.Width(line))
	}
}

func TestCLIInputDoesNotProtocolColorEAPOL(t *testing.T) {
	line := "> enable eapol drop-logoff|"
	styled := styleCLILine(line)
	if styled != styleText.Render(line) {
		t.Fatalf("cli style = %q, want normal text %q", styled, styleText.Render(line))
	}
	if got := styleTypedLine(styled); got != styled {
		t.Fatalf("cli line was re-tokenized: %q -> %q", styled, got)
	}
}

func TestEAPOLTrafficTokenColors(t *testing.T) {
	cases := []struct {
		line  string
		token string
		style lipgloss.Style
	}{
		{"EAPOL-Logoff dropped", "EAPOL-Logoff", styleWarn},
		{"EAPOL drop-logoff enable", "drop-logoff", styleWarn},
		{"EAPOL macsec-downgrade enable", "macsec-downgrade", styleWarn},
		{"EAPOL start", "start", styleSuccess},
		{"EAPOL success", "success", styleSuccess},
		{"EAPOL failure", "failure", styleError},
		{"EAP request Identity", "request", styleProtocol},
	}
	for _, tc := range cases {
		styled := styleTypedLine(tc.line)
		if !strings.Contains(styled, tc.style.Render(tc.token)) {
			t.Fatalf("styled %q = %q; missing styled token %q", tc.line, styled, tc.token)
		}
	}
}

func TestTrafficCannotExpandRenderedView(t *testing.T) {
	m := NewModel()
	m.width = 72
	m.height = 18
	m.addTraffic("host/en11 " + strings.Repeat("0123456789abcdef:", 20) + " 2001:db8::1>2001:db8::2 TCP")

	view := m.View()
	assertViewWidth(t, view, m.width)
	assertNoFullWidthLines(t, view, m.width)
	assertViewHorizontalInset(t, view, m.width)
	assertViewHeightWithin(t, view, m.height)
	if !strings.Contains(view, "traffic") {
		t.Fatalf("traffic pane missing:\n%s", view)
	}
}

func TestPanelBottomBorderStaysFixedWithTraffic(t *testing.T) {
	m := NewModel()
	m.width = 90
	m.height = 24
	empty := m.View()
	emptyBottom := lastBorderLine(empty)
	if emptyBottom < 0 {
		t.Fatalf("no bottom border in empty view:\n%s", empty)
	}

	for i := 0; i < 200; i++ {
		m.addTraffic(strings.Repeat("traffic-line-", 20))
	}
	full := m.View()
	fullBottom := lastBorderLine(full)
	if fullBottom != emptyBottom {
		t.Fatalf("bottom border moved from %d to %d\nempty:\n%s\nfull:\n%s", emptyBottom, fullBottom, empty, full)
	}
	wantBottom := renderHeight(terminalHeight(m.height)) - lipgloss.Height(m.renderFooter(renderWidth(terminalWidth(m.width)))) - 1
	if fullBottom != wantBottom {
		t.Fatalf("bottom border = %d, want %d\n%s", fullBottom, wantBottom, full)
	}
}

func TestArrowKeysMoveFocusedCardAndScroll(t *testing.T) {
	m := NewModel()
	for i := 0; i < 30; i++ {
		m.print("line")
	}
	next, _ := m.Update(tea.KeyMsg{Type: tea.KeyLeft})
	m = next.(Model)
	if m.activeCard != cardOutput {
		t.Fatalf("active card = %s", m.activeCard)
	}
	next, _ = m.Update(tea.KeyMsg{Type: tea.KeyUp})
	m = next.(Model)
	if m.outputScroll != 1 {
		t.Fatalf("output scroll = %d", m.outputScroll)
	}
	next, _ = m.Update(tea.KeyMsg{Type: tea.KeyDown})
	m = next.(Model)
	if m.outputScroll != 0 {
		t.Fatalf("output scroll = %d", m.outputScroll)
	}
}

func TestOutputWrapsBeforeClipping(t *testing.T) {
	rows := wrapLines([]string{"show adapters row with a very long hardware address and a very long address column"}, 24)
	if len(rows) < 2 {
		t.Fatalf("expected wrapped rows, got %v", rows)
	}
	for i, row := range rows {
		if got := lipgloss.Width(row); got > 24 {
			t.Fatalf("row %d width = %d: %q", i, got, row)
		}
	}

	m := NewModel()
	m.width = 60
	m.height = 16
	m.print("show adapters row with a very long hardware address and a very long address column")
	view := m.View()
	if got := lipgloss.Height(view); got > m.height {
		t.Fatalf("view height = %d, terminal height = %d\n%s", got, m.height, view)
	}
	assertViewWidth(t, view, m.width)
	assertViewHorizontalInset(t, view, m.width)
	assertViewHeightWithin(t, view, m.height)
	if strings.Contains(view, "…") {
		t.Fatalf("output was truncated instead of wrapped:\n%s", view)
	}
}

func TestCommandLevelOutputClassification(t *testing.T) {
	muted := []string{
		"> start nat",
		"bridge: start",
		"bridge state: active",
		"nat err: bridge",
		"pcap switch/en12: /tmp/switch.pcap",
		"expected: host adapter",
	}
	for _, line := range muted {
		if !isCommandLevelOutput(line) {
			t.Fatalf("expected muted command output for %q", line)
		}
	}

	plain := []string{
		"host/en11 IP=192.0.2.10 MAC=a0:ad:9f:1c:3c:a5",
		"  en11 ethernet up 1500 a0:ad:9f:1c:3c:a5 192.0.2.10",
		"ARP arp_who_has=192.0.2.1 arp_tell=192.0.2.10",
	}
	for _, line := range plain {
		if isCommandLevelOutput(line) {
			t.Fatalf("expected plain output for %q", line)
		}
	}
}

func TestCommandOutputWrapKeepsContinuationRowsMuted(t *testing.T) {
	line := "nat err: " + strings.Repeat("ifconfig bridge1 rule bad value ", 4)
	rows := wrapOutputLines([]string{line}, []bool{isCommandLevelOutput(line)}, 28)
	if len(rows) < 2 {
		t.Fatalf("expected wrapped command output, got %v", rows)
	}
	for i, row := range rows {
		if !row.muted {
			t.Fatalf("row %d was not muted: %v", i, rows)
		}
	}
}

func TestMutedCommandOutputHighlightsErrToken(t *testing.T) {
	line := "nat err: bridge"
	styled := styleOutputLine(line, true)
	if !strings.Contains(styled, "err:") {
		t.Fatalf("styled output lost err token: %q", styled)
	}
	if got := lipgloss.Width(styled); got != lipgloss.Width(line) {
		t.Fatalf("styled width = %d, want %d: %q", got, lipgloss.Width(line), styled)
	}
}

func TestAppendInputHandlesRunesAndSpace(t *testing.T) {
	value := appendInput("", tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("a")})
	value = appendInput(value, tea.KeyMsg{Type: tea.KeySpace})
	value = appendInput(value, tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("b")})
	if value != "a b" {
		t.Fatalf("value = %q", value)
	}
}

func containsOutput(output []string, want string) bool {
	for _, line := range output {
		if strings.Contains(line, want) {
			return true
		}
	}
	return false
}

func assertViewWidth(t *testing.T, view string, width int) {
	t.Helper()
	for i, line := range strings.Split(view, "\n") {
		if got := lipgloss.Width(line); got > width {
			t.Fatalf("line %d width = %d, terminal width = %d:\n%s", i, got, width, view)
		}
	}
}

func assertNoFullWidthLines(t *testing.T, view string, width int) {
	t.Helper()
	for i, line := range strings.Split(view, "\n") {
		if got := lipgloss.Width(line); got >= width {
			t.Fatalf("line %d width = %d; expected below terminal width %d to avoid autowrap:\n%s", i, got, width, view)
		}
	}
}

func assertViewHorizontalInset(t *testing.T, view string, width int) {
	t.Helper()
	margin := horizontalMargin(terminalWidth(width))
	if margin <= 0 {
		return
	}
	prefix := strings.Repeat(" ", margin)
	for i, line := range strings.Split(view, "\n") {
		if line == "" {
			continue
		}
		if !strings.HasPrefix(line, prefix) {
			t.Fatalf("line %d missing left inset %q:\n%s", i, prefix, view)
		}
		if got := lipgloss.Width(line); got > terminalWidth(width)-margin {
			t.Fatalf("line %d width = %d; expected right inset of at least %d in terminal width %d:\n%s", i, got, margin, terminalWidth(width), view)
		}
		if containsBorderRune(line) {
			wantRightEdge := terminalWidth(width) - margin
			if got := lipgloss.Width(strings.TrimRight(line, " ")); got != wantRightEdge {
				t.Fatalf("line %d visible right edge = %d, want %d:\n%s", i, got, wantRightEdge, view)
			}
		}
	}
}

func containsBorderRune(line string) bool {
	return strings.ContainsAny(line, "╭╮╰╯│")
}

func assertViewHeightWithin(t *testing.T, view string, height int) {
	t.Helper()
	if got := lipgloss.Height(view); got > height {
		t.Fatalf("view height = %d; terminal height = %d:\n%s", got, height, view)
	}
}

func lastBorderLine(view string) int {
	lines := strings.Split(view, "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		if strings.Contains(lines[i], "╰") {
			return i
		}
	}
	return -1
}

func countOutput(output []string, want string) int {
	var count int
	for _, line := range output {
		if strings.Contains(line, want) {
			count++
		}
	}
	return count
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func adaptersToConfig(name string, adapterRole string) profile.AdapterConfig {
	return profile.FromAdapter(adapterRole, adapters.Adapter{Name: name})
}
