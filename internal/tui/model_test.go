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
	t.Setenv("GOLAN_CONFIG_DIR", t.TempDir())
	m := NewModel()
	m.adapters = []adapters.Adapter{{Name: "en11"}}
	m.executeCommand("set en11 host")
	m.executeCommand("conf en11")
	m.executeCommand("set ip 192.0.2.10")
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

func TestCtrlCStopsActiveCapture(t *testing.T) {
	m := NewModel()
	m.listener = &listen.Session{}
	m.capMode = "bridge"
	next, _ := m.Update(tea.KeyMsg{Type: tea.KeyCtrlC})
	got := next.(Model)
	if got.listener != nil || got.capMode != "" {
		t.Fatalf("capture state = listener:%v mode:%q", got.listener, got.capMode)
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
	if !strings.Contains(view, "tab autocomplete") {
		t.Fatalf("footer hints missing:\n%s", view)
	}
	if got := lipgloss.Height(view); got > m.height {
		t.Fatalf("view height = %d, terminal height = %d\n%s", got, m.height, view)
	}
	assertViewWidth(t, view, m.width)
	assertViewHeightBelow(t, view, m.height)
}

func TestTrafficCannotExpandRenderedView(t *testing.T) {
	m := NewModel()
	m.width = 72
	m.height = 18
	m.addTraffic("host/en11 " + strings.Repeat("0123456789abcdef:", 20) + " 2001:db8::1>2001:db8::2 TCP")

	view := m.View()
	assertViewWidth(t, view, m.width)
	assertNoFullWidthLines(t, view, m.width)
	assertViewHeightBelow(t, view, m.height)
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
	assertViewHeightBelow(t, view, m.height)
	if strings.Contains(view, "…") {
		t.Fatalf("output was truncated instead of wrapped:\n%s", view)
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

func assertViewHeightBelow(t *testing.T, view string, height int) {
	t.Helper()
	if got := lipgloss.Height(view); got >= height {
		t.Fatalf("view height = %d; expected below terminal height %d to avoid vertical scroll:\n%s", got, height, view)
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
