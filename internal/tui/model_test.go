package tui

import (
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"golan/internal/adapters"
	bridge "golan/internal/bridge"
	"golan/internal/configs"
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
	if len(m.output) == 0 {
		t.Fatal("expected help output")
	}
	m.executeCommand("clear")
	if len(m.output) != 0 {
		t.Fatalf("output = %v", m.output)
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
	if !strings.Contains(view, "tab autocomplete") {
		t.Fatalf("footer hints missing:\n%s", view)
	}
	if got := lipgloss.Height(view); got > m.height {
		t.Fatalf("view height = %d, terminal height = %d\n%s", got, m.height, view)
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
