package tui

import (
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"golan/internal/adapters"
	bridge "golan/internal/bridge"
	"golan/internal/configs"
	"golan/internal/edge"
	"golan/internal/inspect"
	"golan/internal/listen"
	networkobs "golan/internal/network"
	"golan/internal/policy"
	"golan/internal/profile"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

func TestExecuteCommandSelectSetAndConfirm(t *testing.T) {
	m := NewModel()
	m.adapters = []adapters.Adapter{{Name: "en0", Kind: "ethernet"}}

	m.executeCommand("set adapter en0 host")
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

func TestCommandReplacesAdapterWithSameRole(t *testing.T) {
	m := NewModel()
	m.adapters = []adapters.Adapter{{Name: "en0"}, {Name: "en1"}, {Name: "en2"}}

	m.executeCommand("set adapter en0 host")
	delete(m.lockPending, "en0")
	m.executeCommand("set adapter en1 switch")
	delete(m.lockPending, "en1")
	m.executeCommand("set adapter en2 host")

	if len(m.profile.Adapters) != 2 {
		t.Fatalf("selected adapters = %d", len(m.profile.Adapters))
	}
	if _, ok := m.profile.ByName("en0"); ok {
		t.Fatalf("old host adapter was retained: %+v", m.profile.Adapters)
	}
	if cfg, ok := m.profile.ByName("en2"); !ok || cfg.AdapterRole != profile.AdapterRoleHost {
		t.Fatalf("replacement host adapter missing: %+v", m.profile.Adapters)
	}
}

func TestCommandsRejectAmbiguousArity(t *testing.T) {
	tests := []struct {
		command string
		want    string
	}{
		{command: "show adapters extra", want: "use: show adapters|config|bridge|nat|edge|project|rules|health|captures"},
		{command: "load lab extra", want: "use: load [name]"},
		{command: "load <> extra", want: "use: load [name]"},
		{command: "start listen extra", want: "use: start listen"},
		{command: "stop listen extra", want: "use: stop listen|bridge|nat|edge"},
		{command: "set adapter en11 host extra", want: "use: set adapter <name> <host|switch>"},
		{command: "unset adapter en11 extra", want: "use: unset adapter <name>"},
		{command: "cleanup now", want: "use: cleanup"},
	}
	for _, test := range tests {
		m := NewModel()
		m.adapters = []adapters.Adapter{{Name: "en11"}}
		if cmd := m.executeCommand(test.command); cmd != nil {
			t.Errorf("%q returned command", test.command)
		}
		if !containsOutput(m.output, test.want) {
			t.Errorf("%q output = %v, want %q", test.command, m.output, test.want)
		}
		if len(m.profile.Adapters) != 0 {
			t.Errorf("%q changed profile: %+v", test.command, m.profile)
		}
	}
}

func TestUpdateCLIExecutesCommand(t *testing.T) {
	m := NewModel()
	m.adapters = []adapters.Adapter{{Name: "en0"}}
	m.input = "set adapter en0 host"

	next, _ := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	got := next.(Model)
	if len(got.profile.Adapters) != 1 {
		t.Fatalf("selected adapters = %d", len(got.profile.Adapters))
	}
}

func TestFullScreenHelpSearchAndRestoresContext(t *testing.T) {
	m := NewModel()
	m.width = 100
	m.height = 32
	m.workspace = workspaceRules
	m.activeCard = cardOutput
	m.outputScroll = 7
	m.input = "draft command"

	next, _ := m.Update(tea.KeyMsg{Type: tea.KeyF1})
	m = next.(Model)
	if !m.help.open || !strings.Contains(m.View(), "HELP") {
		t.Fatal("F1 did not open full-screen help")
	}
	for _, key := range []tea.KeyMsg{{Type: tea.KeyRunes, Runes: []rune{'/'}}, {Type: tea.KeyRunes, Runes: []rune{'T'}}, {Type: tea.KeyRunes, Runes: []rune{'L'}}, {Type: tea.KeyRunes, Runes: []rune{'S'}}} {
		next, _ = m.Update(key)
		m = next.(Model)
	}
	if m.help.query != "TLS" || len(m.help.matches) == 0 {
		t.Fatalf("help search query=%q matches=%v", m.help.query, m.help.matches)
	}
	next, _ = m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = next.(Model)
	next, _ = m.Update(tea.KeyMsg{Type: tea.KeyF1})
	m = next.(Model)
	if m.help.open {
		t.Fatal("F1 did not close help")
	}
	if m.workspace != workspaceRules || m.activeCard != cardOutput ||
		m.outputScroll != 7 || m.input != "draft command" {
		t.Fatalf(
			"context was not restored: workspace=%s card=%v output=%d input=%q",
			m.workspace, m.activeCard, m.outputScroll, m.input,
		)
	}
}

func TestGuidedRuleEditorCommitsTypedRevision(t *testing.T) {
	m := NewModel()
	m.workspace = workspaceRules
	m.activeCard = cardOutput
	next, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'r'}})
	m = next.(Model)
	if !m.ruleEditor.open || !strings.Contains(m.View(), "GUIDED RULE EDITOR") || !strings.Contains(m.View(), "0 frames available") {
		t.Fatalf("guided editor did not open:\n%s", m.View())
	}
	next, _ = m.Update(tea.KeyMsg{Type: tea.KeyCtrlS})
	m = next.(Model)
	active, ok := m.policyStore.Active()
	if !ok || m.ruleEditor.open || len(active.Rules()) != 1 {
		t.Fatalf("active=%v editor=%v rules=%#v", ok, m.ruleEditor.open, active.Rules())
	}
	rule := active.Rules()[0]
	if rule.ID != "rule-1" || len(rule.Match.Directions) != 1 || len(rule.Match.DstPorts.Values) != 2 || string(rule.Actions[0].Kind) != "block" {
		t.Fatalf("committed rule = %#v", rule)
	}
}

func TestMatchReplaceEditorRetainsActiveRevisionOnInvalidDraft(t *testing.T) {
	m := NewModel()
	m.workspace = workspaceRules
	m.activeCard = cardOutput
	if err := m.policyStore.Activate("baseline", nil); err != nil {
		t.Fatal(err)
	}
	next, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'M'}})
	m = next.(Model)
	if !m.ruleEditor.open || !m.ruleEditor.replace || !strings.Contains(m.View(), "MATCH AND REPLACE") {
		t.Fatal("match-and-replace editor did not open")
	}
	next, _ = m.Update(tea.KeyMsg{Type: tea.KeyCtrlS})
	m = next.(Model)
	active, ok := m.policyStore.Active()
	if !ok || active.Revision() != "baseline" || !m.ruleEditor.open || !strings.Contains(m.ruleEditor.diagnostic, "requires a search value") {
		t.Fatalf("active=%v revision=%q editor=%v diagnostic=%q", ok, active.Revision(), m.ruleEditor.open, m.ruleEditor.diagnostic)
	}
}

func TestWindowResizeUpdatesResponsiveDimensions(t *testing.T) {
	for _, size := range []tea.WindowSizeMsg{
		{Width: 72, Height: 24},
		{Width: 200, Height: 60},
	} {
		m := NewModel()
		next, _ := m.Update(tea.WindowSizeMsg{Width: 140, Height: 50})
		m = next.(Model)
		next, _ = m.Update(size)
		m = next.(Model)
		if m.width != size.Width || m.height != size.Height {
			t.Fatalf("dimensions = %dx%d, want %dx%d", m.width, m.height, size.Width, size.Height)
		}
	}
}

func TestEdgeSettingsStageWithoutStartingNetworking(t *testing.T) {
	m := NewModel()
	m.adapters = []adapters.Adapter{{Name: "en0"}, {Name: "en7"}}
	m.executeCommand("set edge mode route")
	m.executeCommand("set edge upstream en0")
	m.executeCommand("set edge port-forward tcp 8443 443")
	if m.edgeConfiguredMode != "route" || m.edgeUpstream != "en0" || m.edgeSession != nil || len(m.edgeForwards) != 1 {
		t.Fatalf("edge mode=%q upstream=%q session=%v", m.edgeConfiguredMode, m.edgeUpstream, m.edgeSession)
	}
	if !containsOutput(m.output, "applies to next session") {
		t.Fatalf("output = %v", m.output)
	}
	m.executeCommand("show edge")
	if !containsOutput(m.output, "next mode=route upstream=en0") {
		t.Fatalf("staged route settings are not visible: %v", m.output)
	}
}

func TestCleanupResetsStagedNetworkingWithoutDeletingPersistentState(t *testing.T) {
	m := NewModel()
	m.offline = true
	m.profile.Adapters = []profile.AdapterConfig{adaptersToConfig("en11", profile.AdapterRoleHost)}
	m.profile.Bridge.Config.Label = "staged bridge"
	m.activeAdapter = "en11"
	m.edgeConfiguredMode = string(edge.ModeRoute)
	m.edgeUpstream = "en0"
	m.edgeForwards = []edgeForwardSetting{{Protocol: "tcp", ListenPort: 8443, TargetPort: 443}}
	m.bridgeControlledOptions.QueueDepth = 2048
	m.eapolSuppressLogoff = false
	m.eapolDowngradeMACsec = false
	project := m.project
	policyStore := m.policyStore

	cmd := m.executeCommand("cleanup")
	if cmd == nil || m.runtimeOperation != "cleanup" {
		t.Fatalf("cleanup command=%v operation=%q", cmd != nil, m.runtimeOperation)
	}
	next, _ := m.Update(cmd())
	got := next.(Model)
	defaults := bridge.DefaultEAPOLPolicy()
	if len(got.profile.Adapters) != 0 || got.profile.Bridge.Config.Label != "" || got.activeAdapter != "" ||
		got.edgeConfiguredMode != string(edge.ModeObserve) || got.edgeUpstream != "auto" || len(got.edgeForwards) != 0 ||
		got.bridgeControlledOptions != bridge.DefaultControlledOptions() ||
		got.eapolSuppressLogoff != defaults.SuppressLogoff || got.eapolDowngradeMACsec != defaults.DowngradeMACsec {
		t.Fatalf("cleanup retained staged state: profile=%#v edge=%s/%s forwards=%#v bridge=%#v eapol=%t/%t",
			got.profile, got.edgeConfiguredMode, got.edgeUpstream, got.edgeForwards, got.bridgeControlledOptions,
			got.eapolSuppressLogoff, got.eapolDowngradeMACsec)
	}
	if got.project != project || got.policyStore != policyStore || !containsOutput(got.output, "cleanup [PASS]") {
		t.Fatalf("persistent state changed or completion missing: project=%p policy=%p output=%v", got.project, got.policyStore, got.output)
	}
}

func TestCleanupRestoresAdapterSnapshotsInStableOrder(t *testing.T) {
	states := map[string]bridge.InterfaceRestoreState{
		"en12": {IfName: "en12", ServiceStateKnown: true, ServiceEnabled: false, InterfaceStateKnown: true, InterfaceUp: false},
		"en11": {IfName: "en11", ServiceStateKnown: true, ServiceEnabled: true, InterfaceStateKnown: true, InterfaceUp: true},
	}
	var restored []bridge.InterfaceRestoreState
	cmd := cleanupOwnedStateCmdWith(
		nil,
		nil,
		nil,
		nil,
		states,
		func(string, string) error { return nil },
		func(state bridge.InterfaceRestoreState) error {
			restored = append(restored, state)
			return nil
		},
	)
	msg := cmd().(cleanupMsg)
	if len(restored) != 2 || restored[0] != states["en11"] || restored[1] != states["en12"] || msg.restorationIncomplete() {
		t.Fatalf("restored=%#v msg=%#v", restored, msg)
	}
}

func TestCleanupRetainsFailedAdapterRestorationForRetry(t *testing.T) {
	state := bridge.InterfaceRestoreState{IfName: "en11", ServiceStateKnown: true, ServiceEnabled: true, InterfaceStateKnown: true, InterfaceUp: true}
	m := NewModel()
	m.offline = true
	m.profile.Adapters = []profile.AdapterConfig{adaptersToConfig("en11", profile.AdapterRoleHost)}
	m.restoreState["en11"] = state
	m.beginRuntimeOperation("cleanup")
	cmd := cleanupOwnedStateCmdWith(
		nil,
		nil,
		nil,
		nil,
		m.restoreState,
		func(string, string) error { return nil },
		func(bridge.InterfaceRestoreState) error { return errors.New("adapter busy") },
	)
	next, _ := m.Update(cmd())
	got := next.(Model)
	if _, ok := got.restoreState["en11"]; !ok || !got.lockFailed["en11"] || len(got.profile.Adapters) != 0 ||
		!containsOutput(got.output, "cleanup [WARN]") || got.runtimeOperation != "" {
		t.Fatalf("failed cleanup was not retryable: restore=%#v failed=%#v profile=%#v operation=%q output=%v",
			got.restoreState, got.lockFailed, got.profile, got.runtimeOperation, got.output)
	}
	got.showHealth()
	if !containsOutput(got.output, "restoration snapshots=1 isolate-pending=0 restore-pending=0 failed=1") {
		t.Fatalf("health did not expose retry state: %v", got.output)
	}
}

func TestCleanupDoesNotRestoreAdaptersBeforeRuntimeCleanupFinishes(t *testing.T) {
	state := bridge.InterfaceRestoreState{IfName: "en11", InterfaceStateKnown: true, InterfaceUp: true}
	m := NewModel()
	m.offline = true
	m.profile.Adapters = []profile.AdapterConfig{adaptersToConfig("en11", profile.AdapterRoleHost)}
	m.restoreState["en11"] = state
	m.beginRuntimeOperation("cleanup")
	next, _ := m.Update(cleanupMsg{edgeCleanupPending: true})
	got := next.(Model)
	if _, ok := got.restoreState["en11"]; !ok || len(got.profile.Adapters) != 1 ||
		!containsOutput(got.output, "cleanup [WARN]") || got.runtimeOperation != "" {
		t.Fatalf("pending runtime cleanup exposed adapter restoration: restore=%#v profile=%#v operation=%q output=%v",
			got.restoreState, got.profile, got.runtimeOperation, got.output)
	}
}

func TestCleanupStopsCurrentEdgeSessionBeforeReset(t *testing.T) {
	m := NewModel()
	m.offline = true
	m.edgeSession = &edge.Session{}
	m.edgeMode = string(edge.ModeRoute)
	m.edgeConfiguredMode = string(edge.ModeRoute)
	cmd := m.executeCommand("cleanup")
	if cmd == nil {
		t.Fatal("cleanup did not schedule edge teardown")
	}
	next, _ := m.Update(cmd())
	got := next.(Model)
	if got.edgeSession != nil || got.edgeMode != "" || got.edgeConfiguredMode != string(edge.ModeObserve) ||
		!containsOutput(got.output, "cleanup [PASS]") {
		t.Fatalf("edge cleanup did not finish: session=%v active=%q configured=%q output=%v",
			got.edgeSession, got.edgeMode, got.edgeConfiguredMode, got.output)
	}
}

func TestCleanupBlocksRuntimePolicyMutation(t *testing.T) {
	m := NewModel()
	m.beginRuntimeOperation(cleanupOperation)
	if cmd := m.executeCommand("policy use open-internet"); cmd != nil {
		t.Fatal("policy mutation scheduled work during cleanup")
	}
	if _, ok := m.policyStore.Active(); ok || !containsOutput(m.output, "policy err: operation pending: cleanup") {
		t.Fatalf("policy mutation was not blocked: output=%v", m.output)
	}
}

func TestEdgePortForwardInventoryAndTargetedRemoval(t *testing.T) {
	m := NewModel()
	m.executeCommand("set edge port-forward tcp 8443 443")
	m.executeCommand("set edge port-forward udp 5353 53")
	m.executeCommand("set edge port-forward list")
	for _, want := range []string{"edge port-forwards: 2", "tcp/8443 -> client:443", "udp/5353 -> client:53"} {
		if !containsOutput(m.output, want) {
			t.Fatalf("missing %q in output %v", want, m.output)
		}
	}

	m.executeCommand("set edge port-forward remove tcp 8443")
	if len(m.edgeForwards) != 1 || m.edgeForwards[0].Protocol != "udp" || m.edgeForwards[0].ListenPort != 5353 {
		t.Fatalf("targeted removal retained %#v", m.edgeForwards)
	}
	before := append([]edgeForwardSetting(nil), m.edgeForwards...)
	for _, command := range []string{
		"set edge port-forward remove udp 0",
		"set edge port-forward remove icmp 5353",
		"set edge port-forward remove tcp 8443",
	} {
		m.executeCommand(command)
		if !reflect.DeepEqual(m.edgeForwards, before) {
			t.Fatalf("invalid removal %q mutated forwards: %#v", command, m.edgeForwards)
		}
	}
	if got := m.completionCandidates("set edge port-forward "); !containsString(got, "list") || !containsString(got, "remove") {
		t.Fatalf("port-forward operation completions=%v", got)
	}
	if got := m.completionCandidates("set edge port-forward remove "); !reflect.DeepEqual(got, []string{"tcp", "udp"}) {
		t.Fatalf("remove protocol completions=%v", got)
	}
	if got := m.completionCandidates("set edge port-forward remove udp "); !reflect.DeepEqual(got, []string{"5353"}) {
		t.Fatalf("remove port completions=%v", got)
	}
}

func TestControlledBridgeSettingsStageValidateCompleteAndReachStarter(t *testing.T) {
	m := NewModel()
	if m.bridgeControlledOptions != bridge.DefaultControlledOptions() {
		t.Fatalf("defaults=%#v", m.bridgeControlledOptions)
	}
	m.executeCommand("set bridge queue-depth 2048")
	m.executeCommand("set bridge overload fail-closed")
	want := bridge.DefaultControlledOptions()
	want.QueueDepth = 2048
	want.Overload = bridge.OverloadFailClosed
	if m.bridgeControlledOptions != want || !containsOutput(m.output, "applies to next controlled session") {
		t.Fatalf("staged=%#v output=%v", m.bridgeControlledOptions, m.output)
	}
	for _, command := range []string{
		"set bridge queue-depth 0",
		"set bridge queue-depth 4097",
		"set bridge overload direct",
	} {
		m.executeCommand(command)
		if m.bridgeControlledOptions != want {
			t.Fatalf("invalid command %q mutated options: %#v", command, m.bridgeControlledOptions)
		}
	}
	m.executeCommand("show bridge")
	if !containsOutput(m.output, "controlled next queue-depth=2048 overload=fail-closed") {
		t.Fatalf("staged controlled settings are not visible: %v", m.output)
	}
	settings := m.setCompletions([]string{"set", "bridge"}, true)
	for _, candidate := range []string{"queue-depth", "overload"} {
		if !containsString(settings, candidate) {
			t.Fatalf("controlled setting completions missing %q: %v", candidate, settings)
		}
	}
	if got := m.setCompletions([]string{"set", "bridge", "overload"}, true); !reflect.DeepEqual(got, []string{"fail-closed", "fail-open"}) {
		t.Fatalf("overload completions=%v", got)
	}

	host := profile.AdapterConfig{Name: "en11", HardwarePort: "Host LAN", NetworkService: "Renamed Host", CurrentMAC: "02:00:00:00:00:11"}
	sw := profile.AdapterConfig{Name: "en12", HardwarePort: "Switch LAN", NetworkService: "Renamed Switch", CurrentMAC: "02:00:00:00:00:12"}
	var received bridge.ControlledOptions
	var receivedHost, receivedSwitch bridge.Adapter
	cmd := startBridgeCmdWithStart(host, sw, bridge.DefaultEAPOLPolicy(), bridge.ModeControlled, "revision", nil, want,
		func(hostAdapter bridge.Adapter, switchAdapter bridge.Adapter, _ string, mode bridge.Mode, _ bridge.EAPOLPolicy, _ string, _ []policy.Rule, options bridge.ControlledOptions) (*bridge.Session, error) {
			received = options
			receivedHost, receivedSwitch = hostAdapter, switchAdapter
			return &bridge.Session{Mode: mode}, nil
		})
	message := cmd().(bridgeStartedMsg)
	if message.err != nil || message.mode != bridge.ModeControlled || received != want || receivedHost.NetworkService != "Renamed Host" || receivedSwitch.NetworkService != "Renamed Switch" {
		t.Fatalf("message=%#v received=%#v host=%#v switch=%#v", message, received, receivedHost, receivedSwitch)
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
		t.Fatalf("output=%v", m.output)
	}
}

func TestShowAdaptersKeepsPartialDiscoveryResults(t *testing.T) {
	m := NewModel()
	m.loading = false
	m.err = errors.New("hardware enrichment unavailable")
	m.adapters = []adapters.Adapter{{Name: "en11", Kind: "ethernet"}}

	m.showAdapters()
	for _, want := range []string{"adapters warn: hardware enrichment unavailable", "en11"} {
		if !containsOutput(m.output, want) {
			t.Fatalf("missing %q in output %v", want, m.output)
		}
	}
}

func TestSetAdapterStagesRoleWithoutContext(t *testing.T) {
	m := NewModel()
	m.adapters = []adapters.Adapter{{Name: "en11"}}

	m.executeCommand("set adapter en11 host")
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
	m.executeCommand("set adapter en11 host")
	delete(m.lockPending, "en11")
	m.executeCommand("conf en11")

	cmd := m.executeCommand("up")
	if cmd == nil {
		t.Fatal("expected adapter state command")
	}
	if !containsOutput(m.output, "adapter state: en11 -> up") {
		t.Fatalf("output = %v", m.output)
	}
}

func TestActiveAdapterStateIsBlockedDuringSession(t *testing.T) {
	m := NewModel()
	m.activeAdapter = "en11"
	m.profile.Adapters = []profile.AdapterConfig{adaptersToConfig("en11", profile.AdapterRoleHost)}
	m.listener = &listen.Session{}

	if cmd := m.executeCommand("up"); cmd != nil {
		t.Fatal("adapter state command ran during listener session")
	}
	if !containsOutput(m.output, "adapter state err: listen active") {
		t.Fatalf("output = %v", m.output)
	}
}

func TestAdapterStagingWaitsForIsolation(t *testing.T) {
	m := NewModel()
	m.adapters = []adapters.Adapter{{Name: "en11"}, {Name: "en12"}}
	m.markLockPending("en11")

	if cmd := m.stageAdapter("en12", profile.AdapterRoleSwitch); cmd != nil {
		t.Fatal("second staging command ran during adapter isolation")
	}
	if !containsOutput(m.output, "adapter err: isolate pending en11") {
		t.Fatalf("output = %v", m.output)
	}
}

func TestPendingIsolationBlocksUnsetAndStateMutation(t *testing.T) {
	m := NewModel()
	m.activeAdapter = "en11"
	m.profile.Adapters = []profile.AdapterConfig{adaptersToConfig("en11", profile.AdapterRoleHost)}
	m.markLockPending("en11")

	if cmd := m.executeCommand("unset adapter en11"); cmd != nil {
		t.Fatal("unset ran while isolation was pending")
	}
	if cmd := m.executeCommand("up"); cmd != nil {
		t.Fatal("adapter state mutation ran while isolation was pending")
	}
	if _, ok := m.profile.ByName("en11"); !ok {
		t.Fatal("pending adapter was removed")
	}
	for _, want := range []string{"adapter err: isolate pending en11", "adapter state err: isolate pending en11"} {
		if !containsOutput(m.output, want) {
			t.Fatalf("missing %q in output %v", want, m.output)
		}
	}
}

func TestFailedAdapterIsolationCanBeRetried(t *testing.T) {
	m := NewModel()
	m.adapters = []adapters.Adapter{{Name: "en11"}}
	m.profile.Adapters = []profile.AdapterConfig{adaptersToConfig("en11", profile.AdapterRoleHost)}
	m.lockFailed["en11"] = true

	if cmd := m.stageAdapter("en11", profile.AdapterRoleHost); cmd == nil {
		t.Fatal("failed adapter isolation could not be retried")
	}
	if !m.lockPending["en11"] || m.lockFailed["en11"] {
		t.Fatalf("lock state pending=%v failed=%v", m.lockPending, m.lockFailed)
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
	m.input = "set adapter en11 "
	m.refreshCompletions()
	m.applyCompletion()
	if m.input != "set adapter en11 host" {
		t.Fatalf("input = %q", m.input)
	}
	if !containsString(m.completions, "host") || !containsString(m.completions, "switch") {
		t.Fatalf("completions = %v", m.completions)
	}
	m.applyCompletion()
	if m.input != "set adapter en11 switch" {
		t.Fatalf("cycled input = %q", m.input)
	}
}

func TestUnsetDeselectsActiveAdapter(t *testing.T) {
	m := NewModel()
	m.adapters = []adapters.Adapter{{Name: "en11"}}
	m.executeCommand("set adapter en11 host")
	delete(m.lockPending, "en11")
	m.executeCommand("conf en11")
	m.executeCommand("unset adapter en11")
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
	m.executeCommand("set adapter en11 host")
	m.executeCommand("conf en11")
	m.executeCommand("set ip 192.0.2.10")
	m.eapolSuppressLogoff = false
	m.eapolDowngradeMACsec = true
	m.saveConfig("lab")

	loaded := NewModel()
	loaded.adapters = []adapters.Adapter{{Name: "en11"}}
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
	if loaded.eapolSuppressLogoff || !loaded.eapolDowngradeMACsec {
		t.Fatalf("loaded settings logoff=%v downgrade=%v", loaded.eapolSuppressLogoff, loaded.eapolDowngradeMACsec)
	}
}

func TestLoadRejectsAdapterMissingFromInventory(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("GOLAN_CONFIG_DIR", dir)
	m := NewModel()
	m.adapters = []adapters.Adapter{{Name: "en11"}}
	m.executeCommand("set adapter en11 host")
	m.saveConfig("lab")

	loaded := NewModel()
	loaded.adapters = []adapters.Adapter{{Name: "en12"}}
	if cmd := loaded.executeCommand("load lab"); cmd != nil {
		t.Fatal("unexpected lockdown command for invalid config")
	}
	if !containsOutput(loaded.output, "load err: profile adapter \"en11\" is not present") {
		t.Fatalf("output = %v", loaded.output)
	}
	if len(loaded.profile.Adapters) != 0 {
		t.Fatalf("profile changed: %+v", loaded.profile)
	}
}

func TestFailedAdapterIsolationBlocksBridgeStart(t *testing.T) {
	m := NewModel()
	m.profile.Adapters = []profile.AdapterConfig{
		adaptersToConfig("en11", profile.AdapterRoleHost),
		adaptersToConfig("en12", profile.AdapterRoleSwitch),
	}
	m.markLockPending("en11")

	next, _ := m.Update(adapterLockdownMsg{
		name:  "en11",
		role:  profile.AdapterRoleHost,
		state: bridge.InterfaceRestoreState{IfName: "en11", InterfaceStateKnown: true, InterfaceUp: true},
		err:   errors.New("permission denied"),
	})
	got := next.(Model)
	if !got.lockFailed["en11"] || got.lockPending["en11"] {
		t.Fatal("failed isolation was not retained as a startup gate")
	}
	if cmd := got.executeCommand("start bridge fast"); cmd != nil {
		t.Fatal("bridge start proceeded after failed isolation")
	}
	if !containsOutput(got.output, "bridge err: adapter isolate pending en11") {
		t.Fatalf("output = %v", got.output)
	}
}

func TestFailedAdapterRestoreRemainsRetryable(t *testing.T) {
	state := bridge.InterfaceRestoreState{IfName: "en11", InterfaceStateKnown: true, InterfaceUp: true}
	m := NewModel()
	m.restoreState["en11"] = state
	m.restorePending["en11"] = true

	next, _ := m.Update(adapterRestoreMsg{name: "en11", state: state, err: errors.New("busy")})
	got := next.(Model)
	if _, ok := got.restoreState["en11"]; !ok || got.restorePending["en11"] {
		t.Fatalf("restore state = %+v pending=%v", got.restoreState, got.restorePending)
	}
	if cmd := got.executeCommand("unset adapter en11"); cmd == nil {
		t.Fatal("failed restoration was not retryable")
	}
}

func TestSuccessfulAdapterRestoreClearsMatchingState(t *testing.T) {
	state := bridge.InterfaceRestoreState{IfName: "en11", InterfaceStateKnown: true}
	m := NewModel()
	m.restoreState["en11"] = state
	m.restorePending["en11"] = true

	next, _ := m.Update(adapterRestoreMsg{name: "en11", state: state})
	got := next.(Model)
	if _, ok := got.restoreState["en11"]; ok || got.restorePending["en11"] {
		t.Fatalf("restore state = %+v pending=%v", got.restoreState, got.restorePending)
	}
}

func TestRemovedCommandsAreNotSuggested(t *testing.T) {
	commands := topLevelCommands()
	for _, removed := range []string{"?", "cls", "config", "configure", "exit", "reset", "confirm", "save", "listen", "bridge", "repeater", "intercept", "logger", "flow", "findings"} {
		if containsString(commands, removed) {
			t.Fatalf("removed command %q was suggested: %v", removed, commands)
		}
	}
	m := NewModel()
	m.adapters = []adapters.Adapter{{Name: "en11"}}
	if got := m.completionCandidates("bridge "); len(got) != 0 {
		t.Fatalf("removed bridge command still completes: %v", got)
	}
	if got := m.completionCandidates("set "); containsString(got, "en11") {
		t.Fatalf("adapter shorthand still completes: %v", got)
	}
}

func TestCLIRejectsRetiredAliases(t *testing.T) {
	tests := []struct {
		command string
		want    string
	}{
		{command: "?", want: "unknown: ?"},
		{command: "cls", want: "unknown: cls"},
		{command: "config", want: "unknown: config"},
		{command: "configure", want: "unknown: configure"},
		{command: "exit", want: "unknown: exit"},
		{command: "show adapter", want: "use: show adapters|config|bridge|nat|edge|project|rules|health|captures"},
		{command: "show conf", want: "use: show adapters|config|bridge|nat|edge|project|rules|health|captures"},
		{command: "show policy", want: "use: show adapters|config|bridge|nat|edge|project|rules|health|captures"},
		{command: "show status", want: "use: show adapters|config|bridge|nat|edge|project|rules|health|captures"},
		{command: "show capture", want: "use: show adapters|config|bridge|nat|edge|project|rules|health|captures"},
		{command: "set en11 host", want: "ctx: none; use: conf <adapter>"},
		{command: "set adapter en11", want: "use: set adapter <name> <host|switch>"},
		{command: "set adapter en11 1", want: "role err: host|switch"},
		{command: "unset", want: "use: unset adapter <name>"},
		{command: "start bridge", want: "use: start bridge <fast|controlled>"},
		{command: "start edge", want: "use: start edge <observe|route>"},
		{command: "network filter risk", want: "use: network show"},
		{command: "network filter action", want: "use: network show"},
		{command: "canvas rebuild", want: "use: canvas build"},
		{command: "canvas export destination.canvas", want: "use: canvas build"},
	}

	for _, test := range tests {
		m := NewModel()
		m.adapters = []adapters.Adapter{{Name: "en11"}}
		if cmd := m.executeCommand(test.command); cmd != nil {
			t.Errorf("%q returned a command", test.command)
		}
		if !containsOutput(m.output, test.want) {
			t.Errorf("%q output=%v, want %q", test.command, m.output, test.want)
		}
		if len(m.profile.Adapters) != 0 || m.bridge != nil || m.edgeSession != nil {
			t.Errorf("%q changed runtime state: profile=%+v bridge=%v edge=%v", test.command, m.profile, m.bridge, m.edgeSession)
		}
	}
}

func TestPolicyPresetAutocompleteMatchesBuiltins(t *testing.T) {
	m := NewModel()
	want := []string{"block-internet", "controlled-bridge", "high-latency", "observe-everything", "open-internet", "packet-loss", "web-only"}
	if got := m.completionCandidates("policy use "); !reflect.DeepEqual(got, want) {
		t.Fatalf("policy preset completions=%v, want %v", got, want)
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
			!containsOutput(m.output, "use: disable rule <id>|eapol drop-logoff|eapol macsec-downgrade") {
			t.Fatalf("%q did not print strict usage: %v", command, m.output)
		}
	}
}

func TestShowConfigPrintsSettings(t *testing.T) {
	m := NewModel()
	m.eapolSuppressLogoff = false
	m.eapolDowngradeMACsec = true

	m.executeCommand("show config")
	for _, want := range []string{
		"settings:",
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
		Kind:      "discovery",
		Adapter:   "en11",
		Role:      profile.AdapterRoleHost,
		Field:     "ip",
		Value:     "192.0.2.10",
		Evidence:  "ipv4 source",
		Packet:    "IPv4",
		DeviceMAC: "02:00:00:00:00:11",
	})
	cfg, _ := m.profile.ByName("en11")
	if cfg.IP != "192.0.2.10" {
		t.Fatalf("IP = %q", cfg.IP)
	}

	m.applyDiscovery(listen.Event{
		Kind:      "discovery",
		Adapter:   "en11",
		Role:      profile.AdapterRoleHost,
		Field:     "ip",
		Value:     "192.0.2.11",
		Evidence:  "arp sender ip",
		Packet:    "ARP",
		DeviceMAC: "02:00:00:00:00:11",
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
	if len(m.output) != 0 || len(m.networkDevices()) != 1 || len(m.networkDevices()[0].IPs) != 2 {
		t.Fatalf("discovery should update Network without Main output: output=%v devices=%#v", m.output, m.networkDevices())
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

func TestRoutineTrafficEventsDoNotCreateUIHistory(t *testing.T) {
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
}

func TestCategoricalRiskGoesToNetworkWithoutMainOutput(t *testing.T) {
	m := NewModel()
	signal := inspect.Signal{
		Protocol: "HTTP", Kind: "Basic authentication", DeviceMAC: "02:00:00:00:00:11",
	}
	m.handleListenEvent(listen.Event{
		Kind:    listen.KindSignal,
		Adapter: "en11",
		Role:    profile.AdapterRoleHost,
		Message: signal.Encode(),
	})
	if len(m.output) != 0 {
		t.Fatalf("risk leaked into Main output: %v", m.output)
	}
	devices := m.networkDevices()
	if len(devices) != 1 || !deviceHasCategory(devices[0], networkobs.CategoryRisk) {
		t.Fatalf("network devices = %#v", devices)
	}
}

func TestSensitiveDetectionDoesNotMutateLiveCanvas(t *testing.T) {
	m := NewModel()
	signal := inspect.Signal{
		Protocol:  "HTTP",
		Kind:      "Basic authentication",
		DeviceMAC: "02:00:00:00:00:11",
		Src:       "192.168.1.10",
		Dst:       "192.168.1.20",
	}

	m.handleListenEvent(listen.Event{
		Kind:    listen.KindSignal,
		Adapter: "en11",
		Role:    profile.AdapterRoleHost,
		Message: signal.Encode(),
	})

	if len(m.canvasMap.Hosts) != 0 {
		t.Fatalf("live signal mutated Network-derived canvas: %+v", m.canvasMap.Hosts)
	}
}

func TestSeededWindowSizeStillTracksTerminalResize(t *testing.T) {
	m := NewModelWithSize(90, 26)
	next, _ := m.Update(tea.WindowSizeMsg{Width: 200, Height: 80})
	m = next.(Model)

	if m.width != 200 || m.height != 80 {
		t.Fatalf("size = %dx%d, want 200x80", m.width, m.height)
	}
}

func TestEAPOLDiscoveryIsAggregatedInNetworkWithoutMainOutput(t *testing.T) {
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
		Kind:      "discovery",
		Adapter:   "en11",
		Role:      profile.AdapterRoleHost,
		Field:     "eapol",
		Value:     "Start",
		Evidence:  "type",
		Packet:    "EAPOL / 802.1X",
		DeviceMAC: "02:00:00:00:00:11",
	})
	m.applyDiscovery(listen.Event{
		Kind:      "discovery",
		Adapter:   "en11",
		Role:      profile.AdapterRoleHost,
		Field:     "eapol",
		Value:     "Start",
		Evidence:  "type",
		Packet:    "EAPOL / 802.1X",
		DeviceMAC: "02:00:00:00:00:11",
	})
	m.applyDiscovery(listen.Event{
		Kind:      "discovery",
		Adapter:   "en11",
		Role:      profile.AdapterRoleHost,
		Field:     "eap_code",
		Value:     "success",
		Evidence:  "code",
		Packet:    "EAPOL / 802.1X",
		DeviceMAC: "02:00:00:00:00:11",
	})

	devices := m.networkDevices()
	if len(m.output) != 0 || len(devices) != 1 || !deviceHasCategory(devices[0], networkobs.CategoryAccess) {
		t.Fatalf("output=%v devices=%#v", m.output, devices)
	}
	var startCount uint64
	for _, observation := range devices[0].Observations {
		if observation.Kind == "eapol" && strings.Contains(observation.Summary, "Start") {
			startCount = observation.Count
		}
	}
	if startCount != 2 {
		t.Fatalf("EAPOL start count=%d observations=%#v", startCount, devices[0].Observations)
	}
}

func TestMACsecDiscoveryIsAggregatedInNetwork(t *testing.T) {
	m := NewModel()
	m.applyDiscovery(listen.Event{
		Kind:      "discovery",
		Adapter:   "en12",
		Role:      profile.AdapterRoleSwitch,
		Field:     "macsec",
		Value:     "0x88e5",
		Evidence:  "ether type",
		Packet:    "MACsec",
		DeviceMAC: "02:00:00:00:00:12",
	})

	m.applyDiscovery(listen.Event{
		Kind:      "discovery",
		Adapter:   "en12",
		Role:      profile.AdapterRoleSwitch,
		Field:     "eapol_type",
		Value:     "5",
		Evidence:  "type number",
		Packet:    "EAPOL / 802.1X",
		DeviceMAC: "02:00:00:00:00:12",
	})
	devices := m.networkDevices()
	if len(m.output) != 0 || len(devices) != 1 || !deviceHasCategory(devices[0], networkobs.CategoryAccess) ||
		!containsString(devices[0].Protocols, "MACSEC") || !containsString(devices[0].Protocols, "EAPOL") {
		t.Fatalf("output=%v devices=%#v", m.output, devices)
	}
}

func TestBridgeStartRequiresHostAndSwitch(t *testing.T) {
	m := NewModel()
	cmd := m.executeCommand("start bridge fast")
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
	cmd := m.executeCommand("start bridge fast")
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

func TestBridgeStartCannotOverlapPendingStart(t *testing.T) {
	m := NewModel()
	m.profile.Adapters = append(m.profile.Adapters,
		adaptersToConfig("en11", profile.AdapterRoleHost),
		adaptersToConfig("en12", profile.AdapterRoleSwitch),
	)

	if cmd := m.executeCommand("start bridge fast"); cmd == nil {
		t.Fatal("first bridge start command is nil")
	}
	if cmd := m.executeCommand("start bridge fast"); cmd != nil {
		t.Fatal("second bridge start overlapped the first")
	}
	if !containsOutput(m.output, "bridge err: operation pending: bridge start") {
		t.Fatalf("output = %v", m.output)
	}
}

func TestBridgeStartAllowsAutoHostMAC(t *testing.T) {
	m := NewModel()
	m.profile.Adapters = append(m.profile.Adapters,
		adaptersToConfig("en11", profile.AdapterRoleHost),
		adaptersToConfig("en12", profile.AdapterRoleSwitch),
	)

	cmd := m.executeCommand("start bridge fast")
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

	cmd := m.executeCommand("start bridge fast")
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
	cmd := m.executeCommand("start bridge fast")
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

func TestConfigMutationAndRefreshRefuseActiveBridge(t *testing.T) {
	m := NewModel()
	m.bridge = &bridge.Session{}
	m.activeAdapter = "bridge"

	if cmd := m.executeCommand("set ip 192.0.2.10"); cmd != nil {
		t.Fatal("config mutation ran during bridge session")
	}
	if cmd := m.executeCommand("refresh"); cmd != nil {
		t.Fatal("adapter refresh ran during bridge session")
	}
	for _, want := range []string{"set err: bridge active", "refresh err: bridge active"} {
		if !containsOutput(m.output, want) {
			t.Fatalf("missing %q in output %v", want, m.output)
		}
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

func TestBridgeStoppedEventKeepsSessionForCleanupRetry(t *testing.T) {
	session := &bridge.Session{}
	m := NewModel()
	m.bridge = session

	cmd := m.handleBridgeEvent(session, bridge.Event{Kind: bridge.KindStopped, State: "cleanup-pending", Err: errors.New("restore failed")})
	if cmd != nil {
		t.Fatal("stopped bridge scheduled another event wait")
	}
	if m.bridge != session || m.bridgeState != "cleanup-pending" {
		t.Fatalf("bridge state = session:%p state:%q", m.bridge, m.bridgeState)
	}
	if !containsOutput(m.output, "bridge: cleanup pending; use: stop bridge") {
		t.Fatalf("output = %v", m.output)
	}
}

func TestListenStoppedEventReportsFinalizationError(t *testing.T) {
	m := NewModel()
	m.capMode = "listen"
	m.handleListenEvent(listen.Event{Kind: listen.KindStopped, Adapter: "en11", Role: "host", Err: errors.New("sync failed")})

	if !containsOutput(m.output, "listen err host/en11: sync failed") {
		t.Fatalf("output = %v", m.output)
	}
}

func TestListenStopResultDoesNotRepeatReportedError(t *testing.T) {
	session := &listen.Session{}
	m := NewModel()
	m.listener = session
	m.capMode = "listen"
	m.handleListenEvent(listen.Event{Kind: listen.KindStopped, Adapter: "en11", Role: "host", Err: errors.New("sync failed")})

	next, _ := m.Update(listenStoppedMsg{session: session, err: errors.New("sync failed")})
	got := next.(Model)
	if countOutput(got.output, "sync failed") != 1 {
		t.Fatalf("output = %v", got.output)
	}
}

func TestBridgeStopResultDoesNotRepeatPendingCleanup(t *testing.T) {
	session := &bridge.Session{}
	m := NewModel()
	m.bridge = session
	m.handleBridgeEvent(session, bridge.Event{Kind: bridge.KindStopped, State: "cleanup-pending", Err: errors.New("restore failed")})

	next, _ := m.Update(bridgeStoppedMsg{session: session, cleanupPending: true, err: errors.New("restore failed")})
	got := next.(Model)
	if countOutput(got.output, "restore failed") != 1 || countOutput(got.output, "cleanup pending") != 1 {
		t.Fatalf("output = %v", got.output)
	}
}

func TestCtrlCDefersCaptureCleanupToProgramBoundary(t *testing.T) {
	m := NewModel()
	m.listener = &listen.Session{Dir: "/tmp/golan-pcaps/listen"}
	m.capMode = "bridge"
	m.rememberPcapDir(m.listener.Dir)
	next, cmd := m.Update(tea.KeyMsg{Type: tea.KeyCtrlC})
	got := next.(Model)
	if got.listener == nil || got.capMode != "bridge" {
		t.Fatalf("capture state = listener:%v mode:%q", got.listener, got.capMode)
	}
	if cmd == nil {
		t.Fatal("expected quit command")
	}
	if _, ok := cmd().(tea.QuitMsg); !ok {
		t.Fatalf("command returned %T", cmd())
	}
	if err := Shutdown(got); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
	if dirs := PcapDirs(got); len(dirs) != 1 || dirs[0] != "/tmp/golan-pcaps/listen" {
		t.Fatalf("pcap dirs = %v", dirs)
	}
}

func TestShutdownCancelsUnstartedPrivilegedEffect(t *testing.T) {
	m := NewModel()
	ran := false
	m.trackEffect(func() tea.Msg {
		ran = true
		return adapterStateMsg{name: "en11", state: "down"}
	})

	if err := m.shutdown(); err != nil {
		t.Fatalf("shutdown: %v", err)
	}
	if ran {
		t.Fatal("unstarted effect ran during shutdown")
	}
	if pending := m.effects.waitPending(); len(pending) != 0 {
		t.Fatalf("pending effects = %+v", pending)
	}
}

func TestShutdownWaitsForRunningPrivilegedEffect(t *testing.T) {
	m := NewModel()
	started := make(chan struct{})
	release := make(chan struct{})
	cmd := m.trackEffect(func() tea.Msg {
		close(started)
		<-release
		return adapterStateMsg{name: "en11", state: "down"}
	})
	commandDone := make(chan struct{})
	go func() {
		defer close(commandDone)
		cmd()
	}()
	<-started

	shutdownDone := make(chan error, 1)
	go func() { shutdownDone <- m.shutdown() }()
	close(release)
	if err := <-shutdownDone; err != nil {
		t.Fatalf("shutdown: %v", err)
	}
	<-commandDone
	if pending := m.effects.waitPending(); len(pending) != 0 {
		t.Fatalf("pending effects = %+v", pending)
	}
}

func TestShutdownPublishesArtifactsFromUnconsumedResult(t *testing.T) {
	m := NewModel()
	session := &bridge.Session{Dir: "/tmp/golan-pcaps/pending-bridge"}
	cmd := m.trackEffect(func() tea.Msg { return bridgeStartedMsg{session: session} })
	cmd()

	if err := Shutdown(m); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
	if dirs := PcapDirs(m); !reflect.DeepEqual(dirs, []string{session.Dir}) {
		t.Fatalf("pcap dirs = %v", dirs)
	}
}

func TestStopListenRunsOutsideUpdate(t *testing.T) {
	session := &listen.Session{}
	m := NewModel()
	m.listener = session
	m.capMode = "listen"

	cmd := m.executeCommand("stop listen")
	if cmd == nil {
		t.Fatal("stop listen command is nil")
	}
	if m.listener != session {
		t.Fatal("executeCommand stopped the listener synchronously")
	}

	next, _ := m.Update(cmd())
	got := next.(Model)
	if got.listener != nil || got.capMode != "" {
		t.Fatalf("listener state remains: listener=%p mode=%q", got.listener, got.capMode)
	}
}

func TestListenStartRollsBackRaisedInterfaces(t *testing.T) {
	var calls []string
	setState := func(name, state string) error {
		calls = append(calls, name+":"+state)
		if name == "en12" && state == "up" {
			return errors.New("permission denied")
		}
		return nil
	}
	start := func([]listen.Target) (*listen.Session, error) {
		t.Fatal("listen start reached after interface setup failure")
		return nil, nil
	}
	cmd := startListenWithState([]listen.Target{{Name: "en11"}, {Name: "en12"}}, "listen", setState, start)
	msg := cmd().(listenStartedMsg)
	if msg.err == nil || len(msg.cleanupPending) != 0 {
		t.Fatalf("message = %+v", msg)
	}
	want := []string{"en11:up", "en12:up", "en11:down"}
	if !reflect.DeepEqual(calls, want) {
		t.Fatalf("calls = %v, want %v", calls, want)
	}
}

func TestListenStopRetainsFailedIsolationCleanup(t *testing.T) {
	setState := func(name, state string) error {
		if name == "en11" && state == "down" {
			return errors.New("busy")
		}
		return nil
	}
	cmd := stopListenCmdWithState(nil, []string{"en11", "en12"}, setState)
	msg := cmd().(listenStoppedMsg)
	if msg.err == nil || !reflect.DeepEqual(msg.cleanupPending, []string{"en11"}) {
		t.Fatalf("message = %+v", msg)
	}
}

func TestListenStopTimeoutKeepsSessionForRetry(t *testing.T) {
	session := &listen.Session{}
	m := NewModel()
	m.listener = session
	m.capMode = "listen"

	next, _ := m.Update(listenStoppedMsg{session: session, sessionPending: true, err: errors.New("timed out")})
	got := next.(Model)
	if got.listener != session || got.capMode != "listen" {
		t.Fatalf("listener state = %p mode=%q", got.listener, got.capMode)
	}
	if !containsOutput(got.output, "listen: cleanup pending; use: stop listen") {
		t.Fatalf("output = %v", got.output)
	}
}

func TestCtrlCDefersBridgeCleanupToProgramBoundary(t *testing.T) {
	m := NewModel()
	m.bridge = &bridge.Session{Dir: "/tmp/golan-pcaps/bridge"}
	m.rememberPcapDir(m.bridge.Dir)
	next, cmd := m.Update(tea.KeyMsg{Type: tea.KeyCtrlC})
	got := next.(Model)
	if got.bridge == nil {
		t.Fatalf("bridge state = bridge:%v state:%q", got.bridge, got.bridgeState)
	}
	if cmd == nil {
		t.Fatal("expected quit command")
	}
	if err := Shutdown(got); err != nil {
		t.Fatalf("Shutdown: %v", err)
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

func TestViewUsesContextPromptAndWorkbenchChrome(t *testing.T) {
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
	if !strings.Contains(view, "goLAN") || !strings.Contains(view, "WORKBENCH") {
		t.Fatalf("product bar missing:\n%s", view)
	}
	if !strings.Contains(view, "▌") || strings.ContainsAny(view, "╭╮╰╯") {
		t.Fatalf("flat active-pane chrome missing:\n%s", view)
	}
	if strings.Contains(view, "try:") || strings.Contains(view, "complete:") {
		t.Fatalf("old completion labels still present:\n%s", view)
	}
	if strings.Contains(view, "golan init") {
		t.Fatalf("right top pane is not blank:\n%s", view)
	}
	for _, removed := range []string{"New Project", "traffic"} {
		if strings.Contains(view, removed) {
			t.Fatalf("Setup retained redundant %q pane:\n%s", removed, view)
		}
	}
	for _, want := range []string{"s settings · Ctrl+S save", "Ctrl+P palette", "Shift+Left/Right pane", "F2-F4 workspace"} {
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
	if styled != styleAutocomplete.Render(line) {
		t.Fatalf("autocomplete style = %q, want autocomplete surface %q", styled, styleAutocomplete.Render(line))
	}
	if got := lipgloss.Width(styled); got != lipgloss.Width(line) {
		t.Fatalf("styled width = %d, want %d", got, lipgloss.Width(line))
	}
}

func TestPaneRowsRestoreBaseBackgroundAfterStyledText(t *testing.T) {
	previous := lipgloss.ColorProfile()
	lipgloss.SetColorProfile(0) // termenv.TrueColor
	t.Cleanup(func() { lipgloss.SetColorProfile(previous) })

	value := styleField.Render("host=") + styleValue.Render("example.test")
	row := paneLine(value, 40)
	prefix, _, ok := styleEnvelope(stylePaneBody)
	if !ok || prefix == "" {
		t.Fatal("pane body did not produce a background style prefix")
	}
	parts := strings.Split(row, ansiFullReset)
	if len(parts) < 3 {
		t.Fatalf("expected nested styled fragments in row: %q", row)
	}
	for index, part := range parts[1 : len(parts)-1] {
		if !strings.HasPrefix(part, prefix) {
			t.Fatalf("background was not restored after reset %d: %q", index, row)
		}
	}
}

func TestCLIInputAndAutocompletePaintFullInnerWidth(t *testing.T) {
	previous := lipgloss.ColorProfile()
	lipgloss.SetColorProfile(0) // termenv.TrueColor
	t.Cleanup(func() { lipgloss.SetColorProfile(previous) })

	m := NewModelWithSize(64, 20)
	m.input = "set host"
	m.completions = []string{"host", "switch", "gateway"}
	rendered := m.renderCLI(40, 6)
	lines := strings.Split(rendered, "\n")
	if len(lines) < 3 {
		t.Fatalf("CLI rendered too few rows: %q", rendered)
	}
	for index, line := range lines[1:3] {
		if got := lipgloss.Width(line); got != 40 {
			t.Fatalf("CLI row %d width = %d, want 40: %q", index, got, line)
		}
		style := styleCLIInput
		if index == 1 {
			style = styleAutocomplete
		}
		prefix, _, ok := styleEnvelope(style)
		if !ok || prefix == "" {
			t.Fatalf("CLI row %d did not produce a surface style", index)
		}
		start := strings.Index(line, prefix)
		if start < 0 {
			t.Fatalf("CLI row %d lacks its surface prefix: %q", index, line)
		}
		span := line[start+len(prefix):]
		end := strings.Index(span, ansiFullReset)
		if end < 0 {
			t.Fatalf("CLI row %d lacks its surface terminator: %q", index, line)
		}
		if got := lipgloss.Width(span[:end]); got != 38 {
			t.Fatalf("CLI row %d surface width = %d, want 38: %q", index, got, line)
		}
	}
}

func TestCLIInputDoesNotProtocolColorEAPOL(t *testing.T) {
	line := "> enable eapol drop-logoff|"
	styled := styleCLILine(line)
	if styled != styleCLIInput.Render(line) {
		t.Fatalf("cli style = %q, want input surface %q", styled, styleCLIInput.Render(line))
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

func TestNetworkCannotExpandRenderedView(t *testing.T) {
	m := NewModel()
	m.width = 72
	m.height = 18
	m.workspace = workspaceNetwork
	m.networkTracker = networkobs.NewTracker("test", "listen", time.Now())
	m.networkTracker.ObserveRisk(networkobs.Risk{Adapter: "en11", DeviceMAC: "02:00:00:00:00:11", Protocol: "EAP", Kind: "authentication material observed"})

	view := m.View()
	assertViewWidth(t, view, m.width)
	assertNoFullWidthLines(t, view, m.width)
	assertViewHorizontalInset(t, view, m.width)
	assertViewHeightWithin(t, view, m.height)
	if !strings.Contains(view, "devices") {
		t.Fatalf("device pane missing:\n%s", view)
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
		m.print(strings.Repeat("output-line-", 20))
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
	next, _ := m.Update(tea.KeyMsg{Type: tea.KeyShiftLeft})
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

func TestHorizontalNavigationMovesBetweenTrafficAndInspector(t *testing.T) {
	m := NewModel()
	m.workspace = workspaceNetwork
	m.activeCard = cardOutput
	for _, want := range []cardFocus{cardInspector, cardOutput} {
		next, _ := m.Update(tea.KeyMsg{Type: tea.KeyShiftRight})
		m = next.(Model)
		if m.activeCard != want {
			t.Fatalf("right focus=%s want=%s", m.activeCard, want)
		}
	}
	next, _ := m.Update(tea.KeyMsg{Type: tea.KeyShiftLeft})
	m = next.(Model)
	if m.activeCard != cardInspector {
		t.Fatalf("left focus=%s want=%s", m.activeCard, cardInspector)
	}
}

func TestOutputWrapsBeforeClipping(t *testing.T) {
	rows := wrapLine("show adapters row with a very long hardware address and a very long address column", 24)
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
	for _, want := range []string{"show adapters row", "hardware address", "address column"} {
		if !strings.Contains(view, want) {
			t.Fatalf("output lost wrapped content %q:\n%s", want, view)
		}
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
		"host/en11 IP=192.0.2.10 MAC=00:00:5e:00:53:01",
		"  en11 ethernet up 1500 00:00:5e:00:53:01 192.0.2.10",
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
	rows := wrapOutputLinesStyled([]string{line}, []bool{isCommandLevelOutput(line)}, nil, 28)
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
	return strings.ContainsAny(line, "─━")
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
		if strings.ContainsAny(lines[i], "─━") {
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
