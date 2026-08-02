package tui

import (
	"strings"
	"testing"

	"golan/internal/adapters"
	bridge "golan/internal/bridge"
	"golan/internal/configs"
	"golan/internal/listen"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

func TestSettingsEditorGroupsImpactsAndExactCancel(t *testing.T) {
	m := NewModelWithSize(160, 42)
	m.activeCard = cardOutput
	m.edgeForwards = []edgeForwardSetting{{Protocol: "tcp", ListenPort: 8080, TargetPort: 80}}
	m.openSettingsEditor()
	if !m.settingsEditor.open || m.settingsEditor.returnCard != cardOutput {
		t.Fatalf("settings state=%#v", m.settingsEditor)
	}
	view := m.renderSettingsEditor()
	for _, want := range []string{
		"SESSION", "ADDRESSING", "POLICY", "PRIVACY", "PERFORMANCE",
		"[LIVE]", "[RECONFIGURE LINK]", "[DISRUPTS CONNECTIONS]",
		"Port forward", "Redact observed secrets", "Ctrl+S commit",
	} {
		if !strings.Contains(view, want) {
			t.Fatalf("settings view missing %q:\n%s", want, view)
		}
	}
	for _, retired := range []string{"INTERCEPT", "PROXY", "HOLD", "FLOW"} {
		if strings.Contains(view, retired) {
			t.Fatalf("settings view retained %q:\n%s", retired, view)
		}
	}

	next, command := m.updateSettingsEditor(tea.KeyMsg{Type: tea.KeyRight})
	m = next.(Model)
	if command != nil || m.settingsEditor.draft.edgeMode == m.edgeConfiguredMode || m.edgeConfiguredMode != "observe" {
		t.Fatalf("draft mutation leaked: mode=%q draft=%q command=%v", m.edgeConfiguredMode, m.settingsEditor.draft.edgeMode, command != nil)
	}
	next, _ = m.updateSettingsEditor(tea.KeyMsg{Type: tea.KeyEsc})
	m = next.(Model)
	if m.settingsEditor.open || m.edgeConfiguredMode != "observe" || m.activeCard != cardOutput || len(m.edgeForwards) != 1 {
		t.Fatalf("cancel state mode=%q card=%v forwards=%#v editor=%#v", m.edgeConfiguredMode, m.activeCard, m.edgeForwards, m.settingsEditor)
	}
}

func TestSettingsImpactsRightAlignAndSelectedBadgesShareHighlight(t *testing.T) {
	m := NewModelWithSize(120, 36)
	m.openSettingsEditor()
	const rowWidth = 94
	document, _ := m.settingsEditorDocument(rowWidth)
	impactRows := 0
	badgeStarts := make(map[int]bool)
	for _, row := range document {
		if !strings.Contains(row, "[") {
			continue
		}
		if strings.Contains(row, "[LIVE]") || strings.Contains(row, "[RECONFIGURE LINK]") {
			impactRows++
			badgeStarts[strings.Index(row, "[")] = true
			if got := lipgloss.Width(row); got != rowWidth {
				t.Fatalf("impact row width=%d want=%d: %q", got, rowWidth, row)
			}
		}
	}
	if impactRows == 0 {
		t.Fatal("settings document had no impact rows")
	}
	if len(badgeStarts) < 2 {
		t.Fatalf("differently sized badge groups unexpectedly share a left edge: %v", badgeStarts)
	}
	if got := styleContextSelected.GetBackground(); got != colorSelection {
		t.Fatalf("selected impact background=%v want=%v", got, colorSelection)
	}
	view := m.renderSettingsEditor()
	for _, impact := range []settingsImpact{settingsImpactReconfigure, settingsImpactDisrupts} {
		badge := styleContextSelected.Render("[" + string(impact) + "]")
		if !strings.Contains(view, badge) {
			t.Fatalf("selected badge does not share row highlight: %q\n%s", badge, view)
		}
	}
}

func TestSettingsEditorValidatesAndCommitsCompleteDraftAtomically(t *testing.T) {
	m := NewModel()
	m.adapters = []adapters.Adapter{{Name: "en0"}}
	m.openSettingsEditor()
	m.settingsEditor.draft.edgeMode = "route"
	m.settingsEditor.draft.edgeUpstream = "en0"
	m.settingsEditor.draft.eapolLogoff = false
	m.settingsEditor.draft.redactSecrets = false
	m.settingsEditor.draft.controlled.QueueDepth = 512
	if err := m.addSettingsPortForward("tcp 8080 80"); err != nil {
		t.Fatal(err)
	}
	m.commitSettingsEditor()
	if m.settingsEditor.open || m.edgeConfiguredMode != "route" || m.edgeUpstream != "en0" ||
		m.eapolSuppressLogoff || m.redactObservedSecrets || m.bridgeControlledOptions.QueueDepth != 512 || len(m.edgeForwards) != 1 {
		t.Fatalf("committed state editor=%#v mode=%q upstream=%q eapol=%t controlled=%#v forwards=%#v", m.settingsEditor, m.edgeConfiguredMode, m.edgeUpstream, m.eapolSuppressLogoff, m.bridgeControlledOptions, m.edgeForwards)
	}
	output := strings.Join(m.output, "\n")
	for _, want := range []string{"settings: committed", "LIVE", "RECONFIGURE LINK", "DISRUPTS CONNECTIONS", "forwards=1", "redact-secrets=false"} {
		if !strings.Contains(output, want) {
			t.Fatalf("commit output missing %q: %s", want, output)
		}
	}
}

func TestSecretRedactionSettingStagesAndCancelsExactly(t *testing.T) {
	m := NewModel()
	m.openSettingsEditor()
	for index, row := range m.settingsRows() {
		if row.kind == settingsRowRedactSecrets {
			m.settingsEditor.cursor = index
			break
		}
	}
	m.cycleSettingsValue(1)
	if m.settingsEditor.draft.redactSecrets || !m.redactObservedSecrets {
		t.Fatalf("privacy draft leaked before commit: draft=%t model=%t", m.settingsEditor.draft.redactSecrets, m.redactObservedSecrets)
	}
	next, _ := m.updateSettingsEditor(tea.KeyMsg{Type: tea.KeyEsc})
	m = next.(Model)
	if m.settingsEditor.open || !m.redactObservedSecrets {
		t.Fatalf("cancel changed privacy state: editor=%#v model=%t", m.settingsEditor, m.redactObservedSecrets)
	}
}

func TestSettingsEditorBlockerPreventsPartialCommit(t *testing.T) {
	m := NewModel()
	m.listener = &listen.Session{}
	m.openSettingsEditor()
	m.settingsEditor.draft.edgeMode = "route"
	m.settingsEditor.draft.eapolLogoff = false
	m.commitSettingsEditor()
	if !m.settingsEditor.open || m.edgeConfiguredMode != "observe" || !m.eapolSuppressLogoff {
		t.Fatalf("blocked commit leaked state mode=%q eapol=%t editor=%#v", m.edgeConfiguredMode, m.eapolSuppressLogoff, m.settingsEditor)
	}
	if !strings.Contains(m.settingsEditor.err, "listen active") {
		t.Fatalf("blocker error=%q", m.settingsEditor.err)
	}
}

func TestSettingsEditorLiveOnlyPolicyCommitWorksWithActiveBridge(t *testing.T) {
	m := NewModel()
	m.bridge = &bridge.Session{}
	m.openSettingsEditor()
	m.settingsEditor.draft.eapolLogoff = false
	m.settingsEditor.draft.eapolMACsec = false
	m.commitSettingsEditor()
	if m.settingsEditor.open || m.eapolSuppressLogoff || m.eapolDowngradeMACsec {
		t.Fatalf("live commit state editor=%#v logoff=%t macsec=%t", m.settingsEditor, m.eapolSuppressLogoff, m.eapolDowngradeMACsec)
	}
	if output := strings.Join(m.output, "\n"); !strings.Contains(output, "impacts=LIVE") {
		t.Fatalf("live commit output=%q", output)
	}
}

func TestSettingsEditorInventoryAddRemoveResetAndValidation(t *testing.T) {
	m := NewModel()
	m.openSettingsEditor()
	if err := m.addSettingsPortForward("udp 5353 53"); err != nil {
		t.Fatal(err)
	}
	if err := m.addSettingsPortForward("udp 5353 54"); err == nil || !strings.Contains(err.Error(), "duplicated") {
		t.Fatalf("duplicate forward error=%v", err)
	}
	rows := m.settingsRows()
	for index, row := range rows {
		if row.kind == settingsRowPortForward {
			m.settingsEditor.cursor = index
			break
		}
	}
	m.removeSettingsInventoryItem()
	if len(m.settingsEditor.draft.forwards) != 0 || len(m.settingsEditor.original.forwards) != 0 {
		t.Fatalf("forward removal draft=%#v original=%#v", m.settingsEditor.draft.forwards, m.settingsEditor.original.forwards)
	}
	m.settingsEditor.draft.forwards = []edgeForwardSetting{{Protocol: "tcp", ListenPort: 8080, TargetPort: 80}}
	m.settingsEditor.original.forwards = []edgeForwardSetting{{Protocol: "udp", ListenPort: 5353, TargetPort: 53}}
	next, _ := m.updateSettingsEditor(tea.KeyMsg{Type: tea.KeyCtrlR})
	m = next.(Model)
	m.settingsEditor.draft.forwards[0].TargetPort = 5354
	if m.settingsEditor.original.forwards[0].TargetPort != 53 {
		t.Fatalf("reset draft aliases original: %#v", m.settingsEditor)
	}
}

func TestSettingsCommandAndMainShortcutOpenEditor(t *testing.T) {
	m := NewModel()
	m.executeCommand("settings")
	if !m.settingsEditor.open {
		t.Fatal("settings command did not open editor")
	}
	m.closeSettingsEditor()
	m.workspace = workspaceMain
	m.activeCard = cardOutput
	next, command := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'s'}})
	m = next.(Model)
	if command != nil || !m.settingsEditor.open || m.settingsEditor.returnCard != cardOutput {
		t.Fatalf("Main shortcut state=%#v command=%v", m.settingsEditor, command != nil)
	}
}

func TestRuntimeSettingsSnapshotRoundTripAndLegacyInterceptNormalization(t *testing.T) {
	m := NewModel()
	m.edgeConfiguredMode = "route"
	m.edgeUpstream = "en0"
	m.edgeForwards = []edgeForwardSetting{{Protocol: "tcp", ListenPort: 8080, TargetPort: 80}}
	m.bridgeControlledOptions = bridge.DefaultControlledOptions()
	m.bridgeControlledOptions.QueueDepth = 512
	m.bridgeControlledOptions.Overload = bridge.OverloadFailClosed
	settings := m.snapshotSettings()
	if !settings.SecretsRedacted() {
		t.Fatal("default secret redaction was not snapshotted")
	}

	got := NewModel()
	got.applySnapshotSettings(&settings)
	if got.edgeConfiguredMode != m.edgeConfiguredMode || got.edgeUpstream != m.edgeUpstream ||
		!equalEdgeForwards(got.edgeForwards, m.edgeForwards) || got.bridgeControlledOptions != m.bridgeControlledOptions || got.redactObservedSecrets != m.redactObservedSecrets {
		t.Fatalf("runtime restore got=%#v want=%#v", got.settingsSnapshot(), m.settingsSnapshot())
	}
	m.redactObservedSecrets = false
	settings = m.snapshotSettings()
	got = NewModel()
	got.applySnapshotSettings(&settings)
	if got.redactObservedSecrets {
		t.Fatal("revealed-secret setting did not round trip through runtime settings")
	}

	legacy := configs.DefaultSettings()
	legacy.Runtime.EdgeMode = "intercept"
	got = NewModel()
	got.applySnapshotSettings(&legacy)
	if got.edgeConfiguredMode != "route" || !containsOutput(got.output, "legacy edge intercept settings are retired") {
		t.Fatalf("legacy settings were not normalized safely: mode=%q output=%v", got.edgeConfiguredMode, got.output)
	}
}
