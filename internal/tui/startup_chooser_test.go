package tui

import (
	"strings"
	"testing"

	"golan/internal/adapters"
	"golan/internal/configs"
	"golan/internal/paths"
	"golan/internal/profile"
	workproject "golan/internal/project"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

func TestStartupChooserRendersAllChoicesAndNavigates(t *testing.T) {
	t.Setenv(paths.EnvConfigDir, t.TempDir())
	m := NewStartupModelWithSize(100, 30, true)
	view := m.View()
	for _, choice := range []string{
		"New Project",
		"Open Recent Project",
		"Open Project Directory",
		"Import Project Bundle",
		"Start from Config",
		"Quick Live Session",
	} {
		if !strings.Contains(view, choice) {
			t.Fatalf("startup view missing %q:\n%s", choice, view)
		}
	}
	if !strings.Contains(view, "[offline]") {
		t.Fatalf("offline quick-live state is not visible:\n%s", view)
	}

	m = startupKey(t, m, tea.KeyMsg{Type: tea.KeyDown})
	m = startupKey(t, m, tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'k'}})
	if m.startup.cursor != 0 {
		t.Fatalf("cursor = %d, want navigation back to zero", m.startup.cursor)
	}
	if cmd := m.Init(); cmd == nil {
		t.Fatal("startup model must continue cursor and recent-state initialization")
	}
}

func TestStartupChooserCreatesProjectAndCanReopenFromCommandMode(t *testing.T) {
	t.Setenv(paths.EnvConfigDir, t.TempDir())
	m := NewStartupModelWithSize(100, 30, true)
	m = startupKey(t, m, tea.KeyMsg{Type: tea.KeyEnter})
	if m.startup.view != startupPrompt || m.startup.prompt != startupNewName {
		t.Fatalf("startup prompt = view:%v kind:%v", m.startup.view, m.startup.prompt)
	}
	m = startupType(t, m, "chooser-project")
	m = startupKey(t, m, tea.KeyMsg{Type: tea.KeyEnter})
	if m.startup.open || m.project == nil || !m.project.Dirty() {
		t.Fatalf("project startup = open:%v project:%v dirty:%v", m.startup.open, m.project != nil, m.project != nil && m.project.Dirty())
	}
	if m.listener != nil || m.bridge != nil || m.edgeSession != nil || len(m.restoreState) != 0 || len(m.lockPending) != 0 {
		t.Fatal("creating a startup project mutated runtime networking state")
	}

	m.attachProject(nil)
	m.workspace = workspaceMain
	m = startupKey(t, m, tea.KeyMsg{Type: tea.KeyEnter})
	if !m.startup.open {
		t.Fatal("empty Enter did not reopen the startup chooser")
	}
	m = startupKey(t, m, tea.KeyMsg{Type: tea.KeyEsc})
	if m.startup.open || m.inputMode != modeCommand || m.activeCard != cardCLI {
		t.Fatalf("Esc did not return to command mode: startup=%v mode=%v card=%v", m.startup.open, m.inputMode, m.activeCard)
	}
}

func TestStartupChooserOpensSavedRecentProject(t *testing.T) {
	t.Setenv(paths.EnvConfigDir, t.TempDir())
	project, err := workproject.NewDefault("recent-project")
	if err != nil {
		t.Fatal(err)
	}
	if err := project.Save(); err != nil {
		t.Fatal(err)
	}
	if err := workproject.RememberRecentProject(project); err != nil {
		t.Fatal(err)
	}

	m := NewStartupModelWithSize(100, 30, true)
	m = startupKey(t, m, tea.KeyMsg{Type: tea.KeyDown})
	m = startupKey(t, m, tea.KeyMsg{Type: tea.KeyEnter})
	if m.startup.view != startupRecentProjects {
		t.Fatalf("view = %v", m.startup.view)
	}
	m = startupKey(t, m, tea.KeyMsg{Type: tea.KeyEnter})
	if m.startup.open || m.project == nil || m.project.Path() != project.Path() || m.project.Dirty() {
		t.Fatalf("recent project = startup:%v path:%q dirty:%v", m.startup.open, m.project.Path(), m.project.Dirty())
	}
	if m.listener != nil || m.bridge != nil || m.edgeSession != nil {
		t.Fatal("opening a recent project started networking")
	}
}

func TestStartProjectFromConfigStagesWithoutNetworkEffects(t *testing.T) {
	t.Setenv(paths.EnvConfigDir, t.TempDir())
	wantProfile := profile.Profile{Adapters: []profile.AdapterConfig{{
		AdapterRole: profile.AdapterRoleHost,
		Name:        "persisted-en9",
		IP:          "192.0.2.9",
	}}}
	settings := configs.DefaultSettings()
	settings.EAPOLLogoffDrop = false
	if _, err := configs.Save("lab", configs.Snapshot{
		ActiveAdapter: "persisted-en9",
		Profile:       wantProfile,
		Settings:      &settings,
	}); err != nil {
		t.Fatal(err)
	}

	m := NewStartupModelWithSize(100, 30, true)
	if err := m.startProjectFromConfig("lab.json", "from-config"); err != nil {
		t.Fatal(err)
	}
	manifest := m.project.Manifest()
	if m.project == nil || !m.project.Dirty() || len(manifest.Configs) != 1 {
		t.Fatalf("project config inventory = project:%v dirty:%v configs:%d", m.project != nil, m.project != nil && m.project.Dirty(), len(manifest.Configs))
	}
	staged, ok := m.profile.ByName("persisted-en9")
	if !ok || staged.IP != "192.0.2.9" || m.activeAdapter != "persisted-en9" || m.eapolSuppressLogoff {
		t.Fatalf("staged state = profile:%+v active:%q logoff:%v", m.profile, m.activeAdapter, m.eapolSuppressLogoff)
	}
	if m.listener != nil || m.bridge != nil || m.edgeSession != nil || m.runtimeOperation != "" || len(m.restoreState) != 0 || len(m.lockPending) != 0 || len(m.restorePending) != 0 {
		t.Fatal("config startup rehydrated or mutated live adapters")
	}
	if !m.profileNeedsRehydrate {
		t.Fatal("config startup did not defer live adapter metadata rehydration")
	}
	m.offline = false
	m.adapters = []adapters.Adapter{{Name: "persisted-en9", HardwarePort: "Ethernet 9", NetworkService: "Renamed Lab 9", Kind: "ethernet", MAC: "02:00:00:00:00:09", MTU: 1500}}
	cmd := m.executeStart([]string{"listen"})
	refreshed, _ := m.profile.ByName("persisted-en9")
	if cmd == nil || m.profileNeedsRehydrate || refreshed.HardwarePort != "Ethernet 9" || refreshed.NetworkService != "Renamed Lab 9" || !m.lockPending["persisted-en9"] {
		t.Fatalf("live boundary = cmd:%v needs:%v profile:%+v locks:%v", cmd != nil, m.profileNeedsRehydrate, refreshed, m.lockPending)
	}
	if m.listener != nil || m.bridge != nil || m.edgeSession != nil {
		t.Fatal("metadata refresh started a live session before isolation completed")
	}
}

func TestStartupChooserQuickLiveNeverStartsSession(t *testing.T) {
	t.Setenv(paths.EnvConfigDir, t.TempDir())
	for _, offline := range []bool{true, false} {
		m := NewStartupModelWithSize(100, 30, offline)
		for range 5 {
			m = startupKey(t, m, tea.KeyMsg{Type: tea.KeyDown})
		}
		m = startupKey(t, m, tea.KeyMsg{Type: tea.KeyEnter})
		if offline && (!m.startup.open || !strings.Contains(m.startup.err, "macOS root")) {
			t.Fatalf("offline quick live = open:%v err:%q", m.startup.open, m.startup.err)
		}
		if !offline && (!m.startup.open || m.startup.view != startupLiveModes) {
			t.Fatalf("available quick live did not open mode wizard: open=%v view=%v", m.startup.open, m.startup.view)
		}
		if m.listener != nil || m.bridge != nil || m.edgeSession != nil || m.runtimeOperation != "" {
			t.Fatalf("quick live started a runtime session (offline=%v)", offline)
		}
	}
}

func TestQuickLiveWizardStagesControlledBridgeWithoutStartingIt(t *testing.T) {
	t.Setenv(paths.EnvConfigDir, t.TempDir())
	m := NewStartupModelWithSize(120, 36, false)
	m.adapters = []adapters.Adapter{{Name: "en1", HardwarePort: "USB"}, {Name: "en0", HardwarePort: "Ethernet"}}
	for range 5 {
		m = startupKey(t, m, tea.KeyMsg{Type: tea.KeyDown})
	}
	m = startupKey(t, m, tea.KeyMsg{Type: tea.KeyEnter})
	for range 4 {
		m = startupKey(t, m, tea.KeyMsg{Type: tea.KeyDown})
	}
	m = startupKey(t, m, tea.KeyMsg{Type: tea.KeyEnter})
	if m.startup.view != startupLivePrimary {
		t.Fatalf("live primary view=%v", m.startup.view)
	}
	m = startupKey(t, m, tea.KeyMsg{Type: tea.KeyEnter})
	if m.startup.livePrimary != "en0" || m.startup.view != startupLiveSecondary {
		t.Fatalf("primary=%q view=%v", m.startup.livePrimary, m.startup.view)
	}
	m = startupKey(t, m, tea.KeyMsg{Type: tea.KeyEnter})
	if m.startup.liveSecond != "en1" || m.startup.view != startupLiveReview || !strings.Contains(m.View(), "NO NETWORKING HAS STARTED") {
		t.Fatalf("secondary=%q view=%v\n%s", m.startup.liveSecond, m.startup.view, m.View())
	}
	m = startupKey(t, m, tea.KeyMsg{Type: tea.KeyEnter})
	host, hostOK := m.profile.Role(profile.AdapterRoleHost)
	switchSide, switchOK := m.profile.Role(profile.AdapterRoleSwitch)
	if m.startup.open || !hostOK || !switchOK || host.Name != "en0" || switchSide.Name != "en1" ||
		m.activeAdapter != "bridge" || m.input != "start bridge controlled" || !m.profileNeedsRehydrate {
		t.Fatalf("staged bridge startup=%v host=%#v switch=%#v active=%q input=%q needs=%v", m.startup.open, host, switchSide, m.activeAdapter, m.input, m.profileNeedsRehydrate)
	}
	if m.listener != nil || m.bridge != nil || m.edgeSession != nil || m.runtimeOperation != "" || len(m.lockPending) != 0 || len(m.restoreState) != 0 {
		t.Fatal("Quick Live bridge wizard mutated networking state")
	}
}

func TestQuickLiveWizardStagesEdgeAutoUpstreamWithoutStartingIt(t *testing.T) {
	t.Setenv(paths.EnvConfigDir, t.TempDir())
	m := NewStartupModelWithSize(120, 36, false)
	m.adapters = []adapters.Adapter{{Name: "en7"}}
	for range 5 {
		m = startupKey(t, m, tea.KeyMsg{Type: tea.KeyDown})
	}
	m = startupKey(t, m, tea.KeyMsg{Type: tea.KeyEnter})
	for range 2 {
		m = startupKey(t, m, tea.KeyMsg{Type: tea.KeyDown})
	}
	m = startupKey(t, m, tea.KeyMsg{Type: tea.KeyEnter})
	m = startupKey(t, m, tea.KeyMsg{Type: tea.KeyEnter})
	m = startupKey(t, m, tea.KeyMsg{Type: tea.KeyEnter})
	if m.startup.view != startupLiveReview || m.startup.liveSecond != "auto" {
		t.Fatalf("edge review view=%v second=%q", m.startup.view, m.startup.liveSecond)
	}
	m = startupKey(t, m, tea.KeyMsg{Type: tea.KeyEnter})
	if m.startup.open || m.edgeConfiguredMode != "route" || m.edgeUpstream != "auto" || m.activeAdapter != "en7" || m.input != "start edge route" || !m.profileNeedsRehydrate {
		t.Fatalf("edge staged open=%v mode=%q upstream=%q active=%q input=%q needs=%v", m.startup.open, m.edgeConfiguredMode, m.edgeUpstream, m.activeAdapter, m.input, m.profileNeedsRehydrate)
	}
	if m.listener != nil || m.bridge != nil || m.edgeSession != nil || len(m.lockPending) != 0 {
		t.Fatal("Quick Live edge wizard mutated networking state")
	}
}

func TestQuickLiveReviewBackRestoresExplicitSecondarySelection(t *testing.T) {
	t.Setenv(paths.EnvConfigDir, t.TempDir())
	m := NewStartupModelWithSize(120, 36, false)
	m.adapters = []adapters.Adapter{{Name: "en2"}, {Name: "en0"}, {Name: "en1"}}
	for range 5 {
		m = startupKey(t, m, tea.KeyMsg{Type: tea.KeyDown})
	}
	m = startupKey(t, m, tea.KeyMsg{Type: tea.KeyEnter})
	for range 2 {
		m = startupKey(t, m, tea.KeyMsg{Type: tea.KeyDown})
	}
	m = startupKey(t, m, tea.KeyMsg{Type: tea.KeyEnter})
	m = startupKey(t, m, tea.KeyMsg{Type: tea.KeyEnter})
	for range 2 {
		m = startupKey(t, m, tea.KeyMsg{Type: tea.KeyDown})
	}
	m = startupKey(t, m, tea.KeyMsg{Type: tea.KeyEnter})
	if m.startup.view != startupLiveReview || m.startup.liveSecond != "en2" {
		t.Fatalf("review view=%v second=%q cursor=%d", m.startup.view, m.startup.liveSecond, m.startup.cursor)
	}
	m = startupKey(t, m, tea.KeyMsg{Type: tea.KeyEsc})
	if m.startup.view != startupLiveSecondary || m.startup.cursor != 2 {
		t.Fatalf("restored secondary view=%v cursor=%d want=2", m.startup.view, m.startup.cursor)
	}
	m = startupKey(t, m, tea.KeyMsg{Type: tea.KeyEsc})
	if m.startup.view != startupLivePrimary || m.startup.cursor != 0 {
		t.Fatalf("restored primary view=%v cursor=%d", m.startup.view, m.startup.cursor)
	}
}

func TestStartupChooserResponsiveBoundsAndHelpReturn(t *testing.T) {
	t.Setenv(paths.EnvConfigDir, t.TempDir())
	m := NewStartupModelWithSize(42, 12, true)
	view := m.View()
	if width := lipgloss.Width(view); width > 42 {
		t.Fatalf("view width = %d", width)
	}
	if height := lipgloss.Height(view); height > 12 {
		t.Fatalf("view height = %d", height)
	}
	m = startupKey(t, m, tea.KeyMsg{Type: tea.KeyF1})
	if !m.help.open || !m.startup.open {
		t.Fatal("help did not overlay the startup chooser")
	}
	m = startupKey(t, m, tea.KeyMsg{Type: tea.KeyF1})
	if m.help.open || !m.startup.open || !strings.Contains(m.View(), "GOLAN WORKBENCH START") {
		t.Fatal("help did not return to the startup chooser")
	}
}

func startupKey(t *testing.T, m Model, key tea.KeyMsg) Model {
	t.Helper()
	next, cmd := m.Update(key)
	if cmd != nil && key.Type != tea.KeyCtrlC {
		t.Fatalf("startup key %q unexpectedly scheduled an effect", key.String())
	}
	return next.(Model)
}

func startupType(t *testing.T, m Model, value string) Model {
	t.Helper()
	for _, r := range value {
		m = startupKey(t, m, tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{r}})
	}
	return m
}
