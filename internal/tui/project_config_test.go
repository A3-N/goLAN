package tui

import (
	"strings"
	"testing"

	"golan/internal/configs"
	"golan/internal/paths"
	"golan/internal/profile"
	workproject "golan/internal/project"
)

func TestProjectConfigUpdateStagesValidatedSourceWithVisibleDiff(t *testing.T) {
	t.Setenv(paths.EnvConfigDir, t.TempDir())
	first := configs.Snapshot{
		ActiveAdapter: "en0",
		Profile: profile.Profile{Adapters: []profile.AdapterConfig{{
			AdapterRole: profile.AdapterRoleHost,
			Name:        "en0",
			IP:          "192.0.2.1",
		}}},
	}
	path, err := configs.Save("source", first)
	if err != nil {
		t.Fatal(err)
	}
	project, err := workproject.New(t.TempDir(), "ConfigUpdateWorkbench")
	if err != nil {
		t.Fatal(err)
	}
	record, err := project.ImportConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	second := first
	second.Profile.Adapters = append([]profile.AdapterConfig(nil), first.Profile.Adapters...)
	second.Profile.Adapters[0].IP = "192.0.2.2"
	if _, err := configs.Save("source", second); err != nil {
		t.Fatal(err)
	}

	m := NewProjectModel(project, true, 100, 30)
	m.executeCommand("project config update " + record.ID)
	if len(project.Manifest().Configs) != 2 || !project.Dirty() || !m.profileNeedsRehydrate {
		t.Fatalf("updated config inventory=%#v dirty=%v needs-rehydrate=%v", project.Manifest().Configs, project.Dirty(), m.profileNeedsRehydrate)
	}
	staged, ok := m.profile.ByName("en0")
	if !ok || staged.IP != "192.0.2.2" || m.activeAdapter != "en0" {
		t.Fatalf("staged config=%#v active=%q", m.profile, m.activeAdapter)
	}
	output := strings.Join(m.output, "\n")
	if !strings.Contains(output, "config diff:") || !strings.Contains(output, "profile.Adapters[0].ip") || !strings.Contains(output, `"192.0.2.1" -> "192.0.2.2"`) {
		t.Fatalf("config update output=%q", output)
	}
	if m.listener != nil || m.bridge != nil || m.edgeSession != nil || len(m.lockPending) != 0 {
		t.Fatal("config source update mutated live networking")
	}

	latest := project.Manifest().Configs[1]
	m.executeCommand("project config update " + latest.ID)
	if !strings.Contains(strings.Join(m.output, "\n"), "config source unchanged id="+latest.ID) || len(project.Manifest().Configs) != 2 {
		t.Fatal("unchanged source update created another snapshot")
	}
}

func TestProjectConfigExportSkipsUnchangedAndRedactsSensitiveDiff(t *testing.T) {
	t.Setenv(paths.EnvConfigDir, t.TempDir())
	project, err := workproject.New(t.TempDir(), "ConfigExportWorkbench")
	if err != nil {
		t.Fatal(err)
	}
	m := NewProjectModel(project, true, 100, 30)
	m.profile = profile.Profile{Adapters: []profile.AdapterConfig{{
		AdapterRole: profile.AdapterRoleHost,
		Name:        "en0",
		IP:          "192.0.2.10",
	}}}
	m.activeAdapter = "en0"
	m.executeCommand("project config export exported")
	loaded, path, err := configs.Load("exported")
	if err != nil || loaded.Profile.Adapters[0].IP != "192.0.2.10" || len(project.Manifest().Configs) != 1 {
		t.Fatalf("exported config=%#v path=%q configs=%#v err=%v", loaded, path, project.Manifest().Configs, err)
	}
	m.executeCommand("project config export exported")
	if len(project.Manifest().Configs) != 1 || !strings.Contains(strings.Join(m.output, "\n"), "config export unchanged") {
		t.Fatal("unchanged export rewrote or reimported config")
	}

	m.profile.Adapters[0].Notes = "synthetic-secret-note"
	m.executeCommand("project config export exported")
	output := strings.Join(m.output, "\n")
	if !strings.Contains(output, "[redacted] -> [redacted]") || strings.Contains(output, "synthetic-secret-note") {
		t.Fatalf("sensitive config diff output=%q", output)
	}
	if len(project.Manifest().Configs) != 2 {
		t.Fatalf("changed export configs=%#v", project.Manifest().Configs)
	}
}

func TestProjectConfigUpdateBlockedByAdapterIsolationAndCompletesIDs(t *testing.T) {
	t.Setenv(paths.EnvConfigDir, t.TempDir())
	path, err := configs.Save("source", configs.Snapshot{
		Profile: profile.Profile{Adapters: []profile.AdapterConfig{{AdapterRole: profile.AdapterRoleHost, Name: "en0", IP: "192.0.2.1"}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	project, err := workproject.New(t.TempDir(), "ConfigUpdateBlocked")
	if err != nil {
		t.Fatal(err)
	}
	record, err := project.ImportConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	m := NewProjectModel(project, true, 100, 30)
	m.lockPending["en0"] = true
	m.executeCommand("project config update " + record.ID)
	if len(project.Manifest().Configs) != 1 || !strings.Contains(strings.Join(m.output, "\n"), "adapter isolation is pending") {
		t.Fatal("blocked config update changed project or omitted reason")
	}
	m.input = "project config update "
	m.refreshCompletions()
	if !containsString(m.completions, record.ID) {
		t.Fatalf("config source completions=%v", m.completions)
	}
	m.input = "project config export "
	m.refreshCompletions()
	if !containsString(m.completions, "source.json") {
		t.Fatalf("config export completions=%v", m.completions)
	}
}
