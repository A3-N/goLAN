package project

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golan/internal/paths"
)

func TestRecentProjectsAreDeduplicatedAndAvailable(t *testing.T) {
	configRoot := t.TempDir()
	t.Setenv(paths.EnvConfigDir, configRoot)
	project, err := New(t.TempDir(), "RecentLab")
	if err != nil {
		t.Fatal(err)
	}
	if err := project.Save(); err != nil {
		t.Fatal(err)
	}
	if err := RememberRecentProject(project); err != nil {
		t.Fatal(err)
	}
	if err := RememberRecentProject(project); err != nil {
		t.Fatal(err)
	}

	state, err := LoadRecents()
	if err != nil {
		t.Fatal(err)
	}
	if state.Version != recentVersion || len(state.Projects) != 1 || state.Projects[0].Path != project.Path() || !state.Projects[0].Available {
		t.Fatalf("recent projects = %#v", state.Projects)
	}
	info, err := os.Stat(filepath.Join(configRoot, recentFile))
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("recent file info=%v err=%v", info, err)
	}
}

func TestLoadRecentsRejectsUnknownFieldsAndUnsafeEntries(t *testing.T) {
	configRoot := t.TempDir()
	t.Setenv(paths.EnvConfigDir, configRoot)
	path := filepath.Join(configRoot, recentFile)
	if err := paths.WriteConfigArtifact(path, []byte(`{"version":1,"unknown":true}`)); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadRecents(); err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("unknown-field error = %v", err)
	}
	unsafe := `{"version":1,"projects":[{"name":"escape","path":"../escape.golan","opened_at":"2026-01-01T00:00:00Z"}]}`
	if err := paths.WriteConfigArtifact(path, []byte(unsafe)); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadRecents(); err == nil || !strings.Contains(err.Error(), "recent project entry is invalid") {
		t.Fatalf("unsafe-entry error = %v", err)
	}
}

func TestLoadRecentsDiscardsRetiredCaptures(t *testing.T) {
	configRoot := t.TempDir()
	t.Setenv(paths.EnvConfigDir, configRoot)
	path := filepath.Join(configRoot, recentFile)
	legacy := `{
		"version": 1,
		"projects": [{
			"name": "Legacy Lab",
			"path": "/tmp/LegacyLab.golan",
			"opened_at": "2026-01-01T00:00:00Z"
		}],
		"captures": [{
			"name": "listen-20260101.pcap",
			"path": "/tmp/listen-20260101.pcap",
			"opened_at": "2026-01-01T00:00:00Z"
		}]
	}`
	if err := paths.WriteConfigArtifact(path, []byte(legacy)); err != nil {
		t.Fatal(err)
	}

	state, err := LoadRecents()
	if err != nil {
		t.Fatal(err)
	}
	if state.Version != recentVersion || len(state.Projects) != 1 || state.Projects[0].Name != "Legacy Lab" {
		t.Fatalf("recent state = %#v", state)
	}
	if state.Projects[0].Available {
		t.Fatal("missing legacy project was reported available")
	}
}

func TestLoadRecentsRejectsMalformedRetiredCaptures(t *testing.T) {
	configRoot := t.TempDir()
	t.Setenv(paths.EnvConfigDir, configRoot)
	path := filepath.Join(configRoot, recentFile)
	if err := paths.WriteConfigArtifact(path, []byte(`{"version":1,"captures":true}`)); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadRecents(); err == nil || !strings.Contains(err.Error(), "cannot unmarshal") {
		t.Fatalf("malformed-captures error = %v", err)
	}
}

func TestRememberRecentItemsRejectsSymlinks(t *testing.T) {
	t.Setenv(paths.EnvConfigDir, t.TempDir())
	project, err := New(t.TempDir(), "RealProject")
	if err != nil {
		t.Fatal(err)
	}
	if err := project.Save(); err != nil {
		t.Fatal(err)
	}
	projectLink := filepath.Join(t.TempDir(), "linked.golan")
	if err := os.Symlink(project.Path(), projectLink); err != nil {
		t.Fatal(err)
	}
	linkedProject := &Project{path: projectLink, manifest: project.Manifest()}
	if err := RememberRecentProject(linkedProject); err == nil {
		t.Fatal("symlink project was remembered")
	}
}

func TestRememberRecentProjectRejectsUnsavedDraft(t *testing.T) {
	t.Setenv(paths.EnvConfigDir, t.TempDir())
	project, err := New(t.TempDir(), "UnsavedDraft")
	if err != nil {
		t.Fatal(err)
	}
	if err := RememberRecentProject(project); err == nil {
		t.Fatal("unsaved project draft was added to recent history")
	}
}
