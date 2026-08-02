package tui

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golan/internal/paths"
	workproject "golan/internal/project"

	tea "github.com/charmbracelet/bubbletea"
)

func TestProjectSaveAsCommandRunsAsTrackedEffectAndAttachesResult(t *testing.T) {
	t.Setenv(paths.EnvConfigDir, t.TempDir())
	project, err := workproject.New(t.TempDir(), "AsyncSaveAs")
	if err != nil {
		t.Fatal(err)
	}
	project.SetWorkspace("Rules")
	originalID := project.Manifest().ID
	m := NewProjectModel(project, true, 100, 30)
	destination := filepath.Join(t.TempDir(), "Async Copy.golan")
	cmd := m.executeProject([]string{"save-as", destination})
	if cmd == nil || m.runtimeOperation != projectSaveAsOperation || m.project != project || m.saveAsCancel == nil {
		t.Fatalf("save-as start cmd=%v operation=%q project=%p cancel=%v", cmd != nil, m.runtimeOperation, m.project, m.saveAsCancel != nil)
	}

	next, _ := m.Update(cmd())
	m = next.(Model)
	if m.runtimeOperation != "" || m.saveAsCancel != nil || m.project == project || m.project.Path() != destination || m.project.Dirty() {
		t.Fatalf("save-as result operation=%q cancel=%v project=%p path=%q dirty=%v", m.runtimeOperation, m.saveAsCancel != nil, m.project, m.project.Path(), m.project.Dirty())
	}
	if m.project.Manifest().ID == originalID || m.project.Manifest().Preferences.Workspace != "Rules" {
		t.Fatalf("saved manifest=%#v", m.project.Manifest())
	}
	if !strings.Contains(strings.Join(m.output, "\n"), "project: saved-as "+destination) {
		t.Fatalf("save-as output=%v", m.output)
	}
	if _, err := workproject.Open(destination); err != nil {
		t.Fatalf("open saved project: %v", err)
	}
}

func TestProjectSaveAsEscCancelsAndRetainsSource(t *testing.T) {
	t.Setenv(paths.EnvConfigDir, t.TempDir())
	project, err := workproject.New(t.TempDir(), "CancelSaveAs")
	if err != nil {
		t.Fatal(err)
	}
	if err := project.Save(); err != nil {
		t.Fatal(err)
	}
	m := NewProjectModel(project, true, 100, 30)
	destination := filepath.Join(t.TempDir(), "Canceled Copy.golan")
	cmd := m.executeProject([]string{"save-as", destination})
	if cmd == nil {
		t.Fatal("save-as did not schedule an effect")
	}
	next, cancelCmd := m.Update(tea.KeyMsg{Type: tea.KeyEsc})
	if cancelCmd != nil {
		t.Fatal("Esc scheduled an unexpected command")
	}
	m = next.(Model)
	if m.saveAsCancel != nil || m.runtimeOperation != projectSaveAsOperation {
		t.Fatalf("cancel request state cancel=%v operation=%q", m.saveAsCancel != nil, m.runtimeOperation)
	}
	next, _ = m.Update(cmd())
	m = next.(Model)
	if m.project != project || m.runtimeOperation != "" || m.project.Path() != project.Path() {
		t.Fatalf("canceled result project=%p source=%p operation=%q path=%q", m.project, project, m.runtimeOperation, m.project.Path())
	}
	if _, err := os.Lstat(destination); !os.IsNotExist(err) {
		t.Fatalf("canceled destination exists: %v", err)
	}
	output := strings.Join(m.output, "\n")
	if !strings.Contains(output, "canceling save-as") || !strings.Contains(output, "save-as canceled; source project and destination remain unchanged") {
		t.Fatalf("cancel output=%s", output)
	}
}

func TestShutdownCancelsUnstartedSaveAsEffect(t *testing.T) {
	t.Setenv(paths.EnvConfigDir, t.TempDir())
	project, err := workproject.New(t.TempDir(), "ShutdownSaveAs")
	if err != nil {
		t.Fatal(err)
	}
	if err := project.Save(); err != nil {
		t.Fatal(err)
	}
	m := NewProjectModel(project, true, 100, 30)
	destination := filepath.Join(t.TempDir(), "Shutdown Copy.golan")
	if cmd := m.executeProject([]string{"save-as", destination}); cmd == nil {
		t.Fatal("save-as did not schedule an effect")
	}
	if err := m.shutdown(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(destination); !os.IsNotExist(err) {
		t.Fatalf("shutdown destination exists: %v", err)
	}
	if m.project != project {
		t.Fatal("shutdown changed the active source project")
	}
}
