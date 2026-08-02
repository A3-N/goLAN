package tui

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golan/internal/paths"
	workproject "golan/internal/project"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

func TestBundleExportModalSelectsCapturesAndReportsInventory(t *testing.T) {
	t.Setenv(paths.EnvConfigDir, t.TempDir())
	project, err := workproject.New(t.TempDir(), "BundleModal")
	if err != nil {
		t.Fatal(err)
	}
	first := importModalCapture(t, project, "first.pcap", append([]byte{0xd4, 0xc3, 0xb2, 0xa1}, []byte("first")...))
	second := importModalCapture(t, project, "second.pcapng", append([]byte{0x0a, 0x0d, 0x0d, 0x0a}, []byte("second")...))
	if err := project.Save(); err != nil {
		t.Fatal(err)
	}

	m := NewProjectModel(project, true, 100, 30)
	m.workspace = workspaceMain
	m.openBundleExport()
	if !m.bundleExport.open || m.bundleExport.view != bundleExportPath || !strings.Contains(m.View(), "EXPORT PORTABLE BUNDLE") {
		t.Fatalf("bundle modal state=%#v\n%s", m.bundleExport, m.View())
	}
	destination := filepath.Join(t.TempDir(), "selected.golanproj")
	m.bundleExport.input = destination
	m = bundleKey(t, m, tea.KeyMsg{Type: tea.KeyEnter})
	m = bundleKey(t, m, tea.KeyMsg{Type: tea.KeyEnter})
	if m.bundleExport.view != bundleExportCaptures || len(m.bundleExport.selected) != 2 {
		t.Fatalf("capture selection state=%#v", m.bundleExport)
	}
	m = bundleKey(t, m, tea.KeyMsg{Type: tea.KeyDown})
	m = bundleKey(t, m, tea.KeyMsg{Type: tea.KeySpace})
	if !m.bundleExport.selected[first.ID] || m.bundleExport.selected[second.ID] {
		t.Fatalf("selected captures=%v", m.bundleExport.selected)
	}

	m, cmd := bundleEffectKey(t, m, tea.KeyMsg{Type: tea.KeyEnter})
	if m.runtimeOperation != bundleExportOperation {
		t.Fatalf("runtime operation=%q", m.runtimeOperation)
	}
	m = applyBundleEffect(t, m, cmd)
	if m.bundleExport.view != bundleExportReport || m.runtimeOperation != "" {
		t.Fatalf("bundle result state=%#v operation=%q", m.bundleExport, m.runtimeOperation)
	}
	view := m.View()
	for _, want := range []string{"BUNDLE EXPORT REPORT", "1 included", "1 omitted", first.ID, second.ID} {
		if !strings.Contains(view, want) {
			t.Fatalf("bundle report missing %q:\n%s", want, view)
		}
	}
	output := strings.Join(m.output, "\n")
	if !strings.Contains(output, "captures-included=1/2") || !strings.Contains(output, "omitted capture ids="+second.ID) {
		t.Fatalf("bundle output report=%s", output)
	}

	imported, report, err := workproject.ImportBundleWithReport(context.Background(), destination, t.TempDir(), "ModalImport")
	if err != nil {
		t.Fatal(err)
	}
	manifest := imported.Manifest()
	if len(manifest.Captures) != 1 || manifest.Captures[0].ID != first.ID || len(report.IncludedCaptures) != 1 {
		t.Fatalf("imported manifest=%#v report=%#v", manifest, report)
	}
}

func TestBundleExportModalKindsHelpAndSmallTerminal(t *testing.T) {
	t.Setenv(paths.EnvConfigDir, t.TempDir())
	project, err := workproject.New(t.TempDir(), "BundleModalSmall")
	if err != nil {
		t.Fatal(err)
	}
	if err := project.Save(); err != nil {
		t.Fatal(err)
	}
	m := NewProjectModel(project, true, 42, 12)
	m.workspace = workspaceMain
	m.openBundleExport()
	m.bundleExport.input = filepath.Join(t.TempDir(), "metadata.golanproj")
	m = bundleKey(t, m, tea.KeyMsg{Type: tea.KeyEnter})
	if view := m.View(); lipgloss.Width(view) > 42 || lipgloss.Height(view) > 12 {
		t.Fatalf("small bundle modal exceeds terminal: %dx%d\n%s", lipgloss.Width(view), lipgloss.Height(view), view)
	}
	m = bundleKey(t, m, tea.KeyMsg{Type: tea.KeyF1})
	if !m.help.open || !m.bundleExport.open {
		t.Fatal("help did not retain bundle export modal")
	}
	m = bundleKey(t, m, tea.KeyMsg{Type: tea.KeyF1})
	if m.help.open || !strings.Contains(m.View(), "BUNDLE EVIDENCE LEVEL") {
		t.Fatal("help did not restore bundle export modal")
	}
	m = bundleKey(t, m, tea.KeyMsg{Type: tea.KeyDown})
	if bundleKinds[m.bundleExport.kindCursor] != workproject.BundleMetadata {
		t.Fatalf("bundle kind cursor=%d", m.bundleExport.kindCursor)
	}
}

func importModalCapture(t *testing.T, project *workproject.Project, name string, content []byte) workproject.Capture {
	t.Helper()
	directory := t.TempDir()
	path := filepath.Join(directory, name)
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}
	results, err := project.ImportSessionCaptures(context.Background(), directory)
	if err != nil || len(results) != 1 || results[0].Err != nil || results[0].Duplicate {
		t.Fatalf("index session captures=%#v err=%v", results, err)
	}
	return results[0].Capture
}

func bundleKey(t *testing.T, m Model, key tea.KeyMsg) Model {
	t.Helper()
	next, cmd := m.Update(key)
	if cmd != nil {
		t.Fatalf("bundle key %q unexpectedly scheduled a command", key.String())
	}
	return next.(Model)
}

func bundleEffectKey(t *testing.T, m Model, key tea.KeyMsg) (Model, tea.Cmd) {
	t.Helper()
	next, cmd := m.Update(key)
	if cmd == nil {
		t.Fatalf("bundle key %q did not schedule a command", key.String())
	}
	return next.(Model), cmd
}

func applyBundleEffect(t *testing.T, m Model, cmd tea.Cmd) Model {
	t.Helper()
	next, _ := m.Update(cmd())
	return next.(Model)
}
