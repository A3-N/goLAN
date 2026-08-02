package tui

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golan/internal/listen"
	"golan/internal/paths"
	"golan/internal/policy"
	workproject "golan/internal/project"
)

func TestPolicyHistoryCompareAndRollbackCommands(t *testing.T) {
	m := NewModel()
	first := []policy.Rule{
		{ID: "common", Priority: 20, Enabled: true, Actions: []policy.Action{{Kind: policy.ActionAllow}}},
		{ID: "removed", Priority: 10, Enabled: true, Actions: []policy.Action{{Kind: policy.ActionBlock}}},
	}
	second := []policy.Rule{
		{ID: "common", Priority: 30, Enabled: true, Actions: []policy.Action{{Kind: policy.ActionBlock}}},
		{ID: "added", Priority: 10, Enabled: true, Actions: []policy.Action{{Kind: policy.ActionAllow}}},
	}
	if err := m.commitRules("first", "First", first); err != nil {
		t.Fatal(err)
	}
	if err := m.commitRules("second", "Second", second); err != nil {
		t.Fatal(err)
	}

	m.executeCommand("policy history")
	m.executeCommand("policy compare first second")
	output := strings.Join(m.output, "\n")
	for _, expected := range []string{
		"policy history: active=second revisions=2",
		"* second rules=2 retained",
		"policy compare: first -> second",
		"added: added",
		"removed: removed",
		"changed common: priority,actions",
	} {
		if !strings.Contains(output, expected) {
			t.Fatalf("missing %q in output:\n%s", expected, output)
		}
	}

	m.executeCommand("policy rollback first")
	active, ok := m.policyStore.Active()
	if !ok || active.Revision() != "first" || active.Rules()[0].Actions[0].Kind != policy.ActionAllow {
		t.Fatalf("rollback active=%v revision=%q rules=%#v", ok, active.Revision(), active.Rules())
	}
	if !strings.Contains(strings.Join(m.output, "\n"), "policy: rolled back to first") {
		t.Fatalf("rollback output:\n%s", strings.Join(m.output, "\n"))
	}
}

func TestPolicyRevisionCompletionIncludesHistory(t *testing.T) {
	m := NewModel()
	if err := m.commitRules("baseline", "Baseline", []policy.Rule{{ID: "allow", Enabled: true, Actions: []policy.Action{{Kind: policy.ActionAllow}}}}); err != nil {
		t.Fatal(err)
	}
	m.input = "policy rollback "
	m.refreshCompletions()
	if !containsString(m.completions, "baseline") {
		t.Fatalf("rollback completions = %v", m.completions)
	}
}

func TestProjectRecoversStrictUnindexedPolicyWithoutActivatingIt(t *testing.T) {
	project, err := workproject.New(t.TempDir(), "InterruptedPolicy")
	if err != nil {
		t.Fatal(err)
	}
	if err := project.Save(); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(project.Path(), "policies", "interrupted.json")
	content := []byte("[{\"id\":\"recovered-rule\",\"enabled\":true,\"match\":{},\"actions\":[{\"kind\":\"allow\"}]}]\n")
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}
	m := NewProjectModel(project, true, 100, 30)
	if output := strings.Join(m.output, "\n"); !strings.Contains(output, "policy artifact needs recovery: "+path) {
		t.Fatalf("open recovery report = %q", output)
	}
	m.executeCommand("project recover policy attach recovered " + path)
	if _, active := m.policyStore.Active(); active {
		t.Fatal("recovered policy was activated implicitly")
	}
	retained, ok := m.policyStore.Revision("recovered")
	if !ok || len(retained.Rules()) != 1 || retained.Rules()[0].ID != "recovered-rule" {
		t.Fatalf("recovered retained=%v rules=%#v", ok, retained.Rules())
	}
	manifest := project.Manifest()
	if len(manifest.Policies) != 1 || manifest.Policies[0].Revision != "recovered" || !project.Dirty() {
		t.Fatalf("recovered manifest=%#v dirty=%v", manifest.Policies, project.Dirty())
	}
	if output := strings.Join(m.output, "\n"); !strings.Contains(output, "recovered policy revision=recovered (inactive, PROJECT*)") {
		t.Fatalf("recovery output = %q", output)
	}
	m.executeCommand("policy rollback recovered")
	active, ok := m.policyStore.Active()
	if !ok || active.Revision() != "recovered" || project.Manifest().Preferences.ActivePolicyRevision != "recovered" {
		t.Fatalf("explicit activation active=%v revision=%q preference=%q", ok, active.Revision(), project.Manifest().Preferences.ActivePolicyRevision)
	}
}

func TestProjectPolicyRecoveryRejectsUnknownFieldsButCanArchive(t *testing.T) {
	project, err := workproject.New(t.TempDir(), "UnsafeInterruptedPolicy")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(project.Path(), "policies", "unsafe.json")
	content := []byte(`[{"id":"unsafe","enabled":true,"match":{},"actions":[{"kind":"allow"}],"unknown":true}]`)
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}
	m := NewProjectModel(project, true, 100, 30)
	m.executeCommand("project recover policy attach unsafe " + path)
	if len(project.Manifest().Policies) != 0 {
		t.Fatalf("unsafe policy was indexed: %#v", project.Manifest().Policies)
	}
	if output := strings.Join(m.output, "\n"); !strings.Contains(output, "unknown field") {
		t.Fatalf("strict recovery output = %q", output)
	}
	m.executeCommand("project recover policy archive " + path)
	if _, err := os.Stat(filepath.Join(project.Path(), "policies", "archive", "unsafe.json")); err != nil {
		t.Fatalf("unsafe policy was not archived: %v", err)
	}
}

func TestProjectPolicyRecoveryCompletion(t *testing.T) {
	m := NewModel()
	m.input = "project recover "
	m.refreshCompletions()
	if !containsString(m.completions, "policy") || !containsString(m.completions, "session") {
		t.Fatalf("recovery kind completions = %v", m.completions)
	}
	m.input = "project recover policy "
	m.refreshCompletions()
	if !containsString(m.completions, "attach") || !containsString(m.completions, "archive") {
		t.Fatalf("policy recovery completions = %v", m.completions)
	}
}

func TestProjectRecoversFinalizedSessionCapturesAsynchronously(t *testing.T) {
	project, err := workproject.New(t.TempDir(), "SessionRecovery")
	if err != nil {
		t.Fatal(err)
	}
	if err := project.Save(); err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	path := filepath.Join(directory, "original.pcap")
	if err := os.WriteFile(path, append([]byte{0xd4, 0xc3, 0xb2, 0xa1}, []byte("session")...), 0o600); err != nil {
		t.Fatal(err)
	}
	m := NewProjectModel(project, true, 100, 30)
	cmd := m.executeCommand("project recover session " + directory)
	if cmd == nil || m.runtimeOperation != projectCaptureIndexOperation {
		t.Fatalf("session recovery cmd=%v operation=%q", cmd != nil, m.runtimeOperation)
	}
	if m.allowProjectSwitch() {
		t.Fatal("project switch was allowed during session capture indexing")
	}
	next, _ := m.Update(cmd())
	m = next.(Model)
	manifest := project.Manifest()
	if m.runtimeOperation != "" || len(manifest.Captures) != 1 || manifest.Captures[0].Mode != workproject.ImportCopy || !project.Dirty() {
		t.Fatalf("session recovery operation=%q captures=%#v dirty=%v", m.runtimeOperation, manifest.Captures, project.Dirty())
	}
	if output := strings.Join(m.output, "\n"); !strings.Contains(output, "session captures indexed imported=1 deduplicated=0 failed=0 (PROJECT*)") {
		t.Fatalf("session recovery output = %q", output)
	}
	if cmd := m.executeCommand("project recover session " + directory); cmd != nil {
		t.Fatal("completed session directory was scheduled twice")
	}
}

func TestListenFinalizationAutomaticallyIndexesProjectCapture(t *testing.T) {
	project, err := workproject.New(t.TempDir(), "AutomaticSessionIndex")
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	if err := os.WriteFile(filepath.Join(directory, "host.pcap"), append([]byte{0xd4, 0xc3, 0xb2, 0xa1}, []byte("automatic")...), 0o600); err != nil {
		t.Fatal(err)
	}
	session := &listen.Session{Dir: directory}
	m := NewProjectModel(project, true, 100, 30)
	m.listener = session
	m.capMode = "listen"
	next, cmd := m.Update(listenStoppedMsg{session: session, artifactDir: directory})
	m = next.(Model)
	if cmd == nil {
		t.Fatal("listen finalization did not schedule project indexing")
	}
	next, _ = m.Update(cmd())
	m = next.(Model)
	if len(project.Manifest().Captures) != 1 || m.listener != nil {
		t.Fatalf("automatic captures=%#v listener=%p", project.Manifest().Captures, m.listener)
	}
}

func TestShutdownIndexesRememberedProjectCaptureDirectory(t *testing.T) {
	project, err := workproject.New(t.TempDir(), "ShutdownSessionIndex")
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	if err := os.WriteFile(filepath.Join(directory, "edge.pcap"), append([]byte{0xd4, 0xc3, 0xb2, 0xa1}, []byte("shutdown")...), 0o600); err != nil {
		t.Fatal(err)
	}
	m := NewProjectModel(project, true, 100, 30)
	m.rememberPcapDir(directory)
	if cmd := m.startProjectCaptureIndex(directory); cmd == nil {
		t.Fatal("index command was not scheduled before shutdown")
	}
	if err := m.shutdown(); err != nil {
		t.Fatal(err)
	}
	if len(project.Manifest().Captures) != 1 {
		t.Fatalf("shutdown captures = %#v", project.Manifest().Captures)
	}
}

func TestProjectOpenReportsAssociatedInterruptedSessionAndRecoveryClearsMarker(t *testing.T) {
	t.Setenv(paths.EnvConfigDir, t.TempDir())
	project, err := workproject.New(t.TempDir(), "HardCrashSession")
	if err != nil {
		t.Fatal(err)
	}
	runtimeRoot, err := paths.PcapRoot()
	if err != nil {
		t.Fatal(err)
	}
	directory := filepath.Join(runtimeRoot, "hard-crash")
	if err := os.MkdirAll(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "original.pcap"), append([]byte{0xd4, 0xc3, 0xb2, 0xa1}, []byte("hard-crash")...), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := project.AssociateSession(directory); err != nil {
		t.Fatal(err)
	}
	m := NewProjectModel(project, true, 100, 30)
	if output := strings.Join(m.output, "\n"); !strings.Contains(output, "interrupted live session needs recovery: "+directory) {
		t.Fatalf("interrupted session report = %q", output)
	}
	cmd := m.executeCommand("project recover session " + directory)
	if cmd == nil {
		t.Fatal("interrupted session recovery did not start")
	}
	next, _ := m.Update(cmd())
	m = next.(Model)
	if len(project.Manifest().Captures) != 1 {
		t.Fatalf("hard-crash session captures = %#v", project.Manifest().Captures)
	}
	if got, err := project.RecoverableSessions(); err != nil || len(got) != 0 {
		t.Fatalf("recoverable sessions after import=%v err=%v", got, err)
	}
}

func TestStartupRecentsRenderAndOpenProjectByIndex(t *testing.T) {
	t.Setenv(paths.EnvConfigDir, t.TempDir())
	project, err := workproject.New(t.TempDir(), "RecentWorkbench")
	if err != nil {
		t.Fatal(err)
	}
	if err := project.Save(); err != nil {
		t.Fatal(err)
	}
	if err := workproject.RememberRecentProject(project); err != nil {
		t.Fatal(err)
	}
	m := NewModelWithSize(160, 40)
	next, _ := m.Update(loadRecentsCmd(0)())
	m = next.(Model)
	m.openStartupChooser()
	m.startup.view = startupRecentProjects
	view := m.View()
	for _, expected := range []string{"OPEN RECENT PROJECT", "RecentWorkbench"} {
		if !strings.Contains(view, expected) {
			t.Fatalf("startup view missing %q:\n%s", expected, view)
		}
	}
	m.closeStartupChooser()
	m.executeCommand("project recent")
	if output := strings.Join(m.output, "\n"); !strings.Contains(output, "project 1 RecentWorkbench") || strings.Contains(output, "capture ") {
		t.Fatalf("recent output = %q", output)
	}
	m.executeCommand("project open-recent 1")
	if m.project == nil || m.project.Path() != project.Path() {
		t.Fatalf("opened recent project = %v", m.project)
	}
}

func TestRecentCommandCompletionUsesIndexes(t *testing.T) {
	m := NewModel()
	m.recents = workproject.RecentState{
		Version:  1,
		Projects: []workproject.RecentProject{{Name: "One", Path: "/tmp/One.golan"}, {Name: "Two", Path: "/tmp/Two.golan"}},
	}
	m.input = "project open-recent "
	m.refreshCompletions()
	if !containsString(m.completions, "1") || !containsString(m.completions, "2") {
		t.Fatalf("recent project completions = %v", m.completions)
	}
	m.input = "project import "
	m.refreshCompletions()
	if containsString(m.completions, "recent-pcap") || containsString(m.completions, "pcap") {
		t.Fatalf("retired capture import completions = %v", m.completions)
	}
}

func TestProjectRestoresAndRollsBackActivePolicy(t *testing.T) {
	project, err := workproject.New(t.TempDir(), "PolicyRestore")
	if err != nil {
		t.Fatal(err)
	}
	m := NewProjectModel(project, true, 100, 30)
	first := []policy.Rule{{ID: "allow", Enabled: true, Actions: []policy.Action{{Kind: policy.ActionAllow}}}}
	second := []policy.Rule{{ID: "block", Enabled: true, Actions: []policy.Action{{Kind: policy.ActionBlock}}}}
	if err := m.commitRules("first", "First", first); err != nil {
		t.Fatal(err)
	}
	if err := m.commitRules("second", "Second", second); err != nil {
		t.Fatal(err)
	}
	if err := project.Save(); err != nil {
		t.Fatal(err)
	}

	opened, err := workproject.Open(project.Path())
	if err != nil {
		t.Fatal(err)
	}
	restored := NewProjectModel(opened, true, 100, 30)
	active, ok := restored.policyStore.Active()
	if !ok || active.Revision() != "second" || active.Rules()[0].ID != "block" {
		t.Fatalf("restored active=%v revision=%q rules=%#v output=%v", ok, active.Revision(), active.Rules(), restored.output)
	}
	restored.executeCommand("policy compare first second")
	if _, ok := restored.policyStore.Revision("first"); !ok {
		t.Fatal("comparison did not lazily load the saved first revision")
	}
	restored.executeCommand("policy rollback first")
	active, ok = restored.policyStore.Active()
	if !ok || active.Revision() != "first" || opened.Manifest().Preferences.ActivePolicyRevision != "first" || !opened.Dirty() {
		t.Fatalf("rollback active=%v revision=%q preference=%q dirty=%v", ok, active.Revision(), opened.Manifest().Preferences.ActivePolicyRevision, opened.Dirty())
	}
	if err := opened.Save(); err != nil {
		t.Fatal(err)
	}
	reopened, err := workproject.Open(opened.Path())
	if err != nil {
		t.Fatal(err)
	}
	afterRestart := NewProjectModel(reopened, true, 100, 30)
	active, ok = afterRestart.policyStore.Active()
	if !ok || active.Revision() != "first" {
		t.Fatalf("rollback was not restored after restart: active=%v revision=%q output=%v", ok, active.Revision(), afterRestart.output)
	}
}

func TestProjectRejectsUnknownFieldsInActivePolicyArtifact(t *testing.T) {
	project, err := workproject.New(t.TempDir(), "UnsafePolicy")
	if err != nil {
		t.Fatal(err)
	}
	content := []byte(`[{"id":"bad","enabled":true,"match":{},"actions":[{"kind":"allow"}],"unknown":true}]`)
	if _, err := project.SavePolicyRevision("bad", "Bad", content); err != nil {
		t.Fatal(err)
	}
	if err := project.SetActivePolicyRevision("bad"); err != nil {
		t.Fatal(err)
	}
	if err := project.Save(); err != nil {
		t.Fatal(err)
	}
	opened, err := workproject.Open(project.Path())
	if err != nil {
		t.Fatal(err)
	}
	m := NewProjectModel(opened, true, 100, 30)
	if _, ok := m.policyStore.Active(); ok {
		t.Fatal("unsafe saved policy was activated")
	}
	if output := strings.Join(m.output, "\n"); !strings.Contains(output, "unknown field") {
		t.Fatalf("restore warning = %q", output)
	}
}
