package tui

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	bridge "golan/internal/bridge"
	"golan/internal/canvas"
	"golan/internal/configs"
	"golan/internal/dataplane"
	"golan/internal/policy"
	workproject "golan/internal/project"

	tea "github.com/charmbracelet/bubbletea"
)

func (m *Model) executeProject(args []string) tea.Cmd {
	if len(args) == 0 {
		m.print("use: project new|open|open-recent|recent|config|journals|sessions|save|save-as|close|import|export|recover")
		return nil
	}
	switch strings.ToLower(args[0]) {
	case "new":
		if !m.allowProjectSwitch() {
			return nil
		}
		if len(args) != 2 {
			m.print("use: project new <name>")
			return nil
		}
		project, err := workproject.NewDefault(args[1])
		if err != nil {
			m.print("project err: new " + err.Error())
			return nil
		}
		m.attachProject(project)
		m.workspace = workspaceMain
		m.print("project: new " + project.Path() + " (PROJECT*)")
	case "open":
		if !m.allowProjectSwitch() {
			return nil
		}
		if len(args) != 2 {
			m.print("use: project open <directory.golan>")
			return nil
		}
		project, err := workproject.Open(args[1])
		if err != nil {
			m.print("project err: open " + err.Error())
			return nil
		}
		m.attachProject(project)
		m.rememberRecentProject(project)
		m.workspace = workspaceMain
		m.print("project: open " + project.Path())
		m.reportUnindexedProjectArtifacts()
	case "save":
		if len(args) != 1 || m.project == nil {
			m.print("project err: no active project")
			return nil
		}
		if err := m.project.Save(); err != nil {
			m.print("project err: save " + err.Error())
			return nil
		}
		m.rememberRecentProject(m.project)
		m.print("project: saved " + m.project.Path())
	case "save-as":
		if !m.allowProjectSwitch() {
			return nil
		}
		if len(args) != 2 || m.project == nil {
			m.print("use: project save-as <directory.golan>")
			return nil
		}
		destination, err := filepath.Abs(args[1])
		if err != nil {
			m.print("project err: save-as " + err.Error())
			return nil
		}
		return m.startProjectSaveAs(destination)
	case "recent":
		if len(args) != 1 {
			m.print("use: project recent")
			return nil
		}
		m.showRecentItems()
	case "open-recent":
		if len(args) != 2 {
			m.print("use: project open-recent <index>")
			return nil
		}
		m.openRecentProject(args[1])
	case "sessions":
		m.projectSessionsCommand(args[1:])
	case "config":
		m.projectConfigCommand(args[1:])
	case "journals":
		m.projectCaptureJournalsCommand(args[1:])
	case "close":
		m.closeProjectCommand(args[1:])
	case "import":
		m.importProjectCommand(args[1:])
	case "export":
		return m.exportProjectCommand(args[1:])
	case "recover":
		return m.recoverProjectArtifact(args[1:])
	default:
		m.print("use: project new|open|open-recent|recent|config|journals|sessions|save|save-as|close|import|export|recover")
	}
	return nil
}

func (m *Model) projectCaptureJournalsCommand(args []string) {
	if m.project == nil {
		m.print("project err: no active project")
		return
	}
	if len(args) != 1 || !strings.EqualFold(args[0], "list") {
		m.print("use: project journals list")
		return
	}
	manifest := m.project.Manifest()
	journals := append([]workproject.CaptureJournal(nil), manifest.CaptureJournals...)
	sort.Slice(journals, func(i, j int) bool {
		if journals[i].Mode == journals[j].Mode {
			if journals[i].CaptureID == journals[j].CaptureID {
				return journals[i].ID < journals[j].ID
			}
			return journals[i].CaptureID < journals[j].CaptureID
		}
		return journals[i].Mode < journals[j].Mode
	})
	m.print(fmt.Sprintf("project: capture journals=%d", len(journals)))
	for _, journal := range journals {
		m.print(fmt.Sprintf(
			"  id=%s mode=%s capture=%s records=%d complete=%t sha256=%s",
			journal.ID, journal.Mode, journal.CaptureID, journal.Records, journal.Complete, journal.SHA256,
		))
	}
}

const projectSaveAsOperation = "project save-as"

func (m *Model) startProjectSaveAs(destination string) tea.Cmd {
	if m.project == nil {
		m.print("project err: no active project")
		return nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	m.saveAsCancel = cancel
	m.beginRuntimeOperation(projectSaveAsOperation)
	source := m.project
	m.print("project: save-as staging " + destination + " (Esc cancels)")
	return m.trackEffect(func() tea.Msg {
		next, err := source.SaveAsContext(ctx, filepath.Dir(destination), filepath.Base(destination))
		return projectSaveAsMsg{source: source, next: next, destination: destination, err: err}
	})
}

func (m *Model) applyProjectSaveAs(msg projectSaveAsMsg) {
	if m.saveAsCancel != nil {
		m.saveAsCancel()
		m.saveAsCancel = nil
	}
	m.clearRuntimeOperation(projectSaveAsOperation)
	if msg.next != nil {
		if msg.source != m.project {
			m.print("project warn: save-as completed at " + msg.next.Path() + " but the active project changed; destination was not attached")
			return
		}
		m.attachProject(msg.next)
		m.rememberRecentProject(msg.next)
		if msg.err != nil {
			m.print("project warn: save-as " + msg.err.Error())
			m.print("project: saved-as destination is complete and active " + msg.next.Path())
			return
		}
		m.print("project: saved-as " + msg.next.Path())
		return
	}
	if errors.Is(msg.err, context.Canceled) {
		m.print("project: save-as canceled; source project and destination remain unchanged")
		return
	}
	if msg.err != nil {
		m.print("project err: save-as " + msg.err.Error())
	}
}

func (m *Model) projectConfigCommand(args []string) {
	if m.project == nil {
		m.print("project err: no active project")
		return
	}
	if len(args) == 1 && strings.EqualFold(args[0], "list") {
		manifest := m.project.Manifest()
		m.print(fmt.Sprintf("project: config sources=%d", len(manifest.Configs)))
		for index, source := range manifest.Configs {
			m.print(fmt.Sprintf("  config %d id=%s name=%s sha256=%s source=%s", index+1, source.ID, source.Name, source.SHA256, source.SourcePath))
		}
		return
	}
	switch strings.ToLower(args[0]) {
	case "update":
		if len(args) != 2 {
			m.print("use: project config update <source-id>")
			return
		}
		m.updateProjectConfigSource(args[1])
	case "export":
		if len(args) != 2 {
			m.print("use: project config export <name.json>")
			return
		}
		m.exportProjectConfig(args[1])
	default:
		m.print("use: project config list | project config update <source-id> | project config export <name.json>")
	}
}

func (m *Model) updateProjectConfigSource(id string) {
	if blocker := m.adapterMutationBlocker(); blocker != "" {
		m.print("project err: cannot update config source while " + blocker)
		return
	}
	if pending := m.pendingLocks(); len(pending) > 0 {
		m.print("project err: cannot update config source while adapter isolation is pending or failed: " + strings.Join(pending, ","))
		return
	}
	if len(m.restoreState) > 0 {
		m.print("project err: restore or deselect isolated adapters before updating staged config")
		return
	}
	previous, previousContent, err := m.project.ReadConfigSnapshot(id)
	if err != nil {
		m.print("project err: update config " + err.Error())
		return
	}
	before, err := configs.Decode(previousContent)
	if err != nil {
		m.print("project err: update config existing snapshot: " + err.Error())
		return
	}
	after, _, digest, err := configs.LoadFile(previous.SourcePath)
	if err != nil {
		m.print("project err: update config source: " + err.Error())
		return
	}
	if err := validateProjectConfigSnapshot(after); err != nil {
		m.print("project err: update config source: " + err.Error())
		return
	}
	changes, err := configs.Diff(before, after)
	if err != nil {
		m.print("project err: diff config source: " + err.Error())
		return
	}
	_, current, changed, duplicate, err := m.project.UpdateConfigSource(id, digest)
	if err != nil {
		m.print("project err: update config source: " + err.Error())
		return
	}
	if !changed {
		m.print("project: config source unchanged id=" + previous.ID)
		return
	}
	m.stageProjectConfigSnapshot(after)
	status := "snapshotted"
	if duplicate {
		status = "deduplicated"
	}
	suffix := " (project unchanged)"
	if m.project.Dirty() {
		suffix = " (PROJECT*)"
	}
	m.print(fmt.Sprintf("project: config source %s id=%s previous=%s%s", status, current.ID, previous.ID, suffix))
	m.printConfigDiff(changes)
	m.print("project: editable values staged; live adapter metadata refresh remains deferred until start")
}

func (m *Model) exportProjectConfig(name string) {
	if !m.profile.Ready() {
		m.print("project err: export config requires at least one staged adapter")
		return
	}
	settings := m.snapshotSettings()
	candidate := configs.Snapshot{
		Version:       configs.CurrentVersion,
		ActiveAdapter: m.activeAdapter,
		Profile:       m.profile,
		Settings:      &settings,
	}
	var changes []configs.Change
	existing, _, err := configs.Load(name)
	newFile := errors.Is(err, os.ErrNotExist)
	if err != nil && !newFile {
		m.print("project err: export config: " + err.Error())
		return
	}
	if !newFile {
		changes, err = configs.Diff(existing, candidate)
		if err != nil {
			m.print("project err: export config diff: " + err.Error())
			return
		}
		if len(changes) == 0 {
			m.print("project: config export unchanged: " + name)
			return
		}
	}
	path, err := configs.Save(name, candidate)
	if err != nil {
		m.print("project err: export config: " + err.Error())
		return
	}
	record, importErr := m.project.ImportConfig(path)
	if newFile {
		m.print("config diff: new file")
	} else {
		m.printConfigDiff(changes)
	}
	m.print("project: config exported: " + path)
	if importErr != nil {
		m.print("project warn: exported config could not be snapshotted: " + importErr.Error())
		return
	}
	suffix := " (project unchanged)"
	if m.project.Dirty() {
		suffix = " (PROJECT*)"
	}
	m.print(fmt.Sprintf("project: exported config snapshot id=%s sha256=%s%s", record.ID, record.SHA256, suffix))
}

func (m *Model) printConfigDiff(changes []configs.Change) {
	if len(changes) == 0 {
		m.print("config diff: no editable changes (source metadata changed)")
		return
	}
	m.print(fmt.Sprintf("config diff: %d changes", len(changes)))
	const limit = 48
	for index, change := range changes {
		if index == limit {
			m.print(fmt.Sprintf("  ... %d additional changes", len(changes)-limit))
			break
		}
		before, after := change.Before, change.After
		field := strings.ToLower(change.Field)
		values := strings.ToLower(before + " " + after)
		if configDiffSensitive(field) || strings.Contains(values, `"notes"`) || strings.Contains(values, `"discovered"`) || strings.Contains(values, `"observations"`) {
			before, after = "[redacted]", "[redacted]"
		}
		m.print(fmt.Sprintf("  %s: %s -> %s", change.Field, truncateConfigDiffValue(before), truncateConfigDiffValue(after)))
	}
}

func configDiffSensitive(field string) bool {
	return strings.Contains(field, "notes") || strings.Contains(field, "discovered") || strings.Contains(field, "observations")
}

func truncateConfigDiffValue(value string) string {
	const limit = 160
	runes := []rune(value)
	if len(runes) <= limit {
		return value
	}
	return string(runes[:limit-1]) + "…"
}

func (m *Model) reportUnindexedProjectArtifacts() {
	m.reportUnindexedCaptures()
	m.reportUnindexedPolicies()
	m.reportRecoverableSessions()
}

func (m *Model) reportRecoverableSessions() {
	if m.project == nil {
		return
	}
	if !m.refreshAssociatedSessions() {
		m.print("project warn: scan associated sessions: " + m.projectSessionErr)
		return
	}
	recoverable := 0
	stale := 0
	for _, session := range m.projectSessions {
		if session.Recoverable {
			recoverable++
			m.print("project: interrupted live session needs recovery: " + session.Directory)
		} else {
			stale++
			m.print("project: stale live session marker has no capture: " + session.Directory)
		}
	}
	if recoverable > 0 {
		m.print("project: use project recover session <artifact-directory>")
	}
	if stale > 0 {
		m.print("project: use project sessions archive <artifact-directory> after review")
	}
}

func (m *Model) refreshAssociatedSessions() bool {
	if m.project == nil {
		m.projectSessions = nil
		m.projectSessionErr = ""
		return true
	}
	sessions, err := m.project.AssociatedSessions()
	if err != nil {
		m.projectSessionErr = err.Error()
		return false
	}
	m.projectSessions = sessions
	m.projectSessionErr = ""
	return true
}

func (m *Model) projectSessionsCommand(args []string) {
	if m.project == nil {
		m.print("project err: no active project")
		return
	}
	if len(args) == 1 && strings.EqualFold(args[0], "list") {
		if !m.refreshAssociatedSessions() {
			m.print("project err: sessions " + m.projectSessionErr)
			return
		}
		m.print(fmt.Sprintf("project: associated sessions=%d", len(m.projectSessions)))
		for index, session := range m.projectSessions {
			status := "stale"
			if session.Recoverable {
				status = "recoverable"
			}
			m.print(fmt.Sprintf("  session %d %s %s created=%s", index+1, status, session.Directory, session.CreatedAt.UTC().Format(time.RFC3339)))
		}
		return
	}
	if len(args) < 2 || !strings.EqualFold(args[0], "archive") {
		m.print("use: project sessions list | project sessions archive <artifact-directory>")
		return
	}
	if blocker := m.adapterMutationBlocker(); blocker != "" {
		m.print("project err: cannot archive session marker while " + blocker)
		return
	}
	directory := strings.Join(args[1:], " ")
	destination, err := m.project.ArchiveStaleSessionAssociation(directory)
	if err != nil {
		m.print("project err: archive session marker " + err.Error())
		return
	}
	m.refreshAssociatedSessions()
	m.print("project: stale session marker archived: " + destination)
	m.print("project: runtime artifacts retained: " + directory)
}

func (m *Model) reportUnindexedCaptures() {
	if m.project == nil {
		return
	}
	paths, err := m.project.UnindexedCaptures()
	if err != nil {
		m.print("project warn: scan unindexed captures: " + err.Error())
		return
	}
	for _, path := range paths {
		m.print("project: finalized capture needs recovery: " + path)
	}
	if len(paths) > 0 {
		m.print("project: use project recover attach|archive <capture-path>")
	}
}

func (m *Model) reportUnindexedPolicies() {
	if m.project == nil {
		return
	}
	paths, err := m.project.UnindexedPolicies()
	if err != nil {
		m.print("project warn: scan unindexed policies: " + err.Error())
		return
	}
	for _, path := range paths {
		m.print("project: policy artifact needs recovery: " + path)
	}
	if len(paths) > 0 {
		m.print("project: use project recover policy attach <revision> <path> or project recover policy archive <path>")
	}
}

func (m *Model) recoverProjectArtifact(args []string) tea.Cmd {
	if len(args) == 0 {
		m.print("use: project recover attach|archive <capture-path> | project recover policy attach <revision> <path> | project recover policy archive <path> | project recover session <directory>")
		return nil
	}
	switch strings.ToLower(args[0]) {
	case "attach", "archive":
		m.recoverProjectCapture(args)
	case "policy":
		m.recoverProjectPolicy(args[1:])
	case "session":
		if m.project == nil || len(args) < 2 {
			m.print("use: project recover session <artifact-directory>")
			return nil
		}
		if blocker := m.adapterMutationBlocker(); blocker != "" {
			m.print("project err: cannot recover session while " + blocker)
			return nil
		}
		return m.startProjectCaptureIndex(strings.Join(args[1:], " "))
	default:
		m.print("use: project recover attach|archive <capture-path> | project recover policy attach <revision> <path> | project recover policy archive <path> | project recover session <directory>")
	}
	return nil
}

func (m *Model) recoverProjectCapture(args []string) {
	if m.project == nil || len(args) < 2 {
		m.print("use: project recover attach|archive <capture-path>")
		return
	}
	path := strings.Join(args[1:], " ")
	switch strings.ToLower(args[0]) {
	case "attach":
		record, duplicate, err := m.project.AttachUnindexedCapture(context.Background(), path)
		if err != nil {
			m.print("project err: recover attach " + err.Error())
			return
		}
		if duplicate {
			m.print("project: recovery capture duplicates indexed id=" + record.ID + "; archive it explicitly if no longer needed")
			return
		}
		m.print("project: recovered capture id=" + record.ID + " (PROJECT*)")
	case "archive":
		destination, err := m.project.ArchiveUnindexedCapture(path)
		if err != nil {
			m.print("project err: recover archive " + err.Error())
			return
		}
		m.print("project: capture archived (recoverable): " + destination)
	default:
		m.print("use: project recover attach|archive <capture-path>")
	}
}

func (m *Model) recoverProjectPolicy(args []string) {
	if m.project == nil || len(args) < 2 {
		m.print("use: project recover policy attach <revision> <path> | project recover policy archive <path>")
		return
	}
	switch strings.ToLower(args[0]) {
	case "attach":
		if len(args) < 3 {
			m.print("use: project recover policy attach <revision> <path>")
			return
		}
		revision := args[1]
		path := strings.Join(args[2:], " ")
		if _, retained := m.policyStore.Revision(revision); retained {
			m.print(fmt.Sprintf("project err: recover policy revision %q is already retained; choose a different name", revision))
			return
		}
		content, digest, err := m.project.ReadUnindexedPolicy(path)
		if err != nil {
			m.print("project err: recover policy " + err.Error())
			return
		}
		rules, err := decodePolicyRules(content)
		if err != nil {
			m.print("project err: recover policy " + err.Error())
			return
		}
		if _, err := policy.Compile(revision, rules); err != nil {
			m.print("project err: recover policy " + err.Error())
			return
		}
		record, err := m.project.AttachUnindexedPolicy(path, revision, "Recovered "+revision, digest)
		if err != nil {
			m.print("project err: recover policy " + err.Error())
			return
		}
		if err := m.policyStore.Register(record.Revision, rules); err != nil {
			m.print("project warn: recovered policy was indexed but could not be retained: " + err.Error())
			return
		}
		m.print("project: recovered policy revision=" + record.Revision + " (inactive, PROJECT*)")
		m.print("project: use policy compare or policy rollback " + record.Revision)
	case "archive":
		path := strings.Join(args[1:], " ")
		destination, err := m.project.ArchiveUnindexedPolicy(path)
		if err != nil {
			m.print("project err: recover policy archive " + err.Error())
			return
		}
		m.print("project: policy archived (recoverable): " + destination)
	default:
		m.print("use: project recover policy attach <revision> <path> | project recover policy archive <path>")
	}
}

func (m *Model) closeProjectCommand(args []string) {
	if m.project == nil {
		m.print("project: closed")
		return
	}
	if !m.allowProjectSwitch() {
		return
	}
	choice := workproject.CloseCancel
	if !m.project.Dirty() && len(args) == 0 {
		choice = workproject.CloseDiscard
	} else if len(args) == 1 {
		switch strings.ToLower(args[0]) {
		case "save":
			choice = workproject.CloseSave
		case "discard":
			choice = workproject.CloseDiscard
		case "cancel":
			choice = workproject.CloseCancel
		default:
			m.print("use: project close [save|discard|cancel]")
			return
		}
	} else if m.project.Dirty() {
		m.print("project: unsaved; use: project close save|discard|cancel")
		return
	}
	closed, err := m.project.Close(choice)
	if err != nil {
		m.print("project err: close " + err.Error())
		return
	}
	if closed {
		m.attachProject(nil)
		m.print("project: closed")
	} else {
		m.print("project: close canceled")
	}
}

func (m *Model) importProjectCommand(args []string) {
	if len(args) < 2 {
		m.print("use: project import config|bundle <path> [name]")
		return
	}
	kind := strings.ToLower(args[0])
	if kind == "bundle" {
		if !m.allowProjectSwitch() {
			return
		}
		name := strings.TrimSuffix(filepath.Base(args[1]), filepath.Ext(args[1]))
		if len(args) == 3 {
			name = args[2]
		}
		root, err := workproject.DefaultRoot()
		if err != nil {
			m.print("project err: import bundle " + err.Error())
			return
		}
		project, report, err := workproject.ImportBundleWithReport(context.Background(), args[1], root, name)
		if err != nil {
			m.print("project err: import bundle " + err.Error())
			return
		}
		m.attachProject(project)
		m.rememberRecentProject(project)
		m.print("project: imported bundle " + project.Path())
		m.printBundleReport("import", report)
		m.reportUnindexedProjectArtifacts()
		return
	}
	if m.project == nil {
		m.print("project err: no active project")
		return
	}
	switch kind {
	case "config":
		record, err := m.project.ImportConfig(args[1])
		if err != nil {
			m.print("project err: import config " + err.Error())
			return
		}
		m.print("project: config imported sha256=" + record.SHA256)
	default:
		m.print("use: project import config|bundle <path> [name]")
	}
}

func (m *Model) exportProjectCommand(args []string) tea.Cmd {
	if m.project == nil {
		m.print("project err: no active project")
		return nil
	}
	if len(args) == 1 && strings.EqualFold(args[0], "bundle") {
		m.openBundleExport()
		return nil
	}
	if len(args) < 2 || strings.ToLower(args[0]) != "bundle" || len(args) > 3 {
		m.print("use: project export bundle [<path.golanproj> [full|metadata|sanitized]]")
		return nil
	}
	kind := workproject.BundleFull
	if len(args) == 3 {
		kind = workproject.BundleKind(strings.ToLower(args[2]))
	}
	return m.startBundleExport(args[1], kind, nil, false)
}

func (m *Model) executePolicy(args []string) tea.Cmd {
	if len(args) == 0 {
		m.print("use: policy use|history|compare|rollback ...")
		return nil
	}
	switch strings.ToLower(args[0]) {
	case "use":
		if len(args) != 2 {
			m.print("use: policy use <preset>")
			return nil
		}
		rules, err := policy.Preset(args[1])
		if err != nil {
			m.print("policy err: " + err.Error())
			return nil
		}
		revision := strings.ToLower(strings.ReplaceAll(args[1], " ", "-"))
		if err := m.commitRules(revision, "Preset "+args[1], rules); err != nil {
			m.print("policy err: " + err.Error())
			return nil
		}
		m.workspace = workspaceRules
		m.print("policy: active " + revision)
	case "history":
		if len(args) != 1 {
			m.print("use: policy history")
			return nil
		}
		m.showPolicyHistory()
	case "compare":
		if len(args) == 2 {
			active, ok := m.policyStore.Active()
			if !ok {
				m.print("policy err: compare requires an active revision or two revision names")
				return nil
			}
			m.showPolicyComparison(active.Revision(), args[1])
		} else if len(args) == 3 {
			m.showPolicyComparison(args[1], args[2])
		} else {
			m.print("use: policy compare [from-revision] <to-revision>")
		}
	case "rollback":
		if len(args) != 2 {
			m.print("use: policy rollback <revision>")
			return nil
		}
		m.rollbackPolicy(args[1])
	default:
		m.print("use: policy use|history|compare|rollback ...")
	}
	return nil
}

func (m *Model) executeDelete(args []string) tea.Cmd {
	if len(args) != 2 || strings.ToLower(args[0]) != "rule" {
		m.print("use: delete rule <id>")
		return nil
	}
	return m.mutateRule(args[1], "delete")
}

func (m *Model) mutateRule(id, operation string) tea.Cmd {
	revision, ok := m.policyStore.Active()
	if !ok {
		m.print("policy err: no active revision")
		return nil
	}
	rules := revision.Rules()
	found := false
	var next []policy.Rule
	for _, rule := range rules {
		if rule.ID != id {
			next = append(next, rule)
			continue
		}
		found = true
		switch operation {
		case "enable":
			rule.Enabled = true
			rule.Revision++
			next = append(next, rule)
		case "disable":
			rule.Enabled = false
			rule.Revision++
			next = append(next, rule)
		case "delete":
		}
	}
	if !found {
		m.print("policy err: rule " + id + " not found")
		return nil
	}
	nextRevision := revision.Revision() + "-edit"
	if err := m.commitRules(nextRevision, nextRevision, next); err != nil {
		m.print("policy err: " + err.Error())
		return nil
	}
	m.print(fmt.Sprintf("rule: %s %s", id, operation))
	return nil
}

func (m *Model) commitRules(revision, name string, rules []policy.Rule) error {
	if _, err := policy.Compile(revision, rules); err != nil {
		return err
	}
	content, err := json.MarshalIndent(rules, "", "  ")
	if err != nil {
		return err
	}
	if m.project != nil {
		if _, err := m.project.SavePolicyRevision(revision, name, append(content, '\n')); err != nil {
			return err
		}
	}
	if err := m.policyStore.Register(revision, rules); err != nil {
		return err
	}
	if err := m.applyPolicyToRuntime(revision, rules); err != nil {
		return err
	}
	if err := m.policyStore.ActivateRevision(revision); err != nil {
		return err
	}
	if m.project != nil {
		if err := m.project.SetActivePolicyRevision(revision); err != nil {
			return err
		}
	}
	return nil
}

func (m *Model) executeCanvas(args []string) tea.Cmd {
	if len(args) == 0 {
		m.print("use: canvas build [session-id] | canvas auto-layout | canvas reset-generated confirm | canvas snapshot <destination.canvas>")
		return nil
	}
	switch strings.ToLower(args[0]) {
	case "build":
		m.buildNetworkCanvas(args[1:])
		return nil
	case "auto-layout":
		if len(args) != 1 {
			m.print("use: canvas auto-layout")
			return nil
		}
		m.buildNetworkCanvas(nil)
		return nil
	case "reset-generated":
		if len(args) != 2 || !strings.EqualFold(args[1], "confirm") {
			m.print("use: canvas reset-generated confirm")
			return nil
		}
		m.canvasMap = canvas.NewMap()
		m.canvasDirty = true
		m.print("canvas: generated network observations reset")
		return nil
	case "snapshot":
		if len(args) != 2 {
			m.print("use: canvas snapshot <destination.canvas>")
			return nil
		}
		if m.canvasMap == nil || len(m.canvasMap.Hosts) == 0 {
			m.print("canvas err: build from Network observations first")
			return nil
		}
		if err := m.canvasMap.WriteFile(args[1]); err != nil {
			m.print("canvas err: export " + err.Error())
			return nil
		}
		m.print("canvas: exported " + args[1])
		return nil
	default:
		m.print("use: canvas build [session-id] | canvas auto-layout | canvas reset-generated confirm | canvas snapshot <destination.canvas>")
		return nil
	}
}

func (m *Model) showProject() {
	if m.project == nil {
		m.print("project: none")
		return
	}
	manifest := m.project.Manifest()
	state := "saved"
	if m.project.Dirty() {
		state = "PROJECT*"
	}
	m.print(fmt.Sprintf("project: %s %s", manifest.Name, state))
	m.print("  path: " + m.project.Path())
	m.print(fmt.Sprintf(
		"  configs=%d policies=%d captures=%d capture-journals=%d network-sessions=%d",
		len(manifest.Configs),
		len(manifest.Policies),
		len(manifest.Captures),
		len(manifest.CaptureJournals),
		len(manifest.NetworkSessions),
	))
}

func (m *Model) showRules() {
	revision, ok := m.policyStore.Active()
	if !ok {
		m.print("rules: none")
		return
	}
	capabilities := m.currentCapabilities()
	m.print(fmt.Sprintf("rules: revision=%s mode=%s", revision.Revision(), capabilities.Mode()))
	for _, rule := range revision.Rules() {
		status, required, reason := m.compatibilityForCapabilities(rule, capabilities)
		line := fmt.Sprintf("  %s %s enabled=%v priority=%d requires=%s", status, rule.ID, rule.Enabled, rule.Priority, required)
		if reason != "" {
			line += " " + reason
		}
		m.print(line)
	}
	diagnostics := revision.Diagnostics(capabilities)
	if len(diagnostics) == 0 {
		m.print("  diagnostics: none")
		return
	}
	for _, diagnostic := range diagnostics {
		m.print("  " + diagnostic.String())
	}
}

func (m Model) currentCapabilities() dataplane.Capabilities {
	switch {
	case m.edgeMode == "observe":
		return dataplane.ForMode(dataplane.ModeEdgeObserve)
	case m.edgeMode == "route":
		return dataplane.ForMode(dataplane.ModeEdgeRoute)
	case m.natActive && m.bridge != nil && m.bridge.NATSnapshot().Active:
		return dataplane.ForMode(dataplane.ModeNAT)
	case m.bridge != nil && m.bridgeMode == "controlled":
		return dataplane.ForMode(dataplane.ModeControlledBridge)
	case m.bridge != nil:
		return dataplane.ForMode(dataplane.ModeFastBridge)
	case m.listener != nil:
		return dataplane.ForMode(dataplane.ModeListen)
	case m.offline:
		capabilities, _ := dataplane.New(dataplane.Mode("offline"), map[dataplane.Capability]dataplane.Status{
			dataplane.CapabilityObserve: dataplane.StatusUnsupported,
		})
		return capabilities
	default:
		return dataplane.ForMode(dataplane.ModeListen)
	}
}

func (m *Model) showEdge() {
	state := "off"
	if m.edgeMode != "" {
		state = "on " + m.edgeMode
	}
	m.print("edge state: " + state)
	m.print(fmt.Sprintf("  next mode=%s upstream=%s", m.edgeConfiguredMode, m.edgeUpstream))
	for _, forward := range m.edgeForwards {
		m.print(fmt.Sprintf("  forward %s/%d -> client:%d", forward.Protocol, forward.ListenPort, forward.TargetPort))
	}
}

func (m *Model) showNAT() {
	state := "off"
	var snapshot bridge.NATSnapshot
	if m.bridge != nil {
		snapshot = m.bridge.NATSnapshot()
	}
	if snapshot.Active {
		state = "on"
	} else if snapshot.CleanupPending {
		state = "cleanup-pending"
	}
	m.print("nat state: " + state)
	if !snapshot.Active && !snapshot.CleanupPending {
		return
	}
	m.print(fmt.Sprintf(
		"  endpoint=%s address=%s pf-anchor=%s pf-endpoint=%t pf-restore=%t l2-endpoint=%t l2-restore=%t",
		snapshot.BridgeName, snapshot.AddressMode, snapshot.PFAnchor,
		snapshot.PFEndpointRules, snapshot.PFRestorationOwned,
		snapshot.L2EndpointRules, snapshot.L2RestorationOwned,
	))
	revision := snapshot.PolicyRevision
	if revision == "" {
		revision = "none"
	}
	m.print(fmt.Sprintf(
		"  policy=%s live=%d shadow=%d unsupported=%d",
		revision, snapshot.LivePolicyRules,
		snapshot.ShadowPolicyRules, snapshot.UnsupportedPolicyRules,
	))
}

func (m *Model) activeBridgeRules() (string, []policy.Rule) {
	rules := policy.BuiltinEAPOLRules(m.eapolSuppressLogoff, m.eapolDowngradeMACsec)
	revision := "builtins"
	if m.policyStore != nil {
		if active, ok := m.policyStore.Active(); ok {
			revision = active.Revision()
			rules = append(rules, active.Rules()...)
		}
	}
	return revision, rules
}
