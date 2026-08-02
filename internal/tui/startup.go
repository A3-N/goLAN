package tui

import (
	"fmt"
	"strconv"
	"strings"

	workproject "golan/internal/project"

	tea "github.com/charmbracelet/bubbletea"
)

func loadRecentsCmd(epoch uint64) tea.Cmd {
	return func() tea.Msg {
		state, err := workproject.LoadRecents()
		return recentsLoadedMsg{epoch: epoch, state: state, err: err}
	}
}

func (m *Model) reloadRecents() error {
	m.recentEpoch++
	state, err := workproject.LoadRecents()
	if err != nil {
		m.recentErr = err.Error()
		return err
	}
	m.recents = state
	m.recentErr = ""
	m.refreshCompletions()
	return nil
}

func (m *Model) rememberRecentProject(project *workproject.Project) {
	if err := workproject.RememberRecentProject(project); err != nil {
		m.recentErr = err.Error()
		m.print("project warn: remember recent project: " + err.Error())
		return
	}
	if err := m.reloadRecents(); err != nil {
		m.print("project warn: reload recent items: " + err.Error())
	}
}

func (m *Model) ensureRecents() bool {
	if m.recents.Version != 0 && m.recentErr == "" {
		return true
	}
	if err := m.reloadRecents(); err != nil {
		m.print("project err: recent items " + err.Error())
		return false
	}
	return true
}

func (m *Model) showRecentItems() {
	if !m.ensureRecents() {
		return
	}
	m.print(fmt.Sprintf("recent: projects=%d", len(m.recents.Projects)))
	for index, entry := range m.recents.Projects {
		m.print(fmt.Sprintf("  project %d %s %s%s", index+1, entry.Name, entry.Path, recentMissingLabel(entry.Available)))
	}
}

func (m *Model) openRecentProject(value string) {
	if !m.allowProjectSwitch() || !m.ensureRecents() {
		return
	}
	index, err := recentIndex(value, len(m.recents.Projects))
	if err != nil {
		m.print("project err: open-recent " + err.Error())
		return
	}
	entry := m.recents.Projects[index]
	if !entry.Available {
		m.print("project err: recent project is missing: " + entry.Path)
		return
	}
	project, err := workproject.Open(entry.Path)
	if err != nil {
		m.print("project err: open-recent " + err.Error())
		return
	}
	m.attachProject(project)
	m.rememberRecentProject(project)
	m.workspace = workspaceMain
	m.print("project: open " + project.Path())
	m.reportUnindexedProjectArtifacts()
}

func recentIndex(value string, count int) (int, error) {
	index, err := strconv.Atoi(strings.TrimSpace(value))
	if err != nil || index < 1 || index > count {
		return 0, fmt.Errorf("select an index from 1 to %d", count)
	}
	return index - 1, nil
}

func recentMissingLabel(available bool) string {
	if available {
		return ""
	}
	return " [missing]"
}

func (m Model) recentProjectIndexes() []string {
	result := make([]string, len(m.recents.Projects))
	for index := range m.recents.Projects {
		result[index] = strconv.Itoa(index + 1)
	}
	return result
}
