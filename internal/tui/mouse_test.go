package tui

import (
	"strings"
	"testing"
	"time"

	networkobs "golan/internal/network"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

func TestWorkspaceTabsWrapAndRemainClickable(t *testing.T) {
	for _, width := range []int{160, 100, 70, 30} {
		m := NewModelWithSize(width, 32)
		geometry := m.workbenchGeometry()
		if len(geometry.Tabs) != 3 || len(geometry.Tabs) != len(workspaces) {
			t.Fatalf("width=%d tab count=%d want=3", width, len(geometry.Tabs))
		}
		for _, tab := range geometry.Tabs {
			if tab.Rect.X < geometry.Margin ||
				tab.Rect.X+tab.Rect.Width > geometry.Margin+geometry.ContentWidth ||
				tab.Rect.Y < 1 || tab.Rect.Y >= geometry.MainY {
				t.Fatalf("width=%d tab=%q rect=%#v geometry=%#v", width, tab.Workspace, tab.Rect, geometry)
			}
		}
		if got, want := lipgloss.Height(m.renderTabs(geometry.ContentWidth)), geometry.MainY-1; got != want {
			t.Fatalf("width=%d tab height=%d want=%d", width, got, want)
		}
	}
}

func TestClickingEveryWorkspaceTabSwitchesAndRestoresLayout(t *testing.T) {
	m := NewModelWithSize(100, 30)
	for _, target := range workspaces {
		m.maximized = true
		tab, ok := tabForWorkspace(m.workbenchGeometry(), target)
		if !ok {
			t.Fatalf("missing tab for %q", target)
		}
		m = updateMouseModel(t, m, tea.MouseEvent{
			X: tab.Rect.X + tab.Rect.Width/2, Y: tab.Rect.Y,
			Action: tea.MouseActionPress, Button: tea.MouseButtonLeft,
		})
		if m.workspace != target || m.maximized {
			t.Fatalf("tab %q selected workspace=%q maximized=%t", target, m.workspace, m.maximized)
		}
	}
}

func TestWorkspacesOwnOnlyContractPanes(t *testing.T) {
	tests := []struct {
		workspace workspace
		cards     []cardFocus
	}{
		{workspaceMain, []cardFocus{cardOutput, cardCLI}},
		{workspaceNetwork, []cardFocus{cardOutput, cardInspector}},
		{workspaceRules, []cardFocus{cardOutput, cardInspector}},
	}
	for _, width := range []int{180, 70, 40} {
		for _, test := range tests {
			m := NewModelWithSize(width, 40)
			m.workspace = test.workspace
			geometry := m.workbenchGeometry()
			if len(geometry.Panes) != len(test.cards) {
				t.Fatalf("width=%d workspace=%s panes=%#v want=%#v", width, test.workspace, geometry.Panes, test.cards)
			}
			for _, card := range test.cards {
				if _, ok := paneForCard(geometry, card); !ok {
					t.Fatalf("width=%d workspace=%s missing card=%v", width, test.workspace, card)
				}
			}
			if test.workspace != workspaceMain {
				if _, ok := paneForCard(geometry, cardCLI); ok {
					t.Fatalf("width=%d workspace=%s exposed Main CLI", width, test.workspace)
				}
			}
		}
	}
}

func TestEveryWorkspaceUsesFlatWorkbenchChrome(t *testing.T) {
	for _, candidate := range workspaces {
		m := NewModelWithSize(180, 40)
		m.workspace = candidate
		m.activeCard = cardOutput
		geometry := m.workbenchGeometry()
		view := m.View()
		activeTab := "[" + workspaceShortcutLabel(candidate) + " " + string(candidate) + "]"
		if !strings.Contains(view, "goLAN") || !strings.Contains(view, "WORKBENCH") || !strings.Contains(view, activeTab) {
			t.Fatalf("workspace=%s missing chrome:\n%s", candidate, view)
		}
		if strings.ContainsAny(view, "╭╮╰╯") {
			t.Fatalf("workspace=%s retained rounded chrome:\n%s", candidate, view)
		}
		if got := paneHeaderCount(view); got != len(geometry.Panes) {
			t.Fatalf("workspace=%s pane headers=%d want=%d:\n%s", candidate, got, len(geometry.Panes), view)
		}
	}
}

func TestMouseClickSelectsNetworkDeviceBeforeFullscreen(t *testing.T) {
	m := NewModelWithSize(180, 40)
	m.workspace = workspaceNetwork
	m.activeCard = cardOutput
	devices := []networkobs.Device{
		{Key: "en0/02:00:00:00:00:01", MAC: "02:00:00:00:00:01", Adapter: "en0", FirstSeen: time.Unix(1, 0), LastSeen: time.Unix(1, 0)},
		{Key: "en0/02:00:00:00:00:02", MAC: "02:00:00:00:00:02", Adapter: "en0", FirstSeen: time.Unix(2, 0), LastSeen: time.Unix(2, 0)},
		{Key: "en0/02:00:00:00:00:03", MAC: "02:00:00:00:00:03", Adapter: "en0", FirstSeen: time.Unix(3, 0), LastSeen: time.Unix(3, 0)},
	}
	m.networkTracker = networkobs.LoadTracker(networkobs.Session{ID: "mouse", Mode: "listen", StartedAt: time.Unix(1, 0), Devices: devices})
	m.ensureNetworkSelection()
	output, ok := paneForCard(m.workbenchGeometry(), cardOutput)
	if !ok {
		t.Fatal("Network device pane is missing")
	}
	m = updateMouseModel(t, m, tea.MouseEvent{
		X: output.Rect.X + 4, Y: output.Rect.Y + 4,
		Action: tea.MouseActionPress, Button: tea.MouseButtonLeft,
	})
	want := m.networkDevices()[1].Key
	if m.selectedNetworkDevice != want || !m.maximized {
		t.Fatalf("selected=%s want=%s maximized=%t", m.selectedNetworkDevice, want, m.maximized)
	}
}

func TestMouseHoverFocusesClickMaximizesAndTabRestores(t *testing.T) {
	m := NewModelWithSize(160, 40)
	m.workspace = workspaceNetwork
	inspector, ok := paneForCard(m.workbenchGeometry(), cardInspector)
	if !ok {
		t.Fatal("desktop Inspector is missing")
	}
	x, y := rectCenter(inspector.Rect)
	m = updateMouseModel(t, m, tea.MouseEvent{X: x, Y: y, Action: tea.MouseActionMotion})
	if m.activeCard != cardInspector || m.maximized {
		t.Fatalf("hover card=%v maximized=%t", m.activeCard, m.maximized)
	}
	m = updateMouseModel(t, m, tea.MouseEvent{X: x, Y: y, Action: tea.MouseActionPress, Button: tea.MouseButtonLeft})
	if m.activeCard != cardInspector || !m.maximized {
		t.Fatalf("click card=%v maximized=%t", m.activeCard, m.maximized)
	}
	if panes := m.workbenchGeometry().Panes; len(panes) != 1 || panes[0].Card != cardInspector {
		t.Fatalf("maximized panes=%#v", panes)
	}
	tab, _ := tabForWorkspace(m.workbenchGeometry(), workspaceNetwork)
	m = updateMouseModel(t, m, tea.MouseEvent{X: tab.Rect.X + 1, Y: tab.Rect.Y, Action: tea.MouseActionPress, Button: tea.MouseButtonLeft})
	if m.maximized || paneHeaderCount(m.View()) != 2 {
		t.Fatalf("active tab did not restore two-pane Live layout:\n%s", m.View())
	}
}

func TestEveryContractPaneCanRenderFullscreen(t *testing.T) {
	tests := []struct {
		workspace workspace
		card      cardFocus
	}{{workspaceMain, cardOutput}, {workspaceMain, cardCLI}, {workspaceNetwork, cardOutput}, {workspaceNetwork, cardInspector}, {workspaceRules, cardInspector}}
	for _, test := range tests {
		m := NewModelWithSize(160, 40)
		m.workspace, m.activeCard, m.maximized = test.workspace, test.card, true
		geometry := m.workbenchGeometry()
		if len(geometry.Panes) != 1 || geometry.Panes[0].Card != test.card {
			t.Fatalf("workspace=%s card=%v panes=%#v", test.workspace, test.card, geometry.Panes)
		}
		if got := lipgloss.Height(m.View()); got > m.height {
			t.Fatalf("workspace=%s card=%v height=%d terminal=%d", test.workspace, test.card, got, m.height)
		}
	}
}

func paneHeaderCount(view string) int {
	return strings.Count(view, "▌") + strings.Count(view, "▏")
}

func TestMouseWheelOperatesOnPaneUnderPointer(t *testing.T) {
	m := NewModelWithSize(160, 40)
	for range 100 {
		m.print("scrollable output")
	}
	output, _ := paneForCard(m.workbenchGeometry(), cardOutput)
	x, y := rectCenter(output.Rect)
	m = updateMouseModel(t, m, tea.MouseEvent{X: x, Y: y, Action: tea.MouseActionPress, Button: tea.MouseButtonWheelUp})
	if m.activeCard != cardOutput || m.outputScroll != 1 || m.maximized {
		t.Fatalf("wheel card=%v scroll=%d maximized=%t", m.activeCard, m.outputScroll, m.maximized)
	}
}

func TestHiddenInspectorIsNotMouseTarget(t *testing.T) {
	m := NewModelWithSize(160, 40)
	m.workspace = workspaceNetwork
	m.inspectorVisible = false
	geometry := m.workbenchGeometry()
	if _, ok := paneForCard(geometry, cardInspector); ok || len(geometry.Panes) != 1 {
		t.Fatalf("hidden Inspector panes=%#v", geometry.Panes)
	}
}

func TestModalMouseDoesNotActivateUnderlyingWorkbench(t *testing.T) {
	m := NewModelWithSize(100, 30)
	m.openHelp()
	beforeWorkspace, beforeCard := m.workspace, m.activeCard
	tab, _ := tabForWorkspace(m.workbenchGeometry(), workspaceRules)
	m = updateMouseModel(t, m, tea.MouseEvent{X: tab.Rect.X + 1, Y: tab.Rect.Y, Action: tea.MouseActionPress, Button: tea.MouseButtonLeft})
	if m.workspace != beforeWorkspace || m.activeCard != beforeCard || !m.help.open {
		t.Fatalf("modal click workspace=%q card=%v help=%t", m.workspace, m.activeCard, m.help.open)
	}
	m = updateMouseModel(t, m, tea.MouseEvent{X: 1, Y: 4, Action: tea.MouseActionPress, Button: tea.MouseButtonWheelDown})
	if m.help.scroll != 1 {
		t.Fatalf("help wheel scroll=%d", m.help.scroll)
	}
}

func TestHelpDisclosureRowsAreClickable(t *testing.T) {
	m := NewModelWithSize(100, 30)
	m.openHelp()
	document := helpTreeDocument(m.help)
	wantID := helpCategoryID("Navigation")
	row := -1
	for index, line := range document {
		if line.ID == wantID {
			row = index
			break
		}
	}
	if row < 0 {
		t.Fatal("Navigation help category is missing")
	}
	m = updateMouseModel(t, m, tea.MouseEvent{X: 2, Y: row + 1, Action: tea.MouseActionPress, Button: tea.MouseButtonLeft})
	if m.help.selected != wantID || !m.help.expanded[wantID] || !strings.Contains(m.renderHelp(), "[-] Navigation") {
		t.Fatalf("click did not expand Navigation: help=%#v\n%s", m.help, m.renderHelp())
	}
}

func TestCellRectUsesHalfOpenBoundaries(t *testing.T) {
	rect := cellRect{X: 2, Y: 3, Width: 4, Height: 5}
	for _, point := range [][2]int{{2, 3}, {5, 7}} {
		if !rect.contains(point[0], point[1]) {
			t.Fatalf("expected point %v inside %#v", point, rect)
		}
	}
	for _, point := range [][2]int{{1, 3}, {6, 3}, {2, 2}, {2, 8}} {
		if rect.contains(point[0], point[1]) {
			t.Fatalf("expected point %v outside %#v", point, rect)
		}
	}
}

func updateMouseModel(t *testing.T, model Model, event tea.MouseEvent) Model {
	t.Helper()
	next, _ := model.Update(tea.MouseMsg(event))
	got, ok := next.(Model)
	if !ok {
		t.Fatalf("mouse update returned %T", next)
	}
	return got
}

func paneForCard(geometry workbenchGeometry, card cardFocus) (paneCell, bool) {
	for _, pane := range geometry.Panes {
		if pane.Card == card {
			return pane, true
		}
	}
	return paneCell{}, false
}

func tabForWorkspace(geometry workbenchGeometry, target workspace) (workspaceTabCell, bool) {
	for _, tab := range geometry.Tabs {
		if tab.Workspace == target {
			return tab, true
		}
	}
	return workspaceTabCell{}, false
}

func rectCenter(rect cellRect) (int, int) {
	return rect.X + rect.Width/2, rect.Y + rect.Height/2
}
