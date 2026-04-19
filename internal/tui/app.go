package tui

import (
	tea "github.com/charmbracelet/bubbletea"
)

// viewState tracks which view is currently active.
type viewState int

const (
	viewSelector  viewState = iota
	viewDashboard
)

// Model is the root Bubbletea model that manages view routing.
type Model struct {
	view      viewState
	selector  SelectorModel
	dashboard DashboardModel
	width     int
	height    int
	quitting  bool
}

// NewModel creates the root application model.
func NewModel() Model {
	return Model{
		view:     viewSelector,
		selector: NewSelectorModel(),
	}
}

func (m Model) Init() tea.Cmd {
	return m.selector.Init()
}

type teardownDoneMsg struct{}

func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case teardownDoneMsg:
		return m, tea.Quit

	case tea.KeyMsg:
		switch msg.String() {
		case "ctrl+c", "q":
			if m.quitting {
				return m, nil
			}
			m.quitting = true
			if m.view == viewDashboard {
				return m, func() tea.Msg {
					_ = m.dashboard.Shutdown()
					return teardownDoneMsg{}
				}
			}
			return m, tea.Quit
		case "esc":
			if m.quitting {
				return m, nil
			}
			if m.view == viewSelector {
				// Esc on selector = quit.
				m.quitting = true
				return m, tea.Quit
			} else if m.view == viewDashboard {
				// Esc on dashboard = tear down bridge, go back to selector.
				_ = m.dashboard.Shutdown()
				m.view = viewSelector
				m.selector = NewSelectorModel()
				m.selector.width = m.width
				m.selector.height = m.height
				return m, m.selector.Init()
			}
		}

	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
	}

	switch m.view {
	case viewSelector:
		return m.updateSelector(msg)
	case viewDashboard:
		return m.updateDashboard(msg)
	}

	return m, nil
}

func (m Model) updateSelector(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmd tea.Cmd

	// Check if selector produced a result — transition to dashboard.
	if result, ok := msg.(SelectorResult); ok {
		m.view = viewDashboard
		m.dashboard = NewDashboardModel(result.IfaceA, result.IfaceB)
		// Seed the dashboard with the current window size so it doesn't render blank.
		m.dashboard.width = m.width
		m.dashboard.height = m.height
		return m, m.dashboard.Init()
	}

	m.selector, cmd = m.selector.Update(msg)
	return m, cmd
}

func (m Model) updateDashboard(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmd tea.Cmd
	m.dashboard, cmd = m.dashboard.Update(msg)
	return m, cmd
}

func (m Model) View() string {
	if m.quitting {
		return styleDim.Render("\n  Shutting down bridge and restoring settings...\n\n")
	}

	switch m.view {
	case viewSelector:
		return m.selector.View()
	case viewDashboard:
		return m.dashboard.View()
	default:
		return ""
	}
}
