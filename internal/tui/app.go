package tui

import (
	"math/rand"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// viewState tracks which view is currently active.
type viewState int

const (
	viewSelector viewState = iota
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

	shutdownFrame  int
	shutdownPhrase int
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
type returnToSelectorMsg struct{}
type shutdownTickMsg struct {
	phrase int
}

const (
	dashboardShutdownTimeout = 20 * time.Second
	shutdownTickInterval     = 120 * time.Millisecond
)

var (
	shutdownFrames  = []string{"|", "/", "-", "\\"}
	shutdownPhrases = []string{
		"Restoring interface state",
		"Removing bridge members",
		"Flushing NAT and bridge rules",
		"Waiting for cleanup hooks",
		"Returning adapters to baseline",
	}
)

func dashboardShutdownCmd(dashboard DashboardModel, next tea.Msg) tea.Cmd {
	return func() tea.Msg {
		done := make(chan struct{})
		go func() {
			_ = dashboard.Shutdown()
			close(done)
		}()
		select {
		case <-done:
			return next
		case <-time.After(dashboardShutdownTimeout):
			return next
		}
	}
}

func shutdownTickCmd() tea.Cmd {
	return tea.Tick(shutdownTickInterval, func(time.Time) tea.Msg {
		return shutdownTickMsg{
			phrase: rand.Intn(len(shutdownPhrases)),
		}
	})
}

func shutdownCmd(dashboard DashboardModel, next tea.Msg) tea.Cmd {
	return tea.Batch(dashboardShutdownCmd(dashboard, next), shutdownTickCmd())
}

func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case teardownDoneMsg:
		return m, tea.Quit

	case returnToSelectorMsg:
		m.view = viewSelector
		m.selector = NewSelectorModel()
		m.selector.width = m.width
		m.selector.height = m.height
		m.quitting = false
		m.shutdownFrame = 0
		m.shutdownPhrase = 0
		return m, m.selector.Init()

	case shutdownTickMsg:
		if !m.quitting {
			return m, nil
		}
		m.shutdownFrame++
		m.shutdownPhrase = msg.phrase
		return m, shutdownTickCmd()

	case tea.KeyMsg:
		switch msg.String() {
		case "ctrl+c", "q":
			if m.quitting {
				return m, nil
			}
			m.quitting = true
			if m.view == viewDashboard {
				return m, shutdownCmd(m.dashboard, teardownDoneMsg{})
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
				// Esc on dashboard = tear down bridge asynchronously, then go back to selector.
				m.quitting = true // Show "shutting down" while teardown runs
				return m, shutdownCmd(m.dashboard, returnToSelectorMsg{})
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
		return m.renderShutdownView()
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

func (m Model) renderShutdownView() string {
	frame := shutdownFrames[m.shutdownFrame%len(shutdownFrames)]
	phrase := shutdownPhrases[m.shutdownPhrase%len(shutdownPhrases)]
	dots := shutdownDots(m.shutdownFrame)

	line := styleWarning.Render(frame) + " " +
		styleVal.Render("Shutting down bridge and restoring settings") +
		styleDim.Render(dots)
	detail := styleDim.Render(phrase + "...")

	body := line + "\n" + detail
	if m.width <= 0 || m.height <= 0 {
		return "\n  " + body + "\n\n"
	}

	boxWidth := m.width - 4
	if boxWidth > 64 {
		boxWidth = 64
	}
	if boxWidth < 36 {
		boxWidth = m.width
	}
	if boxWidth < 1 {
		boxWidth = 1
	}
	contentWidth := boxWidth - 2
	if contentWidth < 1 {
		contentWidth = 1
	}

	panel := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(colorBorder).
		Padding(0, 1).
		Width(contentWidth).
		MaxWidth(boxWidth).
		Render(body)

	return lipgloss.Place(m.width, m.height, lipgloss.Center, lipgloss.Center, panel)
}

func shutdownDots(frame int) string {
	return strings.Repeat(".", (frame+1)%4)
}
