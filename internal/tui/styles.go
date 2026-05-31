package tui

import "github.com/charmbracelet/lipgloss"

var (
	colorText   = lipgloss.Color("#d7dce2")
	colorMuted  = lipgloss.Color("#7d8793")
	colorAccent = lipgloss.Color("#62d2a2")
	colorWarn   = lipgloss.Color("#e5b95c")
	colorError  = lipgloss.Color("#ef6f6c")
	colorPanel  = lipgloss.Color("#3a4450")

	styleTitle  = lipgloss.NewStyle().Foreground(colorAccent).Bold(true)
	styleMuted  = lipgloss.NewStyle().Foreground(colorMuted)
	styleKey    = lipgloss.NewStyle().Foreground(colorAccent).Bold(true)
	styleWarn   = lipgloss.NewStyle().Foreground(colorWarn)
	styleError  = lipgloss.NewStyle().Foreground(colorError).Bold(true)
	styleText   = lipgloss.NewStyle().Foreground(colorText)
	styleValue  = lipgloss.NewStyle().Foreground(colorText).Bold(true)
	styleHeader = lipgloss.NewStyle().Foreground(colorAccent).Bold(true)
	stylePanel  = lipgloss.NewStyle().Foreground(colorPanel)
)
