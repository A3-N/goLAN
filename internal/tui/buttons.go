package tui

import (
	"strings"

	"github.com/charmbracelet/lipgloss"
)

type textButtonTone int

const (
	buttonNeutral textButtonTone = iota
	buttonPrimary
	buttonDanger
)

type textButton struct {
	ID       string
	Label    string
	Tone     textButtonTone
	Active   bool
	Disabled bool
}

type textButtonBar struct {
	Prefix  string
	Buttons []textButton
	Suffix  string
}

func renderTextButtonBar(bar textButtonBar) string {
	var rendered strings.Builder
	rendered.WriteString(bar.Prefix)
	for index, button := range bar.Buttons {
		if index > 0 {
			rendered.WriteByte(' ')
		}
		label := "[" + button.Label + "]"
		style := styleButton
		switch {
		case button.Disabled:
			style = styleButtonDisabled
		case button.Active:
			style = styleButtonActive
		case button.Tone == buttonPrimary:
			style = styleButtonPrimary
		case button.Tone == buttonDanger:
			style = styleButtonDanger
		}
		rendered.WriteString(style.Render(label))
	}
	rendered.WriteString(bar.Suffix)
	return rendered.String()
}

func textButtonAt(bar textButtonBar, column int) (textButton, bool) {
	if column < lipgloss.Width(bar.Prefix) {
		return textButton{}, false
	}
	position := lipgloss.Width(bar.Prefix)
	for index, button := range bar.Buttons {
		if index > 0 {
			position++
		}
		width := lipgloss.Width("[" + button.Label + "]")
		if column >= position && column < position+width {
			return button, true
		}
		position += width
	}
	return textButton{}, false
}
