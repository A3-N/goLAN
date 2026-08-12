package tui

import (
	"strings"
	"unicode"
	"unicode/utf8"
)

const maxDisplayTextRunes = 64

// safeDisplayText bounds untrusted labels before they reach terminal rows.
func safeDisplayText(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return "none"
	}
	value = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return '?'
		}
		return r
	}, value)
	if utf8.RuneCountInString(value) <= maxDisplayTextRunes {
		return value
	}
	runes := []rune(value)
	return string(runes[:maxDisplayTextRunes]) + "…"
}
