package tui

import (
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/charmbracelet/lipgloss"
)

var (
	colorText   = lipgloss.Color("#d7dce2")
	colorMuted  = lipgloss.Color("#7d8793")
	colorAccent = lipgloss.Color("#62d2a2")
	colorWarn   = lipgloss.Color("#e5b95c")
	colorError  = lipgloss.Color("#ef6f6c")
	colorPanel  = lipgloss.Color("#3a4450")
	colorSecret = lipgloss.Color("#ff8bd1")
	colorIP     = lipgloss.Color("#8ec8ff")
	colorMAC    = lipgloss.Color("#e5b95c")
	colorUser   = lipgloss.Color("#bda8ff")

	styleTitle    = lipgloss.NewStyle().Foreground(colorAccent).Bold(true)
	styleMuted    = lipgloss.NewStyle().Foreground(colorMuted)
	styleKey      = lipgloss.NewStyle().Foreground(colorAccent).Bold(true)
	styleWarn     = lipgloss.NewStyle().Foreground(colorWarn)
	styleError    = lipgloss.NewStyle().Foreground(colorError).Bold(true)
	styleText     = lipgloss.NewStyle().Foreground(colorText)
	styleValue    = lipgloss.NewStyle().Foreground(colorText).Bold(true)
	styleHeader   = lipgloss.NewStyle().Foreground(colorAccent).Bold(true)
	stylePanel    = lipgloss.NewStyle().Foreground(colorPanel)
	styleProtocol = lipgloss.NewStyle().Foreground(colorAccent).Bold(true)
	styleSecret   = lipgloss.NewStyle().Foreground(colorSecret).Bold(true)
	styleIP       = lipgloss.NewStyle().Foreground(colorIP).Bold(true)
	styleMAC      = lipgloss.NewStyle().Foreground(colorMAC)
	styleUser     = lipgloss.NewStyle().Foreground(colorUser).Bold(true)
	styleField    = lipgloss.NewStyle().Foreground(colorMuted)
)

var (
	ipv4TokenPattern = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?\b`)
	macTokenPattern  = regexp.MustCompile(`\b[0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){2,5}\b`)
)

func styleTypedLine(line string) string {
	if line == "" || strings.Contains(line, "\x1b[") {
		return line
	}
	var out strings.Builder
	for i := 0; i < len(line); {
		r := rune(line[i])
		size := 1
		if r >= 0x80 {
			r, size = utf8Rune(line[i:])
		}
		if unicode.IsSpace(r) {
			out.WriteString(line[i : i+size])
			i += size
			continue
		}
		start := i
		for i < len(line) {
			r = rune(line[i])
			size = 1
			if r >= 0x80 {
				r, size = utf8Rune(line[i:])
			}
			if unicode.IsSpace(r) {
				break
			}
			i += size
		}
		out.WriteString(styleTypedToken(line[start:i]))
	}
	return out.String()
}

func utf8Rune(value string) (rune, int) {
	return utf8.DecodeRuneInString(value)
}

func styleTypedToken(token string) string {
	if token == "" {
		return token
	}
	if key, value, ok := strings.Cut(token, "="); ok {
		renderedKey := styleField.Render(key + "=")
		switch classifiedKey(key) {
		case "secret":
			return renderedKey + styleSecret.Render(value)
		case "identity":
			return renderedKey + styleUser.Render(value)
		case "ip":
			return renderedKey + styleIP.Render(value)
		case "mac":
			return renderedKey + styleMAC.Render(value)
		default:
			return renderedKey + styleValue.Render(value)
		}
	}
	upper := strings.ToUpper(strings.Trim(token, ":,;()[]"))
	switch upper {
	case "HTTP", "NTLM", "KERBEROS", "SMTP", "FTP", "POP3", "IMAP", "IRC", "LDAP", "SNMP", "MSSQL", "CARD", "EAPOL", "ARP", "IPV4", "IPV6", "VLAN", "ETH", "DHCP", "TCP", "UDP", "ICMPV4", "ICMPV6":
		return styleProtocol.Render(token)
	case "SAVED", "AUTO", "SUCCESS":
		return styleWarn.Render(token)
	case "ERROR", "ERR", "FAILURE", "FAILED":
		return styleError.Render(token)
	}
	return styleAddresses(token)
}

func classifiedKey(key string) string {
	key = strings.ToLower(strings.TrimSpace(key))
	switch key {
	case "secret", "pass", "password", "passwd", "pwd", "token", "api_key", "key", "auth":
		return "secret"
	case "user", "username", "domain":
		return "identity"
	case "ip", "ipv4", "ipv6", "gateway", "dns", "arp_sender_ip", "arp_target_ip", "arp_who_has", "arp_tell":
		return "ip"
	case "mac", "ether_src", "ether_dst", "arp_sender_mac", "arp_target_mac":
		return "mac"
	default:
		return ""
	}
}

func styleAddresses(token string) string {
	token = macTokenPattern.ReplaceAllStringFunc(token, func(match string) string {
		return styleMAC.Render(match)
	})
	token = ipv4TokenPattern.ReplaceAllStringFunc(token, func(match string) string {
		return styleIP.Render(match)
	})
	return token
}
