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
	colorInfo   = lipgloss.Color("#8ec8ff")
	colorWarn   = lipgloss.Color("#e5b95c")
	colorError  = lipgloss.Color("#ef6f6c")
	colorErrDim = lipgloss.Color("#c98282")
	colorPanel  = lipgloss.Color("#3a4450")
	colorSecret = lipgloss.Color("#ff8bd1")
	colorIP     = colorInfo
	colorMAC    = lipgloss.Color("#e5b95c")
	colorUser   = lipgloss.Color("#bda8ff")

	styleTitle    = lipgloss.NewStyle().Foreground(colorAccent).Bold(true)
	styleMuted    = lipgloss.NewStyle().Foreground(colorMuted)
	styleKey      = lipgloss.NewStyle().Foreground(colorAccent).Bold(true)
	styleWarn     = lipgloss.NewStyle().Foreground(colorWarn)
	styleError    = lipgloss.NewStyle().Foreground(colorError).Bold(true)
	styleErrDim   = lipgloss.NewStyle().Foreground(colorErrDim)
	styleText     = lipgloss.NewStyle().Foreground(colorText)
	styleValue    = lipgloss.NewStyle().Foreground(colorText).Bold(true)
	styleHeader   = lipgloss.NewStyle().Foreground(colorAccent).Bold(true)
	stylePanel    = lipgloss.NewStyle().Foreground(colorPanel)
	styleProtocol = lipgloss.NewStyle().Foreground(colorInfo).Bold(true)
	styleSuccess  = lipgloss.NewStyle().Foreground(colorAccent).Bold(true)
	styleSecret   = lipgloss.NewStyle().Foreground(colorSecret).Bold(true)
	styleIP       = lipgloss.NewStyle().Foreground(colorIP).Bold(true)
	styleMAC      = lipgloss.NewStyle().Foreground(colorMAC)
	styleUser     = lipgloss.NewStyle().Foreground(colorUser).Bold(true)
	styleField    = lipgloss.NewStyle().Foreground(colorMuted)
)

var (
	ipv4TokenPattern     = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?\b`)
	macTokenPattern      = regexp.MustCompile(`\b[0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){2,5}\b`)
	errCommandLogPattern = regexp.MustCompile(`(?i)\berr:`)
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

func styleOutputLine(line string, muted bool) string {
	if !muted || line == "" || strings.Contains(line, "\x1b[") {
		return line
	}
	return styleMutedCommandLine(line)
}

func styleMutedCommandLine(line string) string {
	matches := errCommandLogPattern.FindAllStringIndex(line, -1)
	if len(matches) == 0 {
		return styleMuted.Render(line)
	}

	var out strings.Builder
	last := 0
	for _, match := range matches {
		out.WriteString(styleMuted.Render(line[last:match[0]]))
		out.WriteString(styleErrDim.Render(line[match[0]:match[1]]))
		last = match[1]
	}
	out.WriteString(styleMuted.Render(line[last:]))
	return out.String()
}

func isCommandLevelOutput(line string) bool {
	line = strings.TrimSpace(line)
	if line == "" || strings.Contains(line, "\x1b[") {
		return false
	}
	lower := strings.ToLower(line)
	if strings.HasPrefix(lower, ">") {
		return true
	}
	if strings.Contains(lower, " err:") || strings.Contains(lower, " warn ") || strings.Contains(lower, " warn:") {
		return true
	}
	if strings.Contains(lower, " error") || strings.Contains(lower, " failed") {
		return true
	}

	first := lower
	if cut := strings.IndexAny(first, " :"); cut >= 0 {
		first = first[:cut]
	}
	switch first {
	case "adapter", "adapters", "bridge", "canvas", "configs", "ctx", "eapol", "err", "error", "expected", "listen", "load", "loaded", "macsec", "nat", "pcap", "refresh", "role", "save", "saved", "send", "set", "staged", "unknown", "use":
		return true
	}
	return false
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
	case "HTTP", "NTLM", "KERBEROS", "SMTP", "FTP", "POP3", "IMAP", "IRC", "LDAP", "SNMP", "MSSQL", "CARD", "EAPOL", "EAP", "EAPOL-MKA", "REQUEST", "RESPONSE", "IDENTITY", "MKA", "DETECTED", "DROP", "DROPPED", "DROPPING", "DOWNGRADE", "FORWARDED", "FORWARDING", "ENABLE", "DISABLE", "ENABLED", "DISABLED", "PASS", "TYPE", "ARP", "IPV4", "IPV6", "VLAN", "ETH", "DHCP", "TCP", "UDP", "ICMPV4", "ICMPV6":
		return styleProtocol.Render(token)
	case "MACSEC", "LOGOFF", "EAPOL-LOGOFF", "DROP-LOGOFF", "MACSEC-DOWNGRADE":
		return styleWarn.Render(token)
	case "START", "EAPOL-START", "SUCCESS", "EAPOL-SUCCESS", "AUTHORIZED":
		return styleSuccess.Render(token)
	case "ERROR", "ERR", "FAILURE", "EAPOL-FAILURE", "FAILED", "REJECTED":
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
