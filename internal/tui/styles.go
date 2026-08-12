package tui

import (
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/charmbracelet/lipgloss"
)

var (
	colorCanvas    = lipgloss.Color("#0b1018")
	colorChrome    = lipgloss.Color("#111827")
	colorSurface   = lipgloss.Color("#172131")
	colorRaised    = lipgloss.Color("#202d40")
	colorSelection = lipgloss.Color("#293a52")
	colorBrand     = lipgloss.Color("#8b7cf6")
	colorOnBrand   = lipgloss.Color("#090c13")
	colorText      = lipgloss.Color("#dce5f2")
	colorMuted     = lipgloss.Color("#8190a5")
	colorAccent    = lipgloss.Color("#4fd1c5")
	colorInfo      = lipgloss.Color("#78a9ff")
	colorWarn      = lipgloss.Color("#d9ae62")
	colorError     = lipgloss.Color("#ff7185")
	colorErrDim    = lipgloss.Color("#c67b89")
	colorPanel     = lipgloss.Color("#46566d")
	colorSecret    = lipgloss.Color("#dc8cff")
	colorIP        = colorInfo
	colorMAC       = lipgloss.Color("#dfb96f")
	colorUser      = lipgloss.Color("#aea2ff")

	styleCanvas          = lipgloss.NewStyle().Background(colorCanvas)
	styleMuted           = lipgloss.NewStyle().Foreground(colorMuted).Background(colorCanvas)
	styleKey             = lipgloss.NewStyle().Foreground(colorAccent).Background(colorCanvas).Bold(true)
	styleWarn            = lipgloss.NewStyle().Foreground(colorWarn).Background(colorCanvas)
	styleError           = lipgloss.NewStyle().Foreground(colorError).Background(colorCanvas).Bold(true)
	styleErrDim          = lipgloss.NewStyle().Foreground(colorErrDim).Background(colorCanvas)
	styleText            = lipgloss.NewStyle().Foreground(colorText).Background(colorCanvas)
	styleValue           = lipgloss.NewStyle().Foreground(colorText).Background(colorCanvas).Bold(true)
	styleHeader          = lipgloss.NewStyle().Foreground(colorAccent).Background(colorCanvas).Bold(true)
	styleProtocol        = lipgloss.NewStyle().Foreground(colorInfo).Background(colorCanvas).Bold(true)
	styleSuccess         = lipgloss.NewStyle().Foreground(colorAccent).Background(colorCanvas).Bold(true)
	styleSecret          = lipgloss.NewStyle().Foreground(colorSecret).Background(colorCanvas).Bold(true)
	styleIP              = lipgloss.NewStyle().Foreground(colorIP).Background(colorCanvas).Bold(true)
	styleMAC             = lipgloss.NewStyle().Foreground(colorMAC).Background(colorCanvas)
	styleUser            = lipgloss.NewStyle().Foreground(colorUser).Background(colorCanvas).Bold(true)
	styleField           = lipgloss.NewStyle().Foreground(colorMuted).Background(colorCanvas)
	styleFocus           = lipgloss.NewStyle().Foreground(colorCanvas).Background(colorAccent).Bold(true)
	styleTab             = lipgloss.NewStyle().Foreground(colorMuted).Background(colorChrome)
	styleShortcut        = lipgloss.NewStyle().Foreground(colorAccent).Background(colorCanvas).Bold(true)
	styleCommand         = lipgloss.NewStyle().Foreground(colorInfo).Background(colorCanvas).Bold(true)
	styleContext         = lipgloss.NewStyle().Foreground(colorWarn).Background(colorCanvas)
	styleContextSelected = lipgloss.NewStyle().Foreground(colorWarn).Background(colorSelection).Bold(true)
	styleButton          = lipgloss.NewStyle().Foreground(colorText).Background(colorRaised).Bold(true)
	styleButtonActive    = lipgloss.NewStyle().Foreground(colorCanvas).Background(colorAccent).Bold(true)
	styleButtonPrimary   = lipgloss.NewStyle().Foreground(colorOnBrand).Background(colorBrand).Bold(true)
	styleButtonDanger    = lipgloss.NewStyle().Foreground(colorError).Background(colorRaised).Bold(true)
	styleButtonDisabled  = lipgloss.NewStyle().Foreground(colorMuted).Background(colorChrome)

	styleTopBar           = lipgloss.NewStyle().Foreground(colorText).Background(colorChrome)
	styleBrand            = lipgloss.NewStyle().Foreground(colorOnBrand).Background(colorBrand).Bold(true)
	styleProduct          = lipgloss.NewStyle().Foreground(colorText).Background(colorChrome).Bold(true)
	styleStatusLabel      = lipgloss.NewStyle().Foreground(colorMuted).Background(colorChrome)
	styleStatusValue      = lipgloss.NewStyle().Foreground(colorText).Background(colorChrome).Bold(true)
	styleStatusOnline     = lipgloss.NewStyle().Foreground(colorAccent).Background(colorChrome).Bold(true)
	styleTabBar           = lipgloss.NewStyle().Foreground(colorMuted).Background(colorChrome)
	styleTabActive        = lipgloss.NewStyle().Foreground(colorAccent).Background(colorSurface).Bold(true).Underline(true)
	stylePaneHeader       = lipgloss.NewStyle().Foreground(colorMuted).Background(colorSurface).Bold(true)
	stylePaneHeaderActive = lipgloss.NewStyle().Foreground(colorText).Background(colorRaised).Bold(true)
	stylePaneBody         = lipgloss.NewStyle().Foreground(colorText).Background(colorCanvas)
	styleCLIInput         = lipgloss.NewStyle().Foreground(colorText).Background(colorSurface)
	styleAutocomplete     = lipgloss.NewStyle().Foreground(colorMuted).Background(colorSurface)
	styleSelectedRow      = lipgloss.NewStyle().Foreground(colorText).Background(colorSelection).Bold(true)
	stylePaneRule         = lipgloss.NewStyle().Foreground(colorPanel).Background(colorCanvas)
	stylePaneRuleActive   = lipgloss.NewStyle().Foreground(colorAccent).Background(colorCanvas)
	styleFooterBar        = lipgloss.NewStyle().Foreground(colorMuted).Background(colorChrome)
)

const ansiFullReset = "\x1b[0m"

// renderStyleLayer keeps a row's base style active across nested Lip Gloss
// fragments. Each nested fragment emits a full SGR reset, which otherwise
// cancels the outer background for every cell that follows it.
func renderStyleLayer(style lipgloss.Style, value string) string {
	prefix, suffix, ok := styleEnvelope(style)
	if !ok || prefix == "" {
		return style.Render(value)
	}
	value = strings.ReplaceAll(value, ansiFullReset, ansiFullReset+prefix)
	return prefix + value + suffix
}

func styleEnvelope(style lipgloss.Style) (string, string, bool) {
	const marker = "\ue000"
	rendered := style.Render(marker)
	index := strings.Index(rendered, marker)
	if index < 0 {
		return "", "", false
	}
	return rendered[:index], rendered[index+len(marker):], true
}

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
	// Doctor rows own their status styling. Classifying a FAIL detail such as
	// "probe failed" as a muted command log would paint over the red badge
	// before paneLine can apply typed status colors.
	if isDoctorStatusOutput(line) {
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

func isDoctorStatusOutput(line string) bool {
	line = strings.TrimSpace(line)
	for _, status := range []string{"PASS", "WARN", "FAIL", "SKIP"} {
		if strings.HasPrefix(line, "["+status+"] ") {
			return true
		}
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
	case "HTTP", "NTLM", "KERBEROS", "SMTP", "FTP", "POP3", "IMAP", "IRC", "LDAP", "SNMP", "MSSQL", "CARD", "EAPOL", "EAP", "EAPOL-MKA", "REQUEST", "RESPONSE", "IDENTITY", "MKA", "DETECTED", "DROP", "DROPPED", "DROPPING", "DOWNGRADE", "FORWARDED", "FORWARDING", "ENABLE", "DISABLE", "ENABLED", "DISABLED", "TYPE", "ARP", "IPV4", "IPV6", "VLAN", "ETH", "DHCP", "TCP", "UDP", "ICMPV4", "ICMPV6":
		return styleProtocol.Render(token)
	case "WARN", "WARNING", "MACSEC", "LOGOFF", "EAPOL-LOGOFF", "DROP-LOGOFF", "MACSEC-DOWNGRADE":
		return styleWarn.Render(token)
	case "PASS", "START", "EAPOL-START", "SUCCESS", "EAPOL-SUCCESS", "AUTHORIZED":
		return styleSuccess.Render(token)
	case "FAIL", "ERROR", "ERR", "FAILURE", "EAPOL-FAILURE", "FAILED", "REJECTED":
		return styleError.Render(token)
	case "SKIP":
		return styleMuted.Render(token)
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
