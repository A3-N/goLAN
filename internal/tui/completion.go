package tui

import (
	"sort"
	"strconv"
	"strings"
	"unicode"

	"golan/internal/configs"
	"golan/internal/profile"

	tea "github.com/charmbracelet/bubbletea"
)

func (c cardFocus) String() string {
	switch c {
	case cardNone:
		return "all panes"
	case cardOutput:
		return "output"
	case cardCLI:
		return "cli"
	case cardInspector:
		return "inspector"
	default:
		return "unknown"
	}
}

func (m *Model) recallHistory(delta int) {
	if len(m.history) == 0 {
		return
	}
	if m.historyIndex == -1 {
		if delta < 0 {
			m.historyIndex = len(m.history) - 1
		} else {
			return
		}
	} else {
		m.historyIndex += delta
	}
	if m.historyIndex < 0 {
		m.historyIndex = 0
	}
	if m.historyIndex >= len(m.history) {
		m.historyIndex = -1
		m.input = ""
		m.refreshCompletions()
		return
	}
	m.input = m.history[m.historyIndex]
	m.refreshCompletions()
}

func (m *Model) applyCompletion() {
	candidates := m.completionCandidates(m.input)
	if len(candidates) == 0 {
		candidates = m.allCompletionCandidates(m.input)
	}
	candidates = dedupe(candidates)
	if len(candidates) == 0 {
		m.completions = nil
		m.resetCompletionCycle()
		return
	}

	context := completionContext(m.input)
	current := currentCompletionToken(m.input)
	if m.canContinueCompletionCycle(context, current) {
		m.cycleIndex = (m.cycleIndex + 1) % len(m.cycleOptions)
		m.completions = m.cycleOptions
		m.input = replaceCurrentToken(m.input, m.cycleOptions[m.cycleIndex])
		return
	}

	m.completions = candidates
	m.cycleContext = context
	m.cycleOptions = candidates
	m.cycleIndex = 0
	m.input = replaceCurrentToken(m.input, candidates[0])
	if len(candidates) == 1 {
		m.resetCompletionCycle()
		if shouldAppendSpace(m.input) {
			m.input += " "
		}
		m.refreshCompletions()
	}
}

func (m *Model) resetCompletionCycle() {
	m.cycleContext = ""
	m.cycleIndex = -1
	m.cycleOptions = nil
}

func (m Model) canContinueCompletionCycle(context, current string) bool {
	if m.cycleIndex < 0 || len(m.cycleOptions) < 2 {
		return false
	}
	if m.cycleContext != context || m.cycleIndex >= len(m.cycleOptions) {
		return false
	}
	return strings.EqualFold(current, m.cycleOptions[m.cycleIndex])
}

func (m *Model) refreshCompletions() {
	if m.inputMode == modeSaveName {
		m.completions = filterPrefix(m.configNames(), strings.ToLower(strings.TrimSpace(m.input)))
		return
	}
	m.completions = m.completionCandidates(m.input)
}

func (m Model) completionCandidates(input string) []string {
	candidates, current := m.completionCandidateSet(input)
	return filterPrefix(candidates, current)
}

func (m Model) allCompletionCandidates(input string) []string {
	candidates, _ := m.completionCandidateSet(input)
	return dedupe(candidates)
}

func (m Model) completionCandidateSet(input string) ([]string, string) {
	tokens, trailingSpace := commandTokens(input)
	if len(tokens) == 0 {
		return topLevelCommands(), ""
	}

	lower := lowerTokens(tokens)
	current := ""
	if !trailingSpace {
		current = lower[len(lower)-1]
	}

	var candidates []string
	switch {
	case len(lower) == 1 && !trailingSpace:
		candidates = topLevelCommands()
	case lower[0] == "show":
		if len(lower) <= 2 {
			candidates = []string{"adapters", "bridge", "captures", "config", "edge", "health", "nat", "project", "rules"}
		}
	case lower[0] == "set":
		candidates = m.setCompletions(lower, trailingSpace)
	case lower[0] == "unset":
		candidates = m.unsetCompletions(lower, trailingSpace)
	case lower[0] == "load":
		if len(lower) <= 2 {
			candidates = m.configNames()
		}
	case lower[0] == "enable", lower[0] == "disable":
		if len(lower) <= 2 {
			candidates = []string{"eapol", "rule"}
		} else if len(lower) <= 3 && lower[1] == "eapol" {
			candidates = []string{"drop-logoff", "macsec-downgrade"}
		} else if len(lower) <= 3 && lower[1] == "rule" {
			candidates = m.ruleIDs()
		}
	case lower[0] == "start":
		if len(lower) <= 2 {
			candidates = []string{"bridge", "edge", "listen", "nat"}
		} else if len(lower) <= 3 && lower[1] == "bridge" {
			candidates = []string{"controlled", "fast"}
		} else if len(lower) <= 3 && lower[1] == "edge" {
			candidates = []string{"observe", "route"}
		}
	case lower[0] == "stop":
		if len(lower) <= 2 {
			candidates = []string{"bridge", "edge", "listen", "nat"}
		}
	case lower[0] == "project":
		if len(lower) == 1 || len(lower) == 2 && !trailingSpace {
			candidates = []string{"close", "config", "export", "import", "journals", "new", "open", "open-recent", "recent", "recover", "save", "save-as", "sessions"}
		} else if lower[1] == "import" && (len(lower) == 2 && trailingSpace || len(lower) == 3 && !trailingSpace) {
			candidates = []string{"bundle", "config"}
		} else if lower[1] == "export" && (len(lower) == 2 && trailingSpace || len(lower) == 3 && !trailingSpace) {
			candidates = []string{"bundle"}
		} else if lower[1] == "export" && lower[2] == "bundle" && (len(lower) == 4 && trailingSpace || len(lower) == 5 && !trailingSpace) {
			candidates = []string{"full", "metadata", "sanitized"}
		} else if lower[1] == "open-recent" && (len(lower) == 2 && trailingSpace || len(lower) == 3 && !trailingSpace) {
			candidates = m.recentProjectIndexes()
		} else if lower[1] == "recover" && (len(lower) == 2 && trailingSpace || len(lower) == 3 && !trailingSpace) {
			candidates = []string{"archive", "attach", "policy", "session"}
		} else if lower[1] == "recover" && lower[2] == "policy" && (len(lower) == 3 && trailingSpace || len(lower) == 4 && !trailingSpace) {
			candidates = []string{"archive", "attach"}
		} else if lower[1] == "sessions" && (len(lower) == 2 && trailingSpace || len(lower) == 3 && !trailingSpace) {
			candidates = []string{"archive", "list"}
		} else if lower[1] == "config" && (len(lower) == 2 && trailingSpace || len(lower) == 3 && !trailingSpace) {
			candidates = []string{"export", "list", "update"}
		} else if lower[1] == "config" && lower[2] == "update" && (len(lower) == 3 && trailingSpace || len(lower) == 4 && !trailingSpace) {
			candidates = m.projectConfigSourceIDs()
		} else if lower[1] == "config" && lower[2] == "export" && (len(lower) == 3 && trailingSpace || len(lower) == 4 && !trailingSpace) {
			candidates = m.configNames()
		} else if lower[1] == "journals" && (len(lower) == 2 && trailingSpace || len(lower) == 3 && !trailingSpace) {
			candidates = []string{"list"}
		}
	case lower[0] == "policy":
		if len(lower) == 1 || (len(lower) == 2 && !trailingSpace) {
			candidates = []string{"compare", "history", "rollback", "use"}
		} else if lower[1] == "use" && ((len(lower) == 2 && trailingSpace) || (len(lower) == 3 && !trailingSpace)) {
			candidates = []string{"block-internet", "controlled-bridge", "high-latency", "observe-everything", "open-internet", "packet-loss", "web-only"}
		} else if lower[1] == "rollback" && ((len(lower) == 2 && trailingSpace) || (len(lower) == 3 && !trailingSpace)) {
			candidates = m.policyRevisionNames()
		} else if lower[1] == "compare" && ((len(lower) == 2 && trailingSpace) || len(lower) == 3 || (len(lower) == 4 && !trailingSpace)) {
			candidates = m.policyRevisionNames()
		}
	case lower[0] == "canvas":
		if len(lower) == 1 || len(lower) == 2 && !trailingSpace {
			candidates = []string{"auto-layout", "build", "reset-generated", "snapshot"}
		} else if lower[1] == "build" &&
			(len(lower) == 2 && trailingSpace ||
				len(lower) == 3 && !trailingSpace) {
			candidates = m.projectNetworkSessionIDs()
		} else if lower[1] == "reset-generated" &&
			(len(lower) == 2 && trailingSpace || len(lower) == 3 && !trailingSpace) {
			candidates = []string{"confirm"}
		}
	case lower[0] == "delete":
		if len(lower) <= 2 {
			candidates = []string{"rule"}
		} else if len(lower) <= 3 && lower[1] == "rule" {
			candidates = m.ruleIDs()
		}
	case lower[0] == "bridge":
		// Bridge is a show target, not a top-level command.
		candidates = nil
	case lower[0] == "network":
		if len(lower) == 1 || len(lower) == 2 && !trailingSpace {
			candidates = []string{"access", "baseline", "compare", "explain", "fate", "filter", "identity", "infrastructure", "passport", "probe", "reset", "rule", "search", "services", "session", "show"}
		} else if (lower[1] == "access" || lower[1] == "explain" || lower[1] == "fate" || lower[1] == "identity") &&
			(len(lower) == 2 && trailingSpace || len(lower) == 3 && !trailingSpace) {
			candidates = m.networkDeviceSelectors()
		} else if lower[1] == "filter" &&
			(len(lower) == 2 && trailingSpace || len(lower) == 3 && !trailingSpace) {
			candidates = []string{"all", "addressing", "dns", "http", "access", "risks", "actions"}
		} else if lower[1] == "search" &&
			(len(lower) == 2 && trailingSpace || len(lower) == 3 && !trailingSpace) {
			candidates = []string{"clear"}
		} else if lower[1] == "session" &&
			(len(lower) == 2 && trailingSpace || len(lower) == 3 && !trailingSpace) {
			candidates = []string{"list", "show"}
		} else if lower[1] == "session" && len(lower) >= 3 && lower[2] == "show" &&
			(len(lower) == 3 && trailingSpace || len(lower) == 4 && !trailingSpace) && m.project != nil {
			for _, session := range m.project.Manifest().NetworkSessions {
				candidates = append(candidates, session.ID)
			}
		} else if lower[1] == "baseline" && (len(lower) == 2 && trailingSpace || len(lower) == 3 && !trailingSpace) {
			candidates = []string{"clear", "set", "show"}
		} else if lower[1] == "baseline" && len(lower) >= 3 && lower[2] == "set" &&
			(len(lower) == 3 && trailingSpace || len(lower) == 4 && !trailingSpace) {
			candidates = m.projectNetworkSessionIDs()
		} else if lower[1] == "compare" && (len(lower) == 2 && trailingSpace || len(lower) == 3 && !trailingSpace) {
			candidates = []string{"baseline", "session"}
		} else if lower[1] == "compare" && len(lower) >= 3 && lower[2] == "session" &&
			(len(lower) == 3 && trailingSpace || len(lower) == 4 && !trailingSpace) {
			candidates = m.projectNetworkSessionIDs()
		} else if lower[1] == "passport" && (len(lower) == 2 && trailingSpace || len(lower) == 3 && !trailingSpace) {
			candidates = []string{"compare", "save", "verify"}
		} else if lower[1] == "probe" && (len(lower) == 2 && trailingSpace || len(lower) == 3 && !trailingSpace) {
			candidates = []string{"plan", "run"}
		} else if lower[1] == "probe" && len(lower) >= 3 && lower[2] == "plan" &&
			(len(lower) == 3 && trailingSpace || len(lower) == 4 && !trailingSpace) {
			candidates = []string{"device", "dhcp", "dns", "gateway", "route"}
		} else if lower[1] == "probe" && len(lower) >= 4 && lower[2] == "plan" && lower[3] == "dhcp" &&
			(len(lower) == 4 && trailingSpace || len(lower) == 5 && !trailingSpace) {
			candidates = m.adapterNames()
		} else if lower[1] == "rule" && (len(lower) == 2 && trailingSpace || len(lower) == 3 && !trailingSpace) {
			candidates = []string{"draft"}
		} else if lower[1] == "rule" && len(lower) >= 3 && lower[2] == "draft" &&
			(len(lower) == 3 && trailingSpace || len(lower) == 4 && !trailingSpace) {
			candidates = m.networkDeviceSelectors()
		}
	case lower[0] == "send":
		if len(lower) <= 2 {
			candidates = []string{"eapol"}
		} else if len(lower) <= 3 && lower[1] == "eapol" {
			candidates = []string{"start"}
		}
	case isConfCommand(lower[0]):
		if len(lower) <= 2 {
			candidates = append(m.selectedAdapterNames(), "bridge")
		}
	default:
		candidates = topLevelCommands()
	}

	return candidates, current
}

func (m Model) projectConfigSourceIDs() []string {
	if m.project == nil {
		return nil
	}
	manifest := m.project.Manifest()
	result := make([]string, 0, len(manifest.Configs))
	for _, source := range manifest.Configs {
		result = append(result, source.ID)
	}
	return dedupe(result)
}

func (m Model) networkDeviceSelectors() []string {
	devices := m.networkDevices()
	result := make([]string, 0, len(devices)*2)
	for _, device := range devices {
		result = append(result, strconv.FormatUint(device.Number, 10), device.MAC)
	}
	return dedupe(result)
}

func (m Model) setCompletions(tokens []string, trailingSpace bool) []string {
	if len(tokens) == 1 && !trailingSpace {
		return []string{"set"}
	}
	if len(tokens) == 1 || (len(tokens) == 2 && !trailingSpace) {
		return append([]string{"adapter", "bridge", "edge"}, propertyKeys()...)
	}

	target := tokens[1]
	if target == "bridge" {
		if len(tokens) == 2 || (len(tokens) == 3 && !trailingSpace) {
			return []string{"overload", "queue-depth"}
		}
		if (len(tokens) == 3 && trailingSpace) || (len(tokens) == 4 && !trailingSpace) {
			switch tokens[2] {
			case "queue-depth":
				return []string{"256", "512", "1024", "2048", "4096"}
			case "overload":
				return []string{"fail-closed", "fail-open"}
			}
		}
		return nil
	}
	if target == "edge" {
		if len(tokens) == 2 || (len(tokens) == 3 && !trailingSpace) {
			return []string{"mode", "port-forward", "upstream"}
		}
		if (len(tokens) == 3 && trailingSpace) || (len(tokens) == 4 && !trailingSpace) {
			switch tokens[2] {
			case "mode":
				return []string{"observe", "route"}
			case "upstream":
				return append([]string{"auto"}, m.adapterNames()...)
			case "port-forward":
				return []string{"clear", "list", "remove", "tcp", "udp"}
			}
		}
		if tokens[2] == "port-forward" && len(tokens) >= 4 && tokens[3] == "remove" {
			switch {
			case (len(tokens) == 4 && trailingSpace) || (len(tokens) == 5 && !trailingSpace):
				return []string{"tcp", "udp"}
			case (len(tokens) == 5 && trailingSpace) || (len(tokens) == 6 && !trailingSpace):
				if len(tokens) >= 5 {
					return m.edgePortForwardListenPorts(tokens[4])
				}
			}
		}
		return nil
	}
	if target == "adapter" {
		if len(tokens) >= 3 && trailingSpace {
			return profile.AdapterRoles()
		}
		if len(tokens) >= 4 && !trailingSpace {
			return profile.AdapterRoles()
		}
		return m.adapterNames()
	}
	if len(tokens) == 2 && trailingSpace {
		return m.valueCompletions(target)
	}
	if len(tokens) == 3 && !trailingSpace {
		return m.valueCompletions(target)
	}
	return nil
}

func (m Model) edgePortForwardListenPorts(protocol string) []string {
	protocol = strings.ToLower(protocol)
	ports := make([]string, 0, len(m.edgeForwards))
	for _, forward := range m.edgeForwards {
		if forward.Protocol == protocol {
			ports = append(ports, strconv.Itoa(int(forward.ListenPort)))
		}
	}
	return dedupe(ports)
}

func topLevelCommands() []string {
	return []string{"show", "settings", "set", "unset", "conf", "load", "project", "policy", "canvas", "network", "enable", "disable", "delete", "start", "stop", "send", "cleanup", "clear", "refresh", "doctor", "help", "up", "down", "quit"}
}

func (m Model) ruleIDs() []string {
	if m.policyStore == nil {
		return nil
	}
	revision, ok := m.policyStore.Active()
	if !ok {
		return nil
	}
	var ids []string
	for _, rule := range revision.Rules() {
		ids = append(ids, rule.ID)
	}
	sort.Strings(ids)
	return ids
}

func (m Model) unsetCompletions(tokens []string, trailingSpace bool) []string {
	if len(tokens) == 1 && !trailingSpace {
		return []string{"unset"}
	}
	if len(tokens) == 1 || (len(tokens) == 2 && !trailingSpace) {
		return []string{"adapter"}
	}
	if tokens[1] == "adapter" {
		return m.selectedAdapterNames()
	}
	return nil
}

func propertyKeys() []string {
	fields := profile.Fields()
	out := make([]string, 0, len(fields))
	for _, field := range fields {
		out = append(out, field.Key)
	}
	return out
}

func (m Model) valueCompletions(key string) []string {
	values := baseValueCompletions(key)
	if isBridgeContext(m.activeAdapter) {
		cfg := m.profile.BridgeAdapterSnapshot()
		values = append(values, cfg.Values(key)...)
	} else if cfg, ok := m.profile.ByName(m.activeAdapter); ok {
		values = append(values, cfg.Values(key)...)
	}
	return dedupe(values)
}

func baseValueCompletions(key string) []string {
	switch profile.CanonicalKey(key) {
	case "state":
		return []string{"auto", "up", "down"}
	case "dhcp":
		return []string{"auto", "manual", "off"}
	case "role":
		return []string{"auto", "client", "uplink", "mirror", "spare"}
	default:
		return []string{"auto"}
	}
}

func (m Model) adapterNames() []string {
	out := make([]string, 0, len(m.adapters))
	for _, adapter := range m.adapters {
		out = append(out, adapter.Name)
	}
	sort.Strings(out)
	return out
}

func (m Model) selectedAdapterNames() []string {
	out := make([]string, 0, len(m.profile.Adapters))
	for _, adapter := range m.profile.Adapters {
		out = append(out, adapter.Name)
	}
	sort.Strings(out)
	return out
}

func (m Model) configNames() []string {
	names, err := configs.List()
	if err != nil {
		return nil
	}
	return names
}

func filterPrefix(values []string, prefix string) []string {
	if prefix == "" {
		return dedupe(values)
	}
	var out []string
	for _, value := range values {
		if strings.HasPrefix(strings.ToLower(value), prefix) {
			out = append(out, value)
		}
	}
	return dedupe(out)
}

func dedupe(values []string) []string {
	seen := make(map[string]bool, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func commandTokens(input string) ([]string, bool) {
	runes := []rune(input)
	trailingSpace := len(runes) > 0 && unicode.IsSpace(runes[len(runes)-1])
	return strings.Fields(input), trailingSpace
}

func lowerTokens(tokens []string) []string {
	out := make([]string, len(tokens))
	for i, token := range tokens {
		out[i] = strings.ToLower(token)
	}
	return out
}

func isConfCommand(value string) bool {
	return value == "conf"
}

func completionContext(input string) string {
	runes := []rune(input)
	if len(runes) == 0 {
		return ""
	}
	if unicode.IsSpace(runes[len(runes)-1]) {
		return input
	}
	start := len(runes)
	for start > 0 && !unicode.IsSpace(runes[start-1]) {
		start--
	}
	return string(runes[:start])
}

func currentCompletionToken(input string) string {
	runes := []rune(input)
	end := len(runes)
	for end > 0 && unicode.IsSpace(runes[end-1]) {
		return ""
	}
	start := end
	for start > 0 && !unicode.IsSpace(runes[start-1]) {
		start--
	}
	return string(runes[start:end])
}

func replaceCurrentToken(input, value string) string {
	runes := []rune(input)
	if len(runes) > 0 && unicode.IsSpace(runes[len(runes)-1]) {
		return input + value
	}
	end := len(runes)
	for end > 0 && unicode.IsSpace(runes[end-1]) {
		end--
	}
	start := end
	for start > 0 && !unicode.IsSpace(runes[start-1]) {
		start--
	}
	return string(runes[:start]) + value + string(runes[end:])
}

func shouldAppendSpace(input string) bool {
	runes := []rune(input)
	return len(runes) > 0 && !unicode.IsSpace(runes[len(runes)-1])
}

func appendInput(input string, msg tea.KeyMsg) string {
	switch msg.Type {
	case tea.KeyRunes:
		return input + string(msg.Runes)
	case tea.KeySpace:
		return input + " "
	default:
		return input
	}
}

func trimLastRune(value string) string {
	runes := []rune(value)
	if len(runes) == 0 {
		return value
	}
	return string(runes[:len(runes)-1])
}
