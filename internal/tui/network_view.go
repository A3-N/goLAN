package tui

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	networkobs "golan/internal/network"
)

var networkCategories = []networkobs.Category{
	networkobs.CategoryAddressing,
	networkobs.CategoryDNS,
	networkobs.CategoryHTTP,
	networkobs.CategoryAccess,
	networkobs.CategoryRisk,
	networkobs.CategoryAction,
}

func (m Model) networkDevices() []networkobs.Device {
	if m.networkTracker == nil {
		return nil
	}
	devices := m.networkTracker.Snapshot().Devices
	query := strings.ToLower(strings.TrimSpace(m.networkSearch))
	filtered := devices[:0]
	for _, device := range devices {
		if m.networkFilter != "" && !deviceHasCategory(device, m.networkFilter) {
			continue
		}
		if query != "" && !strings.Contains(networkDeviceSearchText(device), query) {
			continue
		}
		filtered = append(filtered, device)
	}
	return filtered
}

func deviceHasCategory(device networkobs.Device, category networkobs.Category) bool {
	for _, observation := range device.Observations {
		if observation.Category == category {
			return true
		}
	}
	return false
}

func networkDeviceSearchText(device networkobs.Device) string {
	values := []string{device.Key, device.MAC, device.Adapter, device.Role}
	values = append(values, device.IPs...)
	values = append(values, device.Hostnames...)
	values = append(values, device.Protocols...)
	for _, observation := range device.Observations {
		values = append(values, observation.Summary, observation.Source, observation.Destination)
	}
	return strings.ToLower(strings.Join(values, " "))
}

func (m *Model) ensureNetworkSelection() {
	devices := m.networkDevices()
	if len(devices) == 0 {
		m.selectedNetworkDevice = ""
		return
	}
	for _, device := range devices {
		if device.Key == m.selectedNetworkDevice {
			return
		}
	}
	m.selectedNetworkDevice = devices[0].Key
}

func (m *Model) moveNetworkSelection(delta int) {
	devices := m.networkDevices()
	if len(devices) == 0 || delta == 0 {
		return
	}
	index := 0
	for candidate, device := range devices {
		if device.Key == m.selectedNetworkDevice {
			index = candidate
			break
		}
	}
	index = clamp(index+delta, 0, len(devices)-1)
	m.selectedNetworkDevice = devices[index].Key
}

func (m Model) selectedNetworkDeviceSnapshot() (networkobs.Device, bool) {
	for _, device := range m.networkDevices() {
		if device.Key == m.selectedNetworkDevice {
			return device, true
		}
	}
	devices := m.networkDevices()
	if len(devices) == 0 {
		return networkobs.Device{}, false
	}
	return devices[0], true
}

func (m *Model) moveNetworkSection(delta int) {
	if delta == 0 {
		return
	}
	m.networkSection = clamp(m.networkSection+delta, 0, len(networkCategories))
}

func (m *Model) toggleNetworkSection() {
	if m.networkSection <= 0 || m.networkSection > len(networkCategories) {
		return
	}
	if m.networkExpanded == nil {
		m.networkExpanded = make(map[networkobs.Category]bool)
	}
	category := networkCategories[m.networkSection-1]
	next := !m.networkExpanded[category]
	for existing := range m.networkExpanded {
		m.networkExpanded[existing] = false
	}
	m.networkExpanded[category] = next
}

func (m Model) renderNetworkDevices(width, height int) string {
	available := max(1, height-3)
	devices := m.networkDevices()
	allCount := 0
	if m.networkTracker != nil {
		allCount = len(m.networkTracker.Snapshot().Devices)
	}
	rows := []string{renderTextButtonBar(m.networkButtonBar(len(devices), allCount)), networkDeviceHeader(width)}
	selected := 0
	for index, device := range devices {
		if device.Key == m.selectedNetworkDevice {
			selected = index
			break
		}
	}
	listAvailable := max(1, available-2)
	start := visibleSelectionStart(selected, len(devices), listAvailable)
	end := min(len(devices), start+listAvailable)
	for index := start; index < end; index++ {
		prefix := "  "
		if devices[index].Key == m.selectedNetworkDevice {
			prefix = "> "
		}
		rows = append(rows, networkDeviceRow(prefix, index+1, devices[index], width))
	}
	if allCount == 0 {
		rows = append(rows, "", "No devices observed.", "Start listen, bridge, takeover, or edge mode; full traffic is still saved to PCAP.")
	} else if len(devices) == 0 {
		rows = append(rows, "", "No devices match this view.", "Use `network reset` to show the complete inventory.")
	}
	if len(rows) > available {
		rows = rows[:available]
	}
	return box(m.cardTitle("network devices", cardOutput), rows, width, height, m.activeCard == cardOutput)
}

func (m Model) networkButtonBar(visible, total int) textButtonBar {
	buttons := []textButton{{ID: "all", Label: "All", Active: m.networkFilter == ""}}
	for _, category := range networkCategories {
		label := networkCategoryLabel(category)
		buttons = append(buttons, textButton{ID: string(category), Label: label, Active: m.networkFilter == category})
	}
	search := strings.TrimSpace(m.networkSearch)
	if search == "" {
		search = "none"
	}
	return textButtonBar{Prefix: fmt.Sprintf("VIEW %d/%d  ", visible, total), Buttons: buttons, Suffix: "  search=" + safeDisplayText(search)}
}

func networkCategoryLabel(category networkobs.Category) string {
	switch category {
	case networkobs.CategoryDNS:
		return "DNS"
	case networkobs.CategoryHTTP:
		return "HTTP"
	default:
		value := string(category)
		if value == "" {
			return ""
		}
		return strings.ToUpper(value[:1]) + value[1:]
	}
}

func networkCategoryForButton(id string) networkobs.Category {
	switch networkobs.Category(strings.ToLower(strings.TrimSpace(id))) {
	case networkobs.CategoryAddressing:
		return networkobs.CategoryAddressing
	case networkobs.CategoryDNS:
		return networkobs.CategoryDNS
	case networkobs.CategoryHTTP:
		return networkobs.CategoryHTTP
	case networkobs.CategoryAccess:
		return networkobs.CategoryAccess
	case networkobs.CategoryRisk:
		return networkobs.CategoryRisk
	case networkobs.CategoryAction:
		return networkobs.CategoryAction
	default:
		return ""
	}
}

func networkDeviceHeader(width int) string {
	if width >= 100 {
		return "  #   STATE    MAC                 IPs                     VLAN   PROTOCOLS             ALERTS LAST SEEN"
	}
	if width >= 72 {
		return "  #   MAC                 IPs                VLAN   PROTOCOLS        ALERTS"
	}
	return "  #   MAC                 IPs            ALERTS"
}

func networkDeviceRow(prefix string, index int, device networkobs.Device, width int) string {
	ips := "-"
	if len(device.IPs) > 0 {
		ips = strings.Join(device.IPs, ",")
	}
	vlans := "-"
	if len(device.VLANs) > 0 {
		values := make([]string, len(device.VLANs))
		for index, vlan := range device.VLANs {
			values[index] = strconv.Itoa(int(vlan))
		}
		vlans = strings.Join(values, ",")
	}
	protocols := "-"
	if len(device.Protocols) > 0 {
		protocols = strings.Join(device.Protocols, ",")
	}
	alerts := networkDeviceAlertCount(device)
	lastSeen := "--:--:--"
	if !device.LastSeen.IsZero() {
		lastSeen = device.LastSeen.UTC().Format("15:04:05")
	}
	switch {
	case width >= 100:
		return fmt.Sprintf("%s%-3d %-8s %-19s %-23s %-6s %-21s %-6d %s", prefix, index, "SEEN", clipLiveColumn(device.MAC, 19), clipLiveColumn(ips, 23), clipLiveColumn(vlans, 6), clipLiveColumn(protocols, 21), alerts, lastSeen)
	case width >= 72:
		return fmt.Sprintf("%s%-3d %-19s %-18s %-6s %-16s %-6d", prefix, index, clipLiveColumn(device.MAC, 19), clipLiveColumn(ips, 18), clipLiveColumn(vlans, 6), clipLiveColumn(protocols, 16), alerts)
	default:
		return fmt.Sprintf("%s%-3d %-19s %-14s %-6d", prefix, index, clipLiveColumn(device.MAC, 19), clipLiveColumn(ips, 14), alerts)
	}
}

func networkDeviceAlertCount(device networkobs.Device) int {
	count := 0
	for _, observation := range device.Observations {
		if observation.Category == networkobs.CategoryRisk || observation.Category == networkobs.CategoryAction || observation.Severity == networkobs.SeverityError {
			count++
		}
	}
	return count
}

func (m Model) renderNetworkInspector(width, height int) string {
	available := max(1, height-3)
	device, ok := m.selectedNetworkDeviceSnapshot()
	if !ok {
		return box(m.cardTitle("inspector", cardInspector), []string{"Select an observed device.", "Packet detail is intentionally left to the saved capture and external analyzers."}, width, height, m.activeCard == cardInspector)
	}
	rows := []string{
		"IDENTITY",
		"  MAC " + device.MAC,
		"  scope " + emptyNetworkValue(strings.Trim(strings.Join([]string{device.Role, device.Adapter}, "/"), "/")),
		"  first " + networkTime(device.FirstSeen) + " · last " + networkTime(device.LastSeen),
		"  IPs " + emptyNetworkValue(strings.Join(device.IPs, ", ")),
		"  VLANs " + networkVLANs(device.VLANs),
		"  protocols " + emptyNetworkValue(strings.Join(device.Protocols, ", ")),
	}
	for index, category := range networkCategories {
		observations := networkCategoryObservations(device, category)
		selected := m.networkSection == index+1
		marker := "  "
		if selected {
			marker = "> "
		}
		expanded := m.networkExpanded[category]
		toggle := "+"
		if expanded {
			toggle = "-"
		}
		rows = append(rows, fmt.Sprintf("%s[%s] %s (%d)", marker, toggle, strings.ToUpper(string(category)), len(observations)))
		if !expanded {
			continue
		}
		visible := min(5, len(observations))
		for _, observation := range observations[:visible] {
			secret := m.observedSecret(device, observation)
			rows = append(rows, "    "+networkObservationRow(observation, secret, m.redactObservedSecrets, max(20, width-8)))
		}
		if hidden := len(observations) - visible; hidden > 0 {
			rows = append(rows, fmt.Sprintf("    +%d older observation(s)", hidden))
		}
	}
	if m.networkTracker != nil {
		captures := m.networkTracker.Snapshot().CapturePaths
		rows = append(rows, "", fmt.Sprintf("CAPTURES (%d)", len(captures)))
		for _, path := range captures {
			rows = append(rows, "  "+safeDisplayText(path))
		}
	}
	if len(rows) > available {
		rows = rows[:available]
	}
	return box(m.cardTitle("device inspector", cardInspector), rows, width, height, m.activeCard == cardInspector)
}

func networkCategoryObservations(device networkobs.Device, category networkobs.Category) []networkobs.Observation {
	var result []networkobs.Observation
	for _, observation := range device.Observations {
		if observation.Category == category {
			result = append(result, observation)
		}
	}
	sort.Slice(result, func(i, j int) bool { return result[i].LastSeen.After(result[j].LastSeen) })
	return result
}

func (m Model) observedSecret(device networkobs.Device, observation networkobs.Observation) string {
	if observation.Category != networkobs.CategoryRisk || len(m.observedSecrets) == 0 {
		return ""
	}
	return m.observedSecrets[observedSecretKey(device.Adapter, device.MAC, observation.Protocol,
		strings.TrimPrefix(observation.Kind, strings.ToLower(observation.Protocol)+"-"))]
}

func networkObservationRow(observation networkobs.Observation, secret string, redact bool, width int) string {
	line := strings.ToUpper(string(observation.Severity)) + " " + observation.Summary
	if secret != "" {
		if redact {
			secret = "REDACTED"
		} else {
			secret = safeDisplayText(secret)
		}
		line += " [" + secret + "]"
	}
	if observation.Count > 1 {
		line += fmt.Sprintf(" · %dx", observation.Count)
	}
	if observation.Source != "" || observation.Destination != "" {
		line += " · " + observation.Source + " → " + observation.Destination
	}
	return clipLiveColumn(line, width)
}

func clipLiveColumn(value string, width int) string {
	if width <= 0 {
		return ""
	}
	runes := []rune(value)
	if len(runes) <= width {
		return value
	}
	if width == 1 {
		return "…"
	}
	return string(runes[:width-1]) + "…"
}

func networkVLANs(vlans []uint16) string {
	if len(vlans) == 0 {
		return "none"
	}
	values := make([]string, len(vlans))
	for index, vlan := range vlans {
		values[index] = strconv.Itoa(int(vlan))
	}
	return strings.Join(values, ", ")
}

func networkTime(value time.Time) string {
	if value.IsZero() {
		return "unknown"
	}
	return value.UTC().Format(time.RFC3339)
}

func emptyNetworkValue(value string) string {
	if strings.TrimSpace(value) == "" {
		return "none"
	}
	return safeDisplayText(value)
}
