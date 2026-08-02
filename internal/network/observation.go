// Package network builds sanitized, device-centric observations from live
// frames. It deliberately does not expose packet payloads or packet history.
package network

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"golan/internal/dataplane"
	"golan/internal/policy"
	"golan/internal/traffic"
)

const (
	// CurrentVersion is the serialized observation-session schema.
	CurrentVersion = 1
	// MaxDevices bounds hostile or unusually large broadcast domains.
	MaxDevices = 2048
	// MaxObservationsPerDevice bounds persisted metadata for one device.
	MaxObservationsPerDevice = 512
	maxTextRunes             = 255
)

// Category identifies one readable class of network observation.
type Category string

const (
	CategoryAddressing Category = "addressing"
	CategoryDNS        Category = "dns"
	CategoryHTTP       Category = "http"
	CategoryAccess     Category = "access"
	CategoryRisk       Category = "risk"
	CategoryAction     Category = "action"
)

// Severity gives observations a label in addition to any UI color.
type Severity string

const (
	SeverityInfo  Severity = "info"
	SeverityWarn  Severity = "warn"
	SeverityError Severity = "error"
)

// Observation is a payload-free, repeat-aggregated network fact.
type Observation struct {
	Category    Category  `json:"category"`
	Kind        string    `json:"kind"`
	Summary     string    `json:"summary"`
	Protocol    string    `json:"protocol,omitempty"`
	Source      string    `json:"source,omitempty"`
	Destination string    `json:"destination,omitempty"`
	Severity    Severity  `json:"severity"`
	FirstSeen   time.Time `json:"first_seen"`
	LastSeen    time.Time `json:"last_seen"`
	Count       uint64    `json:"count"`
}

// Device is a sanitized snapshot of one directly observed Layer 2 identity.
type Device struct {
	Key          string        `json:"key"`
	MAC          string        `json:"mac"`
	Adapter      string        `json:"adapter,omitempty"`
	Role         string        `json:"role,omitempty"`
	VLANs        []uint16      `json:"vlans,omitempty"`
	IPs          []string      `json:"ips,omitempty"`
	Hostnames    []string      `json:"hostnames,omitempty"`
	Protocols    []string      `json:"protocols,omitempty"`
	FirstSeen    time.Time     `json:"first_seen"`
	LastSeen     time.Time     `json:"last_seen"`
	Observations []Observation `json:"observations,omitempty"`
}

// Session is the immutable, sanitized summary persisted beside live captures.
type Session struct {
	Version      int       `json:"version"`
	ID           string    `json:"id"`
	Mode         string    `json:"mode"`
	StartedAt    time.Time `json:"started_at"`
	EndedAt      time.Time `json:"ended_at,omitempty"`
	CapturePaths []string  `json:"capture_paths,omitempty"`
	Devices      []Device  `json:"devices,omitempty"`
}

// DecodeSession strictly decodes and validates one persisted session.
func DecodeSession(content []byte) (Session, error) {
	var session Session
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&session); err != nil {
		return Session{}, fmt.Errorf("decode network session: %w", err)
	}
	var extra json.RawMessage
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			err = fmt.Errorf("multiple JSON values")
		}
		return Session{}, fmt.Errorf("decode network session: %w", err)
	}
	if err := ValidateSession(session); err != nil {
		return Session{}, err
	}
	return session, nil
}

// ValidateSession checks all bounded persisted observation fields.
func ValidateSession(session Session) error {
	if session.Version != CurrentVersion {
		return fmt.Errorf("unsupported network session version %d", session.Version)
	}
	if cleanText(session.ID) == "" || len(session.Devices) > MaxDevices {
		return fmt.Errorf("network session identity or device count is invalid")
	}
	seen := make(map[string]bool, len(session.Devices))
	for _, device := range session.Devices {
		if cleanText(device.Key) == "" || !validUnicastMAC(device.MAC) || seen[device.Key] ||
			len(device.Observations) > MaxObservationsPerDevice {
			return fmt.Errorf("network session device %q is invalid", device.Key)
		}
		seen[device.Key] = true
		for _, observation := range device.Observations {
			switch observation.Category {
			case CategoryAddressing, CategoryDNS, CategoryHTTP, CategoryAccess, CategoryRisk, CategoryAction:
			default:
				return fmt.Errorf("network observation category %q is invalid", observation.Category)
			}
			if cleanText(observation.Kind) == "" || cleanText(observation.Summary) == "" || observation.Count == 0 {
				return fmt.Errorf("network observation is incomplete")
			}
			if cleanText(observation.Kind) != observation.Kind || cleanText(observation.Summary) != observation.Summary ||
				cleanText(observation.Protocol) != observation.Protocol || cleanText(observation.Source) != observation.Source ||
				cleanText(observation.Destination) != observation.Destination {
				return fmt.Errorf("network observation contains unsafe text")
			}
			switch observation.Severity {
			case SeverityInfo, SeverityWarn, SeverityError:
			default:
				return fmt.Errorf("network observation severity %q is invalid", observation.Severity)
			}
			if observation.Category == CategoryRisk && !validPersistedRisk(observation) {
				return fmt.Errorf("network risk observation is invalid")
			}
			if observation.Category == CategoryHTTP && strings.ContainsAny(observation.Summary, "?#") {
				return fmt.Errorf("network HTTP observation contains a query or fragment")
			}
			if observation.Category == CategoryRisk && (observation.Source != "" || observation.Destination != "") {
				return fmt.Errorf("network risk observation contains endpoint detail")
			}
		}
	}
	return nil
}

// Discovery is the small, package-neutral discovery boundary.
type Discovery struct {
	Adapter   string
	Role      string
	DeviceMAC string
	Field     string
	Value     string
	Evidence  string
	Packet    string
}

// Risk is a categorical protocol warning. It cannot carry credentials.
type Risk struct {
	Adapter   string
	Role      string
	DeviceMAC string
	Protocol  string
	Kind      string
}

type deviceState struct {
	device       Device
	vlans        map[uint16]bool
	ips          map[string]bool
	hostnames    map[string]bool
	protocols    map[string]bool
	observations map[string]*Observation
}

// Tracker owns one bounded live observation session.
type Tracker struct {
	mu      sync.RWMutex
	session Session
	devices map[string]*deviceState
}

// NewTracker starts an empty observation session.
func NewTracker(id, mode string, started time.Time) *Tracker {
	if started.IsZero() {
		started = time.Now().UTC()
	}
	id = cleanText(id)
	if id == "" {
		id = started.UTC().Format("20060102T150405.000000000Z")
	}
	return &Tracker{
		session: Session{Version: CurrentVersion, ID: id, Mode: cleanText(mode), StartedAt: started.UTC()},
		devices: make(map[string]*deviceState),
	}
}

// LoadTracker restores a sanitized session for project review.
func LoadTracker(session Session) *Tracker {
	tracker := NewTracker(session.ID, session.Mode, session.StartedAt)
	tracker.session.EndedAt = session.EndedAt
	tracker.session.CapturePaths = cleanStrings(session.CapturePaths)
	for _, device := range session.Devices {
		state := tracker.ensureDevice(device.Adapter, device.Role, device.MAC, device.VLANs, device.FirstSeen)
		if state == nil {
			continue
		}
		state.device.FirstSeen = device.FirstSeen.UTC()
		state.device.LastSeen = device.LastSeen.UTC()
		for _, ip := range device.IPs {
			state.ips[cleanText(ip)] = true
		}
		for _, hostname := range device.Hostnames {
			state.hostnames[cleanText(hostname)] = true
		}
		for _, protocol := range device.Protocols {
			state.protocols[strings.ToUpper(cleanText(protocol))] = true
		}
		for _, observation := range device.Observations {
			copy := observation
			state.observations[observationKey(copy)] = &copy
		}
	}
	return tracker
}

// ObserveFrame updates device state from one normalized live frame. Routine
// transport traffic is intentionally ignored.
func (t *Tracker) ObserveFrame(frame traffic.Frame, role string, decision policy.DecisionSummary) bool {
	if t == nil || frame.RawLength() == 0 {
		return false
	}
	decoded := frame.Decoded()
	vlans := make([]uint16, 0, len(decoded.VLANs))
	for _, vlan := range decoded.VLANs {
		if vlan.ID > 0 {
			vlans = append(vlans, vlan.ID)
		}
	}
	now := frame.Timestamp.UTC()
	if now.IsZero() {
		now = time.Now().UTC()
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	clientMAC := decoded.SrcMAC
	if decoded.HTTPStatus != 0 {
		clientMAC = decoded.DstMAC
	}
	state := t.ensureDevice(frame.Ingress, role, clientMAC, vlans, now)
	if state == nil {
		return false
	}
	changed := t.touch(state, now)

	if directlyAssociatesSource(frame.Direction) && clientMAC == decoded.SrcMAC && validIP(decoded.SrcIP) {
		changed = addSet(state.ips, decoded.SrcIP) || changed
	}

	for _, name := range decoded.DNSNames {
		if decoded.DNSResponse {
			break
		}
		name = cleanDNSName(name)
		if name == "" {
			continue
		}
		state.protocols["DNS"] = true
		summary := "DNS " + dnsTypeLabel(decoded.DNSType) + " " + name
		changed = t.addObservation(state, Observation{
			Category: CategoryDNS, Kind: "query", Summary: summary,
			Protocol: "DNS", Source: decoded.SrcIP, Destination: decoded.DstIP,
			Severity: SeverityInfo, FirstSeen: now, LastSeen: now, Count: 1,
		}) || changed
	}

	if decoded.HTTPMethod != "" {
		method := strings.ToUpper(cleanText(decoded.HTTPMethod))
		host := cleanHTTPHost(decoded.HTTPHost)
		path := cleanHTTPPath(decoded.HTTPPath)
		if host != "" {
			state.protocols["HTTP"] = true
			summary := strings.TrimSpace("HTTP " + method + " " + host + path)
			changed = t.addObservation(state, Observation{
				Category: CategoryHTTP, Kind: "request", Summary: summary,
				Protocol: "HTTP", Source: decoded.SrcIP, Destination: decoded.DstIP,
				Severity: SeverityWarn, FirstSeen: now, LastSeen: now, Count: 1,
			}) || changed
		}
	}
	if decoded.HTTPStatus != 0 {
		state.protocols["HTTP"] = true
		changed = t.addObservation(state, Observation{
			Category: CategoryHTTP, Kind: "response", Summary: fmt.Sprintf("HTTP response %d", decoded.HTTPStatus),
			Protocol: "HTTP", Source: decoded.SrcIP, Destination: decoded.DstIP,
			Severity: SeverityInfo, FirstSeen: now, LastSeen: now, Count: 1,
		}) || changed
	}
	if decoded.EtherType == 0x888e || decoded.EAPOLType != 0 {
		state.protocols["EAPOL"] = true
		label := eapolTypeLabel(decoded.EAPOLType)
		changed = t.addObservation(state, Observation{
			Category: CategoryAccess, Kind: "eapol", Summary: "EAPOL " + label,
			Protocol: "EAPOL", Source: decoded.SrcMAC, Destination: decoded.DstMAC,
			Severity: SeverityInfo, FirstSeen: now, LastSeen: now, Count: 1,
		}) || changed
	}
	if decoded.EtherType == 0x88e5 {
		state.protocols["MACSEC"] = true
		changed = t.addObservation(state, Observation{
			Category: CategoryAccess, Kind: "macsec", Summary: "MACsec traffic observed",
			Protocol: "MACsec", Source: decoded.SrcMAC, Destination: decoded.DstMAC,
			Severity: SeverityWarn, FirstSeen: now, LastSeen: now, Count: 1,
		}) || changed
	}
	if notableDecision(decision) {
		kind, severity := decisionKind(decision)
		summary := strings.TrimSpace(string(decision.Status) + " " + kind)
		if decision.WinningRuleID != "" {
			summary += " by " + cleanText(decision.WinningRuleID)
		}
		changed = t.addObservation(state, Observation{
			Category: CategoryAction, Kind: kind, Summary: summary,
			Source: decoded.SrcIP, Destination: decoded.DstIP,
			Severity: severity, FirstSeen: now, LastSeen: now, Count: 1,
		}) || changed
	}
	return changed
}

// ObserveDiscovery adds strong addressing and access evidence.
func (t *Tracker) ObserveDiscovery(item Discovery) bool {
	if t == nil {
		return false
	}
	mac := strings.ToLower(strings.TrimSpace(item.DeviceMAC))
	if !validUnicastMAC(mac) {
		if strings.EqualFold(item.Field, "mac") {
			mac = strings.ToLower(strings.TrimSpace(item.Value))
		}
	}
	if !validUnicastMAC(mac) {
		return false
	}
	now := time.Now().UTC()
	t.mu.Lock()
	defer t.mu.Unlock()
	state := t.ensureDevice(item.Adapter, item.Role, mac, nil, now)
	if state == nil {
		return false
	}
	changed := t.touch(state, now)
	field := strings.ToLower(strings.TrimSpace(item.Field))
	value := cleanText(item.Value)
	switch field {
	case "ip", "arp_sender_ip":
		if validIP(value) {
			changed = addSet(state.ips, value) || changed
			changed = t.addObservation(state, Observation{
				Category: CategoryAddressing, Kind: "address", Summary: "address " + value + " via " + cleanText(item.Packet),
				Protocol: cleanText(item.Packet), Severity: SeverityInfo,
				FirstSeen: now, LastSeen: now, Count: 1,
			}) || changed
		}
	case "gateway", "dns", "cidr":
		changed = t.addObservation(state, Observation{
			Category: CategoryAddressing, Kind: field, Summary: field + " " + value + " via " + cleanText(item.Packet),
			Protocol: cleanText(item.Packet), Severity: SeverityInfo,
			FirstSeen: now, LastSeen: now, Count: 1,
		}) || changed
	case "vlan":
		if vlan, err := strconv.ParseUint(value, 10, 16); err == nil && vlan > 0 && vlan <= 4094 {
			changed = addSet(state.vlans, uint16(vlan)) || changed
			changed = t.addObservation(state, Observation{
				Category: CategoryAddressing, Kind: "vlan", Summary: "VLAN " + value,
				Protocol: "802.1Q", Severity: SeverityInfo,
				FirstSeen: now, LastSeen: now, Count: 1,
			}) || changed
		}
	case "eapol", "eapol_type", "eapol_version", "eap_code", "eap_type", "macsec":
		protocol := "EAPOL"
		if field == "macsec" {
			protocol = "MACSEC"
		}
		state.protocols[protocol] = true
		severity := SeverityInfo
		if field == "macsec" || strings.Contains(strings.ToLower(value), "failure") {
			severity = SeverityWarn
		}
		changed = t.addObservation(state, Observation{
			Category: CategoryAccess, Kind: field, Summary: strings.ToUpper(field) + " " + value,
			Protocol: protocol, Severity: severity,
			FirstSeen: now, LastSeen: now, Count: 1,
		}) || changed
	}
	return changed
}

// ObserveRisk records a categorical warning without accepting raw detail.
func (t *Tracker) ObserveRisk(risk Risk) bool {
	if t == nil || !validUnicastMAC(risk.DeviceMAC) {
		return false
	}
	protocol := strings.ToUpper(cleanText(risk.Protocol))
	kind := cleanText(risk.Kind)
	if !allowedRisk(protocol, kind) {
		return false
	}
	now := time.Now().UTC()
	t.mu.Lock()
	defer t.mu.Unlock()
	state := t.ensureDevice(risk.Adapter, risk.Role, risk.DeviceMAC, nil, now)
	if state == nil {
		return false
	}
	changed := t.touch(state, now)
	state.protocols[protocol] = true
	return t.addObservation(state, Observation{
		Category: CategoryRisk, Kind: strings.ToLower(protocol + "-" + kind),
		Summary: protocol + " " + kind + " observed", Protocol: protocol,
		Severity: SeverityWarn, FirstSeen: now, LastSeen: now, Count: 1,
	}) || changed
}

func allowedRisk(protocol, kind string) bool {
	key := strings.ToUpper(cleanText(protocol)) + "\x00" + strings.ToLower(cleanText(kind))
	switch key {
	case "HTTP\x00basic authentication",
		"HTTP\x00plaintext form authentication",
		"NTLM\x00authentication",
		"FTP\x00plaintext authentication",
		"SMTP\x00plaintext authentication",
		"POP3\x00plaintext authentication",
		"IMAP\x00plaintext authentication",
		"IRC\x00plaintext authentication",
		"LDAP\x00simple bind",
		"KERBEROS\x00rc4 pre-authentication",
		"SNMP\x00v1 community authentication",
		"SNMP\x00v2c community authentication",
		"MSSQL\x00login exchange",
		"EAP\x00eap-md5 authentication",
		"EAP\x00cisco leap authentication",
		"EAP\x00eap-mschapv2 authentication":
		return true
	default:
		return false
	}
}

func validPersistedRisk(observation Observation) bool {
	protocol := strings.ToUpper(cleanText(observation.Protocol))
	prefix := protocol + " "
	if protocol == "" || !strings.HasPrefix(observation.Summary, prefix) || !strings.HasSuffix(observation.Summary, " observed") {
		return false
	}
	kind := strings.TrimSuffix(strings.TrimPrefix(observation.Summary, prefix), " observed")
	return allowedRisk(protocol, kind) && observation.Kind == strings.ToLower(protocol+"-"+kind)
}

// AddCapture associates a finalized capture path with this session.
func (t *Tracker) AddCapture(path string) {
	if t == nil {
		return
	}
	path = cleanText(path)
	if path == "" {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, existing := range t.session.CapturePaths {
		if existing == path {
			return
		}
	}
	t.session.CapturePaths = append(t.session.CapturePaths, path)
}

// Finish marks the current session complete.
func (t *Tracker) Finish(ended time.Time) {
	if t == nil {
		return
	}
	if ended.IsZero() {
		ended = time.Now().UTC()
	}
	t.mu.Lock()
	t.session.EndedAt = ended.UTC()
	t.mu.Unlock()
}

// Snapshot returns an ownership-independent deterministic session.
func (t *Tracker) Snapshot() Session {
	if t == nil {
		return Session{Version: CurrentVersion}
	}
	t.mu.RLock()
	defer t.mu.RUnlock()
	out := t.session
	out.CapturePaths = append([]string(nil), t.session.CapturePaths...)
	out.Devices = make([]Device, 0, len(t.devices))
	for _, state := range t.devices {
		device := state.device
		device.VLANs = sortedUint16Keys(state.vlans)
		device.IPs = sortedStringKeys(state.ips)
		device.Hostnames = sortedStringKeys(state.hostnames)
		device.Protocols = sortedStringKeys(state.protocols)
		device.Observations = make([]Observation, 0, len(state.observations))
		for _, observation := range state.observations {
			device.Observations = append(device.Observations, *observation)
		}
		sort.Slice(device.Observations, func(i, j int) bool {
			if device.Observations[i].Category == device.Observations[j].Category {
				return device.Observations[i].Summary < device.Observations[j].Summary
			}
			return device.Observations[i].Category < device.Observations[j].Category
		})
		out.Devices = append(out.Devices, device)
	}
	sort.Slice(out.Devices, func(i, j int) bool {
		if out.Devices[i].LastSeen.Equal(out.Devices[j].LastSeen) {
			return out.Devices[i].Key < out.Devices[j].Key
		}
		return out.Devices[i].LastSeen.After(out.Devices[j].LastSeen)
	})
	return out
}

func (t *Tracker) ensureDevice(adapter, role, mac string, vlans []uint16, now time.Time) *deviceState {
	mac = strings.ToLower(strings.TrimSpace(mac))
	if !validUnicastMAC(mac) {
		return nil
	}
	adapter = cleanText(adapter)
	role = cleanText(role)
	key := strings.ToLower(adapter) + "/" + mac
	state := t.devices[key]
	if state == nil {
		if len(t.devices) >= MaxDevices {
			return nil
		}
		state = &deviceState{
			device: Device{Key: key, MAC: mac, Adapter: adapter, Role: role, FirstSeen: now.UTC(), LastSeen: now.UTC()},
			vlans:  make(map[uint16]bool), ips: make(map[string]bool), hostnames: make(map[string]bool),
			protocols: make(map[string]bool), observations: make(map[string]*Observation),
		}
		t.devices[key] = state
	}
	for _, vlan := range vlans {
		if vlan > 0 && vlan <= 4094 {
			state.vlans[vlan] = true
		}
	}
	return state
}

func (t *Tracker) touch(state *deviceState, now time.Time) bool {
	if now.After(state.device.LastSeen) {
		state.device.LastSeen = now
	}
	return true
}

func (t *Tracker) addObservation(state *deviceState, observation Observation) bool {
	observation.Summary = cleanText(observation.Summary)
	observation.Kind = cleanText(observation.Kind)
	observation.Protocol = cleanText(observation.Protocol)
	observation.Source = cleanText(observation.Source)
	observation.Destination = cleanText(observation.Destination)
	if observation.Summary == "" || observation.Kind == "" {
		return false
	}
	key := observationKey(observation)
	if existing := state.observations[key]; existing != nil {
		existing.Count++
		existing.LastSeen = observation.LastSeen.UTC()
		return true
	}
	if len(state.observations) >= MaxObservationsPerDevice {
		return false
	}
	copy := observation
	state.observations[key] = &copy
	return true
}

func observationKey(observation Observation) string {
	return strings.Join([]string{
		string(observation.Category), strings.ToLower(observation.Kind),
		strings.ToLower(observation.Summary), strings.ToLower(observation.Source),
		strings.ToLower(observation.Destination),
	}, "\x00")
}

func directlyAssociatesSource(direction traffic.Direction) bool {
	switch direction {
	case traffic.DirectionOutbound, traffic.DirectionHostToSwitch:
		return true
	default:
		return false
	}
}

func notableDecision(decision policy.DecisionSummary) bool {
	if decision.Status == dataplane.StatusUnsupported || decision.Edited {
		return true
	}
	return decision.EffectiveVerdict == policy.VerdictBlock || decision.EffectiveVerdict == policy.VerdictRedirect
}

func decisionKind(decision policy.DecisionSummary) (string, Severity) {
	switch {
	case decision.Status == dataplane.StatusUnsupported:
		return "unsupported", SeverityWarn
	case decision.Edited:
		return "edited", SeverityWarn
	case decision.EffectiveVerdict == policy.VerdictBlock:
		return "blocked", SeverityWarn
	case decision.EffectiveVerdict == policy.VerdictRedirect:
		return "redirected", SeverityWarn
	default:
		return "observed", SeverityInfo
	}
}

func validUnicastMAC(value string) bool {
	mac, err := net.ParseMAC(strings.TrimSpace(value))
	return err == nil && len(mac) == 6 && mac[0]&1 == 0 && !allZero(mac)
}

func allZero(value []byte) bool {
	for _, item := range value {
		if item != 0 {
			return false
		}
	}
	return true
}

func validIP(value string) bool { return net.ParseIP(strings.TrimSpace(value)) != nil }

func cleanText(value string) string {
	value = strings.TrimSpace(value)
	value = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, value)
	runes := []rune(value)
	if len(runes) > maxTextRunes {
		value = string(runes[:maxTextRunes])
	}
	return value
}

func cleanDNSName(value string) string {
	value = strings.TrimSuffix(strings.ToLower(cleanText(value)), ".")
	if len(value) > 253 {
		return ""
	}
	return value
}

func cleanHTTPHost(value string) string {
	value = strings.ToLower(cleanText(value))
	if host, _, err := net.SplitHostPort(value); err == nil {
		value = host
	}
	return value
}

func cleanHTTPPath(value string) string {
	value = cleanText(value)
	if parsed, err := url.ParseRequestURI(value); err == nil {
		value = parsed.EscapedPath()
	} else {
		if index := strings.IndexAny(value, "?#"); index >= 0 {
			value = value[:index]
		}
	}
	if value == "" || value == "/" {
		return ""
	}
	runes := []rune(value)
	if len(runes) > 128 {
		value = string(runes[:128]) + "…"
	}
	return value
}

func dnsTypeLabel(value uint16) string {
	switch value {
	case 1:
		return "A"
	case 5:
		return "CNAME"
	case 12:
		return "PTR"
	case 15:
		return "MX"
	case 16:
		return "TXT"
	case 28:
		return "AAAA"
	default:
		if value == 0 {
			return "query"
		}
		return "type-" + strconv.Itoa(int(value))
	}
}

func eapolTypeLabel(value uint8) string {
	switch value {
	case 0:
		return "EAP"
	case 1:
		return "Start"
	case 2:
		return "Logoff"
	case 3:
		return "Key"
	case 5:
		return "MKA"
	default:
		return "type-" + strconv.Itoa(int(value))
	}
}

func addSet[K comparable](values map[K]bool, value K) bool {
	if values[value] {
		return false
	}
	values[value] = true
	return true
}

func sortedStringKeys(values map[string]bool) []string {
	out := make([]string, 0, len(values))
	for value := range values {
		if value != "" {
			out = append(out, value)
		}
	}
	sort.Strings(out)
	return out
}

func sortedUint16Keys(values map[uint16]bool) []uint16 {
	out := make([]uint16, 0, len(values))
	for value := range values {
		out = append(out, value)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func cleanStrings(values []string) []string {
	seen := make(map[string]bool)
	var out []string
	for _, value := range values {
		value = cleanText(value)
		if value != "" && !seen[value] {
			seen[value] = true
			out = append(out, value)
		}
	}
	sort.Strings(out)
	return out
}
