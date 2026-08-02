package canvas

import (
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"
)

const (
	canvasGroupGap = 90
	nodeWidth      = 340
	nodeHeight     = 230
	nodeGapX       = 50
	nodeGapY       = 50
	groupPadX      = 40
	groupTopPad    = 70
	groupBottomPad = 40

	colorInternal = "#2563eb"
	colorExternal = "#f97316"
	colorInfra    = "#64748b"
	colorSelf     = "#a855f7"
	colorGreen    = "#22c55e"
	colorRed      = "#ef4444"
)

// Map is the mutable in-memory network observation model.
type Map struct {
	Hosts         map[string]*Host
	Conversations map[string]*Conversation
}

// Host aggregates observed addresses, roles, services, and annotations.
type Host struct {
	Key       string
	IPs       map[string]bool
	MACs      map[string]bool
	Tags      map[string]bool
	Roles     map[string]bool
	Adapters  map[string]bool
	Services  map[string]*Service
	Notes     map[string]bool
	FirstSeen time.Time
	LastSeen  time.Time
}

type placedHost struct {
	host *Host
	x    int
	y    int
}

// Service aggregates observations for one protocol and port on a host.
type Service struct {
	Protocol string
	Port     uint16
	Name     string
	Count    int
}

// Conversation aggregates traffic between two hosts for one service.
type Conversation struct {
	Key       string
	From      string
	To        string
	Protocol  string
	Service   string
	Port      uint16
	Count     int
	FirstSeen time.Time
	LastSeen  time.Time
}

// NewMap returns an empty observation map.
func NewMap() *Map {
	return &Map{
		Hosts:         make(map[string]*Host),
		Conversations: make(map[string]*Conversation),
	}
}

func newHost(key string, now time.Time) *Host {
	return &Host{
		Key:       key,
		IPs:       make(map[string]bool),
		MACs:      make(map[string]bool),
		Tags:      make(map[string]bool),
		Roles:     make(map[string]bool),
		Adapters:  make(map[string]bool),
		Services:  make(map[string]*Service),
		Notes:     make(map[string]bool),
		FirstSeen: now,
	}
}

// Apply merges one observation and reports whether the map changed.
func (m *Map) Apply(obs Observation) bool {
	if m == nil {
		return false
	}
	switch strings.ToLower(strings.TrimSpace(obs.Kind)) {
	case "host":
		_, changed := m.upsertHost(obs.IP, obs.MAC, obs.Tag, obs.Adapter, obs.Role, obs.Note)
		return changed
	case "service":
		key, changed := m.upsertHost(obs.IP, obs.MAC, obs.Tag, obs.Adapter, obs.Role, obs.Note)
		if key == "" || obs.Port == 0 {
			return changed
		}
		return m.addService(key, obs.Protocol, obs.Port, obs.Service) || changed
	case "conversation":
		from, fromChanged := m.upsertHost(obs.SrcIP, obs.SrcMAC, "", obs.Adapter, obs.Role, "")
		to, toChanged := m.upsertHost(obs.DstIP, obs.DstMAC, "", obs.Adapter, obs.Role, "")
		if from == "" || to == "" || from == to {
			return fromChanged || toChanged
		}
		return m.addConversation(from, to, obs.Protocol, obs.Port, obs.Service) || fromChanged || toChanged
	default:
		return false
	}
}

func (m *Map) upsertHost(ip, mac, tag, adapter, role, note string) (string, bool) {
	ip = cleanIP(ip)
	mac = cleanMAC(mac)
	key := hostKey(ip, mac)
	if key == "" {
		return "", false
	}
	if mac != "" {
		if existing := m.hostKeyByMAC(mac); existing != "" {
			if ip == "" {
				key = existing
			} else if existing != key {
				m.mergeHost(existing, key)
			}
		}
	}
	if ip != "" && mac != "" {
		old := "mac:" + mac
		if old != key {
			m.mergeHost(old, key)
		}
	}
	now := time.Now().UTC()
	host := m.Hosts[key]
	changed := false
	if host == nil {
		host = newHost(key, now)
		m.Hosts[key] = host
		changed = true
	}
	host.LastSeen = now
	if ip != "" && !host.IPs[ip] {
		host.IPs[ip] = true
		for _, role := range ipRoles(ip) {
			host.Roles[role] = true
		}
		changed = true
	}
	if mac != "" && !host.MACs[mac] {
		host.MACs[mac] = true
		changed = true
	}
	for _, value := range []string{tag, role} {
		value = strings.TrimSpace(value)
		if value != "" && !isAuto(value) && !host.Tags[value] {
			host.Tags[value] = true
			changed = true
		}
	}
	for _, role := range hostRolesFromTag(tag) {
		if !host.Roles[role] {
			host.Roles[role] = true
			changed = true
		}
	}
	for _, role := range hostRolesFromTag(role) {
		if !host.Roles[role] {
			host.Roles[role] = true
			changed = true
		}
	}
	if adapter != "" {
		label := strings.Trim(strings.Join([]string{role, adapter}, "/"), "/")
		if label != "" && !host.Adapters[label] {
			host.Adapters[label] = true
			changed = true
		}
	}
	if note != "" && !isAuto(note) && !host.Notes[note] {
		host.Notes[note] = true
		changed = true
	}
	if inferHostTags(host) {
		changed = true
	}
	return key, changed
}

func (m *Map) hostKeyByMAC(mac string) string {
	for key, host := range m.Hosts {
		if host.MACs[mac] {
			return key
		}
	}
	return ""
}

func (m *Map) mergeHost(oldKey, newKey string) {
	if oldKey == newKey {
		return
	}
	old := m.Hosts[oldKey]
	if old == nil {
		return
	}
	target := m.Hosts[newKey]
	if target == nil {
		old.Key = newKey
		m.Hosts[newKey] = old
		delete(m.Hosts, oldKey)
	} else {
		copyBoolMap(target.IPs, old.IPs)
		copyBoolMap(target.MACs, old.MACs)
		copyBoolMap(target.Tags, old.Tags)
		copyBoolMap(target.Roles, old.Roles)
		copyBoolMap(target.Adapters, old.Adapters)
		copyBoolMap(target.Notes, old.Notes)
		for key, service := range old.Services {
			if target.Services[key] == nil {
				target.Services[key] = service
			} else {
				target.Services[key].Count += service.Count
			}
		}
		delete(m.Hosts, oldKey)
	}
	for key, conv := range m.Conversations {
		changed := false
		if conv.From == oldKey {
			conv.From = newKey
			changed = true
		}
		if conv.To == oldKey {
			conv.To = newKey
			changed = true
		}
		if changed {
			delete(m.Conversations, key)
			conv.Key = conversationKey(conv.From, conv.To, conv.Protocol, conv.Port, conv.Service)
			m.Conversations[conv.Key] = conv
		}
	}
}

func (m *Map) addService(hostKey, protocol string, port uint16, name string) bool {
	protocol = strings.ToUpper(strings.TrimSpace(protocol))
	name = strings.TrimSpace(name)
	if name == "" {
		name = serviceName(protocol, port)
	}
	host := m.Hosts[hostKey]
	if host == nil || port == 0 {
		return false
	}
	key := serviceKey(protocol, port, name)
	service := host.Services[key]
	changed := false
	if service == nil {
		host.Services[key] = &Service{Protocol: protocol, Port: port, Name: name, Count: 1}
		changed = true
	} else {
		service.Count++
	}
	if inferServiceTags(host, protocol, port, name) {
		changed = true
	}
	return changed
}

func (m *Map) addConversation(from, to, protocol string, port uint16, service string) bool {
	protocol = strings.ToUpper(strings.TrimSpace(protocol))
	service = strings.TrimSpace(service)
	key := conversationKey(from, to, protocol, port, service)
	now := time.Now().UTC()
	conv := m.Conversations[key]
	if conv == nil {
		m.Conversations[key] = &Conversation{Key: key, From: from, To: to, Protocol: protocol, Port: port, Service: service, Count: 1, FirstSeen: now, LastSeen: now}
		return true
	}
	conv.Count++
	conv.LastSeen = now
	return false
}

func serviceKey(protocol string, port uint16, name string) string {
	return strings.ToLower(fmt.Sprintf("%s/%d/%s", strings.ToUpper(strings.TrimSpace(protocol)), port, strings.TrimSpace(name)))
}

func conversationKey(from, to, protocol string, port uint16, service string) string {
	return strings.ToLower(strings.Join([]string{from, to, protocol, strconv.Itoa(int(port)), service}, "\x00"))
}

func hostKey(ip, mac string) string {
	if ip != "" {
		return "ip:" + ip
	}
	if mac != "" {
		return "mac:" + mac
	}
	return ""
}

func hostSelf(host *Host) bool {
	for tag := range host.Tags {
		switch strings.ToLower(tag) {
		case "self", "local", "debugger":
			return true
		}
	}
	return false
}

func hostSwitch(host *Host) bool {
	for tag := range host.Tags {
		if strings.EqualFold(tag, "switch") {
			return true
		}
	}
	return false
}

func hostGateway(host *Host) bool {
	for tag := range host.Tags {
		switch strings.ToLower(tag) {
		case "gateway", "router", "dns", "dhcp-server":
			return true
		}
	}
	return false
}

func hostRoleInternal(host *Host) bool {
	for tag := range host.Tags {
		switch strings.ToLower(tag) {
		case "host", "dhcp-client":
			return true
		case "switch":
			return false
		}
	}
	for adapter := range host.Adapters {
		if strings.HasPrefix(strings.ToLower(adapter), "host/") {
			return true
		}
		if strings.HasPrefix(strings.ToLower(adapter), "switch/") {
			return false
		}
	}
	return true
}

func splitHosts(hosts []*Host) ([]*Host, []*Host, []*Host) {
	var internal, external, infra []*Host
	for _, host := range hosts {
		if hostReference(host) || (len(host.IPs) == 0 && !hostSelf(host) && !hostSwitch(host) && !hostGateway(host)) {
			infra = append(infra, host)
			continue
		}
		if hostInternal(host) {
			internal = append(internal, host)
		} else {
			external = append(external, host)
		}
	}
	return internal, external, infra
}

func hostInternal(host *Host) bool {
	if len(host.IPs) == 0 {
		return hostRoleInternal(host)
	}
	for ip := range host.IPs {
		if ipClass(ip) != "external-public" {
			return true
		}
	}
	return false
}

func ipClass(value string) string {
	ip, err := netip.ParseAddr(strings.Trim(value, "[]"))
	if err != nil {
		return ""
	}
	if ipv4Broadcast(ip) {
		return "internal-broadcast"
	}
	switch {
	case ip.IsMulticast():
		if ip.IsLinkLocalMulticast() {
			return "internal-link-local-multicast"
		}
		return "internal-multicast"
	case ip.IsPrivate():
		return "internal-private"
	case ip.IsLoopback():
		return "internal-loopback"
	case ip.IsLinkLocalUnicast():
		return "internal-link-local"
	case ip.IsUnspecified():
		return "internal-unspecified"
	default:
		return "external-public"
	}
}

func hostReference(host *Host) bool {
	if host == nil || hostSelf(host) || hostGateway(host) {
		return false
	}
	for tag := range host.Tags {
		switch strings.ToLower(tag) {
		case "broadcast", "multicast":
			return true
		}
	}
	for role := range host.Roles {
		switch strings.ToLower(role) {
		case "internal-broadcast", "internal-multicast", "internal-link-local-multicast":
			return true
		}
	}
	return false
}

func validUnicastMAC(mac net.HardwareAddr) bool {
	if len(mac) != 6 || mac[0]&1 != 0 {
		return false
	}
	for _, b := range mac {
		if b != 0 {
			return true
		}
	}
	return false
}

func ipRoles(value string) []string {
	class := ipClass(value)
	if class == "" {
		return nil
	}
	roles := []string{class}
	if class == "external-public" {
		roles = append(roles, "external")
	} else {
		roles = append(roles, "internal")
	}
	return roles
}

func inferHostTags(host *Host) bool {
	if host == nil {
		return false
	}
	changed := false
	for ip := range host.IPs {
		switch ipClass(ip) {
		case "internal-broadcast":
			changed = addHostTag(host, "broadcast") || changed
			changed = addHostRole(host, "broadcast") || changed
		case "internal-multicast", "internal-link-local-multicast":
			changed = addHostTag(host, "multicast") || changed
			changed = addHostRole(host, "multicast") || changed
		}
		if routerCandidate(ip) {
			changed = addHostTag(host, "router") || changed
			changed = addHostTag(host, "gateway") || changed
			changed = addHostRole(host, "router") || changed
			changed = addHostRole(host, "gateway") || changed
		}
	}
	return changed
}

func inferServiceTags(host *Host, protocol string, port uint16, name string) bool {
	if host == nil {
		return false
	}
	changed := false
	service := strings.ToLower(strings.TrimSpace(name))
	if port == 53 || service == "dns" {
		changed = addHostTag(host, "dns") || changed
		changed = addHostRole(host, "dns-server") || changed
	}
	if (strings.EqualFold(protocol, "UDP") || strings.EqualFold(protocol, "TCP")) && port == 67 {
		changed = addHostTag(host, "dhcp-server") || changed
		changed = addHostRole(host, "dhcp-server") || changed
	}
	return changed
}

func addHostTag(host *Host, tag string) bool {
	tag = strings.TrimSpace(tag)
	if host == nil || tag == "" || host.Tags[tag] {
		return false
	}
	host.Tags[tag] = true
	return true
}

func addHostRole(host *Host, role string) bool {
	role = strings.TrimSpace(role)
	if host == nil || role == "" || host.Roles[role] {
		return false
	}
	host.Roles[role] = true
	return true
}

func routerCandidate(value string) bool {
	ip, err := netip.ParseAddr(strings.Trim(value, "[]"))
	if err != nil || !ip.IsValid() || ip.IsUnspecified() {
		return false
	}
	if ip.Is4() {
		parts := ip.As4()
		return ip.IsPrivate() && parts[3] == 1
	}
	return ip.IsPrivate() && strings.HasSuffix(ip.String(), "::1")
}

func ipv4Broadcast(ip netip.Addr) bool {
	if !ip.Is4() {
		return false
	}
	parts := ip.As4()
	if parts == [4]byte{255, 255, 255, 255} {
		return true
	}
	return ip.IsPrivate() && parts[3] == 255
}

func hostRolesFromTag(value string) []string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "gateway", "router":
		return []string{"router", "gateway"}
	case "dns":
		return []string{"dns-server"}
	case "dhcp-server":
		return []string{"dhcp-server"}
	case "dhcp-client":
		return []string{"dhcp-client"}
	case "switch":
		return []string{"switch"}
	case "self":
		return []string{"local-debugger"}
	default:
		return nil
	}
}

func isAuto(value string) bool {
	value = strings.TrimSpace(value)
	return value == "" || strings.EqualFold(value, "auto")
}
