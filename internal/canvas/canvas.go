package canvas

import (
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"golan/internal/inspect"
	"golan/internal/paths"
	"golan/internal/profile"
)

const EventKind = "canvas"

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

type Observation struct {
	Kind     string `json:"kind"`
	Adapter  string `json:"adapter,omitempty"`
	Role     string `json:"role,omitempty"`
	IP       string `json:"ip,omitempty"`
	MAC      string `json:"mac,omitempty"`
	SrcIP    string `json:"src_ip,omitempty"`
	SrcMAC   string `json:"src_mac,omitempty"`
	DstIP    string `json:"dst_ip,omitempty"`
	DstMAC   string `json:"dst_mac,omitempty"`
	Protocol string `json:"protocol,omitempty"`
	Service  string `json:"service,omitempty"`
	Port     uint16 `json:"port,omitempty"`
	Tag      string `json:"tag,omitempty"`
	Note     string `json:"note,omitempty"`
}

func (o Observation) Encode() string {
	data, err := json.Marshal(o)
	if err != nil {
		return ""
	}
	return string(data)
}

func DecodeObservation(value string) (Observation, error) {
	var obs Observation
	err := json.Unmarshal([]byte(value), &obs)
	return obs, err
}

type Map struct {
	Hosts         map[string]*Host
	Conversations map[string]*Conversation
}

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

type Service struct {
	Protocol string
	Port     uint16
	Name     string
	Count    int
	Secrets  map[string]bool
}

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

func (m *Map) Apply(obs Observation) bool {
	if m == nil {
		return false
	}
	switch strings.ToLower(strings.TrimSpace(obs.Kind)) {
	case "host":
		_, changed := m.upsertHost(obs.IP, obs.MAC, obs.Tag, obs.Adapter, obs.Role, obs.Note)
		return changed
	case "secret":
		return m.applySecret(obs)
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

func (m *Map) ApplyAdapter(cfg profile.AdapterConfig) bool {
	changed := false
	tag := cfg.AdapterRole
	if !isAuto(cfg.Role) {
		tag = cfg.Role
	}
	ip := firstIP(cfg.IP, cfg.Addrs)
	mac := ""
	if !isAuto(cfg.MAC) {
		mac = cfg.MAC
	}
	if ip != "" || mac != "" {
		_, hostChanged := m.upsertHost(ip, mac, "self", cfg.Name, cfg.AdapterRole, configuredHostNote(cfg, ip, mac))
		changed = changed || hostChanged
		if tag != "" && !strings.EqualFold(tag, "self") {
			_, roleChanged := m.upsertHost(ip, mac, tag, cfg.Name, cfg.AdapterRole, "")
			changed = changed || roleChanged
		}
	}
	if mac != "" {
		for _, learnedIP := range discoveredSelfIPs(cfg.Discovered) {
			if learnedIP == ip {
				continue
			}
			_, selfChanged := m.upsertHost(learnedIP, mac, "self", cfg.Name, cfg.AdapterRole, learnedHostNote(learnedIP))
			changed = changed || selfChanged
			if tag != "" && !strings.EqualFold(tag, "self") {
				_, roleChanged := m.upsertHost(learnedIP, mac, tag, cfg.Name, cfg.AdapterRole, "")
				changed = changed || roleChanged
			}
		}
	}
	for _, localIP := range localIPs(cfg.Addrs) {
		_, selfChanged := m.upsertHost(localIP, cfg.CurrentMAC, "self", cfg.Name, cfg.AdapterRole, "local adapter")
		changed = changed || selfChanged
	}
	if cfg.CurrentMAC != "" {
		_, selfChanged := m.upsertHost("", cfg.CurrentMAC, "self", cfg.Name, cfg.AdapterRole, "local adapter")
		changed = changed || selfChanged
	}
	if !isAuto(cfg.Gateway) {
		_, gatewayChanged := m.upsertHost(cfg.Gateway, "", "router", "", "", "")
		changed = changed || gatewayChanged
		_, gatewayTagChanged := m.upsertHost(cfg.Gateway, "", "gateway", "", "", "")
		changed = changed || gatewayTagChanged
	}
	for _, dns := range splitCSV(cfg.DNS) {
		_, dnsChanged := m.upsertHost(dns, "", "dns", "", "", "")
		changed = changed || dnsChanged
	}
	for _, discovered := range cfg.Discovered {
		for _, obs := range FromDiscovery(cfg.Name, cfg.AdapterRole, discovered.Field, discovered.Value, discovered.Evidence, discovered.Packet) {
			if m.Apply(obs) {
				changed = true
			}
		}
	}
	return changed
}

func (m *Map) ApplyProfile(p profile.Profile) bool {
	changed := false
	for _, cfg := range p.Adapters {
		if m.ApplyAdapter(cfg) {
			changed = true
		}
	}
	for _, obs := range p.Bridge.Observations {
		for _, item := range FromDiscovery(obs.Adapter, obs.Role, obs.Field, obs.Value, obs.Evidence, obs.Packet) {
			if m.Apply(item) {
				changed = true
			}
		}
	}
	return changed
}

func FromFinding(f inspect.Finding, adapter, role string) Observation {
	servicePort, service := findingService(f)
	if service == "" {
		service = strings.ToLower(strings.TrimSpace(f.Protocol))
	}
	note := f.Display()
	return Observation{
		Kind:     "secret",
		Adapter:  adapter,
		Role:     role,
		SrcIP:    f.Src,
		DstIP:    f.Dst,
		Protocol: f.Protocol,
		Service:  service,
		Port:     servicePort,
		Tag:      "credential",
		Note:     note,
	}
}

func FromDiscovery(adapter, role, field, value, evidence, packet string) []Observation {
	field = strings.ToLower(strings.TrimSpace(field))
	value = strings.TrimSpace(value)
	if value == "" {
		return nil
	}
	host := Observation{Kind: "host", Adapter: adapter, Role: role, Note: packet + "/" + evidence}
	switch field {
	case "ip", "ipv4_src", "ipv4_dst", "ipv6_src", "ipv6_dst", "arp_sender_ip", "arp_target_ip", "arp_who_has", "arp_tell":
		host.IP = value
	case "gateway":
		host.IP = value
		host.Tag = "gateway"
	case "router":
		host.IP = value
		host.Tag = "router"
	case "dns":
		host.IP = value
		host.Tag = "dns"
	case "mac":
		host.MAC = value
	default:
		return nil
	}
	return []Observation{host}
}

func ObservePacket(packet gopacket.Packet, adapter, role string) []Observation {
	var out []Observation
	var eth *layers.Ethernet
	if layer := packet.Layer(layers.LayerTypeEthernet); layer != nil {
		eth, _ = layer.(*layers.Ethernet)
	}

	if dhcpLayer := packet.Layer(layers.LayerTypeDHCPv4); dhcpLayer != nil {
		dhcp, _ := dhcpLayer.(*layers.DHCPv4)
		clientIP := usableIP(dhcp.ClientIP)
		if clientIP == "" {
			clientIP = usableIP(dhcp.YourClientIP)
		}
		out = append(out, Observation{Kind: "host", Adapter: adapter, Role: role, IP: clientIP, MAC: dhcp.ClientHWAddr.String(), Tag: "dhcp-client"})
		for _, option := range dhcp.Options {
			switch option.Type {
			case layers.DHCPOptRouter:
				for _, ip := range optionIPs(option.Data) {
					out = append(out, Observation{Kind: "host", Adapter: adapter, Role: role, IP: ip, Tag: "router"})
					out = append(out, Observation{Kind: "host", Adapter: adapter, Role: role, IP: ip, Tag: "gateway"})
				}
			case layers.DHCPOptDNS:
				for _, ip := range optionIPs(option.Data) {
					out = append(out, Observation{Kind: "host", Adapter: adapter, Role: role, IP: ip, Tag: "dns"})
				}
			case layers.DHCPOptServerID:
				for _, ip := range optionIPs(option.Data) {
					out = append(out, Observation{Kind: "host", Adapter: adapter, Role: role, IP: ip, Tag: "dhcp-server"})
				}
			}
		}
	}

	if arpLayer := packet.Layer(layers.LayerTypeARP); arpLayer != nil {
		arp, _ := arpLayer.(*layers.ARP)
		srcIP := usableIP(net.IP(arp.SourceProtAddress))
		dstIP := usableIP(net.IP(arp.DstProtAddress))
		srcMAC := net.HardwareAddr(arp.SourceHwAddress)
		dstMAC := net.HardwareAddr(arp.DstHwAddress)
		out = append(out, Observation{Kind: "host", Adapter: adapter, Role: role, IP: srcIP, MAC: macString(srcMAC)})
		out = append(out, Observation{Kind: "host", Adapter: adapter, Role: role, IP: dstIP, MAC: macString(dstMAC)})
		if srcIP != "" && dstIP != "" {
			out = append(out, Observation{Kind: "conversation", Adapter: adapter, Role: role, SrcIP: srcIP, SrcMAC: macString(srcMAC), DstIP: dstIP, DstMAC: macString(dstMAC), Protocol: "ARP"})
		}
	}

	srcIP, dstIP, proto := packetIPs(packet)
	srcMAC, dstMAC := packetMACs(eth, srcIP, dstIP)
	if srcIP != "" {
		out = append(out, Observation{Kind: "host", Adapter: adapter, Role: role, IP: srcIP, MAC: srcMAC})
	}
	if dstIP != "" {
		out = append(out, Observation{Kind: "host", Adapter: adapter, Role: role, IP: dstIP, MAC: dstMAC})
	}

	var srcPort, dstPort uint16
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp, _ := tcpLayer.(*layers.TCP)
		srcPort, dstPort = uint16(tcp.SrcPort), uint16(tcp.DstPort)
		proto = "TCP"
	}
	if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		udp, _ := udpLayer.(*layers.UDP)
		srcPort, dstPort = uint16(udp.SrcPort), uint16(udp.DstPort)
		proto = "UDP"
	}
	if srcIP != "" && dstIP != "" && proto != "" {
		servicePort, serviceName, serverIsDst := serviceFromPorts(proto, srcPort, dstPort)
		out = append(out, Observation{Kind: "conversation", Adapter: adapter, Role: role, SrcIP: srcIP, SrcMAC: srcMAC, DstIP: dstIP, DstMAC: dstMAC, Protocol: proto, Port: servicePort, Service: serviceName})
		if servicePort != 0 {
			hostIP, hostMAC := dstIP, dstMAC
			if !serverIsDst {
				hostIP, hostMAC = srcIP, srcMAC
			}
			out = append(out, Observation{Kind: "service", Adapter: adapter, Role: role, IP: hostIP, MAC: hostMAC, Protocol: proto, Port: servicePort, Service: serviceName})
		}
	}

	if eth != nil && packet.Layer(layers.LayerTypeEAPOL) != nil && validUnicastMAC(eth.SrcMAC) && validUnicastMAC(eth.DstMAC) {
		out = append(out, Observation{Kind: "conversation", Adapter: adapter, Role: role, SrcMAC: eth.SrcMAC.String(), DstMAC: eth.DstMAC.String(), Protocol: "EAPOL", Service: "802.1X"})
	}

	return compactObservations(out)
}

func SessionPath() (string, error) {
	root, err := paths.ConfigRoot()
	if err != nil {
		return "", err
	}
	return filepath.Join(root, "canvases", time.Now().Format("20060102-150405")+".canvas"), nil
}

func (m *Map) WriteFile(path string) error {
	if m == nil {
		return fmt.Errorf("canvas map is nil")
	}
	if strings.TrimSpace(path) == "" {
		return fmt.Errorf("canvas path is empty")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(m.JSONCanvas(), "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(path, append(data, '\n'), 0o644); err != nil {
		return err
	}
	return paths.FinalizeTree(filepath.Dir(path))
}

type JSONCanvas struct {
	Nodes []Node `json:"nodes"`
	Edges []Edge `json:"edges"`
}

type Node struct {
	ID     string `json:"id"`
	Type   string `json:"type"`
	X      int    `json:"x"`
	Y      int    `json:"y"`
	Width  int    `json:"width"`
	Height int    `json:"height"`
	Color  string `json:"color,omitempty"`
	Text   string `json:"text,omitempty"`
	Label  string `json:"label,omitempty"`
}

type Edge struct {
	ID       string `json:"id"`
	FromNode string `json:"fromNode"`
	FromSide string `json:"fromSide,omitempty"`
	ToNode   string `json:"toNode"`
	ToSide   string `json:"toSide,omitempty"`
	ToEnd    string `json:"toEnd,omitempty"`
	Color    string `json:"color,omitempty"`
	Label    string `json:"label,omitempty"`
}

func (m *Map) JSONCanvas() JSONCanvas {
	hosts := sortedHosts(m.Hosts)
	internal, external, infra := splitHosts(hosts)
	internalCols, externalCols, infraCols := 2, 2, 4
	internalWidth := groupWidth(internalCols)
	externalWidth := groupWidth(externalCols)
	canvasWidth := internalWidth + canvasGroupGap + externalWidth
	infraHeight := groupHeight(len(infra), infraCols)
	mainY := infraHeight + canvasGroupGap
	internalHeight := groupHeight(len(internal), internalCols)
	externalHeight := groupHeight(len(external), externalCols)
	nodes := []Node{
		{ID: "group-infra", Type: "group", X: 0, Y: 0, Width: canvasWidth, Height: infraHeight, Label: "Link / Infrastructure", Color: colorInfra},
		{ID: "group-internal", Type: "group", X: 0, Y: mainY, Width: internalWidth, Height: internalHeight, Label: "Internal", Color: colorInternal},
		{ID: "group-external", Type: "group", X: internalWidth + canvasGroupGap, Y: mainY, Width: externalWidth, Height: externalHeight, Label: "External", Color: colorExternal},
	}

	positions := make(map[string]placedHost)
	addHosts := func(list []*Host, x, y, cols int) {
		for idx, host := range list {
			col := idx % cols
			row := idx / cols
			nx := x + groupPadX + col*(nodeWidth+nodeGapX)
			ny := y + groupTopPad + row*(nodeHeight+nodeGapY)
			positions[host.Key] = placedHost{host: host, x: nx, y: ny}
			nodes = append(nodes, Node{
				ID:     nodeID(host.Key),
				Type:   "text",
				X:      nx,
				Y:      ny,
				Width:  nodeWidth,
				Height: nodeHeight,
				Color:  hostColor(host),
				Text:   hostText(host),
			})
		}
	}
	addHosts(infra, 0, 0, infraCols)
	addHosts(internal, 0, mainY, internalCols)
	addHosts(external, internalWidth+canvasGroupGap, mainY, externalCols)

	var edges []Edge
	conversations := sortedConversations(m.Conversations)
	for _, conv := range conversations {
		if _, ok := m.Hosts[conv.From]; !ok {
			continue
		}
		if _, ok := m.Hosts[conv.To]; !ok {
			continue
		}
		sides := edgeSides(positions[conv.From], positions[conv.To])
		edges = append(edges, Edge{
			ID:       edgeID(conv.Key),
			FromNode: nodeID(conv.From),
			FromSide: sides.from,
			ToNode:   nodeID(conv.To),
			ToSide:   sides.to,
			ToEnd:    "arrow",
			Color:    edgeColor(m.Hosts[conv.From], m.Hosts[conv.To]),
			Label:    convLabel(conv),
		})
	}

	return JSONCanvas{Nodes: nodes, Edges: edges}
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
		host.Services[key] = &Service{Protocol: protocol, Port: port, Name: name, Count: 1, Secrets: make(map[string]bool)}
		changed = true
	} else {
		service.Count++
	}
	if inferServiceTags(host, protocol, port, name) {
		changed = true
	}
	return changed
}

func (m *Map) applySecret(obs Observation) bool {
	from, fromChanged := m.upsertHost(obs.SrcIP, obs.SrcMAC, "", obs.Adapter, obs.Role, "")
	to, toChanged := m.upsertHost(obs.DstIP, obs.DstMAC, "", obs.Adapter, obs.Role, "")
	changed := fromChanged || toChanged
	if from != "" && to != "" && from != to {
		if m.addConversation(from, to, obs.Protocol, obs.Port, obs.Service) {
			changed = true
		}
	}
	target := to
	if target == "" {
		target = from
	}
	if target == "" {
		return changed
	}
	protocol := strings.ToUpper(strings.TrimSpace(obs.Protocol))
	if protocol == "" {
		protocol = "SECRET"
	}
	name := strings.TrimSpace(obs.Service)
	if name == "" {
		name = "credential"
	}
	key := serviceKey(protocol, obs.Port, name)
	host := m.Hosts[target]
	if host == nil {
		return changed
	}
	service := host.Services[key]
	if service == nil {
		service = &Service{Protocol: protocol, Port: obs.Port, Name: name, Count: 1, Secrets: make(map[string]bool)}
		host.Services[key] = service
		changed = true
	}
	note := strings.TrimSpace(obs.Note)
	if note != "" && !service.Secrets[note] {
		service.Secrets[note] = true
		changed = true
	}
	if note != "" && !host.Notes["credential: "+note] {
		host.Notes["credential: "+note] = true
		changed = true
	}
	if !host.Tags["credential"] {
		host.Tags["credential"] = true
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

func nodeID(key string) string {
	return "node-" + shortHash(key)
}

func edgeID(key string) string {
	return "edge-" + shortHash(key)
}

func shortHash(value string) string {
	sum := sha1.Sum([]byte(value))
	return hex.EncodeToString(sum[:])[:12]
}

func hostText(host *Host) string {
	title := firstSorted(host.IPs)
	if title == "" {
		title = firstSorted(host.MACs)
	}
	if title == "" {
		title = strings.TrimPrefix(host.Key, "ip:")
		title = strings.TrimPrefix(title, "mac:")
	}
	var lines []string
	lines = append(lines, "# "+title)
	appendList := func(label string, values []string) {
		if len(values) == 0 {
			return
		}
		lines = append(lines, label+": "+strings.Join(values, ", "))
	}
	appendList("mac", sortedKeys(host.MACs))
	if len(host.IPs) > 1 {
		appendList("ip", sortedKeys(host.IPs))
	}
	appendList("class", sortedKeys(host.Roles))
	appendList("tag", sortedKeys(host.Tags))
	appendList("adapter", sortedKeys(host.Adapters))
	if len(host.Services) > 0 {
		lines = append(lines, "services:")
		for _, service := range sortedServices(host.Services) {
			name := service.Name
			if name == "" {
				name = serviceName(service.Protocol, service.Port)
			}
			lines = append(lines, fmt.Sprintf("- %s/%d %s", strings.ToLower(service.Protocol), service.Port, name))
			for _, secret := range sortedKeys(service.Secrets) {
				lines = append(lines, "  secret: "+secret)
			}
		}
	}
	appendList("note", sortedKeys(host.Notes))
	return strings.Join(lines, "\n")
}

func hostColor(host *Host) string {
	tags := sortedKeys(host.Tags)
	for _, tag := range tags {
		switch strings.ToLower(tag) {
		case "self", "local", "debugger":
			return colorSelf
		}
	}
	if hostReference(host) {
		return colorInfra
	}
	if hostInternal(host) {
		return colorInternal
	}
	if len(host.IPs) > 0 {
		return colorExternal
	}
	return colorInfra
}

func edgeColor(from, to *Host) string {
	if from == nil || to == nil {
		return colorInfra
	}
	if hostInternal(from) && hostInternal(to) {
		return colorGreen
	}
	if hostInternal(from) != hostInternal(to) {
		return colorRed
	}
	return colorRed
}

type edgeSidePair struct {
	from string
	to   string
}

func edgeSides(from, to placedHost) edgeSidePair {
	fromCX := from.x + nodeWidth/2
	fromCY := from.y + nodeHeight/2
	toCX := to.x + nodeWidth/2
	toCY := to.y + nodeHeight/2
	dx := toCX - fromCX
	dy := toCY - fromCY
	if abs(dx) >= abs(dy) {
		if dx >= 0 {
			return edgeSidePair{from: "right", to: "left"}
		}
		return edgeSidePair{from: "left", to: "right"}
	}
	if dy >= 0 {
		return edgeSidePair{from: "bottom", to: "top"}
	}
	return edgeSidePair{from: "top", to: "bottom"}
}

func abs(value int) int {
	if value < 0 {
		return -value
	}
	return value
}

func groupWidth(cols int) int {
	if cols < 1 {
		cols = 1
	}
	return groupPadX*2 + cols*nodeWidth + (cols-1)*nodeGapX
}

func groupHeight(count, cols int) int {
	if cols < 1 {
		cols = 1
	}
	rows := (count + cols - 1) / cols
	if rows < 1 {
		rows = 1
	}
	return groupTopPad + rows*nodeHeight + (rows-1)*nodeGapY + groupBottomPad
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

func internalIP(value string) bool {
	return ipClass(value) != "external-public"
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

func firstIP(value string, addrs []string) string {
	if !isAuto(value) {
		return cleanIP(value)
	}
	for _, addr := range addrs {
		if prefix, err := netip.ParsePrefix(addr); err == nil {
			return prefix.Addr().String()
		}
		if ip := cleanIP(addr); ip != "" {
			return ip
		}
	}
	return ""
}

func localIPs(addrs []string) []string {
	var out []string
	for _, addr := range addrs {
		if prefix, err := netip.ParsePrefix(addr); err == nil {
			if ip := cleanIP(prefix.Addr().String()); ip != "" {
				out = append(out, ip)
			}
			continue
		}
		if ip := cleanIP(addr); ip != "" {
			out = append(out, ip)
		}
	}
	return out
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

func configuredHostNote(cfg profile.AdapterConfig, ip, mac string) string {
	var notes []string
	if mac = cleanMAC(mac); mac != "" {
		label := "configured mac"
		if discoveredMAC(cfg.Discovered, mac) {
			label = "configured+learned mac"
		}
		notes = append(notes, label+" "+mac)
	}
	if ip = cleanIP(ip); ip != "" {
		label := "configured ip"
		if isAuto(cfg.IP) {
			label = "local adapter ip"
		}
		if discoveredIP(cfg.Discovered, ip) {
			if isAuto(cfg.IP) {
				label = "learned ip"
			} else {
				label = "configured+learned ip"
			}
		}
		if class := ipClass(ip); class != "" {
			notes = append(notes, fmt.Sprintf("%s %s (%s)", label, ip, class))
		} else {
			notes = append(notes, label+" "+ip)
		}
	}
	if !isAuto(cfg.Notes) {
		notes = append(notes, strings.TrimSpace(cfg.Notes))
	}
	return strings.Join(notes, "; ")
}

func learnedHostNote(ip string) string {
	ip = cleanIP(ip)
	if ip == "" {
		return ""
	}
	if class := ipClass(ip); class != "" {
		return fmt.Sprintf("learned ip %s (%s)", ip, class)
	}
	return "learned ip " + ip
}

func discoveredSelfIPs(discovered []profile.DiscoveredValue) []string {
	seen := make(map[string]bool)
	var out []string
	for _, item := range discovered {
		switch strings.ToLower(strings.TrimSpace(item.Field)) {
		case "ip", "ipv4_src", "ipv6_src", "arp_sender_ip", "arp_tell":
			ip := cleanIP(item.Value)
			if ip == "" || seen[ip] {
				continue
			}
			seen[ip] = true
			out = append(out, ip)
		}
	}
	sort.Strings(out)
	return out
}

func discoveredIP(discovered []profile.DiscoveredValue, value string) bool {
	value = cleanIP(value)
	if value == "" {
		return false
	}
	for _, item := range discovered {
		switch strings.ToLower(strings.TrimSpace(item.Field)) {
		case "ip", "ipv4_src", "ipv4_dst", "ipv6_src", "ipv6_dst", "arp_sender_ip", "arp_target_ip", "arp_who_has", "arp_tell":
			if cleanIP(item.Value) == value {
				return true
			}
		}
	}
	return false
}

func discoveredMAC(discovered []profile.DiscoveredValue, value string) bool {
	value = cleanMAC(value)
	if value == "" {
		return false
	}
	for _, item := range discovered {
		switch strings.ToLower(strings.TrimSpace(item.Field)) {
		case "mac", "ether_src", "ether_dst", "arp_sender_mac", "arp_target_mac":
			if cleanMAC(item.Value) == value {
				return true
			}
		}
	}
	return false
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

func splitCSV(value string) []string {
	if isAuto(value) {
		return nil
	}
	parts := strings.Split(value, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		if ip := cleanIP(part); ip != "" {
			out = append(out, ip)
		}
	}
	return out
}

func isAuto(value string) bool {
	value = strings.TrimSpace(value)
	return value == "" || strings.EqualFold(value, "auto")
}

func convLabel(conv *Conversation) string {
	parts := []string{conv.Protocol}
	if conv.Service != "" {
		parts = append(parts, conv.Service)
	}
	if conv.Port != 0 {
		parts = append(parts, strconv.Itoa(int(conv.Port)))
	}
	if conv.Count > 1 {
		parts = append(parts, fmt.Sprintf("x%d", conv.Count))
	}
	return strings.Join(parts, " ")
}

func findingService(f inspect.Finding) (uint16, string) {
	port := f.Dport
	if port == 0 {
		port = f.Sport
	}
	name := strings.ToLower(strings.TrimSpace(f.Protocol))
	switch strings.ToUpper(f.Protocol) {
	case "HTTP":
		if f.Dport == 443 || f.Sport == 443 {
			name = "https"
			port = 443
		} else if f.Dport == 80 || f.Sport == 80 {
			name = "http"
			port = 80
		}
	case "KERBEROS":
		name = "kerberos"
		if f.Dport == 88 || f.Sport == 88 {
			port = 88
		}
	case "LDAP":
		name = "ldap"
		if f.Dport == 636 || f.Sport == 636 {
			name = "ldaps"
			port = 636
		} else if f.Dport == 389 || f.Sport == 389 {
			port = 389
		}
	case "MSSQL":
		name = "mssql"
		if f.Dport == 1433 || f.Sport == 1433 {
			port = 1433
		}
	}
	if f.Kind != "" {
		name = strings.TrimSpace(name + " " + f.Kind)
	}
	return port, name
}

func sortedHosts(hosts map[string]*Host) []*Host {
	out := make([]*Host, 0, len(hosts))
	for _, host := range hosts {
		out = append(out, host)
	}
	sort.Slice(out, func(i, j int) bool {
		return hostSortLabel(out[i]) < hostSortLabel(out[j])
	})
	return out
}

func hostSortLabel(host *Host) string {
	if ip := firstSorted(host.IPs); ip != "" {
		return "0:" + ip
	}
	return "1:" + firstSorted(host.MACs)
}

func sortedConversations(conversations map[string]*Conversation) []*Conversation {
	out := make([]*Conversation, 0, len(conversations))
	for _, conv := range conversations {
		out = append(out, conv)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Key < out[j].Key
	})
	return out
}

func sortedServices(services map[string]*Service) []*Service {
	out := make([]*Service, 0, len(services))
	for _, service := range services {
		out = append(out, service)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Protocol == out[j].Protocol {
			return out[i].Port < out[j].Port
		}
		return out[i].Protocol < out[j].Protocol
	})
	return out
}

func sortedKeys(values map[string]bool) []string {
	out := make([]string, 0, len(values))
	for value := range values {
		if strings.TrimSpace(value) != "" {
			out = append(out, value)
		}
	}
	sort.Strings(out)
	return out
}

func firstSorted(values map[string]bool) string {
	keys := sortedKeys(values)
	if len(keys) == 0 {
		return ""
	}
	return keys[0]
}

func copyBoolMap(dst, src map[string]bool) {
	for key, value := range src {
		if value {
			dst[key] = true
		}
	}
}

func packetIPs(packet gopacket.Packet) (string, string, string) {
	if layer := packet.Layer(layers.LayerTypeIPv4); layer != nil {
		ip, _ := layer.(*layers.IPv4)
		return usableIP(ip.SrcIP), usableIP(ip.DstIP), ip.Protocol.String()
	}
	if layer := packet.Layer(layers.LayerTypeIPv6); layer != nil {
		ip, _ := layer.(*layers.IPv6)
		return usableIP(ip.SrcIP), usableIP(ip.DstIP), ip.NextHeader.String()
	}
	return "", "", ""
}

func packetMACs(eth *layers.Ethernet, srcIP, dstIP string) (string, string) {
	if eth == nil {
		return "", ""
	}
	srcMAC, dstMAC := "", ""
	if internalIP(srcIP) && validUnicastMAC(eth.SrcMAC) {
		srcMAC = eth.SrcMAC.String()
	}
	if internalIP(dstIP) && validUnicastMAC(eth.DstMAC) {
		dstMAC = eth.DstMAC.String()
	}
	return srcMAC, dstMAC
}

func serviceFromPorts(protocol string, srcPort, dstPort uint16) (uint16, string, bool) {
	srcName := serviceName(protocol, srcPort)
	dstName := serviceName(protocol, dstPort)
	if dstName != "" || (dstPort > 0 && dstPort < 1024) {
		return dstPort, dstName, true
	}
	if srcName != "" || (srcPort > 0 && srcPort < 1024) {
		return srcPort, srcName, false
	}
	return 0, "", true
}

func serviceName(protocol string, port uint16) string {
	switch strings.ToUpper(protocol) {
	case "TCP":
		switch port {
		case 21:
			return "ftp"
		case 22:
			return "ssh"
		case 25:
			return "smtp"
		case 53:
			return "dns"
		case 80:
			return "http"
		case 110:
			return "pop3"
		case 143:
			return "imap"
		case 389:
			return "ldap"
		case 443:
			return "https"
		case 445:
			return "smb"
		case 587:
			return "submission"
		case 636:
			return "ldaps"
		case 1433:
			return "mssql"
		}
	case "UDP":
		switch port {
		case 53:
			return "dns"
		case 67, 68:
			return "dhcp"
		case 88:
			return "kerberos"
		case 123:
			return "ntp"
		case 161, 162:
			return "snmp"
		}
	}
	return ""
}

func optionIPs(data []byte) []string {
	var out []string
	for i := 0; i+3 < len(data); i += 4 {
		if ip := usableIP(net.IP(data[i : i+4])); ip != "" {
			out = append(out, ip)
		}
	}
	return out
}

func compactObservations(in []Observation) []Observation {
	var out []Observation
	seen := make(map[string]bool)
	for _, obs := range in {
		if obs.IP == "" && obs.MAC == "" && obs.SrcIP == "" && obs.SrcMAC == "" && obs.DstIP == "" && obs.DstMAC == "" {
			continue
		}
		key := obs.Encode()
		if key == "" || seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, obs)
	}
	return out
}

func cleanIP(value string) string {
	value = strings.TrimSpace(value)
	if value == "" || isAuto(value) {
		return ""
	}
	if ip, err := netip.ParseAddr(strings.Trim(value, "[]")); err == nil && !ip.IsUnspecified() {
		return ip.String()
	}
	return ""
}

func cleanMAC(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" || isAuto(value) {
		return ""
	}
	mac, err := net.ParseMAC(value)
	if err != nil || !validUnicastMAC(mac) {
		return ""
	}
	return mac.String()
}

func macString(mac net.HardwareAddr) string {
	if validUnicastMAC(mac) {
		return mac.String()
	}
	return ""
}

func usableIP(ip net.IP) string {
	if ip == nil || ip.IsUnspecified() {
		return ""
	}
	return ip.String()
}
