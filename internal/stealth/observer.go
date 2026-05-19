package stealth

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// ObservedHost represents a host seen traversing the bridge.
type ObservedHost struct {
	MAC       net.HardwareAddr
	IPs       []net.IP
	FirstSeen time.Time
	LastSeen  time.Time
	PktCount  uint64
}

// Conversation tracks a recent observed talker pair.
type Conversation struct {
	SrcMAC    net.HardwareAddr
	DstMAC    net.HardwareAddr
	SrcIP     net.IP
	DstIP     net.IP
	VLANID    uint16
	Protocol  string
	SrcPort   uint16
	DstPort   uint16
	FirstSeen time.Time
	LastSeen  time.Time
	Packets   uint64
	Bytes     uint64
}

// DNSQuery records a DNS lookup observed from the target device.
type DNSQuery struct {
	Name      string
	Type      string   // A, AAAA, CNAME, etc.
	Response  []string // resolved IPs/values
	Timestamp time.Time
}

// VLANInfo tracks a single observed VLAN on the wire.
type VLANInfo struct {
	ID        uint16
	FirstSeen time.Time
	LastSeen  time.Time
	PktCount  uint64
	Subnet    string // inferred from host IPs if possible
}

// GatewayInfo holds confirmed gateway intelligence.
type GatewayInfo struct {
	MAC       net.HardwareAddr
	IP        net.IP
	Confirmed bool   // true once traffic volume confirms this is the gateway
	PktCount  uint64 // packets from this host (high = likely gateway)
}

// NACEvent is a compact passive control-plane event for the TUI map.
type NACEvent struct {
	Timestamp time.Time
	Kind      string
	Interface string
	Direction string
	Summary   string
	VLANID    uint16
	SrcMAC    net.HardwareAddr
	DstMAC    net.HardwareAddr
	SrcIP     net.IP
	DstIP     net.IP
}

// EAPOLTelemetry tracks observed 802.1X state without modifying traffic.
type EAPOLTelemetry struct {
	Detected         bool
	PortOpen         bool
	SupplicantMAC    net.HardwareAddr
	AuthenticatorMAC net.HardwareAddr
	VLANID           uint16
	Starts           int
	Logoffs          int
	Requests         int
	Responses        int
	Successes        int
	Failures         int
	KeyFrames        int
	MKAFrames        int
	LastMethod       string
	LastCode         string
	LastDirection    string
	LastSeen         time.Time
}

// DHCPTelemetry tracks DHCP evidence that appears after authorization.
type DHCPTelemetry struct {
	Seen         bool
	Discovers    int
	Offers       int
	Requests     int
	ACKs         int
	NAKs         int
	LastType     string
	ClientMAC    net.HardwareAddr
	OfferedIP    net.IP
	ACKIP        net.IP
	ServerIP     net.IP
	RouterIP     net.IP
	Netmask      net.IPMask
	Hostname     string
	LeaseSeconds uint32
	LastSeen     time.Time
}

// RADIUSTelemetry tracks visible RADIUS control-plane outcomes.
type RADIUSTelemetry struct {
	Seen                bool
	AccessRequests      int
	AccessAccepts       int
	AccessRejects       int
	AccessChallenges    int
	AccountingRequests  int
	AccountingResponses int
	LastCode            string
	LastIdentifier      uint8
	ClientIP            net.IP
	ServerIP            net.IP
	UserName            string
	CallingStationID    string
	CalledStationID     string
	NASIPAddress        net.IP
	NASPortID           string
	FilterID            string
	ReplyMessage        string
	AssignedVLAN        string
	LastSeen            time.Time
	FirstRequestSeen    time.Time
	LastRequestSeen     time.Time
	LastResponseSeen    time.Time
}

// PortState is goLAN's passive best-effort view of the switchport state.
type PortState string

const (
	PortStateUnknown        PortState = "unknown"
	PortStateAuthenticating PortState = "authenticating"
	PortStateAccepted       PortState = "accepted"
	PortStateOpen           PortState = "open"
	PortStateRejected       PortState = "rejected"
	PortStateClosed         PortState = "closed"
)

// PortTelemetry tracks evidence that the switchport is blocked, authenticating,
// accepted by policy, or passing traffic. This is independent of 802.1X because
// MAB, open ports, static-IP devices, and guest VLANs may never emit EAPOL.
type PortTelemetry struct {
	State      PortState
	Confidence int
	Reason     string
	Evidence   string
	VLANID     uint16
	SrcMAC     net.HardwareAddr
	DstMAC     net.HardwareAddr
	SrcIP      net.IP
	DstIP      net.IP
	LastSeen   time.Time
}

// NetworkMap is a continuously-updated passive view of the network.
type NetworkMap struct {
	mu                    sync.RWMutex
	SeenEvents            map[string]time.Time
	Hosts                 map[string]*ObservedHost // keyed by MAC string
	Conversations         map[string]*Conversation
	CredentialFindings    map[string]*CredentialExposure
	CredentialSessions    map[string]credentialSession
	DNSLog                []DNSQuery           // recent DNS queries (capped)
	VLANs                 map[uint16]*VLANInfo // all VLANs observed
	Gateway               GatewayInfo          // confirmed gateway details
	EAPOL                 EAPOLTelemetry
	DHCP                  DHCPTelemetry
	RADIUS                RADIUSTelemetry
	Port                  PortTelemetry
	RecentEvents          []NACEvent
	maxDNSLog             int // cap on DNS log entries
	maxHosts              int // cap on hosts map size
	maxConversations      int
	maxCredentials        int
	maxCredentialSessions int
	maxEvents             int // cap on recent control-plane events
}

// NewNetworkMap creates an empty network map with sensible limits.
func NewNetworkMap() *NetworkMap {
	return &NetworkMap{
		SeenEvents:            make(map[string]time.Time),
		Hosts:                 make(map[string]*ObservedHost),
		Conversations:         make(map[string]*Conversation),
		CredentialFindings:    make(map[string]*CredentialExposure),
		CredentialSessions:    make(map[string]credentialSession),
		VLANs:                 make(map[uint16]*VLANInfo),
		Port:                  PortTelemetry{State: PortStateUnknown},
		maxDNSLog:             200,
		maxHosts:              500,
		maxConversations:      300,
		maxCredentials:        120,
		maxCredentialSessions: 1000,
		maxEvents:             120,
	}
}

// HostCount returns the number of observed hosts.
func (nm *NetworkMap) HostCount() int {
	nm.mu.RLock()
	defer nm.mu.RUnlock()
	return len(nm.Hosts)
}

// VLANCount returns the number of observed VLANs.
func (nm *NetworkMap) VLANCount() int {
	nm.mu.RLock()
	defer nm.mu.RUnlock()
	return len(nm.VLANs)
}

// VLANIDs returns a sorted list of observed VLAN IDs.
func (nm *NetworkMap) VLANIDs() []uint16 {
	nm.mu.RLock()
	defer nm.mu.RUnlock()
	ids := make([]uint16, 0, len(nm.VLANs))
	for id := range nm.VLANs {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	return ids
}

// HostSummary is a compact host row for a NetworkMapSnapshot.
type HostSummary struct {
	MAC       net.HardwareAddr
	IPs       []net.IP
	PktCount  uint64
	FirstSeen time.Time
	LastSeen  time.Time
}

// ConversationSummary is a compact talker row for a NetworkMapSnapshot.
type ConversationSummary struct {
	SrcMAC   net.HardwareAddr
	DstMAC   net.HardwareAddr
	SrcIP    net.IP
	DstIP    net.IP
	VLANID   uint16
	Protocol string
	SrcPort  uint16
	DstPort  uint16
	Packets  uint64
	Bytes    uint64
	LastSeen time.Time
}

// NetworkMapSnapshot is a lock-free copy for TUI rendering.
type NetworkMapSnapshot struct {
	HostCount           int
	Hosts               []HostSummary
	Conversations       []ConversationSummary
	CredentialExposures []CredentialExposureSummary
	DNSLog              []DNSQuery
	VLANIDs             []uint16
	Gateway             GatewayInfo
	EAPOL               EAPOLTelemetry
	DHCP                DHCPTelemetry
	RADIUS              RADIUSTelemetry
	Port                PortTelemetry
	RecentEvents        []NACEvent
}

// Snapshot returns a bounded copy of the passive map for rendering.
func (nm *NetworkMap) Snapshot() NetworkMapSnapshot {
	nm.mu.RLock()
	defer nm.mu.RUnlock()

	hosts := make([]HostSummary, 0, len(nm.Hosts))
	for _, host := range nm.Hosts {
		ips := make([]net.IP, len(host.IPs))
		for i, ip := range host.IPs {
			ips[i] = copyIP(ip)
		}
		hosts = append(hosts, HostSummary{
			MAC:       copyMAC(host.MAC),
			IPs:       ips,
			PktCount:  host.PktCount,
			FirstSeen: host.FirstSeen,
			LastSeen:  host.LastSeen,
		})
	}
	sort.Slice(hosts, func(i, j int) bool { return hosts[i].PktCount > hosts[j].PktCount })
	if len(hosts) > 8 {
		hosts = hosts[:8]
	}

	conversations := make([]ConversationSummary, 0, len(nm.Conversations))
	for _, conv := range nm.Conversations {
		conversations = append(conversations, ConversationSummary{
			SrcMAC:   copyMAC(conv.SrcMAC),
			DstMAC:   copyMAC(conv.DstMAC),
			SrcIP:    copyIP(conv.SrcIP),
			DstIP:    copyIP(conv.DstIP),
			VLANID:   conv.VLANID,
			Protocol: conv.Protocol,
			SrcPort:  conv.SrcPort,
			DstPort:  conv.DstPort,
			Packets:  conv.Packets,
			Bytes:    conv.Bytes,
			LastSeen: conv.LastSeen,
		})
	}
	sort.Slice(conversations, func(i, j int) bool {
		if conversations[i].LastSeen.Equal(conversations[j].LastSeen) {
			return conversations[i].Packets > conversations[j].Packets
		}
		return conversations[i].LastSeen.After(conversations[j].LastSeen)
	})
	if len(conversations) > 12 {
		conversations = conversations[:12]
	}

	credentialExposures := make([]CredentialExposureSummary, 0, len(nm.CredentialFindings))
	for _, finding := range nm.CredentialFindings {
		credentialExposures = append(credentialExposures, copyCredentialSummary(finding))
	}
	sort.Slice(credentialExposures, func(i, j int) bool {
		if credentialExposures[i].LastSeen.Equal(credentialExposures[j].LastSeen) {
			return credentialExposures[i].Count > credentialExposures[j].Count
		}
		return credentialExposures[i].LastSeen.After(credentialExposures[j].LastSeen)
	})
	if len(credentialExposures) > 12 {
		credentialExposures = credentialExposures[:12]
	}

	vlanIDs := make([]uint16, 0, len(nm.VLANs))
	for id := range nm.VLANs {
		vlanIDs = append(vlanIDs, id)
	}
	sort.Slice(vlanIDs, func(i, j int) bool { return vlanIDs[i] < vlanIDs[j] })

	dnsLog := make([]DNSQuery, len(nm.DNSLog))
	for i, query := range nm.DNSLog {
		dnsLog[i] = query
		dnsLog[i].Response = append([]string(nil), query.Response...)
	}
	if len(dnsLog) > 8 {
		dnsLog = dnsLog[len(dnsLog)-8:]
	}

	events := make([]NACEvent, len(nm.RecentEvents))
	for i, event := range nm.RecentEvents {
		events[i] = event
		events[i].Interface = event.Interface
		events[i].SrcMAC = copyMAC(event.SrcMAC)
		events[i].DstMAC = copyMAC(event.DstMAC)
		events[i].SrcIP = copyIP(event.SrcIP)
		events[i].DstIP = copyIP(event.DstIP)
	}
	if len(events) > 10 {
		events = events[len(events)-10:]
	}

	gateway := nm.Gateway
	gateway.MAC = copyMAC(gateway.MAC)
	gateway.IP = copyIP(gateway.IP)

	eapol := nm.EAPOL
	eapol.SupplicantMAC = copyMAC(eapol.SupplicantMAC)
	eapol.AuthenticatorMAC = copyMAC(eapol.AuthenticatorMAC)

	dhcp := nm.DHCP
	dhcp.ClientMAC = copyMAC(dhcp.ClientMAC)
	dhcp.OfferedIP = copyIP(dhcp.OfferedIP)
	dhcp.ACKIP = copyIP(dhcp.ACKIP)
	dhcp.ServerIP = copyIP(dhcp.ServerIP)
	dhcp.RouterIP = copyIP(dhcp.RouterIP)
	dhcp.Netmask = append(net.IPMask(nil), dhcp.Netmask...)

	radius := nm.RADIUS
	radius.ClientIP = copyIP(radius.ClientIP)
	radius.ServerIP = copyIP(radius.ServerIP)
	radius.NASIPAddress = copyIP(radius.NASIPAddress)

	port := nm.Port
	if port.State == "" {
		port.State = PortStateUnknown
	}
	port.SrcMAC = copyMAC(port.SrcMAC)
	port.DstMAC = copyMAC(port.DstMAC)
	port.SrcIP = copyIP(port.SrcIP)
	port.DstIP = copyIP(port.DstIP)

	return NetworkMapSnapshot{
		HostCount:           len(nm.Hosts),
		Hosts:               hosts,
		Conversations:       conversations,
		CredentialExposures: credentialExposures,
		DNSLog:              dnsLog,
		VLANIDs:             vlanIDs,
		Gateway:             gateway,
		EAPOL:               eapol,
		DHCP:                dhcp,
		RADIUS:              radius,
		Port:                port,
		RecentEvents:        events,
	}
}

// Observer passively watches all traffic traversing the bridge to build
// a network map. It runs on the bridge interface (bridge0) after creation,
// capturing bidirectional traffic without generating any packets.
type Observer struct {
	iface string
}

// NewObserver creates an observer for the given bridge interface.
func NewObserver(iface string) *Observer {
	return &Observer{iface: iface}
}

// Run starts the passive observation loop. It returns the NetworkMap which
// is continuously updated. The caller should read it via the RWMutex.
// Blocks until context is cancelled.
func (o *Observer) Run(ctx context.Context, targetMAC net.HardwareAddr, eventLog func(string)) *NetworkMap {
	nm := NewNetworkMap()
	o.RunInto(ctx, targetMAC, nm, eventLog)
	return nm
}

// RunInto starts the passive observation loop using a caller-owned NetworkMap.
// This lets the TUI read the map while observation is still running.
func (o *Observer) RunInto(ctx context.Context, targetMAC net.HardwareAddr, nm *NetworkMap, eventLog func(string)) {
	if nm == nil {
		nm = NewNetworkMap()
	}
	handle, err := pcap.OpenLive(o.iface, 65535, true, pcap.BlockForever)
	if err != nil {
		eventLog(fmt.Sprintf("[!][RECON] Failed to start network observer: %v", err))
		return
	}
	o.runIntoHandle(ctx, targetMAC, nm, eventLog, handle)
}

// StartInto starts the passive observation loop in the background. It returns
// an error before marking an interface active when the pcap handle cannot open.
func (o *Observer) StartInto(ctx context.Context, targetMAC net.HardwareAddr, nm *NetworkMap, eventLog func(string)) error {
	if nm == nil {
		nm = NewNetworkMap()
	}
	handle, err := pcap.OpenLive(o.iface, 65535, true, pcap.BlockForever)
	if err != nil {
		return err
	}
	go o.runIntoHandle(ctx, targetMAC, nm, eventLog, handle)
	return nil
}

func (o *Observer) runIntoHandle(ctx context.Context, targetMAC net.HardwareAddr, nm *NetworkMap, eventLog func(string), handle *pcap.Handle) {
	defer handle.Close()
	if eventLog == nil {
		eventLog = func(string) {}
	}

	eventLog(fmt.Sprintf("[*][RECON] Network observer active on %s — passively mapping traffic...", o.iface))

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packets := packetSource.Packets()

	// Rate-limiting: don't spam the log.
	lastHostLog := make(map[string]time.Time) // MAC → last log time
	lastDNSLog := make(map[string]time.Time)  // domain → last log time
	hostLogCooldown := 30 * time.Second
	dnsLogCooldown := 60 * time.Second
	vlanChangeLogged := make(map[uint16]bool)

	for {
		select {
		case <-ctx.Done():
			return
		case packet := <-packets:
			if packet == nil {
				continue
			}

			o.processPacket(packet, targetMAC, nm, eventLog,
				lastHostLog, lastDNSLog, hostLogCooldown, dnsLogCooldown, vlanChangeLogged)
		}
	}
}

// processPacket handles a single packet for all observation purposes.
func (o *Observer) processPacket(
	packet gopacket.Packet,
	targetMAC net.HardwareAddr,
	nm *NetworkMap,
	eventLog func(string),
	lastHostLog map[string]time.Time,
	lastDNSLog map[string]time.Time,
	hostLogCooldown, dnsLogCooldown time.Duration,
	vlanChangeLogged map[uint16]bool,
) {
	now := time.Now()

	// ── Layer 2: Ethernet ──────────────────────────────────────────
	ethLayer := packet.Layer(layers.LayerTypeEthernet)
	if ethLayer == nil {
		return
	}
	eth, _ := ethLayer.(*layers.Ethernet)
	srcMAC := eth.SrcMAC

	// Skip broadcast/multicast sources.
	if srcMAC[0]&1 != 0 {
		return
	}

	// ── VLAN tracking ──────────────────────────────────────────────
	vlanID := uint16(0)
	dot1qLayer := packet.Layer(layers.LayerTypeDot1Q)
	if dot1qLayer != nil {
		dot1q, _ := dot1qLayer.(*layers.Dot1Q)
		if dot1q.VLANIdentifier != 0 {
			vlanID = dot1q.VLANIdentifier
			o.trackVLAN(nm, vlanID, now, eventLog, vlanChangeLogged)
		}
	}

	// ── 802.1X / EAPOL control-plane ───────────────────────────────
	if eapolLayer := packet.Layer(layers.LayerTypeEAPOL); eapolLayer != nil {
		eapol, _ := eapolLayer.(*layers.EAPOL)
		o.processEAPOL(packet, eth, eapol, vlanID, targetMAC, nm, now, eventLog)
	}

	// ── IPv4: Host tracking + static IP inference ──────────────────
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer != nil {
		ipv4, _ := ipLayer.(*layers.IPv4)

		// Track the source host (MAC → IP mapping).
		if !ipv4.SrcIP.IsUnspecified() && !ipv4.SrcIP.IsMulticast() {
			o.trackHost(nm, srcMAC, ipv4.SrcIP, now, eventLog, lastHostLog, hostLogCooldown, targetMAC)
		}
		o.trackConversation(packet, nm, eth, ipv4, vlanID, now, uint64(len(packet.Data())))

		if macEqual(eth.DstMAC, targetMAC) && !macEqual(srcMAC, targetMAC) &&
			!ipv4.SrcIP.IsUnspecified() && !ipv4.SrcIP.IsMulticast() {
			nm.mu.Lock()
			nm.EAPOL.PortOpen = true
			o.markPortStateLocked(nm, PortStateOpen, 85, "Network IPv4 traffic reached target", now, NACEvent{
				Timestamp: now,
				Kind:      "PORT",
				Interface: o.iface,
				Direction: "network→device",
				Summary:   "Network IPv4 traffic reached target; switch port is passing traffic",
				VLANID:    vlanID,
				SrcMAC:    copyMAC(eth.SrcMAC),
				DstMAC:    copyMAC(eth.DstMAC),
				SrcIP:     copyIP(ipv4.SrcIP),
				DstIP:     copyIP(ipv4.DstIP),
			}, eventLog)
			nm.mu.Unlock()
		}

		// Also track the destination host if we know its MAC from ARP.
		// (We get this from ARP tracking below, not from the IPv4 header.)
	}

	// ── ARP: MAC → IP mapping + gateway confirmation ───────────────
	arpLayer := packet.Layer(layers.LayerTypeARP)
	if arpLayer != nil {
		arp, _ := arpLayer.(*layers.ARP)
		senderMAC := net.HardwareAddr(arp.SourceHwAddress)
		senderIP := net.IP(arp.SourceProtAddress)

		if !senderIP.IsUnspecified() && !senderIP.IsLoopback() &&
			!strings.HasPrefix(senderIP.String(), "169.254") && senderMAC[0]&1 == 0 {
			o.trackHost(nm, senderMAC, senderIP, now, eventLog, lastHostLog, hostLogCooldown, targetMAC)
		}

		// Gateway confirmation: if non-target host has high packet count, it's likely the gateway.
		if !macEqual(senderMAC, targetMAC) && !senderIP.IsUnspecified() {
			o.checkGateway(nm, senderMAC, senderIP, eventLog)
		}

		if !macEqual(senderMAC, targetMAC) &&
			(macEqual(eth.DstMAC, targetMAC) || macEqual(net.HardwareAddr(arp.DstHwAddress), targetMAC)) {
			nm.mu.Lock()
			nm.EAPOL.PortOpen = true
			o.markPortStateLocked(nm, PortStateOpen, 85, "Network ARP reached target", now, NACEvent{
				Timestamp: now,
				Kind:      "PORT",
				Interface: o.iface,
				Direction: "network→device",
				Summary:   "Network ARP reached target; switch port is passing L2 traffic",
				VLANID:    vlanID,
				SrcMAC:    copyMAC(eth.SrcMAC),
				DstMAC:    copyMAC(eth.DstMAC),
				SrcIP:     copyIP(senderIP),
				DstIP:     copyIP(net.IP(arp.DstProtAddress)),
			}, eventLog)
			nm.mu.Unlock()
		}
	}

	// ── DNS: Query/Response logging ────────────────────────────────
	dnsLayer := packet.Layer(layers.LayerTypeDNS)
	if dnsLayer != nil {
		dns, _ := dnsLayer.(*layers.DNS)

		// Log ALL observed DNS traffic on the wire for maximum network recon.
		isQuery := !dns.QR
		o.processDNS(dns, isQuery, nm, now, eventLog, lastDNSLog, dnsLogCooldown)
	}

	// ── DHCP and RADIUS control-plane ───────────────────────────────
	if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		udp, _ := udpLayer.(*layers.UDP)
		if udp.SrcPort == 67 || udp.DstPort == 67 {
			if dhcpLayer := packet.Layer(layers.LayerTypeDHCPv4); dhcpLayer != nil {
				dhcp, _ := dhcpLayer.(*layers.DHCPv4)
				o.processDHCP(dhcp, eth, vlanID, targetMAC, nm, now, eventLog)
			}
		}
		if isRADIUSPort(uint16(udp.SrcPort)) || isRADIUSPort(uint16(udp.DstPort)) {
			radiusLayer := packet.Layer(layers.LayerTypeRADIUS)
			if radiusLayer == nil && len(udp.Payload) > 0 {
				radiusPacket := gopacket.NewPacket(udp.Payload, layers.LayerTypeRADIUS, gopacket.Default)
				radiusLayer = radiusPacket.Layer(layers.LayerTypeRADIUS)
			}
			if radiusLayer != nil && ipLayer != nil {
				radius, _ := radiusLayer.(*layers.RADIUS)
				ipv4, _ := ipLayer.(*layers.IPv4)
				o.processRADIUS(radius, ipv4, vlanID, nm, now, eventLog)
			}
		}
	}

	if ipLayer != nil {
		ipv4, _ := ipLayer.(*layers.IPv4)
		o.processCredentialExposure(packet, ipv4, vlanID, nm, now, eventLog)
	}
}

func (o *Observer) processEAPOL(packet gopacket.Packet, eth *layers.Ethernet, eapol *layers.EAPOL, vlanID uint16,
	targetMAC net.HardwareAddr, nm *NetworkMap, now time.Time, eventLog func(string)) {

	direction := "other"
	if macEqual(eth.SrcMAC, targetMAC) {
		direction = "device→switch"
	} else if macEqual(eth.DstMAC, targetMAC) {
		direction = "switch→device"
	}

	summary := ""
	method := ""

	nm.mu.Lock()
	nm.EAPOL.Detected = true
	nm.EAPOL.LastSeen = now
	nm.EAPOL.LastDirection = direction
	if len(nm.EAPOL.SupplicantMAC) == 0 && len(targetMAC) > 0 {
		nm.EAPOL.SupplicantMAC = copyMAC(targetMAC)
	}
	if direction == "switch→device" && len(nm.EAPOL.AuthenticatorMAC) == 0 && eth.SrcMAC[0]&1 == 0 {
		nm.EAPOL.AuthenticatorMAC = copyMAC(eth.SrcMAC)
	}
	if vlanID != 0 && nm.EAPOL.VLANID == 0 {
		nm.EAPOL.VLANID = vlanID
	}

	switch eapol.Type {
	case layers.EAPOLTypeStart:
		nm.EAPOL.Starts++
		nm.EAPOL.LastCode = "Start"
		summary = "EAPOL-Start"
		o.markPortStateLocked(nm, PortStateAuthenticating, 20, "EAPOL-Start observed", now, NACEvent{
			Timestamp: now,
			Kind:      "PORT",
			Interface: o.iface,
			Direction: direction,
			Summary:   "EAPOL-Start observed; authentication starting",
			VLANID:    vlanID,
			SrcMAC:    copyMAC(eth.SrcMAC),
			DstMAC:    copyMAC(eth.DstMAC),
		}, eventLog)

	case layers.EAPOLTypeLogOff:
		nm.EAPOL.Logoffs++
		nm.EAPOL.LastCode = "Logoff"
		nm.EAPOL.PortOpen = false
		summary = "EAPOL-Logoff"
		o.markPortStateLocked(nm, PortStateClosed, 70, "EAPOL-Logoff observed", now, NACEvent{
			Timestamp: now,
			Kind:      "PORT",
			Interface: o.iface,
			Direction: direction,
			Summary:   "EAPOL-Logoff observed; port may be closing",
			VLANID:    vlanID,
			SrcMAC:    copyMAC(eth.SrcMAC),
			DstMAC:    copyMAC(eth.DstMAC),
		}, eventLog)

	case layers.EAPOLTypeKey:
		nm.EAPOL.KeyFrames++
		nm.EAPOL.LastCode = "Key"
		summary = "EAPOL-Key"

	case layers.EAPOLType(5):
		nm.EAPOL.MKAFrames++
		nm.EAPOL.LastCode = "MKA"
		summary = "EAPOL-MKA / MACsec key agreement"

	case layers.EAPOLTypeEAP:
		if eapLayer := packet.Layer(layers.LayerTypeEAP); eapLayer != nil {
			eap, _ := eapLayer.(*layers.EAP)
			method = eapMethodName(uint8(eap.Type))
			switch eap.Code {
			case layers.EAPCodeRequest:
				nm.EAPOL.Requests++
				nm.EAPOL.LastCode = "Request"
				summary = "EAP-Request"
				o.markPortStateLocked(nm, PortStateAuthenticating, 40, "EAP request observed", now, NACEvent{
					Timestamp: now,
					Kind:      "PORT",
					Interface: o.iface,
					Direction: direction,
					Summary:   "EAP request observed; authentication in progress",
					VLANID:    vlanID,
					SrcMAC:    copyMAC(eth.SrcMAC),
					DstMAC:    copyMAC(eth.DstMAC),
				}, eventLog)
			case layers.EAPCodeResponse:
				nm.EAPOL.Responses++
				nm.EAPOL.LastCode = "Response"
				summary = "EAP-Response"
				o.markPortStateLocked(nm, PortStateAuthenticating, 45, "EAP response observed", now, NACEvent{
					Timestamp: now,
					Kind:      "PORT",
					Interface: o.iface,
					Direction: direction,
					Summary:   "EAP response observed; authentication in progress",
					VLANID:    vlanID,
					SrcMAC:    copyMAC(eth.SrcMAC),
					DstMAC:    copyMAC(eth.DstMAC),
				}, eventLog)
			case layers.EAPCodeSuccess:
				nm.EAPOL.Successes++
				nm.EAPOL.LastCode = "Success"
				nm.EAPOL.PortOpen = true
				summary = "EAP-Success; port appears authorized"
				o.markPortStateLocked(nm, PortStateOpen, 95, "EAP-Success observed", now, NACEvent{
					Timestamp: now,
					Kind:      "PORT",
					Interface: o.iface,
					Direction: direction,
					Summary:   "EAP-Success observed; switch port authorized",
					VLANID:    vlanID,
					SrcMAC:    copyMAC(eth.SrcMAC),
					DstMAC:    copyMAC(eth.DstMAC),
				}, eventLog)
			case layers.EAPCodeFailure:
				nm.EAPOL.Failures++
				nm.EAPOL.LastCode = "Failure"
				nm.EAPOL.PortOpen = false
				summary = "EAP-Failure; authentication rejected"
				o.markPortStateLocked(nm, PortStateRejected, 95, "EAP-Failure observed", now, NACEvent{
					Timestamp: now,
					Kind:      "PORT",
					Interface: o.iface,
					Direction: direction,
					Summary:   "EAP-Failure observed; authentication rejected",
					VLANID:    vlanID,
					SrcMAC:    copyMAC(eth.SrcMAC),
					DstMAC:    copyMAC(eth.DstMAC),
				}, eventLog)
			default:
				nm.EAPOL.LastCode = fmt.Sprintf("EAP code %d", eap.Code)
				summary = nm.EAPOL.LastCode
			}
			if method != "" && method != "Unknown" {
				nm.EAPOL.LastMethod = method
			}
		} else {
			nm.EAPOL.LastCode = "EAP"
			summary = "EAPOL-EAP"
		}

	default:
		nm.EAPOL.LastCode = fmt.Sprintf("Type %d", eapol.Type)
		summary = nm.EAPOL.LastCode
	}

	if method != "" && method != "Unknown" && summary != "" {
		summary += " " + method
	}
	o.addEventLocked(nm, NACEvent{
		Timestamp: now,
		Kind:      "EAPOL",
		Interface: o.iface,
		Direction: direction,
		Summary:   summary,
		VLANID:    vlanID,
		SrcMAC:    copyMAC(eth.SrcMAC),
		DstMAC:    copyMAC(eth.DstMAC),
	})
	nm.mu.Unlock()

	if summary != "" {
		eventLog(fmt.Sprintf("[*][AUTH] %s: %s", direction, summary))
	}
}

func (o *Observer) processDHCP(dhcp *layers.DHCPv4, eth *layers.Ethernet, vlanID uint16, targetMAC net.HardwareAddr,
	nm *NetworkMap, now time.Time, eventLog func(string)) {

	msgType := "DHCP"
	for _, opt := range dhcp.Options {
		if opt.Type == layers.DHCPOptMessageType && len(opt.Data) == 1 {
			msgType = layers.DHCPMsgType(opt.Data[0]).String()
			break
		}
	}

	nm.mu.Lock()
	nm.DHCP.Seen = true
	nm.DHCP.LastType = msgType
	nm.DHCP.LastSeen = now
	if len(dhcp.ClientHWAddr) > 0 {
		nm.DHCP.ClientMAC = copyMAC(dhcp.ClientHWAddr)
	}

	switch msgType {
	case "Discover":
		nm.DHCP.Discovers++
	case "Offer":
		nm.DHCP.Offers++
		if dhcp.YourClientIP != nil {
			nm.DHCP.OfferedIP = copyIP(dhcp.YourClientIP)
		}
		if macEqual(dhcp.ClientHWAddr, targetMAC) {
			nm.EAPOL.PortOpen = true
			o.markPortStateLocked(nm, PortStateOpen, 90, "DHCP Offer reached target", now, NACEvent{
				Timestamp: now,
				Kind:      "PORT",
				Interface: o.iface,
				Direction: "network→device",
				Summary:   "DHCP Offer reached target; switch port is open",
				VLANID:    vlanID,
				SrcMAC:    copyMAC(eth.SrcMAC),
				DstMAC:    copyMAC(eth.DstMAC),
				SrcIP:     copyIP(nm.DHCP.ServerIP),
				DstIP:     copyIP(dhcp.YourClientIP),
			}, eventLog)
		}
	case "Request":
		nm.DHCP.Requests++
	case "Ack":
		nm.DHCP.ACKs++
		if dhcp.YourClientIP != nil {
			nm.DHCP.ACKIP = copyIP(dhcp.YourClientIP)
		}
		if macEqual(dhcp.ClientHWAddr, targetMAC) {
			nm.EAPOL.PortOpen = true
			o.markPortStateLocked(nm, PortStateOpen, 95, "DHCP ACK reached target", now, NACEvent{
				Timestamp: now,
				Kind:      "PORT",
				Interface: o.iface,
				Direction: "network→device",
				Summary:   "DHCP ACK reached target; switch port is open",
				VLANID:    vlanID,
				SrcMAC:    copyMAC(eth.SrcMAC),
				DstMAC:    copyMAC(eth.DstMAC),
				SrcIP:     copyIP(nm.DHCP.ServerIP),
				DstIP:     copyIP(dhcp.YourClientIP),
			}, eventLog)
		}
	case "Nak":
		nm.DHCP.NAKs++
	}

	for _, opt := range dhcp.Options {
		switch opt.Type {
		case layers.DHCPOptServerID:
			if len(opt.Data) >= 4 {
				nm.DHCP.ServerIP = copyIP(net.IP(opt.Data[:4]))
			}
		case layers.DHCPOptRouter:
			if len(opt.Data) >= 4 {
				nm.DHCP.RouterIP = copyIP(net.IP(opt.Data[:4]))
			}
		case layers.DHCPOptSubnetMask:
			if len(opt.Data) == 4 {
				nm.DHCP.Netmask = append(net.IPMask(nil), opt.Data...)
			}
		case layers.DHCPOptHostname:
			nm.DHCP.Hostname = sanitizeText(opt.Data)
		case layers.DHCPOptLeaseTime:
			if len(opt.Data) == 4 {
				nm.DHCP.LeaseSeconds = binary.BigEndian.Uint32(opt.Data)
			}
		}
	}

	summary := msgType
	if nm.DHCP.ACKIP != nil && msgType == "Ack" {
		summary += " " + nm.DHCP.ACKIP.String()
	} else if nm.DHCP.OfferedIP != nil && msgType == "Offer" {
		summary += " " + nm.DHCP.OfferedIP.String()
	}
	o.addEventLocked(nm, NACEvent{
		Timestamp: now,
		Kind:      "DHCP",
		Interface: o.iface,
		Direction: "network",
		Summary:   summary,
		VLANID:    vlanID,
		SrcMAC:    copyMAC(eth.SrcMAC),
		DstMAC:    copyMAC(eth.DstMAC),
	})
	nm.mu.Unlock()

	eventLog(fmt.Sprintf("[*][AUTH] DHCP %s observed", summary))
}

func (o *Observer) processRADIUS(radius *layers.RADIUS, ipv4 *layers.IPv4, vlanID uint16,
	nm *NetworkMap, now time.Time, eventLog func(string)) {

	code := radius.Code.String()
	nm.mu.Lock()
	nm.RADIUS.Seen = true
	nm.RADIUS.LastCode = code
	nm.RADIUS.LastIdentifier = uint8(radius.Identifier)
	nm.RADIUS.LastSeen = now

	switch radius.Code {
	case layers.RADIUSCodeAccessRequest:
		nm.RADIUS.AccessRequests++
		nm.RADIUS.ClientIP = copyIP(ipv4.SrcIP)
		nm.RADIUS.ServerIP = copyIP(ipv4.DstIP)
		if nm.RADIUS.FirstRequestSeen.IsZero() {
			nm.RADIUS.FirstRequestSeen = now
		}
		nm.RADIUS.LastRequestSeen = now
		o.markPortStateLocked(nm, PortStateAuthenticating, 35, "RADIUS Access-Request observed", now, NACEvent{
			Timestamp: now,
			Kind:      "PORT",
			Interface: o.iface,
			Direction: ipv4.SrcIP.String() + "→" + ipv4.DstIP.String(),
			Summary:   "RADIUS Access-Request observed; switch is attempting authentication",
			VLANID:    vlanID,
			SrcIP:     copyIP(ipv4.SrcIP),
			DstIP:     copyIP(ipv4.DstIP),
		}, eventLog)
	case layers.RADIUSCodeAccessAccept:
		nm.RADIUS.AccessAccepts++
		nm.RADIUS.ServerIP = copyIP(ipv4.SrcIP)
		nm.RADIUS.ClientIP = copyIP(ipv4.DstIP)
		nm.RADIUS.LastResponseSeen = now
		o.markPortStateLocked(nm, PortStateAccepted, 75, "RADIUS Access-Accept observed", now, NACEvent{
			Timestamp: now,
			Kind:      "PORT",
			Interface: o.iface,
			Direction: ipv4.SrcIP.String() + "→" + ipv4.DstIP.String(),
			Summary:   "RADIUS Access-Accept observed; waiting for EAP-Success or data-plane proof",
			VLANID:    vlanID,
			SrcIP:     copyIP(ipv4.SrcIP),
			DstIP:     copyIP(ipv4.DstIP),
		}, eventLog)
	case layers.RADIUSCodeAccessReject:
		nm.RADIUS.AccessRejects++
		nm.RADIUS.ServerIP = copyIP(ipv4.SrcIP)
		nm.RADIUS.ClientIP = copyIP(ipv4.DstIP)
		nm.RADIUS.LastResponseSeen = now
		nm.EAPOL.PortOpen = false
		o.markPortStateLocked(nm, PortStateRejected, 90, "RADIUS Access-Reject observed", now, NACEvent{
			Timestamp: now,
			Kind:      "PORT",
			Interface: o.iface,
			Direction: ipv4.SrcIP.String() + "→" + ipv4.DstIP.String(),
			Summary:   "RADIUS Access-Reject observed; policy rejected authentication",
			VLANID:    vlanID,
			SrcIP:     copyIP(ipv4.SrcIP),
			DstIP:     copyIP(ipv4.DstIP),
		}, eventLog)
	case layers.RADIUSCodeAccessChallenge:
		nm.RADIUS.AccessChallenges++
		nm.RADIUS.ServerIP = copyIP(ipv4.SrcIP)
		nm.RADIUS.ClientIP = copyIP(ipv4.DstIP)
		nm.RADIUS.LastResponseSeen = now
		o.markPortStateLocked(nm, PortStateAuthenticating, 55, "RADIUS Access-Challenge observed", now, NACEvent{
			Timestamp: now,
			Kind:      "PORT",
			Interface: o.iface,
			Direction: ipv4.SrcIP.String() + "→" + ipv4.DstIP.String(),
			Summary:   "RADIUS Access-Challenge observed; challenge/response in progress",
			VLANID:    vlanID,
			SrcIP:     copyIP(ipv4.SrcIP),
			DstIP:     copyIP(ipv4.DstIP),
		}, eventLog)
	case layers.RADIUSCodeAccountingRequest:
		nm.RADIUS.AccountingRequests++
		nm.RADIUS.ClientIP = copyIP(ipv4.SrcIP)
		nm.RADIUS.ServerIP = copyIP(ipv4.DstIP)
	case layers.RADIUSCodeAccountingResponse:
		nm.RADIUS.AccountingResponses++
		nm.RADIUS.ServerIP = copyIP(ipv4.SrcIP)
		nm.RADIUS.ClientIP = copyIP(ipv4.DstIP)
		nm.RADIUS.LastResponseSeen = now
	}

	for _, attr := range radius.Attributes {
		switch attr.Type {
		case layers.RADIUSAttributeTypeUserName:
			nm.RADIUS.UserName = sanitizeText(attr.Value)
		case layers.RADIUSAttributeTypeCallingStationId:
			nm.RADIUS.CallingStationID = sanitizeText(attr.Value)
		case layers.RADIUSAttributeTypeCalledStationId:
			nm.RADIUS.CalledStationID = sanitizeText(attr.Value)
		case layers.RADIUSAttributeTypeNASIPAddress:
			if len(attr.Value) >= 4 {
				nm.RADIUS.NASIPAddress = copyIP(net.IP(attr.Value[:4]))
			}
		case layers.RADIUSAttributeTypeNASPortId:
			nm.RADIUS.NASPortID = sanitizeText(attr.Value)
		case layers.RADIUSAttributeTypeFilterId:
			nm.RADIUS.FilterID = sanitizeText(attr.Value)
		case layers.RADIUSAttributeTypeReplyMessage:
			nm.RADIUS.ReplyMessage = sanitizeText(attr.Value)
		case layers.RADIUSAttributeTypeTunnelPrivateGroupID:
			nm.RADIUS.AssignedVLAN = sanitizeTaggedText(attr.Value)
		}
	}

	summary := code
	if nm.RADIUS.AssignedVLAN != "" && radius.Code == layers.RADIUSCodeAccessAccept {
		summary += " VLAN " + nm.RADIUS.AssignedVLAN
	}
	o.addEventLocked(nm, NACEvent{
		Timestamp: now,
		Kind:      "RADIUS",
		Interface: o.iface,
		Direction: ipv4.SrcIP.String() + "→" + ipv4.DstIP.String(),
		Summary:   summary,
		VLANID:    vlanID,
		SrcIP:     copyIP(ipv4.SrcIP),
		DstIP:     copyIP(ipv4.DstIP),
	})
	nm.mu.Unlock()

	eventLog(fmt.Sprintf("[*][AUTH] RADIUS %s %s → %s", summary, ipv4.SrcIP, ipv4.DstIP))
}

func (o *Observer) addEventLocked(nm *NetworkMap, event NACEvent) {
	if event.Summary == "" {
		return
	}
	key := event.Kind + "|" + event.Direction + "|" + event.Summary + "|" + formatEventIP(event.SrcIP) + "|" + formatEventIP(event.DstIP) + "|" + fmt.Sprintf("%d", event.VLANID)
	if last, ok := nm.SeenEvents[key]; ok && event.Timestamp.Sub(last) < 2*time.Second {
		return
	}
	nm.SeenEvents[key] = event.Timestamp
	if len(nm.SeenEvents) > nm.maxEvents*4 {
		cutoff := event.Timestamp.Add(-2 * time.Minute)
		for seenKey, seenAt := range nm.SeenEvents {
			if seenAt.Before(cutoff) {
				delete(nm.SeenEvents, seenKey)
			}
		}
	}
	nm.RecentEvents = append(nm.RecentEvents, event)
	if len(nm.RecentEvents) > nm.maxEvents {
		nm.RecentEvents = nm.RecentEvents[len(nm.RecentEvents)-nm.maxEvents:]
	}
}

func (o *Observer) markPortStateLocked(nm *NetworkMap, state PortState, confidence int, reason string, now time.Time, event NACEvent, eventLog func(string)) {
	if state == "" {
		state = PortStateUnknown
	}
	if confidence < 0 {
		confidence = 0
	}
	if confidence > 100 {
		confidence = 100
	}
	if event.Timestamp.IsZero() {
		event.Timestamp = now
	}
	if event.Kind == "" {
		event.Kind = "PORT"
	}
	if event.Summary == "" {
		event.Summary = reason
	}

	current := nm.Port
	shouldUpdate := current.State == "" ||
		current.State == PortStateUnknown ||
		state == PortStateRejected ||
		state == PortStateClosed ||
		(current.State != PortStateRejected && current.State != PortStateClosed && confidence >= current.Confidence)

	// Do not let generic in-progress evidence downgrade a proven open/accepted port.
	if (current.State == PortStateOpen || current.State == PortStateAccepted) && state == PortStateAuthenticating {
		shouldUpdate = false
	}
	if current.State == PortStateOpen && state == PortStateAccepted {
		shouldUpdate = false
	}

	if !shouldUpdate {
		return
	}

	stateChanged := current.State != state || current.Reason != reason
	nm.Port = PortTelemetry{
		State:      state,
		Confidence: confidence,
		Reason:     reason,
		Evidence:   event.Summary,
		VLANID:     event.VLANID,
		SrcMAC:     copyMAC(event.SrcMAC),
		DstMAC:     copyMAC(event.DstMAC),
		SrcIP:      copyIP(event.SrcIP),
		DstIP:      copyIP(event.DstIP),
		LastSeen:   now,
	}
	o.addEventLocked(nm, event)

	if stateChanged && eventLog != nil {
		eventLog(fmt.Sprintf("[*][AUTH] Switch port state: %s (%d%%) — %s", strings.ToUpper(string(state)), confidence, reason))
	}
}

func formatEventIP(ip net.IP) string {
	if len(ip) == 0 {
		return ""
	}
	return ip.String()
}

// trackVLAN records a VLAN observation and logs new VLANs or trunk detection.
func (o *Observer) trackVLAN(nm *NetworkMap, vlanID uint16, now time.Time,
	eventLog func(string), vlanChangeLogged map[uint16]bool) {

	nm.mu.Lock()
	defer nm.mu.Unlock()

	info, exists := nm.VLANs[vlanID]
	if !exists {
		info = &VLANInfo{
			ID:        vlanID,
			FirstSeen: now,
		}
		nm.VLANs[vlanID] = info

		// Log the discovery.
		if !vlanChangeLogged[vlanID] {
			vlanChangeLogged[vlanID] = true

			if len(nm.VLANs) == 1 {
				eventLog(fmt.Sprintf("[+][VLAN] 802.1Q VLAN %d detected on wire", vlanID))
			} else {
				// Multiple VLANs = possible trunk port → actionable intel.
				ids := make([]string, 0, len(nm.VLANs))
				for id := range nm.VLANs {
					ids = append(ids, fmt.Sprintf("%d", id))
				}
				eventLog(fmt.Sprintf("[!][VLAN] Multiple VLANs detected: %s — possible trunk port",
					strings.Join(ids, ", ")))
			}
		}
	}

	info.LastSeen = now
	info.PktCount++
}

// trackHost records a host observation and logs new hosts with rate-limiting.
func (o *Observer) trackHost(nm *NetworkMap, mac net.HardwareAddr, ip net.IP, now time.Time,
	eventLog func(string), lastLog map[string]time.Time, cooldown time.Duration,
	targetMAC net.HardwareAddr) {

	macStr := mac.String()

	nm.mu.Lock()
	defer nm.mu.Unlock()

	// Enforce host cap.
	if len(nm.Hosts) >= nm.maxHosts {
		if _, exists := nm.Hosts[macStr]; !exists {
			return // At cap, don't add new hosts
		}
	}

	host, exists := nm.Hosts[macStr]
	if !exists {
		host = &ObservedHost{
			MAC:       make(net.HardwareAddr, len(mac)),
			FirstSeen: now,
		}
		copy(host.MAC, mac)
		nm.Hosts[macStr] = host
	}

	host.LastSeen = now
	host.PktCount++

	// Add IP if not already tracked.
	ipStr := ip.String()
	hasIP := false
	for _, existing := range host.IPs {
		if existing.Equal(ip) {
			hasIP = true
			break
		}
	}
	if !hasIP {
		newIP := make(net.IP, len(ip))
		copy(newIP, ip)
		host.IPs = append(host.IPs, newIP)
	}

	// Rate-limited logging for new host discoveries (skip target — already known).
	if !macEqual(mac, targetMAC) {
		if lastTime, seen := lastLog[macStr]; !seen || now.Sub(lastTime) > cooldown {
			lastLog[macStr] = now

			if !exists {
				// Brand new host.
				eventLog(fmt.Sprintf("[+][RECON] New host observed: %s (%s)", ipStr, macStr))
			} else if !hasIP {
				// Known host, new IP (DHCP change? dual-homed?).
				eventLog(fmt.Sprintf("[*][RECON] Host %s added IP: %s", macStr, ipStr))
			}
		}
	}
}

// checkGateway uses traffic volume heuristics to confirm the gateway.
func (o *Observer) checkGateway(nm *NetworkMap, mac net.HardwareAddr, ip net.IP, eventLog func(string)) {
	nm.mu.Lock()
	defer nm.mu.Unlock()

	macStr := mac.String()
	host, exists := nm.Hosts[macStr]
	if !exists {
		return
	}

	// If this host has significantly more traffic than others, it's the gateway.
	// Threshold: 50 packets before we bother checking.
	if host.PktCount < 50 {
		return
	}

	if nm.Gateway.Confirmed {
		return // Already confirmed
	}

	// Check if this host has the most traffic of all non-target hosts.
	maxOther := uint64(0)
	for otherMAC, otherHost := range nm.Hosts {
		if otherMAC != macStr && otherHost.PktCount > maxOther {
			maxOther = otherHost.PktCount
		}
	}

	// Gateway typically has 2x+ more traffic than any other non-target host.
	if host.PktCount > maxOther*2 && host.PktCount >= 50 {
		nm.Gateway.MAC = make(net.HardwareAddr, len(mac))
		copy(nm.Gateway.MAC, mac)
		nm.Gateway.IP = make(net.IP, len(ip))
		copy(nm.Gateway.IP, ip)
		nm.Gateway.Confirmed = true
		nm.Gateway.PktCount = host.PktCount

		eventLog(fmt.Sprintf("[+][RECON] Gateway confirmed via traffic analysis: %s (%s)",
			ip.String(), macStr))
	}
}

func (o *Observer) trackConversation(packet gopacket.Packet, nm *NetworkMap, eth *layers.Ethernet, ipv4 *layers.IPv4, vlanID uint16, now time.Time, bytes uint64) {
	if nm == nil || eth == nil || ipv4 == nil {
		return
	}
	if ipv4.SrcIP.IsUnspecified() || ipv4.DstIP.IsUnspecified() || ipv4.SrcIP.IsMulticast() || ipv4.DstIP.IsMulticast() {
		return
	}

	proto, srcPort, dstPort := conversationProtocol(packet, ipv4)
	key := fmt.Sprintf("%d|%s|%s|%s|%d|%d", vlanID, ipv4.SrcIP, ipv4.DstIP, proto, srcPort, dstPort)

	nm.mu.Lock()
	defer nm.mu.Unlock()

	conv, exists := nm.Conversations[key]
	if !exists {
		if len(nm.Conversations) >= nm.maxConversations {
			pruneOldestConversationLocked(nm)
		}
		conv = &Conversation{
			SrcMAC:    copyMAC(eth.SrcMAC),
			DstMAC:    copyMAC(eth.DstMAC),
			SrcIP:     copyIP(ipv4.SrcIP),
			DstIP:     copyIP(ipv4.DstIP),
			VLANID:    vlanID,
			Protocol:  proto,
			SrcPort:   srcPort,
			DstPort:   dstPort,
			FirstSeen: now,
		}
		nm.Conversations[key] = conv
	}
	conv.LastSeen = now
	conv.Packets++
	conv.Bytes += bytes
}

func conversationProtocol(packet gopacket.Packet, ipv4 *layers.IPv4) (string, uint16, uint16) {
	if ipv4 == nil {
		return "IP", 0, 0
	}
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp, _ := tcpLayer.(*layers.TCP)
		return "TCP", uint16(tcp.SrcPort), uint16(tcp.DstPort)
	}
	if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		udp, _ := udpLayer.(*layers.UDP)
		srcPort := uint16(udp.SrcPort)
		dstPort := uint16(udp.DstPort)
		switch {
		case srcPort == 53 || dstPort == 53:
			return "DNS", srcPort, dstPort
		case srcPort == 67 || srcPort == 68 || dstPort == 67 || dstPort == 68:
			return "DHCP", srcPort, dstPort
		case isRADIUSPort(srcPort) || isRADIUSPort(dstPort):
			return "RADIUS", srcPort, dstPort
		case srcPort == 161 || srcPort == 162 || dstPort == 161 || dstPort == 162:
			return "SNMP", srcPort, dstPort
		default:
			return "UDP", srcPort, dstPort
		}
	}
	if packet.Layer(layers.LayerTypeICMPv4) != nil {
		return "ICMP", 0, 0
	}
	if ipv4.Protocol.String() != "" {
		return ipv4.Protocol.String(), 0, 0
	}
	return "IP", 0, 0
}

func pruneOldestConversationLocked(nm *NetworkMap) {
	var oldestKey string
	var oldest time.Time
	for key, conv := range nm.Conversations {
		if oldestKey == "" || conv.LastSeen.Before(oldest) {
			oldestKey = key
			oldest = conv.LastSeen
		}
	}
	if oldestKey != "" {
		delete(nm.Conversations, oldestKey)
	}
}

// processDNS extracts DNS query names and response records.
func (o *Observer) processDNS(dns *layers.DNS, isQuery bool, nm *NetworkMap, now time.Time,
	eventLog func(string), lastLog map[string]time.Time, cooldown time.Duration) {

	if isQuery && len(dns.Questions) > 0 {
		for _, q := range dns.Questions {
			name := string(q.Name)
			if name == "" {
				continue
			}

			// Rate limit: don't log the same domain repeatedly.
			if lastTime, seen := lastLog[name]; seen && now.Sub(lastTime) < cooldown {
				continue
			}
			lastLog[name] = now

			qType := dnsTypeString(q.Type)

			nm.mu.Lock()
			if len(nm.DNSLog) < nm.maxDNSLog {
				nm.DNSLog = append(nm.DNSLog, DNSQuery{
					Name:      name,
					Type:      qType,
					Timestamp: now,
				})
			}
			nm.mu.Unlock()

			eventLog(fmt.Sprintf("[*][NET] DNS query: %s (%s)", name, qType))
		}
	}

	// Log DNS responses (answers) to map hostnames to IPs.
	if !isQuery && len(dns.Answers) > 0 {
		for _, a := range dns.Answers {
			name := string(a.Name)
			if name == "" {
				continue
			}

			var resolved string
			switch a.Type {
			case layers.DNSTypeA:
				if a.IP != nil {
					resolved = a.IP.String()
				}
			case layers.DNSTypeAAAA:
				if a.IP != nil {
					resolved = a.IP.String()
				}
			case layers.DNSTypeCNAME:
				resolved = string(a.CNAME)
			default:
				continue
			}

			if resolved == "" {
				continue
			}

			// Rate limit responses too.
			key := name + "→" + resolved
			if lastTime, seen := lastLog[key]; seen && now.Sub(lastTime) < cooldown {
				continue
			}
			lastLog[key] = now

			// Update existing DNS log entry with response if we have the query.
			nm.mu.Lock()
			for i := len(nm.DNSLog) - 1; i >= 0 && i >= len(nm.DNSLog)-20; i-- {
				if nm.DNSLog[i].Name == name {
					nm.DNSLog[i].Response = append(nm.DNSLog[i].Response, resolved)
					break
				}
			}
			nm.mu.Unlock()

			eventLog(fmt.Sprintf("[+][NET] DNS resolved: %s → %s", name, resolved))
		}
	}
}

func isRADIUSPort(port uint16) bool {
	switch port {
	case 1812, 1813, 1645, 1646:
		return true
	default:
		return false
	}
}

func eapMethodName(eapType uint8) string {
	switch eapType {
	case 1:
		return "Identity"
	case 4:
		return "EAP-MD5"
	case 13:
		return "EAP-TLS"
	case 17:
		return "LEAP"
	case 21:
		return "EAP-TTLS"
	case 25:
		return "PEAP"
	case 29:
		return "MSCHAPv2"
	case 43:
		return "EAP-FAST"
	default:
		return "Unknown"
	}
}

func sanitizeText(data []byte) string {
	s := strings.Map(func(r rune) rune {
		if r < 32 || r == 127 {
			return -1
		}
		return r
	}, string(data))
	return strings.TrimSpace(s)
}

func sanitizeTaggedText(data []byte) string {
	if len(data) == 0 {
		return ""
	}
	if data[0] < 32 && len(data) > 1 {
		data = data[1:]
	}
	return sanitizeText(data)
}

// dnsTypeString returns a human-readable DNS type string.
func dnsTypeString(t layers.DNSType) string {
	switch t {
	case layers.DNSTypeA:
		return "A"
	case layers.DNSTypeAAAA:
		return "AAAA"
	case layers.DNSTypeCNAME:
		return "CNAME"
	case layers.DNSTypeMX:
		return "MX"
	case layers.DNSTypeNS:
		return "NS"
	case layers.DNSTypeTXT:
		return "TXT"
	case layers.DNSTypePTR:
		return "PTR"
	case layers.DNSTypeSRV:
		return "SRV"
	case layers.DNSTypeSOA:
		return "SOA"
	default:
		return fmt.Sprintf("Type%d", t)
	}
}
