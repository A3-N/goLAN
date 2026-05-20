package stealth

import (
	"bytes"
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
	"github.com/google/gopacket/macs"
	"github.com/google/gopacket/pcap"
)

const (
	maxObserverRateLimitEntries = 4096
	maxDNSResponsesPerQuery     = 16
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
	ClientIP  net.IP
	ServerIP  net.IP
	VLANID    uint16
	Timestamp time.Time
}

// HostSignal records passive identity evidence for an endpoint.
type HostSignal struct {
	MAC       net.HardwareAddr
	IP        net.IP
	Kind      string
	Value     string
	Tags      []string
	Count     uint64
	FirstSeen time.Time
	LastSeen  time.Time
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
	DNSServers   []net.IP
	Netmask      net.IPMask
	Hostname     string
	VendorClass  string
	ClientID     string
	DomainName   string
	DomainSearch string
	ParamRequest []byte
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
	HostSignals           map[string]*HostSignal
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
	maxHostSignals        int
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
		HostSignals:           make(map[string]*HostSignal),
		CredentialFindings:    make(map[string]*CredentialExposure),
		CredentialSessions:    make(map[string]credentialSession),
		VLANs:                 make(map[uint16]*VLANInfo),
		Port:                  PortTelemetry{State: PortStateUnknown},
		maxDNSLog:             200,
		maxHosts:              500,
		maxConversations:      300,
		maxHostSignals:        600,
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

// HostSignalSummary is a compact passive endpoint evidence row.
type HostSignalSummary struct {
	MAC      net.HardwareAddr
	IP       net.IP
	Kind     string
	Value    string
	Tags     []string
	Count    uint64
	LastSeen time.Time
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
	HostSignals         []HostSignalSummary
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
	if len(hosts) > 64 {
		hosts = hosts[:64]
	}

	hostSignals := make([]HostSignalSummary, 0, len(nm.HostSignals))
	for _, signal := range nm.HostSignals {
		hostSignals = append(hostSignals, HostSignalSummary{
			MAC:      copyMAC(signal.MAC),
			IP:       copyIP(signal.IP),
			Kind:     signal.Kind,
			Value:    signal.Value,
			Tags:     append([]string(nil), signal.Tags...),
			Count:    signal.Count,
			LastSeen: signal.LastSeen,
		})
	}
	sort.Slice(hostSignals, func(i, j int) bool {
		if hostSignals[i].LastSeen.Equal(hostSignals[j].LastSeen) {
			return hostSignals[i].Count > hostSignals[j].Count
		}
		return hostSignals[i].LastSeen.After(hostSignals[j].LastSeen)
	})
	if len(hostSignals) > 120 {
		hostSignals = hostSignals[:120]
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
	if len(conversations) > 80 {
		conversations = conversations[:80]
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
		dnsLog[i].ClientIP = copyIP(query.ClientIP)
		dnsLog[i].ServerIP = copyIP(query.ServerIP)
	}
	if len(dnsLog) > 64 {
		dnsLog = dnsLog[len(dnsLog)-64:]
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
	if len(events) > 64 {
		events = events[len(events)-64:]
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
	dhcp.DNSServers = copyIPList(dhcp.DNSServers)
	dhcp.Netmask = append(net.IPMask(nil), dhcp.Netmask...)
	dhcp.ParamRequest = append([]byte(nil), dhcp.ParamRequest...)

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
		HostSignals:         hostSignals,
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
	lastRateLimitPrune := time.Now()

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
			if time.Since(lastRateLimitPrune) > time.Minute {
				now := time.Now()
				pruneObserverTimeMap(lastHostLog, now.Add(-5*time.Minute), maxObserverRateLimitEntries)
				pruneObserverTimeMap(lastDNSLog, now.Add(-10*time.Minute), maxObserverRateLimitEntries)
				lastRateLimitPrune = now
			}
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
	o.processEthernetSignals(eth, nm, now)

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

	if lldpLayer := packet.Layer(layers.LayerTypeLinkLayerDiscoveryInfo); lldpLayer != nil {
		lldp, _ := lldpLayer.(*layers.LinkLayerDiscoveryInfo)
		o.processLLDP(lldp, eth, vlanID, targetMAC, nm, now, eventLog, lastHostLog, hostLogCooldown)
	}
	if cdpLayer := packet.Layer(layers.LayerTypeCiscoDiscoveryInfo); cdpLayer != nil {
		cdp, _ := cdpLayer.(*layers.CiscoDiscoveryInfo)
		o.processCDP(cdp, eth, vlanID, targetMAC, nm, now, eventLog, lastHostLog, hostLogCooldown)
	}

	// ── IPv4: Host tracking + static IP inference ──────────────────
	var ipv4 *layers.IPv4
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer != nil {
		ipv4, _ = ipLayer.(*layers.IPv4)

		// Track the source host (MAC → IP mapping).
		if !ipv4.SrcIP.IsUnspecified() && !ipv4.SrcIP.IsMulticast() {
			o.trackHost(nm, srcMAC, ipv4.SrcIP, now, eventLog, lastHostLog, hostLogCooldown, targetMAC)
		}
		o.trackConversation(packet, nm, eth, ipv4, vlanID, now, uint64(len(packet.Data())))
		o.processIPv4Signals(packet, eth, ipv4, vlanID, nm, now)

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
		o.processARPSignals(arp, nm, now)

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
		o.processDNS(dns, isQuery, nm, ipv4, vlanID, now, eventLog, lastDNSLog, dnsLogCooldown)
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

func (o *Observer) processEthernetSignals(eth *layers.Ethernet, nm *NetworkMap, now time.Time) {
	if eth == nil || len(eth.SrcMAC) < 3 {
		return
	}
	prefix := [3]byte{eth.SrcMAC[0], eth.SrcMAC[1], eth.SrcMAC[2]}
	vendor := strings.TrimSpace(macs.ValidMACPrefixMap[prefix])
	if vendor == "" {
		return
	}
	o.recordHostSignal(nm, eth.SrcMAC, nil, "oui", vendor, []string{"oui", vendorSignalTag(vendor)}, now)
}

func (o *Observer) processIPv4Signals(packet gopacket.Packet, eth *layers.Ethernet, ipv4 *layers.IPv4, vlanID uint16, nm *NetworkMap, now time.Time) {
	if packet == nil || eth == nil || ipv4 == nil {
		return
	}
	if !ipv4.SrcIP.IsUnspecified() && !ipv4.SrcIP.IsMulticast() {
		o.recordHostSignal(nm, eth.SrcMAC, ipv4.SrcIP, "ip-stack", fmt.Sprintf("ttl=%d", ipv4.TTL), ttlSignalTags(ipv4.TTL), now)
	}

	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp, _ := tcpLayer.(*layers.TCP)
		if tcp.SYN && !tcp.ACK {
			value, tags := tcpFingerprint(ipv4, tcp)
			o.recordHostSignal(nm, eth.SrcMAC, ipv4.SrcIP, "tcp-fingerprint", value, tags, now)
		}
		o.processTCPPayloadSignals(tcp, eth, ipv4, nm, now)
	}
	if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		udp, _ := udpLayer.(*layers.UDP)
		o.processUDPPayloadSignals(udp, eth, ipv4, vlanID, nm, now)
	}
}

func (o *Observer) processTCPPayloadSignals(tcp *layers.TCP, eth *layers.Ethernet, ipv4 *layers.IPv4, nm *NetworkMap, now time.Time) {
	if tcp == nil || eth == nil || ipv4 == nil || len(tcp.Payload) == 0 {
		return
	}
	srcPort := uint16(tcp.SrcPort)
	dstPort := uint16(tcp.DstPort)
	payload := tcp.Payload

	if bytes.HasPrefix(payload, []byte("SSH-")) {
		line := firstPayloadLine(payload)
		o.recordHostSignal(nm, eth.SrcMAC, ipv4.SrcIP, "ssh-banner", line, []string{"ssh", "server-banner"}, now)
		return
	}

	if host, userAgent := parseHTTPRequestHeaders(payload); host != "" || userAgent != "" {
		if host != "" {
			o.recordHostSignal(nm, eth.DstMAC, ipv4.DstIP, "http-host", host, []string{"http", "web", "http-host"}, now)
		}
		if userAgent != "" {
			o.recordHostSignal(nm, eth.SrcMAC, ipv4.SrcIP, "http-user-agent", userAgent, userAgentTags(userAgent), now)
		}
	}
	if server := parseHTTPResponseServer(payload); server != "" {
		o.recordHostSignal(nm, eth.SrcMAC, ipv4.SrcIP, "http-server", server, []string{"http", "web", "http-server"}, now)
	}

	if srcPort == 443 || dstPort == 443 || srcPort == 8443 || dstPort == 8443 || looksLikeTLSClientHello(payload) {
		if sni := parseTLSSNI(payload); sni != "" {
			o.recordHostSignal(nm, eth.DstMAC, ipv4.DstIP, "tls-sni", sni, []string{"tls", "sni", "https"}, now)
		}
	}
}

func (o *Observer) processUDPPayloadSignals(udp *layers.UDP, eth *layers.Ethernet, ipv4 *layers.IPv4, vlanID uint16, nm *NetworkMap, now time.Time) {
	if udp == nil || eth == nil || ipv4 == nil || len(udp.Payload) == 0 {
		return
	}
	srcPort := uint16(udp.SrcPort)
	dstPort := uint16(udp.DstPort)
	payload := udp.Payload
	if srcPort == 1900 || dstPort == 1900 {
		if value := parseHeaderLikeValue(payload, "SERVER"); value != "" {
			o.recordHostSignal(nm, eth.SrcMAC, ipv4.SrcIP, "ssdp-server", value, []string{"ssdp", "upnp", "iot-discovery"}, now)
		}
		if value := firstString(parseHeaderLikeValue(payload, "ST"), parseHeaderLikeValue(payload, "NT")); value != "" {
			o.recordHostSignal(nm, eth.SrcMAC, ipv4.SrcIP, "ssdp-type", value, []string{"ssdp", "upnp", "service-discovery"}, now)
		}
	}
	if srcPort == 3702 || dstPort == 3702 {
		o.recordHostSignal(nm, eth.SrcMAC, ipv4.SrcIP, "ws-discovery", "WS-Discovery", []string{"ws-discovery", "windows", "printer-discovery"}, now)
	}
	if srcPort == 5355 || dstPort == 5355 {
		o.recordHostSignal(nm, eth.SrcMAC, ipv4.SrcIP, "llmnr", "LLMNR", []string{"llmnr", "windows-name-resolution", "windows"}, now)
	}
	if srcPort == 137 || dstPort == 137 || srcPort == 138 || dstPort == 138 {
		o.recordHostSignal(nm, eth.SrcMAC, ipv4.SrcIP, "netbios", "NetBIOS", []string{"netbios", "windows-name-resolution", "windows"}, now)
	}
	if vlanID != 0 {
		o.recordHostSignal(nm, eth.SrcMAC, ipv4.SrcIP, "vlan", fmt.Sprintf("%d", vlanID), []string{fmt.Sprintf("vlan/%d", vlanID)}, now)
	}
}

func (o *Observer) processARPSignals(arp *layers.ARP, nm *NetworkMap, now time.Time) {
	if arp == nil || len(arp.SourceHwAddress) == 0 {
		return
	}
	srcMAC := net.HardwareAddr(arp.SourceHwAddress)
	srcIP := net.IP(arp.SourceProtAddress)
	dstIP := net.IP(arp.DstProtAddress)
	tags := []string{"arp"}
	value := "arp"
	switch {
	case srcIP.Equal(dstIP) && !srcIP.IsUnspecified():
		value = "gratuitous arp"
		tags = append(tags, "gratuitous-arp", "address-owner")
	case srcIP.IsUnspecified() && !dstIP.IsUnspecified():
		value = "arp probe for " + dstIP.String()
		tags = append(tags, "arp-probe", "duplicate-address-detection")
	case arp.Operation == layers.ARPRequest:
		value = "arp who-has " + dstIP.String()
		tags = append(tags, "arp-request")
	case arp.Operation == layers.ARPReply:
		value = "arp reply"
		tags = append(tags, "arp-reply")
	}
	o.recordHostSignal(nm, srcMAC, srcIP, "arp", value, tags, now)
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

func (o *Observer) processLLDP(info *layers.LinkLayerDiscoveryInfo, eth *layers.Ethernet, vlanID uint16, targetMAC net.HardwareAddr,
	nm *NetworkMap, now time.Time, eventLog func(string), lastHostLog map[string]time.Time, hostLogCooldown time.Duration) {
	if info == nil || eth == nil || nm == nil {
		return
	}
	mgmtIP := lldpMgmtIPv4(info)
	if len(mgmtIP) > 0 {
		o.trackHost(nm, eth.SrcMAC, mgmtIP, now, eventLog, lastHostLog, hostLogCooldown, targetMAC)
	}

	parts := []string{}
	if value := sanitizeText([]byte(info.SysName)); value != "" {
		parts = append(parts, "sys="+value)
	}
	if value := sanitizeText([]byte(info.PortDescription)); value != "" {
		parts = append(parts, "port="+value)
	}
	if len(mgmtIP) > 0 {
		parts = append(parts, "mgmt="+mgmtIP.String())
	}
	if caps := lldpCapabilitiesText(info.SysCapabilities.EnabledCap); len(caps) > 0 {
		parts = append(parts, "caps="+strings.Join(caps, ","))
	}
	if value := sanitizeText([]byte(info.SysDescription)); value != "" {
		parts = append(parts, "desc="+value)
	}
	if len(parts) == 0 {
		parts = append(parts, "LLDP advertisement")
	}
	summary := strings.Join(parts, " ")

	nm.mu.Lock()
	o.recordHostSignalLocked(nm, eth.SrcMAC, mgmtIP, "lldp", summary, lldpSignalTags(info, summary), now)
	o.addEventLocked(nm, NACEvent{
		Timestamp: now,
		Kind:      "LLDP",
		Interface: o.iface,
		Direction: "l2-advertisement",
		Summary:   limitEventSummary(summary),
		VLANID:    vlanID,
		SrcMAC:    copyMAC(eth.SrcMAC),
		DstMAC:    copyMAC(eth.DstMAC),
		SrcIP:     copyIP(mgmtIP),
	})
	nm.mu.Unlock()
}

func (o *Observer) processCDP(info *layers.CiscoDiscoveryInfo, eth *layers.Ethernet, vlanID uint16, targetMAC net.HardwareAddr,
	nm *NetworkMap, now time.Time, eventLog func(string), lastHostLog map[string]time.Time, hostLogCooldown time.Duration) {
	if info == nil || eth == nil || nm == nil {
		return
	}
	mgmtIP := firstIPv4(info.MgmtAddresses...)
	if len(mgmtIP) == 0 {
		mgmtIP = firstIPv4(info.Addresses...)
	}
	if len(mgmtIP) > 0 {
		o.trackHost(nm, eth.SrcMAC, mgmtIP, now, eventLog, lastHostLog, hostLogCooldown, targetMAC)
	}

	parts := []string{}
	if value := sanitizeText([]byte(firstString(info.SysName, info.DeviceID))); value != "" {
		parts = append(parts, "sys="+value)
	}
	if value := sanitizeText([]byte(info.Platform)); value != "" {
		parts = append(parts, "platform="+value)
	}
	if value := sanitizeText([]byte(info.PortID)); value != "" {
		parts = append(parts, "port="+value)
	}
	if len(mgmtIP) > 0 {
		parts = append(parts, "mgmt="+mgmtIP.String())
	}
	if caps := cdpCapabilitiesText(info.Capabilities); len(caps) > 0 {
		parts = append(parts, "caps="+strings.Join(caps, ","))
	}
	if info.NativeVLAN != 0 {
		parts = append(parts, fmt.Sprintf("native-vlan=%d", info.NativeVLAN))
	}
	if value := sanitizeText([]byte(info.Version)); value != "" {
		parts = append(parts, "version="+value)
	}
	if len(parts) == 0 {
		parts = append(parts, "CDP advertisement")
	}
	summary := strings.Join(parts, " ")

	nm.mu.Lock()
	o.recordHostSignalLocked(nm, eth.SrcMAC, mgmtIP, "cdp", summary, cdpSignalTags(info, summary), now)
	o.addEventLocked(nm, NACEvent{
		Timestamp: now,
		Kind:      "CDP",
		Interface: o.iface,
		Direction: "l2-advertisement",
		Summary:   limitEventSummary(summary),
		VLANID:    vlanID,
		SrcMAC:    copyMAC(eth.SrcMAC),
		DstMAC:    copyMAC(eth.DstMAC),
		SrcIP:     copyIP(mgmtIP),
	})
	nm.mu.Unlock()
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
		case layers.DHCPOptDNS:
			nm.DHCP.DNSServers = dhcpIPv4List(opt.Data)
		case layers.DHCPOptSubnetMask:
			if len(opt.Data) == 4 {
				nm.DHCP.Netmask = append(net.IPMask(nil), opt.Data...)
			}
		case layers.DHCPOptHostname:
			nm.DHCP.Hostname = sanitizeText(opt.Data)
		case layers.DHCPOptClassID:
			nm.DHCP.VendorClass = sanitizeText(opt.Data)
		case layers.DHCPOptClientID:
			nm.DHCP.ClientID = formatDHCPClientID(opt.Data)
		case layers.DHCPOptDomainName:
			nm.DHCP.DomainName = sanitizeText(opt.Data)
		case layers.DHCPOptDomainSearch:
			nm.DHCP.DomainSearch = sanitizeText(opt.Data)
		case layers.DHCPOptParamsRequest:
			nm.DHCP.ParamRequest = append([]byte(nil), opt.Data...)
		case layers.DHCPOptLeaseTime:
			if len(opt.Data) == 4 {
				nm.DHCP.LeaseSeconds = binary.BigEndian.Uint32(opt.Data)
			}
		}
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
	dhcpIP := firstIPNonNil(nm.DHCP.ACKIP, nm.DHCP.OfferedIP)
	if len(nm.DHCP.Hostname) > 0 {
		o.recordHostSignalLocked(nm, nm.DHCP.ClientMAC, dhcpIP, "dhcp-hostname", nm.DHCP.Hostname, []string{"dhcp-hostname", "dhcp-option-12"}, now)
	}
	if len(nm.DHCP.VendorClass) > 0 {
		o.recordHostSignalLocked(nm, nm.DHCP.ClientMAC, dhcpIP, "dhcp-vendor", nm.DHCP.VendorClass, dhcpVendorTags(nm.DHCP.VendorClass), now)
	}
	if len(nm.DHCP.ClientID) > 0 {
		o.recordHostSignalLocked(nm, nm.DHCP.ClientMAC, dhcpIP, "dhcp-client-id", nm.DHCP.ClientID, []string{"dhcp-client-id", "dhcp-option-61"}, now)
	}
	if len(nm.DHCP.DomainName) > 0 {
		o.recordHostSignalLocked(nm, nm.DHCP.ClientMAC, dhcpIP, "dhcp-domain", nm.DHCP.DomainName, []string{"dhcp-domain", "dhcp-option-15"}, now)
	}
	if len(nm.DHCP.DomainSearch) > 0 {
		o.recordHostSignalLocked(nm, nm.DHCP.ClientMAC, dhcpIP, "dhcp-search", nm.DHCP.DomainSearch, []string{"dhcp-search", "dhcp-option-119"}, now)
	}
	if len(nm.DHCP.ParamRequest) > 0 {
		o.recordHostSignalLocked(nm, nm.DHCP.ClientMAC, dhcpIP, "dhcp-params", formatDHCPParamRequestSignal(nm.DHCP.ParamRequest), dhcpParamTags(nm.DHCP.ParamRequest), now)
	}
	nm.mu.Unlock()

	eventLog(fmt.Sprintf("[*][AUTH] DHCP %s observed", summary))
}

func dhcpIPv4List(data []byte) []net.IP {
	seen := make(map[string]bool)
	out := make([]net.IP, 0, len(data)/4)
	for len(data) >= net.IPv4len {
		ip := net.IP(data[:net.IPv4len]).To4()
		data = data[net.IPv4len:]
		if ip == nil || ip.IsUnspecified() || ip.IsMulticast() {
			continue
		}
		key := ip.String()
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, copyIP(ip))
	}
	return out
}

func copyIPList(values []net.IP) []net.IP {
	if len(values) == 0 {
		return nil
	}
	out := make([]net.IP, 0, len(values))
	for _, value := range values {
		if copied := copyIP(value); copied != nil {
			out = append(out, copied)
		}
	}
	return out
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

func lldpMgmtIPv4(info *layers.LinkLayerDiscoveryInfo) net.IP {
	if info == nil || info.MgmtAddress.Subtype != layers.IANAAddressFamilyIPV4 || len(info.MgmtAddress.Address) < 4 {
		return nil
	}
	return copyIP(net.IP(info.MgmtAddress.Address[:4]))
}

func firstIPv4(values ...net.IP) net.IP {
	for _, ip := range values {
		if parsed := ip.To4(); parsed != nil && !parsed.IsUnspecified() && !parsed.IsMulticast() {
			return copyIP(parsed)
		}
	}
	return nil
}

func lldpCapabilitiesText(caps layers.LLDPCapabilities) []string {
	var out []string
	if caps.Bridge {
		out = append(out, "bridge")
	}
	if caps.Router {
		out = append(out, "router")
	}
	if caps.WLANAP {
		out = append(out, "wlan-ap")
	}
	if caps.Phone {
		out = append(out, "phone")
	}
	if caps.Repeater {
		out = append(out, "repeater")
	}
	if caps.StationOnly {
		out = append(out, "station")
	}
	if caps.CVLAN {
		out = append(out, "c-vlan")
	}
	if caps.SVLAN {
		out = append(out, "s-vlan")
	}
	return out
}

func cdpCapabilitiesText(caps layers.CDPCapabilities) []string {
	var out []string
	if caps.L3Router {
		out = append(out, "router")
	}
	if caps.L2Switch {
		out = append(out, "switch")
	}
	if caps.TBBridge || caps.SPBridge {
		out = append(out, "bridge")
	}
	if caps.IsPhone {
		out = append(out, "phone")
	}
	if caps.IsHost {
		out = append(out, "host")
	}
	if caps.L1Repeater {
		out = append(out, "repeater")
	}
	if caps.RemotelyManaged {
		out = append(out, "remote-managed")
	}
	return out
}

func lldpSignalTags(info *layers.LinkLayerDiscoveryInfo, summary string) []string {
	tags := []string{"lldp", "l2-discovery", "network-discovery"}
	if info != nil {
		tags = append(tags, capabilitySignalTags(lldpCapabilitiesText(info.SysCapabilities.EnabledCap))...)
	}
	tags = append(tags, networkIdentityTags(summary)...)
	return tags
}

func cdpSignalTags(info *layers.CiscoDiscoveryInfo, summary string) []string {
	tags := []string{"cdp", "cisco-discovery", "l2-discovery", "network-discovery", "vendor:cisco", "cisco"}
	if info != nil {
		tags = append(tags, capabilitySignalTags(cdpCapabilitiesText(info.Capabilities))...)
	}
	tags = append(tags, networkIdentityTags(summary)...)
	return tags
}

func capabilitySignalTags(caps []string) []string {
	var tags []string
	for _, cap := range caps {
		switch strings.ToLower(strings.TrimSpace(cap)) {
		case "switch", "bridge", "c-vlan", "s-vlan":
			tags = append(tags, "switch", "bridge", "device:switch")
		case "router":
			tags = append(tags, "router", "device:router")
		case "phone":
			tags = append(tags, "phone", "device:phone")
		case "wlan-ap":
			tags = append(tags, "wireless-ap", "device:ap")
		case "repeater":
			tags = append(tags, "repeater", "device:network")
		case "host", "station":
			tags = append(tags, "device:host")
		case "remote-managed":
			tags = append(tags, "remote-managed")
		}
	}
	return tags
}

func networkIdentityTags(values ...string) []string {
	joined := strings.ToLower(strings.Join(values, " "))
	var tags []string
	addVendor := func(canonical string, aliases ...string) {
		for _, alias := range aliases {
			if strings.Contains(joined, alias) {
				tags = append(tags, "vendor:"+canonical, canonical)
				return
			}
		}
	}

	addVendor("cisco", "cisco", "ios-xe", "ios xr", "nx-os", "meraki")
	addVendor("extreme", "extreme", "extremexos", "exos", "voss")
	addVendor("juniper", "juniper", "junos")
	addVendor("aruba", "aruba", "procurve")
	addVendor("hpe", "hewlett packard", "hewlett-packard", "hpe ", "hp ")
	addVendor("fortinet", "fortinet", "fortigate", "fortios")
	addVendor("mikrotik", "mikrotik", "routeros")
	addVendor("ubiquiti", "ubiquiti", "unifi", "edgeos")
	addVendor("ruckus", "ruckus", "brocade icx")
	addVendor("brocade", "brocade")
	addVendor("dell", "dell ", "powerconnect", "force10", "os10")
	addVendor("huawei", "huawei")
	addVendor("paloalto", "palo alto", "pan-os", "panos")
	addVendor("checkpoint", "checkpoint", "check point", "gaia")
	addVendor("netgear", "netgear")
	addVendor("sonicwall", "sonicwall")
	addVendor("tplink", "tp-link", "tplink")
	addVendor("openwrt", "openwrt")

	switch {
	case strings.Contains(joined, "ip phone") || strings.Contains(joined, "phone"):
		tags = append(tags, "phone", "device:phone")
	case strings.Contains(joined, "access point") || strings.Contains(joined, "aironet") ||
		strings.Contains(joined, "air-ap") || strings.Contains(joined, "wlan-ap") ||
		strings.Contains(joined, "wifi") || strings.Contains(joined, "unifi ap"):
		tags = append(tags, "wireless-ap", "device:ap")
	}
	if strings.Contains(joined, "firewall") || strings.Contains(joined, "fortigate") ||
		strings.Contains(joined, "pan-os") || strings.Contains(joined, "sonicwall") ||
		strings.Contains(joined, "checkpoint") || strings.Contains(joined, "check point") {
		tags = append(tags, "firewall", "device:firewall")
	}
	if strings.Contains(joined, "switch") || strings.Contains(joined, "catalyst") ||
		strings.Contains(joined, "nexus") || strings.Contains(joined, "procurve") ||
		strings.Contains(joined, "powerconnect") || strings.Contains(joined, "icx") {
		tags = append(tags, "switch", "bridge", "device:switch")
	}
	if strings.Contains(joined, "router") || strings.Contains(joined, "isr") || strings.Contains(joined, "asr") {
		tags = append(tags, "router", "device:router")
	}
	if strings.Contains(joined, "linux") || strings.Contains(joined, "openwrt") {
		tags = append(tags, "unix-like", "os-hint:unix")
	}
	if strings.Contains(joined, "windows") {
		tags = append(tags, "windows", "os-hint:windows")
	}
	return tags
}

func limitEventSummary(value string) string {
	value = strings.Join(strings.Fields(value), " ")
	if len(value) > 180 {
		return value[:177] + "..."
	}
	return value
}

func firstString(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
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

func (o *Observer) recordHostSignal(nm *NetworkMap, mac net.HardwareAddr, ip net.IP, kind string, value string, tags []string, now time.Time) {
	if nm == nil || strings.TrimSpace(kind) == "" {
		return
	}
	value = limitSignalValue(value)
	tags = sanitizeSignalTags(tags)
	if value == "" && len(tags) == 0 {
		return
	}

	nm.mu.Lock()
	defer nm.mu.Unlock()
	o.recordHostSignalLocked(nm, mac, ip, kind, value, tags, now)
}

func (o *Observer) recordHostSignalLocked(nm *NetworkMap, mac net.HardwareAddr, ip net.IP, kind string, value string, tags []string, now time.Time) {
	if nm == nil || strings.TrimSpace(kind) == "" {
		return
	}
	value = limitSignalValue(value)
	tags = sanitizeSignalTags(tags)
	if value == "" && len(tags) == 0 {
		return
	}
	if nm.HostSignals == nil {
		nm.HostSignals = make(map[string]*HostSignal)
	}
	if len(nm.HostSignals) >= nm.maxHostSignals {
		if _, exists := nm.HostSignals[hostSignalKey(mac, ip, kind, value)]; !exists {
			pruneOldestHostSignalLocked(nm)
		}
	}
	key := hostSignalKey(mac, ip, kind, value)
	signal := nm.HostSignals[key]
	if signal == nil {
		signal = &HostSignal{
			MAC:       copyMAC(mac),
			IP:        copyIP(ip),
			Kind:      strings.TrimSpace(kind),
			Value:     value,
			FirstSeen: now,
		}
		nm.HostSignals[key] = signal
	}
	signal.Tags = appendUniqueStringsStealth(signal.Tags, tags...)
	signal.Count++
	signal.LastSeen = now
}

func hostSignalKey(mac net.HardwareAddr, ip net.IP, kind string, value string) string {
	macPart := strings.ToLower(mac.String())
	ipPart := ""
	if ip4 := ip.To4(); ip4 != nil {
		ipPart = ip4.String()
	} else if len(ip) > 0 {
		ipPart = ip.String()
	}
	return strings.Join([]string{macPart, ipPart, strings.TrimSpace(kind), strings.TrimSpace(value)}, "|")
}

func pruneOldestHostSignalLocked(nm *NetworkMap) {
	var oldestKey string
	var oldest time.Time
	for key, signal := range nm.HostSignals {
		if oldestKey == "" || signal.LastSeen.Before(oldest) {
			oldestKey = key
			oldest = signal.LastSeen
		}
	}
	if oldestKey != "" {
		delete(nm.HostSignals, oldestKey)
	}
}

func sanitizeSignalTags(tags []string) []string {
	out := make([]string, 0, len(tags))
	for _, tag := range tags {
		tag = strings.ToLower(strings.TrimSpace(tag))
		if tag == "" {
			continue
		}
		out = appendUniqueStringsStealth(out, tag)
	}
	return out
}

func limitSignalValue(value string) string {
	value = strings.Join(strings.Fields(strings.TrimSpace(value)), " ")
	if len(value) > 96 {
		return value[:93] + "..."
	}
	return value
}

func appendUniqueStringsStealth(values []string, additions ...string) []string {
	for _, addition := range additions {
		addition = strings.TrimSpace(addition)
		if addition == "" {
			continue
		}
		found := false
		for _, existing := range values {
			if existing == addition {
				found = true
				break
			}
		}
		if !found {
			values = append(values, addition)
		}
	}
	return values
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
		srcPort := uint16(tcp.SrcPort)
		dstPort := uint16(tcp.DstPort)
		if packet.Layer(layers.LayerTypeDNS) != nil {
			return "DNS", srcPort, dstPort
		}
		return serviceProtocolName(srcPort, dstPort, true), srcPort, dstPort
	}
	if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		udp, _ := udpLayer.(*layers.UDP)
		srcPort := uint16(udp.SrcPort)
		dstPort := uint16(udp.DstPort)
		if packet.Layer(layers.LayerTypeDNS) != nil {
			return "DNS", srcPort, dstPort
		}
		if packet.Layer(layers.LayerTypeDHCPv4) != nil {
			return "DHCP", srcPort, dstPort
		}
		if packet.Layer(layers.LayerTypeRADIUS) != nil {
			return "RADIUS", srcPort, dstPort
		}
		return serviceProtocolName(srcPort, dstPort, false), srcPort, dstPort
	}
	if packet.Layer(layers.LayerTypeICMPv4) != nil {
		return "ICMP", 0, 0
	}
	if ipv4.Protocol.String() != "" {
		return ipv4.Protocol.String(), 0, 0
	}
	return "IP", 0, 0
}

func serviceProtocolName(srcPort, dstPort uint16, tcp bool) string {
	servicePort := dstPort
	if isKnownConversationServicePort(srcPort) && !isKnownConversationServicePort(dstPort) {
		servicePort = srcPort
	}
	if !tcp {
		switch {
		case srcPort == 53 || dstPort == 53:
			return "DNS"
		case srcPort == 67 || srcPort == 68 || dstPort == 67 || dstPort == 68:
			return "DHCP"
		case isRADIUSPort(srcPort) || isRADIUSPort(dstPort):
			return "RADIUS"
		case srcPort == 161 || srcPort == 162 || dstPort == 161 || dstPort == 162:
			return "SNMP"
		case srcPort == 123 || dstPort == 123:
			return "NTP"
		case srcPort == 514 || dstPort == 514:
			return "SYSLOG"
		case srcPort == 137 || srcPort == 138 || dstPort == 137 || dstPort == 138:
			return "NBNS"
		case srcPort == 5353 || dstPort == 5353:
			return "MDNS"
		case srcPort == 5355 || dstPort == 5355:
			return "LLMNR"
		case srcPort == 1900 || dstPort == 1900:
			return "SSDP"
		case srcPort == 3702 || dstPort == 3702:
			return "WSD"
		default:
			return "UDP"
		}
	}
	switch servicePort {
	case 21:
		return "FTP"
	case 22:
		return "SSH"
	case 23:
		return "TELNET"
	case 111:
		return "RPCBIND"
	case 25, 465, 587:
		return "SMTP"
	case 53:
		return "DNS"
	case 80, 8080:
		return "HTTP"
	case 88, 464:
		return "KERBEROS"
	case 110, 995:
		return "POP3"
	case 135:
		return "MSRPC"
	case 139, 445:
		return "SMB"
	case 143, 993:
		return "IMAP"
	case 389, 636, 3268, 3269:
		return "LDAP"
	case 515:
		return "LPD"
	case 631:
		return "IPP"
	case 2049:
		return "NFS"
	case 443, 8443:
		return "HTTPS"
	case 9100:
		return "JETDIRECT"
	case 3389:
		return "RDP"
	case 5985, 5986:
		return "WINRM"
	default:
		return "TCP"
	}
}

func isKnownConversationServicePort(port uint16) bool {
	switch port {
	case 21, 22, 23, 25, 53, 67, 68, 69, 80, 88, 110, 111, 123, 135, 137, 138, 139, 143, 161, 162, 389, 443, 445, 464, 465, 514, 515, 587, 631, 636, 993, 995, 1812, 1813, 1900, 2049, 3268, 3269, 3389, 3702, 5353, 5355, 5985, 5986, 8080, 8443, 9100:
		return true
	default:
		return false
	}
}

func ttlSignalTags(ttl uint8) []string {
	tags := []string{fmt.Sprintf("ttl/%d", ttl)}
	switch {
	case ttl >= 120 && ttl <= 128:
		tags = append(tags, "stack:windows")
	case ttl >= 60 && ttl <= 64:
		tags = append(tags, "stack:unix")
	case ttl >= 250:
		tags = append(tags, "stack:network")
	}
	return tags
}

func tcpFingerprint(ipv4 *layers.IPv4, tcp *layers.TCP) (string, []string) {
	if tcp == nil {
		return "", nil
	}
	parts := []string{
		fmt.Sprintf("ttl=%d", ipv4.TTL),
		fmt.Sprintf("win=%d", tcp.Window),
	}
	tags := append([]string{"tcp-fingerprint"}, ttlSignalTags(ipv4.TTL)...)
	optionNames := make([]string, 0, len(tcp.Options))
	for _, opt := range tcp.Options {
		switch opt.OptionType {
		case layers.TCPOptionKindMSS:
			if len(opt.OptionData) >= 2 {
				mss := binary.BigEndian.Uint16(opt.OptionData[:2])
				parts = append(parts, fmt.Sprintf("mss=%d", mss))
				tags = append(tags, fmt.Sprintf("mss/%d", mss))
			}
			optionNames = append(optionNames, "mss")
		case layers.TCPOptionKindWindowScale:
			if len(opt.OptionData) >= 1 {
				parts = append(parts, fmt.Sprintf("wscale=%d", opt.OptionData[0]))
				tags = append(tags, "wscale")
			}
			optionNames = append(optionNames, "wscale")
		case layers.TCPOptionKindSACKPermitted:
			tags = append(tags, "sack")
			optionNames = append(optionNames, "sack")
		case layers.TCPOptionKindTimestamps:
			tags = append(tags, "timestamps")
			optionNames = append(optionNames, "ts")
		case layers.TCPOptionKindNop:
			optionNames = append(optionNames, "nop")
		}
	}
	if len(optionNames) > 0 {
		parts = append(parts, "opts="+strings.Join(optionNames, "-"))
		tags = append(tags, "opts:"+strings.Join(optionNames, "-"))
	}
	switch {
	case ipv4.TTL >= 120 && ipv4.TTL <= 128 && tcp.Window >= 64000:
		tags = append(tags, "os-hint:windows")
	case ipv4.TTL >= 60 && ipv4.TTL <= 64:
		tags = append(tags, "os-hint:unix")
	case ipv4.TTL >= 250:
		tags = append(tags, "os-hint:network")
	}
	return strings.Join(parts, " "), tags
}

func parseHTTPRequestHeaders(payload []byte) (host string, userAgent string) {
	if !looksLikeHTTPRequest(payload) {
		return "", ""
	}
	return parseHeaderLikeValue(payload, "HOST"), parseHeaderLikeValue(payload, "USER-AGENT")
}

func parseHTTPResponseServer(payload []byte) string {
	if !bytes.HasPrefix(payload, []byte("HTTP/")) {
		return ""
	}
	return parseHeaderLikeValue(payload, "SERVER")
}

func parseHeaderLikeValue(payload []byte, name string) string {
	limit := len(payload)
	if limit > 4096 {
		limit = 4096
	}
	name = strings.ToUpper(name)
	for _, rawLine := range strings.Split(string(payload[:limit]), "\n") {
		line := strings.TrimSpace(strings.TrimRight(rawLine, "\r"))
		if line == "" {
			continue
		}
		idx := strings.IndexByte(line, ':')
		if idx <= 0 {
			continue
		}
		if strings.ToUpper(strings.TrimSpace(line[:idx])) == name {
			return sanitizeText([]byte(strings.TrimSpace(line[idx+1:])))
		}
	}
	return ""
}

func looksLikeHTTPRequest(payload []byte) bool {
	methods := [][]byte{
		[]byte("GET "), []byte("POST "), []byte("HEAD "), []byte("PUT "),
		[]byte("DELETE "), []byte("OPTIONS "), []byte("PATCH "), []byte("CONNECT "),
	}
	for _, method := range methods {
		if bytes.HasPrefix(payload, method) {
			return true
		}
	}
	return false
}

func firstPayloadLine(payload []byte) string {
	limit := len(payload)
	if limit > 160 {
		limit = 160
	}
	line := string(payload[:limit])
	if idx := strings.IndexAny(line, "\r\n"); idx >= 0 {
		line = line[:idx]
	}
	return sanitizeText([]byte(line))
}

func looksLikeTLSClientHello(payload []byte) bool {
	return len(payload) >= 6 && payload[0] == 0x16 && payload[5] == 0x01
}

func parseTLSSNI(payload []byte) string {
	if len(payload) < 6 || payload[0] != 0x16 {
		return ""
	}
	recordLen := int(binary.BigEndian.Uint16(payload[3:5]))
	if recordLen <= 0 || len(payload) < 5+recordLen {
		return ""
	}
	p := payload[5 : 5+recordLen]
	if len(p) < 42 || p[0] != 0x01 {
		return ""
	}
	pos := 4 + 2 + 32 // handshake header, version, random.
	if pos >= len(p) {
		return ""
	}
	sessionLen := int(p[pos])
	pos++
	pos += sessionLen
	if pos+2 > len(p) {
		return ""
	}
	cipherLen := int(binary.BigEndian.Uint16(p[pos : pos+2]))
	pos += 2 + cipherLen
	if pos >= len(p) {
		return ""
	}
	compressionLen := int(p[pos])
	pos++
	pos += compressionLen
	if pos+2 > len(p) {
		return ""
	}
	extensionsLen := int(binary.BigEndian.Uint16(p[pos : pos+2]))
	pos += 2
	end := pos + extensionsLen
	if end > len(p) {
		return ""
	}
	for pos+4 <= end {
		extType := binary.BigEndian.Uint16(p[pos : pos+2])
		extLen := int(binary.BigEndian.Uint16(p[pos+2 : pos+4]))
		pos += 4
		if pos+extLen > end {
			return ""
		}
		if extType == 0x0000 {
			return parseTLSServerNameExtension(p[pos : pos+extLen])
		}
		pos += extLen
	}
	return ""
}

func parseTLSServerNameExtension(data []byte) string {
	if len(data) < 2 {
		return ""
	}
	listLen := int(binary.BigEndian.Uint16(data[:2]))
	pos := 2
	end := pos + listLen
	if end > len(data) {
		return ""
	}
	for pos+3 <= end {
		nameType := data[pos]
		nameLen := int(binary.BigEndian.Uint16(data[pos+1 : pos+3]))
		pos += 3
		if pos+nameLen > end {
			return ""
		}
		if nameType == 0 {
			return sanitizeText(data[pos : pos+nameLen])
		}
		pos += nameLen
	}
	return ""
}

func userAgentTags(userAgent string) []string {
	lower := strings.ToLower(userAgent)
	tags := []string{"http-user-agent", "client-software"}
	switch {
	case strings.Contains(lower, "windows"):
		tags = append(tags, "windows", "os-hint:windows")
	case strings.Contains(lower, "mac os") || strings.Contains(lower, "iphone") || strings.Contains(lower, "ipad"):
		tags = append(tags, "apple", "bonjour", "os-hint:apple")
	case strings.Contains(lower, "android"):
		tags = append(tags, "android", "unix-like", "os-hint:android")
	case strings.Contains(lower, "linux") || strings.Contains(lower, "x11"):
		tags = append(tags, "unix-like", "os-hint:unix")
	}
	return tags
}

func dhcpVendorTags(vendor string) []string {
	lower := strings.ToLower(vendor)
	tags := []string{"dhcp-vendor", "dhcp-option-60"}
	switch {
	case strings.Contains(lower, "msft") || strings.Contains(lower, "microsoft"):
		tags = append(tags, "windows", "dhcp-vendor:msft")
	case strings.Contains(lower, "android"):
		tags = append(tags, "android", "unix-like", "dhcp-vendor:android")
	case strings.Contains(lower, "apple") || strings.Contains(lower, "darwin"):
		tags = append(tags, "apple", "bonjour", "dhcp-vendor:apple")
	case strings.Contains(lower, "linux") || strings.Contains(lower, "dhcpcd") || strings.Contains(lower, "busybox") || strings.Contains(lower, "systemd"):
		tags = append(tags, "unix-like", "dhcp-vendor:unix")
	case strings.Contains(lower, "pxeclient"):
		tags = append(tags, "pxe", "boot-client")
	}
	return tags
}

func dhcpParamTags(params []byte) []string {
	tags := []string{"dhcp-params", "dhcp-option-55"}
	set := make(map[byte]bool, len(params))
	for _, param := range params {
		set[param] = true
	}
	if set[44] || set[46] {
		tags = append(tags, "netbios-request", "windows")
	}
	if set[119] || set[252] {
		tags = append(tags, "domain-search", "wpad-request")
	}
	if set[121] {
		tags = append(tags, "classless-routes")
	}
	return tags
}

func formatDHCPParamRequestSignal(params []byte) string {
	labels := make([]string, 0, len(params))
	for i, param := range params {
		if i >= 16 {
			labels = append(labels, fmt.Sprintf("+%d", len(params)-i))
			break
		}
		labels = append(labels, fmt.Sprintf("%d", param))
	}
	return strings.Join(labels, ",")
}

func formatDHCPClientID(data []byte) string {
	if len(data) == 0 {
		return ""
	}
	if len(data) == 7 && data[0] == 1 {
		return net.HardwareAddr(data[1:]).String()
	}
	return fmt.Sprintf("%x", data)
}

func vendorSignalTag(vendor string) string {
	lower := strings.ToLower(vendor)
	replacer := strings.NewReplacer(
		" ", "-", "\t", "-", ",", "", ".", "", "(", "", ")", "", "/", "-", "_", "-",
	)
	value := replacer.Replace(lower)
	if len(value) > 40 {
		value = value[:40]
	}
	return "vendor:" + strings.Trim(value, "-")
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
func (o *Observer) processDNS(dns *layers.DNS, isQuery bool, nm *NetworkMap, ipv4 *layers.IPv4, vlanID uint16, now time.Time,
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
			appendDNSQueryLocked(nm, DNSQuery{
				Name:      name,
				Type:      qType,
				ClientIP:  dnsClientIP(ipv4, isQuery),
				ServerIP:  dnsServerIP(ipv4, isQuery),
				VLANID:    vlanID,
				Timestamp: now,
			})
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
			updated := false
			for i := len(nm.DNSLog) - 1; i >= 0 && i >= len(nm.DNSLog)-20; i-- {
				if nm.DNSLog[i].Name == name {
					nm.DNSLog[i].Response = appendDNSResponse(nm.DNSLog[i].Response, resolved)
					nm.DNSLog[i].ClientIP = firstIPNonNil(nm.DNSLog[i].ClientIP, dnsClientIP(ipv4, isQuery))
					nm.DNSLog[i].ServerIP = firstIPNonNil(nm.DNSLog[i].ServerIP, dnsServerIP(ipv4, isQuery))
					if nm.DNSLog[i].VLANID == 0 {
						nm.DNSLog[i].VLANID = vlanID
					}
					updated = true
					break
				}
			}
			if !updated {
				appendDNSQueryLocked(nm, DNSQuery{
					Name:      name,
					Type:      dnsTypeString(a.Type),
					Response:  []string{resolved},
					ClientIP:  dnsClientIP(ipv4, isQuery),
					ServerIP:  dnsServerIP(ipv4, isQuery),
					VLANID:    vlanID,
					Timestamp: now,
				})
			}
			if ip := net.ParseIP(resolved); ip != nil && ip.To4() != nil && ip.IsPrivate() && !ip.IsLinkLocalUnicast() {
				tags := []string{"dns-name", "private-dns-answer", strings.ToLower(dnsTypeString(a.Type))}
				o.recordHostSignalLocked(nm, nil, ip, "dns-name", name, tags, now)
			}
			nm.mu.Unlock()

			eventLog(fmt.Sprintf("[+][NET] DNS resolved: %s → %s", name, resolved))
		}
	}
}

func appendDNSQueryLocked(nm *NetworkMap, query DNSQuery) {
	if nm == nil {
		return
	}
	nm.DNSLog = append(nm.DNSLog, query)
	if len(nm.DNSLog) <= nm.maxDNSLog {
		return
	}
	nm.DNSLog = append([]DNSQuery(nil), nm.DNSLog[len(nm.DNSLog)-nm.maxDNSLog:]...)
}

func appendDNSResponse(values []string, value string) []string {
	value = strings.TrimSpace(value)
	if value == "" {
		return values
	}
	for _, existing := range values {
		if existing == value {
			return values
		}
	}
	values = append(values, value)
	if len(values) > maxDNSResponsesPerQuery {
		return append([]string(nil), values[len(values)-maxDNSResponsesPerQuery:]...)
	}
	return values
}

func pruneObserverTimeMap(values map[string]time.Time, cutoff time.Time, maxEntries int) {
	for key, seenAt := range values {
		if seenAt.Before(cutoff) {
			delete(values, key)
		}
	}
	if maxEntries <= 0 || len(values) <= maxEntries {
		return
	}
	type entry struct {
		key string
		at  time.Time
	}
	entries := make([]entry, 0, len(values))
	for key, seenAt := range values {
		entries = append(entries, entry{key: key, at: seenAt})
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].at.Before(entries[j].at) })
	for len(values) > maxEntries && len(entries) > 0 {
		delete(values, entries[0].key)
		entries = entries[1:]
	}
}

func dnsClientIP(ipv4 *layers.IPv4, isQuery bool) net.IP {
	if ipv4 == nil {
		return nil
	}
	if isQuery {
		return copyIP(ipv4.SrcIP)
	}
	return copyIP(ipv4.DstIP)
}

func dnsServerIP(ipv4 *layers.IPv4, isQuery bool) net.IP {
	if ipv4 == nil {
		return nil
	}
	var ip net.IP
	if isQuery {
		ip = ipv4.DstIP
	} else {
		if ipv4.DstIP.IsMulticast() || ipv4.DstIP.IsLinkLocalMulticast() {
			return nil
		}
		ip = ipv4.SrcIP
	}
	if ip == nil || ip.IsUnspecified() || ip.IsMulticast() || ip.IsLinkLocalMulticast() {
		return nil
	}
	return copyIP(ip)
}

func firstIPNonNil(values ...net.IP) net.IP {
	for _, value := range values {
		if len(value) > 0 {
			return copyIP(value)
		}
	}
	return nil
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
