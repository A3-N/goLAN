package stealth

import (
	"context"
	"fmt"
	"net"
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

// NetworkMap is a continuously-updated passive view of the network.
type NetworkMap struct {
	mu         sync.RWMutex
	Hosts      map[string]*ObservedHost // keyed by MAC string
	DNSLog     []DNSQuery              // recent DNS queries (capped)
	VLANs      map[uint16]*VLANInfo    // all VLANs observed
	Gateway    GatewayInfo             // confirmed gateway details
	maxDNSLog  int                     // cap on DNS log entries
	maxHosts   int                     // cap on hosts map size
}

// NewNetworkMap creates an empty network map with sensible limits.
func NewNetworkMap() *NetworkMap {
	return &NetworkMap{
		Hosts:     make(map[string]*ObservedHost),
		VLANs:     make(map[uint16]*VLANInfo),
		maxDNSLog: 200,
		maxHosts:  500,
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
	return ids
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

	handle, err := pcap.OpenLive(o.iface, 65535, true, pcap.BlockForever)
	if err != nil {
		eventLog(fmt.Sprintf("[!][RECON] Failed to start network observer: %v", err))
		return nm
	}
	defer handle.Close()

	eventLog("[*][RECON] Network observer active — passively mapping traffic through bridge...")

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packets := packetSource.Packets()

	// Rate-limiting: don't spam the log.
	lastHostLog := make(map[string]time.Time)   // MAC → last log time
	lastDNSLog := make(map[string]time.Time)     // domain → last log time
	hostLogCooldown := 30 * time.Second
	dnsLogCooldown := 60 * time.Second
	vlanChangeLogged := make(map[uint16]bool)

	for {
		select {
		case <-ctx.Done():
			return nm
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
	dot1qLayer := packet.Layer(layers.LayerTypeDot1Q)
	if dot1qLayer != nil {
		dot1q, _ := dot1qLayer.(*layers.Dot1Q)
		if dot1q.VLANIdentifier != 0 {
			o.trackVLAN(nm, dot1q.VLANIdentifier, now, eventLog, vlanChangeLogged)
		}
	}

	// ── IPv4: Host tracking + static IP inference ──────────────────
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer != nil {
		ipv4, _ := ipLayer.(*layers.IPv4)

		// Track the source host (MAC → IP mapping).
		if !ipv4.SrcIP.IsUnspecified() && !ipv4.SrcIP.IsMulticast() {
			o.trackHost(nm, srcMAC, ipv4.SrcIP, now, eventLog, lastHostLog, hostLogCooldown, targetMAC)
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
	}

	// ── DNS: Query/Response logging ────────────────────────────────
	dnsLayer := packet.Layer(layers.LayerTypeDNS)
	if dnsLayer != nil {
		dns, _ := dnsLayer.(*layers.DNS)

		// Log ALL observed DNS traffic on the wire for maximum network recon.
		isQuery := !dns.QR
		o.processDNS(dns, isQuery, nm, now, eventLog, lastDNSLog, dnsLogCooldown)
	}
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
