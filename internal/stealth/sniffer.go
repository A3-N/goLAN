package stealth

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// TargetIdentity holds the network identity of the true device we are piggybacking.
type TargetIdentity struct {
	MAC     net.HardwareAddr
	IP      net.IP
	Netmask net.IPMask
	Gateway net.IP
}

// String returns a human readable representation.
func (t TargetIdentity) String() string {
	return fmt.Sprintf("MAC: %s | IP: %s | Mask: %s | GW: %s", t.MAC, t.IP, t.Netmask, t.Gateway)
}

// Sniffer intercepts raw packets on a given interface.
type Sniffer struct {
	iface string
}

// ObserveOptions controls passive target identity selection.
type ObserveOptions struct {
	IgnoreMACs              []string
	RequiredMACObservations int
}

type targetCandidate struct {
	MAC       net.HardwareAddr
	Count     int
	Signals   map[string]int
	FirstSeen time.Time
	LastSeen  time.Time
	Logged    bool
}

// NewSniffer initializes a listener for a specific network interface.
func NewSniffer(iface string) *Sniffer {
	return &Sniffer{iface: iface}
}

// Observe passively listens to the device-side interface and reports target
// identity updates. The L2 bridge only requires the target MAC; IP, gateway,
// and mask are passive diagnostics because actively requesting DHCP can disturb
// a NAC-controlled switch port.
func (s *Sniffer) Observe(ctx context.Context, opts ObserveOptions, eventLog func(string), onUpdate func(TargetIdentity)) error {
	if eventLog == nil {
		eventLog = func(string) {}
	}
	if onUpdate == nil {
		onUpdate = func(TargetIdentity) {}
	}
	if opts.RequiredMACObservations < 1 {
		opts.RequiredMACObservations = 2
	}

	ignoreMACs := parseIgnoreMACs(opts.IgnoreMACs)

	eventLog(fmt.Sprintf("[*] Initializing Pcap handle on interface: %s", s.iface))
	handle, err := pcap.OpenLive(s.iface, 262144, true, pcap.BlockForever)
	if err != nil {
		return err
	}
	defer handle.Close()

	if err := handle.SetDirection(pcap.DirectionIn); err != nil {
		eventLog(fmt.Sprintf("[!] pcap direction filter unavailable: %v", err))
	} else {
		eventLog("[*] Capturing inbound frames from the device-side link.")
	}

	filter := "ether[6] & 1 = 0"
	for _, ignored := range sortedMACKeys(ignoreMACs) {
		filter += " and not ether src " + ignored
	}
	if err := handle.SetBPFFilter(filter); err != nil {
		eventLog(fmt.Sprintf("[!] BPF filter rejected (%s): %v", filter, err))
	} else {
		eventLog(fmt.Sprintf("[*] BPF filter active: %s", filter))
	}
	if len(ignoreMACs) > 0 {
		eventLog(fmt.Sprintf("[*] Ignoring %d known local adapter MAC(s).", len(ignoreMACs)))
	}

	eventLog("[*] Awaiting first valid target-sourced frame...")

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packets := packetSource.Packets()

	id := &TargetIdentity{}
	candidates := make(map[string]*targetCandidate)
	linkLocalLogged := false

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case packet, ok := <-packets:
			if !ok {
				return nil
			}
			if packet == nil {
				continue
			}

			// 1. Process Layer 2 to deduce Target MAC if unknown.
			ethLayer := packet.Layer(layers.LayerTypeEthernet)
			if ethLayer != nil {
				eth, _ := ethLayer.(*layers.Ethernet)

				// Skip broadcast/multicast sources
				if eth.SrcMAC[0]&1 != 0 {
					continue
				}

				// Skip leaked packets originating from the un-spoofed Mac interface.
				if _, ignored := ignoreMACs[macKey(eth.SrcMAC)]; ignored {
					continue
				}

				if len(id.MAC) == 0 {
					signals := packetSignals(packet, eth)
					candidate, ready := recordCandidate(candidates, eth.SrcMAC, signals, opts.RequiredMACObservations)
					if !candidate.Logged || candidate.Count <= 3 || ready {
						eventLog(fmt.Sprintf("[*] Candidate Target MAC %s via %s (seen %d)", candidate.MAC.String(), formatSignals(candidate.Signals), candidate.Count))
						candidate.Logged = true
					}
					if !ready {
						continue
					}
					id.MAC = eth.SrcMAC
					eventLog(fmt.Sprintf("[+] Locked Target MAC: %s using %s evidence over %d frame(s)", id.MAC.String(), formatSignals(candidate.Signals), candidate.Count))
					if isLocallyAdministered(id.MAC) {
						eventLog("[!] Target MAC is locally administered. That can be legitimate, but verify it is not host-generated traffic.")
					}
					onUpdate(*id)
				}

				// If this packet is not from our target, ignore it.
				if len(id.MAC) > 0 && !macEqual(eth.SrcMAC, id.MAC) && !macEqual(eth.DstMAC, id.MAC) {
					continue
				}
			}

			// 2. Process IPv4 to deduce IP.
			var srcIP net.IP
			ipLayer := packet.Layer(layers.LayerTypeIPv4)
			if ipLayer != nil {
				ipv4, _ := ipLayer.(*layers.IPv4)
				srcIP = ipv4.SrcIP

				if ethLayer != nil {
					eth, _ := ethLayer.(*layers.Ethernet)
					if macEqual(eth.SrcMAC, id.MAC) && len(id.IP) == 0 {
						// The target is transmitting with this IP.
						if !srcIP.IsUnspecified() && !srcIP.IsLoopback() && !srcIP.IsMulticast() && !strings.HasPrefix(srcIP.String(), "169.254") {
							id.IP = srcIP
							eventLog(fmt.Sprintf("[+] Passive inference extracted Target IP: %s", id.IP.String()))
							onUpdate(*id)
						}
					}
				}
			}

			// 3. Process ARP to deduce Gateway or IPs quicker.
			arpLayer := packet.Layer(layers.LayerTypeARP)
			if arpLayer != nil {
				arp, _ := arpLayer.(*layers.ARP)
				if arp.Operation == layers.ARPRequest {
					senderMAC := net.HardwareAddr(arp.SourceHwAddress)
					senderIP := net.IP(arp.SourceProtAddress)
					targetIP := net.IP(arp.DstProtAddress)

					if macEqual(senderMAC, id.MAC) {
						if len(id.IP) == 0 && !senderIP.IsUnspecified() {
							if strings.HasPrefix(senderIP.String(), "169.254") {
								if !linkLocalLogged {
									eventLog(fmt.Sprintf("[*] Ignored Link-Local Self-Assignment: %s", senderIP.String()))
									eventLog("[*] L2 activation remains MAC-only; no DHCP response is required.")
									linkLocalLogged = true
								}
							} else {
								id.IP = senderIP
								eventLog(fmt.Sprintf("[+] Discovered Target Real IP: %s", id.IP.String()))
								onUpdate(*id)
							}
						}
					} else {
						// Someone else (gateway/switch) is ARPing for our target device?
						// Or it's a broadcast.
						if len(id.Gateway) == 0 && targetIP.Equal(id.IP) {
							// The sender is likely the Gateway trying to reach our Target Device.
							id.Gateway = senderIP
							eventLog(fmt.Sprintf("> ARP Request revealed possible Gateway IP: %s", id.Gateway.String()))
							onUpdate(*id)
						}
					}
				} else if arp.Operation == layers.ARPReply {
					senderMAC := net.HardwareAddr(arp.SourceHwAddress)
					senderIP := net.IP(arp.SourceProtAddress)

					if macEqual(senderMAC, id.MAC) {
						if len(id.IP) == 0 && !senderIP.IsUnspecified() {
							id.IP = senderIP
							eventLog(fmt.Sprintf("> ARP Reply revealed Target IP: %s", id.IP.String()))
							onUpdate(*id)
						}
					} else {
						// Reply from Gateway or switch?
						if len(id.Gateway) == 0 && len(id.IP) > 0 {
							// If someone replied to our MAC, they might be the gateway.
							id.Gateway = senderIP
							eventLog(fmt.Sprintf("> ARP Reply revealed Gateway IP: %s", id.Gateway.String()))
							onUpdate(*id)
						}
					}
				}
			}

			// 4. Process DHCP (UDP 67/68) to get exact metadata (Gateway, Subnet).
			udpLayer := packet.Layer(layers.LayerTypeUDP)
			if udpLayer != nil {
				udp, _ := udpLayer.(*layers.UDP)
				if udp.SrcPort == 67 || udp.DstPort == 67 {
					dhcpLayer := packet.Layer(layers.LayerTypeDHCPv4)
					if dhcpLayer != nil {
						dhcp, _ := dhcpLayer.(*layers.DHCPv4)
						if macEqual(dhcp.ClientHWAddr, id.MAC) {
							// It's a DHCP ACK meant for our Target
							if dhcp.Operation == layers.DHCPOpReply && dhcp.YourClientIP != nil {
								id.IP = dhcp.YourClientIP
								eventLog(fmt.Sprintf("> DHCP ACK assigned Target IP: %s", id.IP.String()))
								onUpdate(*id)

								// Parse options for Subnet and Router
								for _, opt := range dhcp.Options {
									if opt.Type == layers.DHCPOptSubnetMask {
										id.Netmask = net.IPMask(opt.Data)
										eventLog(fmt.Sprintf("> DHCP ACK revealed Subnet Mask: %s", id.Netmask.String()))
										onUpdate(*id)
									} else if opt.Type == layers.DHCPOptRouter {
										if len(opt.Data) >= 4 {
											id.Gateway = net.IP(opt.Data[:4])
											eventLog(fmt.Sprintf("> DHCP ACK revealed Router/Gateway: %s", id.Gateway.String()))
											onUpdate(*id)
										}
									}
								}
							}
						}
					}
				}
			}

			// No DHCP or gateway is required for L2 activation. Keep observing
			// so static-IP deployments still get diagnostics when traffic appears.
		}
	}
}

// IsLayer2Ready verifies the minimum required data for transparent L2 bridging.
func (t TargetIdentity) IsLayer2Ready() bool {
	return len(t.MAC) > 0
}

// IsComplete verifies that optional L3 diagnostics are fully populated.
func (t TargetIdentity) IsComplete() bool {
	return len(t.MAC) > 0 && len(t.IP) > 0 && len(t.Gateway) > 0
}

func parseIgnoreMACs(raw []string) map[string]net.HardwareAddr {
	ignored := make(map[string]net.HardwareAddr)
	for _, item := range raw {
		mac, err := net.ParseMAC(strings.TrimSpace(item))
		if err != nil {
			continue
		}
		ignored[macKey(mac)] = mac
	}
	return ignored
}

func sortedMACKeys(macs map[string]net.HardwareAddr) []string {
	keys := make([]string, 0, len(macs))
	for key := range macs {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func packetSignals(packet gopacket.Packet, eth *layers.Ethernet) []string {
	signals := []string{}

	switch eth.EthernetType {
	case layers.EthernetTypeEAPOL:
		signals = append(signals, "EAPOL")
	case layers.EthernetTypeARP:
		signals = append(signals, "ARP")
	case layers.EthernetTypeIPv4:
		signals = append(signals, "IPv4")
	case layers.EthernetTypeIPv6:
		signals = append(signals, "IPv6")
	case layers.EthernetTypeLinkLayerDiscovery:
		signals = append(signals, "LLDP")
	case layers.EthernetTypeCiscoDiscovery:
		signals = append(signals, "CDP")
	}

	if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		udp, _ := udpLayer.(*layers.UDP)
		if udp.SrcPort == 67 || udp.SrcPort == 68 || udp.DstPort == 67 || udp.DstPort == 68 {
			signals = append(signals, "DHCP")
		}
	}

	if len(signals) == 0 {
		signals = append(signals, eth.EthernetType.String())
	}
	return signals
}

func recordCandidate(candidates map[string]*targetCandidate, mac net.HardwareAddr, signals []string, requiredCount int) (*targetCandidate, bool) {
	key := macKey(mac)
	now := time.Now()
	candidate := candidates[key]
	if candidate == nil {
		candidate = &targetCandidate{
			MAC:       append(net.HardwareAddr(nil), mac...),
			Signals:   make(map[string]int),
			FirstSeen: now,
		}
		candidates[key] = candidate
	}
	candidate.Count++
	candidate.LastSeen = now
	for _, signal := range signals {
		candidate.Signals[signal]++
	}

	return candidate, candidateReady(candidate, requiredCount)
}

func candidateReady(candidate *targetCandidate, requiredCount int) bool {
	if candidate == nil {
		return false
	}
	for _, strong := range []string{"EAPOL", "ARP", "DHCP"} {
		if candidate.Signals[strong] > 0 {
			return true
		}
	}
	return candidate.Count >= requiredCount
}

func formatSignals(signals map[string]int) string {
	if len(signals) == 0 {
		return "unknown"
	}
	keys := make([]string, 0, len(signals))
	for key := range signals {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	parts := make([]string, 0, len(keys))
	for _, key := range keys {
		parts = append(parts, fmt.Sprintf("%s:%d", key, signals[key]))
	}
	return strings.Join(parts, ",")
}

func macKey(mac net.HardwareAddr) string {
	return strings.ToLower(mac.String())
}

func isLocallyAdministered(mac net.HardwareAddr) bool {
	return len(mac) > 0 && mac[0]&2 != 0
}

func macEqual(a, b net.HardwareAddr) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
