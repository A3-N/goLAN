package stealth

import (
	"context"
	"fmt"
	"net"
	"strings"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// TargetIdentity holds the network identity of the true device we are piggybacking.
type TargetIdentity struct {
	MAC              net.HardwareAddr
	IP               net.IP
	Netmask          net.IPMask
	Gateway          net.IP
	EAPOLDetected    bool             // 802.1X frames seen on the wire
	AuthenticatorMAC net.HardwareAddr // Switch-side MAC sending EAPOL
	VLANID           uint16           // Primary 802.1Q VLAN tag (first seen, 0 = untagged)
	VLANs            []uint16         // All VLAN IDs observed on the wire
	NetworkMap       *NetworkMap      // Populated by observer after bridge UP
}

// String returns a human readable representation.
func (t TargetIdentity) String() string {
	return fmt.Sprintf("MAC: %s | IP: %s | Mask: %s | GW: %s", t.MAC, t.IP, t.Netmask, t.Gateway)
}

// Sniffer intercepts raw packets on a given interface.
type Sniffer struct {
	iface string
}

// NewSniffer initializes a listener for a specific network interface.
func NewSniffer(iface string) *Sniffer {
	return &Sniffer{iface: iface}
}

// Discover passively listens to the interface until it successfully reconstructs the True Device's configuration.
// It relies on ARPs, IP headers, and DHCP configurations.
// The eventLog callback streams internal discoveries dynamically.
func (s *Sniffer) Discover(ctx context.Context, ignoreMACStr string, eventLog func(string), onMacFound func(mac net.HardwareAddr, firstFrame []byte)) (*TargetIdentity, error) {
	if eventLog == nil {
		eventLog = func(string) {}
	}

	ignoreMAC, _ := net.ParseMAC(ignoreMACStr)

	eventLog(fmt.Sprintf("[*] Initializing Pcap handle on interface: %s", s.iface))
	handle, err := pcap.OpenLive(s.iface, 65535, true, pcap.BlockForever)
	if err != nil {
		return nil, err
	}
	defer handle.Close()

	// NOTE: No BPF filter is applied here. The previous filter
	// "outbound and not arp and not rarp" silently blocked EAPOL (0x888E)
	// frames which prevented 802.1X detection. We now capture everything
	// and filter in userspace to also detect EAPOL.

	eventLog("[*] Awaiting first valid unicast MAC to lock onto target...")

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packets := packetSource.Packets()

	id := &TargetIdentity{}
	hasTriggeredMacCallback := false
	linkLocalLogged := false
	lockTarget := func(mac net.HardwareAddr, source string, firstFrame []byte) {
		if len(id.MAC) != 0 || len(mac) == 0 {
			return
		}
		id.MAC = copyMAC(mac)
		eventLog(fmt.Sprintf("[+] Discovered Target MAC via %s: %s", source, id.MAC.String()))
		if onMacFound != nil && !hasTriggeredMacCallback {
			hasTriggeredMacCallback = true
			onMacFound(id.MAC, append([]byte(nil), firstFrame...))
		}
	}

	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case packet := <-packets:
			if packet == nil {
				continue
			}

			// 1. Process Layer 2 to deduce Target MAC if unknown.
			ethLayer := packet.Layer(layers.LayerTypeEthernet)
			if ethLayer != nil {
				eth, _ := ethLayer.(*layers.Ethernet)

				// 1a. Detect 802.1X EAPOL frames (EtherType 0x888E).
				//     These are valid Layer 2 evidence: the first supplicant-side
				//     EAPOL source MAC is enough to activate transparent bridging.
				if eth.EthernetType == 0x888E {
					if ignoreMAC == nil || !macEqual(eth.SrcMAC, ignoreMAC) {
						lockTarget(eth.SrcMAC, "EAPOL", packet.Data())
					}
					if !id.EAPOLDetected {
						id.EAPOLDetected = true
						if len(id.MAC) > 0 && !macEqual(eth.SrcMAC, id.MAC) {
							id.AuthenticatorMAC = copyMAC(eth.SrcMAC)
						}
						eventLog(fmt.Sprintf("[*][802.1X] EAPOL frame detected from %s — 802.1X is active on this port", eth.SrcMAC))
					}
					if id.IsComplete() {
						eventLog("[+] Layer 2 identity constructed from EAPOL. Reconnaissance complete.")
						return id, nil
					}
					continue // Don't process EAPOL as normal traffic
				}

				// Skip broadcast/multicast sources
				if eth.SrcMAC[0]&1 != 0 {
					continue
				}

				// Skip leaked packets originating from the un-spoofed Mac interface.
				if ignoreMAC != nil && macEqual(eth.SrcMAC, ignoreMAC) {
					continue
				}

				// We assume the first unicast source MAC we see entering the device port is the Target Device.
				lockTarget(eth.SrcMAC, "L2 frame", packet.Data())

				// If this packet is not from our target, ignore it.
				if len(id.MAC) > 0 && !macEqual(eth.SrcMAC, id.MAC) && !macEqual(eth.DstMAC, id.MAC) {
					continue
				}
			}

			// 1b. Detect 802.1Q VLAN tags.
			// gopacket automatically decodes Dot1Q headers. If present, record the VLAN ID.
			// This is critical for post-802.1X RADIUS-assigned VLANs.
			dot1qLayer := packet.Layer(layers.LayerTypeDot1Q)
			if dot1qLayer != nil {
				dot1q, _ := dot1qLayer.(*layers.Dot1Q)
				if dot1q.VLANIdentifier != 0 {
					if id.VLANID == 0 {
						id.VLANID = dot1q.VLANIdentifier
						eventLog(fmt.Sprintf("[+][VLAN] Primary 802.1Q VLAN tag detected: VLAN %d", id.VLANID))
					}
					// Track all VLANs seen during initial recon.
					vlanSeen := false
					for _, v := range id.VLANs {
						if v == dot1q.VLANIdentifier {
							vlanSeen = true
							break
						}
					}
					if !vlanSeen {
						id.VLANs = append(id.VLANs, dot1q.VLANIdentifier)
						if len(id.VLANs) > 1 {
							eventLog(fmt.Sprintf("[!][VLAN] Additional VLAN %d detected — possible trunk port", dot1q.VLANIdentifier))
						}
					}
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
									eventLog("[*] Continuing Layer 2 bridge; waiting passively for routable IP evidence.")
									eventLog("[+] Air-gap finalized. Safe to plug in the Router LAN.")
									linkLocalLogged = true
								}
							} else {
								id.IP = senderIP
								eventLog(fmt.Sprintf("[+] Discovered Target Real IP: %s", id.IP.String()))
							}
						}
						if len(id.Gateway) == 0 && isUsableIPv4(targetIP) && !targetIP.Equal(senderIP) {
							id.Gateway = copyIP(targetIP)
							eventLog(fmt.Sprintf("[+] ARP Request revealed possible Gateway IP: %s", id.Gateway.String()))
						}
					} else {
						// Someone else (gateway/switch) is ARPing for our target device.
						// Only treat as gateway if they're specifically asking for our target's IP.
						if len(id.Gateway) == 0 && len(id.IP) > 0 && targetIP.Equal(id.IP) && !senderIP.IsUnspecified() {
							// Filter out link-local (169.254.x.x) — these are self-assigned, not gateways.
							if !strings.HasPrefix(senderIP.String(), "169.254") {
								id.Gateway = senderIP
								eventLog(fmt.Sprintf("[+] ARP Request revealed possible Gateway IP: %s", id.Gateway.String()))
							}
						}
					}
				} else if arp.Operation == layers.ARPReply {
					senderMAC := net.HardwareAddr(arp.SourceHwAddress)
					senderIP := net.IP(arp.SourceProtAddress)
					targetMAC := net.HardwareAddr(arp.DstHwAddress)

					if macEqual(senderMAC, id.MAC) {
						if len(id.IP) == 0 && !senderIP.IsUnspecified() {
							id.IP = senderIP
							eventLog(fmt.Sprintf("[+] ARP Reply revealed Target IP: %s", id.IP.String()))
						}
					} else {
						// Reply directed specifically to our target MAC is likely from the gateway.
						if len(id.Gateway) == 0 && len(id.IP) > 0 && macEqual(targetMAC, id.MAC) {
							if !senderIP.IsUnspecified() && !strings.HasPrefix(senderIP.String(), "169.254") {
								id.Gateway = senderIP
								eventLog(fmt.Sprintf("[+] ARP Reply revealed Gateway IP: %s", id.Gateway.String()))
							}
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
								eventLog(fmt.Sprintf("[+] DHCP ACK assigned Target IP: %s", id.IP.String()))

								// Parse options for Subnet and Router
								for _, opt := range dhcp.Options {
									if opt.Type == layers.DHCPOptSubnetMask {
										id.Netmask = net.IPMask(opt.Data)
										eventLog(fmt.Sprintf("[+] DHCP ACK revealed Subnet Mask: %s", id.Netmask.String()))
									} else if opt.Type == layers.DHCPOptRouter {
										if len(opt.Data) >= 4 {
											id.Gateway = net.IP(opt.Data[:4])
											eventLog(fmt.Sprintf("[+] DHCP ACK revealed Router/Gateway: %s", id.Gateway.String()))
										}
									}
								}
							}
						}
					}
				}
			}

			// Check if we have enough information to form the identity.
			if id.IsComplete() {
				if len(id.IP) == 0 {
					eventLog("[+] Layer 2 identity constructed. IP discovery will continue passively.")
				} else if id.HasGateway() {
					eventLog("[+] Identity fully constructed. Reconnaissance complete.")
				} else {
					eventLog("[+] MAC + IP discovered. Gateway pending (NAT unavailable until found).")
				}
				// We fall back nicely if we couldn't naturally capture a DHCP subnet mask.
				if len(id.IP) > 0 && len(id.Netmask) == 0 {
					id.Netmask = id.IP.DefaultMask()
					eventLog(fmt.Sprintf("[*] Falling back to default subnet mask: %s", id.Netmask.String()))
				}
				return id, nil
			}
		}
	}
}

// IsComplete verifies we have collected the minimum required data to proceed.
// Layer 2 readiness only requires the target MAC. IP, gateway, DHCP, and DNS
// are optional attributes learned continuously after the bridge is active.
func (t TargetIdentity) IsComplete() bool {
	return len(t.MAC) > 0
}

// HasGateway returns whether the gateway has been discovered (needed for NAT proxy).
func (t TargetIdentity) HasGateway() bool {
	return len(t.Gateway) > 0
}

// ObserveIdentity keeps learning optional target attributes after the Layer 2
// bridge is already active. It never gates forwarding; it only enriches the
// TargetIdentity with IP, gateway, VLAN, and 802.1X metadata as evidence appears.
func (s *Sniffer) ObserveIdentity(ctx context.Context, targetMAC net.HardwareAddr, ignoreMACStr string, eventLog func(string), onUpdate func(TargetIdentity)) error {
	if eventLog == nil {
		eventLog = func(string) {}
	}
	if onUpdate == nil {
		onUpdate = func(TargetIdentity) {}
	}

	ignoreMAC, _ := net.ParseMAC(ignoreMACStr)

	handle, err := pcap.OpenLive(s.iface, 65535, true, pcap.BlockForever)
	if err != nil {
		return err
	}
	defer handle.Close()

	eventLog(fmt.Sprintf("[*][RECON] Identity observer active on %s. Layer 3 details are optional.", s.iface))

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packets := packetSource.Packets()

	id := TargetIdentity{MAC: copyMAC(targetMAC)}

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case packet := <-packets:
			if packet == nil {
				continue
			}

			ethLayer := packet.Layer(layers.LayerTypeEthernet)
			if ethLayer == nil {
				continue
			}
			eth, _ := ethLayer.(*layers.Ethernet)

			if ignoreMAC != nil && macEqual(eth.SrcMAC, ignoreMAC) {
				continue
			}

			isTargetFrame := macEqual(eth.SrcMAC, targetMAC) || macEqual(eth.DstMAC, targetMAC)
			if !isTargetFrame && eth.EthernetType != 0x888E {
				continue
			}

			changed := false

			if eth.EthernetType == 0x888E {
				if !id.EAPOLDetected {
					id.EAPOLDetected = true
					changed = true
				}
				if !macEqual(eth.SrcMAC, targetMAC) && len(id.AuthenticatorMAC) == 0 && eth.SrcMAC[0]&1 == 0 {
					id.AuthenticatorMAC = copyMAC(eth.SrcMAC)
					changed = true
				}
			}

			if dot1qLayer := packet.Layer(layers.LayerTypeDot1Q); dot1qLayer != nil {
				dot1q, _ := dot1qLayer.(*layers.Dot1Q)
				if dot1q.VLANIdentifier != 0 && !containsVLAN(id.VLANs, dot1q.VLANIdentifier) {
					if id.VLANID == 0 {
						id.VLANID = dot1q.VLANIdentifier
					}
					id.VLANs = append(id.VLANs, dot1q.VLANIdentifier)
					changed = true
				}
			}

			if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil && macEqual(eth.SrcMAC, targetMAC) {
				ipv4, _ := ipLayer.(*layers.IPv4)
				if isUsableIPv4(ipv4.SrcIP) && !ipv4.SrcIP.Equal(id.IP) {
					id.IP = copyIP(ipv4.SrcIP)
					changed = true
				}
			}

			if arpLayer := packet.Layer(layers.LayerTypeARP); arpLayer != nil {
				arp, _ := arpLayer.(*layers.ARP)
				senderMAC := net.HardwareAddr(arp.SourceHwAddress)
				senderIP := net.IP(arp.SourceProtAddress)
				targetIP := net.IP(arp.DstProtAddress)
				targetARPmac := net.HardwareAddr(arp.DstHwAddress)

				switch {
				case macEqual(senderMAC, targetMAC):
					if isUsableIPv4(senderIP) && !senderIP.Equal(id.IP) {
						id.IP = copyIP(senderIP)
						changed = true
					}
					if arp.Operation == layers.ARPRequest && len(id.Gateway) == 0 && isUsableIPv4(targetIP) && !targetIP.Equal(senderIP) {
						id.Gateway = copyIP(targetIP)
						changed = true
					}

				case arp.Operation == layers.ARPReply && macEqual(targetARPmac, targetMAC):
					if len(id.Gateway) == 0 && isUsableIPv4(senderIP) {
						id.Gateway = copyIP(senderIP)
						changed = true
					}

				case len(id.IP) > 0 && targetIP.Equal(id.IP):
					if len(id.Gateway) == 0 && isUsableIPv4(senderIP) {
						id.Gateway = copyIP(senderIP)
						changed = true
					}
				}
			}

			if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
				udp, _ := udpLayer.(*layers.UDP)
				if udp.SrcPort == 67 || udp.DstPort == 67 {
					if dhcpLayer := packet.Layer(layers.LayerTypeDHCPv4); dhcpLayer != nil {
						dhcp, _ := dhcpLayer.(*layers.DHCPv4)
						if macEqual(dhcp.ClientHWAddr, targetMAC) && dhcp.Operation == layers.DHCPOpReply {
							if isUsableIPv4(dhcp.YourClientIP) && !dhcp.YourClientIP.Equal(id.IP) {
								id.IP = copyIP(dhcp.YourClientIP)
								changed = true
							}
							for _, opt := range dhcp.Options {
								switch opt.Type {
								case layers.DHCPOptSubnetMask:
									if len(opt.Data) == 4 && string(id.Netmask) != string(net.IPMask(opt.Data)) {
										id.Netmask = net.IPMask(copyIP(net.IP(opt.Data)))
										changed = true
									}
								case layers.DHCPOptRouter:
									if len(opt.Data) >= 4 {
										gw := net.IP(opt.Data[:4])
										if isUsableIPv4(gw) && !gw.Equal(id.Gateway) {
											id.Gateway = copyIP(gw)
											changed = true
										}
									}
								}
							}
						}
					}
				}
			}

			if changed {
				onUpdate(id)
			}
		}
	}
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

func copyMAC(mac net.HardwareAddr) net.HardwareAddr {
	if len(mac) == 0 {
		return nil
	}
	dup := make(net.HardwareAddr, len(mac))
	copy(dup, mac)
	return dup
}

func copyIP(ip net.IP) net.IP {
	if len(ip) == 0 {
		return nil
	}
	dup := make(net.IP, len(ip))
	copy(dup, ip)
	return dup
}

func containsVLAN(vlans []uint16, vlan uint16) bool {
	for _, existing := range vlans {
		if existing == vlan {
			return true
		}
	}
	return false
}

func isUsableIPv4(ip net.IP) bool {
	if ip == nil {
		return false
	}
	ip4 := ip.To4()
	if ip4 == nil {
		return false
	}
	return !ip4.IsUnspecified() &&
		!ip4.IsLoopback() &&
		!ip4.IsMulticast() &&
		!strings.HasPrefix(ip4.String(), "169.254")
}
