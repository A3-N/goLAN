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
	NetmaskObserved  bool
	Gateway          net.IP
	EAPOLDetected    bool             // 802.1X frames seen on the wire
	AuthenticatorMAC net.HardwareAddr // Switch-side MAC sending EAPOL
	VLANID           uint16           // Primary 802.1Q VLAN tag (first seen, 0 = untagged)
	VLANs            []uint16         // All VLAN IDs observed on the wire
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
	if ctx == nil {
		return nil, fmt.Errorf("discovery context is required")
	}
	if s == nil || strings.TrimSpace(s.iface) == "" {
		return nil, fmt.Errorf("discovery interface is required")
	}
	if eventLog == nil {
		eventLog = func(string) {}
	}

	ignoreMAC, err := optionalMAC(ignoreMACStr)
	if err != nil {
		return nil, fmt.Errorf("ignore MAC: %w", err)
	}

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
		if len(id.MAC) != 0 || !validUnicastMAC(mac) {
			return
		}
		id.MAC = copyMAC(mac)
		eventLog(fmt.Sprintf("[+] Discovered Target MAC via %s: %s", source, id.MAC.String()))
		if onMacFound != nil && !hasTriggeredMacCallback {
			hasTriggeredMacCallback = true
			onMacFound(copyMAC(id.MAC), append([]byte(nil), firstFrame...))
		}
	}

	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case packet, ok := <-packets:
			if !ok {
				return nil, fmt.Errorf("capture on %s stopped", s.iface)
			}
			if packet == nil {
				continue
			}

			// 1. Process Layer 2 to deduce Target MAC if unknown.
			eth, hasEthernet := packet.Layer(layers.LayerTypeEthernet).(*layers.Ethernet)
			if hasEthernet {

				// 1a. Detect 802.1X EAPOL frames (EtherType 0x888E).
				//     These are valid Layer 2 evidence: the first supplicant-side
				//     EAPOL source MAC is enough to activate transparent bridging.
				if eth.EthernetType == 0x888E {
					if ignoreMAC == nil || !macEqual(eth.SrcMAC, ignoreMAC) {
						lockTarget(eth.SrcMAC, "EAPOL", packet.Data())
					}
					if !id.EAPOLDetected {
						id.EAPOLDetected = true
						if len(id.MAC) > 0 && validUnicastMAC(eth.SrcMAC) && !macEqual(eth.SrcMAC, id.MAC) {
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
				if !validUnicastMAC(eth.SrcMAC) {
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
			if dot1q, ok := packet.Layer(layers.LayerTypeDot1Q).(*layers.Dot1Q); ok {
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
			if ipv4, ok := packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4); ok {
				srcIP = ipv4.SrcIP

				if hasEthernet {
					if macEqual(eth.SrcMAC, id.MAC) && len(id.IP) == 0 {
						// The target is transmitting with this IP.
						if !srcIP.IsUnspecified() && !srcIP.IsLoopback() && !srcIP.IsMulticast() && !strings.HasPrefix(srcIP.String(), "169.254") {
							id.IP = copyIP(srcIP)
							eventLog(fmt.Sprintf("[+] Passive inference extracted Target IP: %s", id.IP.String()))
						}
					}
				}
			}

			// 3. Process ARP to deduce Gateway or IPs quicker.
			if arp, ok := packet.Layer(layers.LayerTypeARP).(*layers.ARP); ok {
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
								id.IP = copyIP(senderIP)
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
								id.Gateway = copyIP(senderIP)
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
							id.IP = copyIP(senderIP)
							eventLog(fmt.Sprintf("[+] ARP Reply revealed Target IP: %s", id.IP.String()))
						}
					} else {
						// Reply directed specifically to our target MAC is likely from the gateway.
						if len(id.Gateway) == 0 && len(id.IP) > 0 && macEqual(targetMAC, id.MAC) {
							if !senderIP.IsUnspecified() && !strings.HasPrefix(senderIP.String(), "169.254") {
								id.Gateway = copyIP(senderIP)
								eventLog(fmt.Sprintf("[+] ARP Reply revealed Gateway IP: %s", id.Gateway.String()))
							}
						}
					}
				}
			}

			// 4. Process DHCP (UDP 67/68) to get exact metadata (Gateway, Subnet).
			if udp, ok := packet.Layer(layers.LayerTypeUDP).(*layers.UDP); ok {
				if udp.SrcPort == 67 || udp.DstPort == 67 {
					if dhcp, ok := packet.Layer(layers.LayerTypeDHCPv4).(*layers.DHCPv4); ok {
						if macEqual(dhcp.ClientHWAddr, id.MAC) {
							// It's a DHCP ACK meant for our Target
							if dhcp.Operation == layers.DHCPOpReply && dhcp.YourClientIP != nil {
								id.IP = copyIP(dhcp.YourClientIP)
								eventLog(fmt.Sprintf("[+] DHCP ACK assigned Target IP: %s", id.IP.String()))

								// Parse options for Subnet and Router
								for _, opt := range dhcp.Options {
									if opt.Type == layers.DHCPOptSubnetMask {
										id.Netmask = append(net.IPMask(nil), opt.Data...)
										id.NetmaskObserved = true
										eventLog(fmt.Sprintf("[+] DHCP ACK revealed Subnet Mask: %s", id.Netmask.String()))
									} else if opt.Type == layers.DHCPOptRouter {
										if len(opt.Data) >= 4 {
											id.Gateway = copyIP(net.IP(opt.Data[:4]))
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
				result := copyIdentity(*id)
				return &result, nil
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

// HasGateway returns whether the gateway has been discovered for routed NAT.
func (t TargetIdentity) HasGateway() bool {
	return len(t.Gateway) > 0
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

func copyIdentity(identity TargetIdentity) TargetIdentity {
	identity.MAC = copyMAC(identity.MAC)
	identity.IP = copyIP(identity.IP)
	identity.Netmask = append(net.IPMask(nil), identity.Netmask...)
	identity.Gateway = copyIP(identity.Gateway)
	identity.AuthenticatorMAC = copyMAC(identity.AuthenticatorMAC)
	identity.VLANs = append([]uint16(nil), identity.VLANs...)
	return identity
}

func optionalMAC(value string) (net.HardwareAddr, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil, nil
	}
	mac, err := net.ParseMAC(value)
	if err != nil {
		return nil, err
	}
	if !validUnicastMAC(mac) {
		return nil, fmt.Errorf("must be a 48-bit unicast address")
	}
	return copyMAC(mac), nil
}

func validUnicastMAC(mac net.HardwareAddr) bool {
	if len(mac) != 6 || mac[0]&1 != 0 {
		return false
	}
	for _, octet := range mac {
		if octet != 0 {
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
