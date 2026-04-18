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

// NewSniffer initializes a listener for a specific network interface.
func NewSniffer(iface string) *Sniffer {
	return &Sniffer{iface: iface}
}

// Discover passively listens to the interface until it successfully reconstructs the True Device's configuration.
// It relies on ARPs, IP headers, and DHCP configurations.
// The eventLog callback streams internal discoveries dynamically.
func (s *Sniffer) Discover(ctx context.Context, ignoreMACStr string, eventLog func(string), onMacFound func(mac net.HardwareAddr)) (*TargetIdentity, error) {
	if eventLog == nil {
		eventLog = func(string) {}
	}

	ignoreMAC, _ := net.ParseMAC(ignoreMACStr)

	eventLog(fmt.Sprintf("[*] Initializing Pcap handle on interface: %s", s.iface))
	handle, err := pcap.OpenLive(s.iface, 1600, true, pcap.BlockForever)
	if err != nil {
		return nil, err
	}
	defer handle.Close()

	if err := handle.SetBPFFilter("outbound and not arp and not rarp"); err == nil {
		// Optimization, ignore BPF errors.
	}

	eventLog("[*] Awaiting first valid unicast MAC to lock onto target...")

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packets := packetSource.Packets()

	id := &TargetIdentity{}
	hasTriggeredMacCallback := false

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
				
				// Skip broadcast/multicast sources
				if eth.SrcMAC[0]&1 != 0 {
					continue
				}

				// Skip leaked packets originating from the un-spoofed Mac interface.
				if ignoreMAC != nil && macEqual(eth.SrcMAC, ignoreMAC) {
					continue
				}

				if len(id.MAC) == 0 {
					// We assume the first unicast source MAC we see entering the device port is the Target Device.
					id.MAC = eth.SrcMAC
					eventLog(fmt.Sprintf("[+] Discovered Target MAC: %s", id.MAC.String()))
					if onMacFound != nil && !hasTriggeredMacCallback {
						hasTriggeredMacCallback = true
						onMacFound(id.MAC)
					}
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
								eventLog(fmt.Sprintf("[*] Ignored Link-Local Self-Assignment: %s", senderIP.String()))
								eventLog("[*] Waiting indefinitely for native DHCP ACK.")
							} else {
								id.IP = senderIP
								eventLog(fmt.Sprintf("[+] Discovered Target Real IP: %s", id.IP.String()))
							}
						}
					} else {
						// Someone else (gateway/switch) is ARPing for our target device?
						// Or it's a broadcast.
						if len(id.Gateway) == 0 && targetIP.Equal(id.IP) {
							// The sender is likely the Gateway trying to reach our Target Device.
							id.Gateway = senderIP
							eventLog(fmt.Sprintf("> ARP Request revealed possible Gateway IP: %s", id.Gateway.String()))
						}
					}
				} else if arp.Operation == layers.ARPReply {
					senderMAC := net.HardwareAddr(arp.SourceHwAddress)
					senderIP := net.IP(arp.SourceProtAddress)
					
					if macEqual(senderMAC, id.MAC) {
						if len(id.IP) == 0 && !senderIP.IsUnspecified() {
							id.IP = senderIP
							eventLog(fmt.Sprintf("> ARP Reply revealed Target IP: %s", id.IP.String()))
						}
					} else {
						// Reply from Gateway or switch?
						if len(id.Gateway) == 0 && len(id.IP) > 0 {
							// If someone replied to our MAC, they might be the gateway.
							id.Gateway = senderIP
							eventLog(fmt.Sprintf("> ARP Reply revealed Gateway IP: %s", id.Gateway.String()))
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

								// Parse options for Subnet and Router
								for _, opt := range dhcp.Options {
									if opt.Type == layers.DHCPOptSubnetMask {
										id.Netmask = net.IPMask(opt.Data)
										eventLog(fmt.Sprintf("> DHCP ACK revealed Subnet Mask: %s", id.Netmask.String()))
									} else if opt.Type == layers.DHCPOptRouter {
										if len(opt.Data) >= 4 {
											id.Gateway = net.IP(opt.Data[:4])
											eventLog(fmt.Sprintf("> DHCP ACK revealed Router/Gateway: %s", id.Gateway.String()))
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
				eventLog("Identity fully constructed. Reconnaissance complete.")
				// We fall back nicely if we couldn't naturally capture a DHCP subnet mask.
				if len(id.Netmask) == 0 {
					id.Netmask = id.IP.DefaultMask()
					eventLog(fmt.Sprintf("Falling back to default subnet mask: %s", id.Netmask.String()))
				}
				return id, nil
			}
		}
	}
}

// IsComplete verifies we have collected the minimum required data for a stealth NAT piggyback.
func (t TargetIdentity) IsComplete() bool {
	return len(t.MAC) > 0 && len(t.IP) > 0 && len(t.Gateway) > 0
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
