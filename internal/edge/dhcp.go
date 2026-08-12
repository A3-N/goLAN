package edge

import (
	"fmt"
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// BuildDHCPReply returns an OFFER for DISCOVER or ACK for a valid REQUEST.
// Non-DHCP and unsupported messages return (nil, false, nil).
func BuildDHCPReply(frame []byte, serverMAC net.HardwareAddr, lease Lease) ([]byte, bool, error) {
	if len(serverMAC) != 6 || serverMAC[0]&1 != 0 {
		return nil, false, fmt.Errorf("DHCP server MAC must be a 48-bit unicast address")
	}
	packet := gopacket.NewPacket(frame, layers.LayerTypeEthernet, gopacket.DecodeOptions{Lazy: false, NoCopy: false})
	dhcp, ok := packet.Layer(layers.LayerTypeDHCPv4).(*layers.DHCPv4)
	if !ok || dhcp.Operation != layers.DHCPOpRequest || len(dhcp.ClientHWAddr) != 6 {
		return nil, false, nil
	}
	messageType := layers.DHCPMsgTypeUnspecified
	for _, option := range dhcp.Options {
		if option.Type == layers.DHCPOptMessageType && len(option.Data) == 1 {
			messageType = layers.DHCPMsgType(option.Data[0])
			break
		}
	}
	replyType := layers.DHCPMsgTypeUnspecified
	switch messageType {
	case layers.DHCPMsgTypeDiscover:
		replyType = layers.DHCPMsgTypeOffer
	case layers.DHCPMsgTypeRequest:
		replyType = layers.DHCPMsgTypeAck
	default:
		return nil, false, nil
	}
	serverIP := net.IP(lease.ServerIP.AsSlice())
	clientIP := net.IP(lease.ClientIP.AsSlice())
	ethernet := &layers.Ethernet{SrcMAC: append(net.HardwareAddr(nil), serverMAC...), DstMAC: net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, EthernetType: layers.EthernetTypeIPv4}
	ipv4 := &layers.IPv4{Version: 4, IHL: 5, TTL: 64, Protocol: layers.IPProtocolUDP, SrcIP: serverIP, DstIP: net.IPv4bcast}
	udp := &layers.UDP{SrcPort: 67, DstPort: 68}
	if err := udp.SetNetworkLayerForChecksum(ipv4); err != nil {
		return nil, false, err
	}
	reply := &layers.DHCPv4{
		Operation: layers.DHCPOpReply, HardwareType: dhcp.HardwareType,
		HardwareLen: dhcp.HardwareLen, HardwareOpts: dhcp.HardwareOpts,
		Xid: dhcp.Xid, Secs: dhcp.Secs, Flags: dhcp.Flags,
		YourClientIP: clientIP, NextServerIP: serverIP,
		ClientHWAddr: append(net.HardwareAddr(nil), dhcp.ClientHWAddr...),
	}
	mask := net.CIDRMask(lease.Subnet.Bits(), 32)
	reply.Options = append(reply.Options,
		layers.NewDHCPOption(layers.DHCPOptMessageType, []byte{byte(replyType)}),
		layers.NewDHCPOption(layers.DHCPOptServerID, serverIP.To4()),
		layers.NewDHCPOption(layers.DHCPOptSubnetMask, []byte(mask)),
		layers.NewDHCPOption(layers.DHCPOptRouter, net.IP(lease.Gateway.AsSlice()).To4()),
		layers.NewDHCPOption(layers.DHCPOptLeaseTime, durationBytes(24*time.Hour)),
	)
	var dns []byte
	for _, address := range lease.DNS {
		if address.Is4() {
			dns = append(dns, address.AsSlice()...)
		}
	}
	if len(dns) > 0 {
		reply.Options = append(reply.Options, layers.NewDHCPOption(layers.DHCPOptDNS, dns))
	}
	buffer := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, ethernet, ipv4, udp, reply); err != nil {
		return nil, false, fmt.Errorf("serialize DHCP reply: %w", err)
	}
	return append([]byte(nil), buffer.Bytes()...), true, nil
}

func durationBytes(duration time.Duration) []byte {
	seconds := uint32(duration / time.Second)
	return []byte{byte(seconds >> 24), byte(seconds >> 16), byte(seconds >> 8), byte(seconds)}
}
