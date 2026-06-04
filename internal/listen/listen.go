package listen

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
	"golan/internal/canvas"
	"golan/internal/inspect"
	"golan/internal/paths"
)

const (
	ethernetTypeEAPOL  = layers.EthernetType(0x888e)
	ethernetTypeMACsec = layers.EthernetType(0x88e5)
	arpRequestOp       = 1
)

// Target describes one staged adapter to passively capture.
type Target struct {
	Name         string
	Role         string
	HardwarePort string
	LocalMAC     string
}

// Event is emitted for listener lifecycle and passive discoveries.
type Event struct {
	Kind     string
	Message  string
	Adapter  string
	Role     string
	Field    string
	Value    string
	Evidence string
	Packet   string
	Path     string
	Err      error
}

// Session owns active capture goroutines.
type Session struct {
	Dir    string
	Events <-chan Event

	cancel context.CancelFunc
	done   chan struct{}
}

// Stop ends all active captures.
func (s *Session) Stop() error {
	if s != nil && s.cancel != nil {
		s.cancel()
	}
	if s == nil || s.done == nil {
		return nil
	}
	select {
	case <-s.done:
		return nil
	case <-time.After(8 * time.Second):
		return fmt.Errorf("listen stop timed out")
	}
}

// Start begins passive capture for each target.
func Start(targets []Target) (*Session, error) {
	if len(targets) == 0 {
		return nil, fmt.Errorf("no adapter")
	}

	dir, err := pcapDir()
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("create pcap dir: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	events := make(chan Event, 128)
	done := make(chan struct{})
	var wg sync.WaitGroup

	for _, target := range targets {
		target := target
		wg.Add(1)
		go func() {
			defer wg.Done()
			runCapture(ctx, target, dir, events)
		}()
	}

	go func() {
		defer close(done)
		wg.Wait()
		if err := paths.FinalizeTree(dir); err != nil {
			sendEvent(context.Background(), events, Event{Kind: "error", Err: fmt.Errorf("finalize pcaps: %w", err)})
		}
		close(events)
	}()

	return &Session{Dir: dir, Events: events, cancel: cancel, done: done}, nil
}

func runCapture(ctx context.Context, target Target, dir string, events chan<- Event) {
	sendEvent(ctx, events, Event{Kind: "log", Adapter: target.Name, Role: target.Role, Message: "listen init " + target.Role + "/" + target.Name})
	sendEvent(ctx, events, Event{Kind: "log", Adapter: target.Name, Role: target.Role, Message: "listen capture: host side only"})
	handle, err := pcap.OpenLive(target.Name, 65535, true, pcap.BlockForever)
	if err != nil {
		sendEvent(ctx, events, Event{Kind: "error", Adapter: target.Name, Role: target.Role, Err: err})
		return
	}
	defer handle.Close()

	path := filepath.Join(dir, fmt.Sprintf("%s-%s.pcap", safeName(target.Role), safeName(target.Name)))
	file, err := os.Create(path)
	if err != nil {
		sendEvent(ctx, events, Event{Kind: "error", Adapter: target.Name, Role: target.Role, Err: err})
		return
	}
	defer file.Close()

	writer := pcapgo.NewWriter(file)
	if err := writer.WriteFileHeader(65535, handle.LinkType()); err != nil {
		sendEvent(ctx, events, Event{Kind: "error", Adapter: target.Name, Role: target.Role, Err: err})
		return
	}

	sendEvent(ctx, events, Event{Kind: "pcap", Adapter: target.Name, Role: target.Role, Path: path})
	sendEvent(ctx, events, Event{Kind: "log", Adapter: target.Name, Role: target.Role, Message: "awaiting host mac on " + target.Name})

	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			handle.Close()
		case <-done:
		}
	}()
	defer close(done)

	ignoreMAC, _ := net.ParseMAC(target.LocalMAC)
	inspector := inspect.New()
	source := gopacket.NewPacketSource(handle, handle.LinkType())
	var lockedMAC net.HardwareAddr
	seenTraffic := make(map[string]bool)
	packetCount := 0
	for {
		select {
		case <-ctx.Done():
			sendEvent(context.Background(), events, Event{Kind: "stopped", Adapter: target.Name, Role: target.Role, Path: path})
			return
		case packet, ok := <-source.Packets():
			if !ok || packet == nil {
				sendEvent(context.Background(), events, Event{Kind: "stopped", Adapter: target.Name, Role: target.Role, Path: path})
				return
			}
			if err := writer.WritePacket(packet.Metadata().CaptureInfo, packet.Data()); err != nil {
				sendEvent(ctx, events, Event{Kind: "error", Adapter: target.Name, Role: target.Role, Err: err, Path: path})
				return
			}
			packetCount++
			if message := trafficLogMessage(target, packet, packetCount, seenTraffic); message != "" {
				sendEvent(ctx, events, Event{Kind: "traffic", Adapter: target.Name, Role: target.Role, Message: message})
			}
			for _, finding := range inspector.AnalyzePacket(packet) {
				sendEvent(ctx, events, Event{Kind: "finding", Adapter: target.Name, Role: target.Role, Message: finding.Encode()})
			}
			for _, observation := range canvas.ObservePacket(packet, target.Name, target.Role) {
				sendEvent(ctx, events, Event{Kind: canvas.EventKind, Adapter: target.Name, Role: target.Role, Message: observation.Encode()})
			}
			if lockedMAC == nil {
				if mac, source := targetSourceMAC(packet, ignoreMAC); mac != nil {
					lockedMAC = append(net.HardwareAddr(nil), mac...)
					sendEvent(ctx, events, Event{Kind: "log", Adapter: target.Name, Role: target.Role, Message: fmt.Sprintf("host mac locked %s via %s", lockedMAC, source)})
				}
			}
			for _, discovery := range AnalyzePacket(packet, ignoreMAC) {
				discovery.Kind = "discovery"
				discovery.Adapter = target.Name
				discovery.Role = target.Role
				sendEvent(ctx, events, discovery)
			}
		}
	}
}

// AnalyzePacket extracts assignable values from Layer 2/3 evidence.
func AnalyzePacket(packet gopacket.Packet, ignoreMAC net.HardwareAddr) []Event {
	var events []Event
	var eth *layers.Ethernet
	if layer := packet.Layer(layers.LayerTypeEthernet); layer != nil {
		eth, _ = layer.(*layers.Ethernet)
	}

	if eth != nil {
		packetName := sourcePacketName(packet, eth)
		if validUnicastMAC(eth.SrcMAC) {
			events = append(events, discovery("ether_src", eth.SrcMAC.String(), "source mac", packetName))
		}
		if validMAC(eth.DstMAC) {
			events = append(events, discovery("ether_dst", eth.DstMAC.String(), "destination mac", packetName))
		}
		if eth.EthernetType != 0 {
			events = append(events, discovery("ether_type", ethernetTypeName(eth.EthernetType), "ether type", packetName))
		}
		if validSourceMAC(eth.SrcMAC, ignoreMAC) {
			events = append(events, discovery("mac", eth.SrcMAC.String(), "source mac", packetName))
		}
	}

	if layer := packet.Layer(layers.LayerTypeDot1Q); layer != nil {
		dot1q, _ := layer.(*layers.Dot1Q)
		if dot1q.VLANIdentifier != 0 {
			events = append(events, discovery("vlan", fmt.Sprintf("%d", dot1q.VLANIdentifier), "802.1Q vlan id", "VLAN-tagged traffic"))
		}
		if dot1q.Type != 0 {
			events = append(events, discovery("vlan_type", ethernetTypeName(dot1q.Type), "inner ether type", "VLAN-tagged traffic"))
		}
	}

	if layer := packet.Layer(layers.LayerTypeARP); layer != nil {
		arp, _ := layer.(*layers.ARP)
		events = append(events, discovery("arp_op", arpOperationName(arp.Operation), "operation", "ARP"))
		srcMAC := net.HardwareAddr(arp.SourceHwAddress)
		if validSourceMAC(srcMAC, ignoreMAC) {
			events = append(events, discovery("mac", srcMAC.String(), "arp sender mac", "ARP"))
		}
		if validUnicastMAC(srcMAC) {
			events = append(events, discovery("arp_sender_mac", srcMAC.String(), "sender mac", "ARP"))
		}
		if targetMAC := net.HardwareAddr(arp.DstHwAddress); validMAC(targetMAC) {
			events = append(events, discovery("arp_target_mac", targetMAC.String(), "target mac", "ARP"))
		}
		if ip := net.IP(arp.SourceProtAddress); observableIPv4(ip) {
			if arp.Operation == arpRequestOp {
				events = append(events, discovery("arp_tell", ip.String(), "tell sender ip", "ARP"))
			}
			events = append(events, discovery("arp_sender_ip", ip.String(), "sender ip", "ARP"))
			if usableIPv4(ip) {
				events = append(events, discovery("ip", ip.String(), "arp sender ip", "ARP"))
			}
		}
		if arp.Operation == arpRequestOp {
			if ip := net.IP(arp.DstProtAddress); observableIPv4(ip) {
				events = append(events, discovery("arp_who_has", ip.String(), "who-has target ip", "ARP"))
			}
		}
		if ip := net.IP(arp.DstProtAddress); observableIPv4(ip) {
			events = append(events, discovery("arp_target_ip", ip.String(), "target ip", "ARP"))
		}
	}

	if layer := packet.Layer(layers.LayerTypeIPv4); layer != nil {
		ipv4, _ := layer.(*layers.IPv4)
		if observableIPv4(ipv4.SrcIP) {
			events = append(events, discovery("ipv4_src", ipv4.SrcIP.String(), "source ip", "IPv4"))
			if usableIPv4(ipv4.SrcIP) {
				events = append(events, discovery("ip", ipv4.SrcIP.String(), "ipv4 source", "IPv4"))
			}
		}
		if observableIPv4(ipv4.DstIP) {
			events = append(events, discovery("ipv4_dst", ipv4.DstIP.String(), "destination ip", "IPv4"))
		}
		if ipv4.Protocol != 0 {
			events = append(events, discovery("ip_proto", ipv4.Protocol.String(), "ipv4 protocol", "IPv4"))
		}
	}

	if layer := packet.Layer(layers.LayerTypeIPv6); layer != nil {
		ipv6, _ := layer.(*layers.IPv6)
		if observableIP(ipv6.SrcIP) {
			events = append(events, discovery("ipv6_src", ipv6.SrcIP.String(), "source ip", "IPv6"))
		}
		if observableIP(ipv6.DstIP) {
			events = append(events, discovery("ipv6_dst", ipv6.DstIP.String(), "destination ip", "IPv6"))
		}
		if ipv6.NextHeader != 0 {
			events = append(events, discovery("ip_proto", ipv6.NextHeader.String(), "ipv6 next header", "IPv6"))
		}
	}

	if layer := packet.Layer(layers.LayerTypeDHCPv4); layer != nil {
		dhcp, _ := layer.(*layers.DHCPv4)
		if validSourceMAC(dhcp.ClientHWAddr, ignoreMAC) {
			events = append(events, discovery("mac", dhcp.ClientHWAddr.String(), "dhcp client mac", "DHCP"))
		}
		if usableIPv4(dhcp.ClientIP) {
			events = append(events, discovery("ip", dhcp.ClientIP.String(), "dhcp client ip", "DHCP"))
		}
		if usableIPv4(dhcp.YourClientIP) {
			events = append(events, discovery("ip", dhcp.YourClientIP.String(), "dhcp assigned ip", "DHCP"))
		}
		for _, option := range dhcp.Options {
			switch option.Type {
			case layers.DHCPOptSubnetMask:
				if len(option.Data) >= 4 {
					mask := net.IPMask(option.Data[:4])
					if ones, bits := mask.Size(); bits == 32 && ones >= 0 {
						events = append(events, discovery("cidr", fmt.Sprintf("%d", ones), "dhcp subnet mask option", "DHCP"))
					}
				}
			case layers.DHCPOptRouter:
				for i := 0; i+3 < len(option.Data); i += 4 {
					ip := net.IP(option.Data[i : i+4])
					if usableIPv4(ip) {
						events = append(events, discovery("gateway", ip.String(), "dhcp router option", "DHCP"))
					}
				}
			case layers.DHCPOptDNS:
				for i := 0; i+3 < len(option.Data); i += 4 {
					ip := net.IP(option.Data[i : i+4])
					if usableIPv4(ip) {
						events = append(events, discovery("dns", ip.String(), "dhcp dns option", "DHCP"))
					}
				}
			}
		}
	}

	if layer := packet.Layer(layers.LayerTypeEAPOL); layer != nil {
		eapol, _ := layer.(*layers.EAPOL)
		events = append(events, discovery("eapol", eapol.Type.String(), "type", "EAPOL / 802.1X"))
		events = append(events, discovery("eapol_type", fmt.Sprintf("%d", eapol.Type), "type number", "EAPOL / 802.1X"))
		events = append(events, discovery("eapol_version", fmt.Sprintf("%d", eapol.Version), "version", "EAPOL / 802.1X"))
	}
	if eth != nil && eth.EthernetType == ethernetTypeMACsec {
		events = append(events, discovery("macsec", "0x88e5", "ether type", "MACsec"))
	}

	if layer := packet.Layer(layers.LayerTypeEAP); layer != nil {
		eap, _ := layer.(*layers.EAP)
		events = append(events, discovery("eap_code", eapCodeName(eap.Code), "code", "EAPOL / 802.1X"))
		if eap.Type != layers.EAPTypeNone {
			events = append(events, discovery("eap_type", eapTypeName(eap.Type), "method", "EAPOL / 802.1X"))
		}
	}

	return dedupeEvents(events)
}

func sourcePacketName(packet gopacket.Packet, eth *layers.Ethernet) string {
	switch {
	case eth != nil && eth.EthernetType == ethernetTypeEAPOL:
		return "EAPOL / 802.1X"
	case eth != nil && eth.EthernetType == ethernetTypeMACsec:
		return "MACsec"
	case packet.Layer(layers.LayerTypeDHCPv4) != nil:
		return "DHCP"
	case packet.Layer(layers.LayerTypeARP) != nil:
		return "ARP"
	case packet.Layer(layers.LayerTypeDot1Q) != nil:
		return "VLAN-tagged traffic"
	case packet.Layer(layers.LayerTypeIPv4) != nil:
		return "IPv4"
	case packet.Layer(layers.LayerTypeIPv6) != nil:
		return "IPv6"
	default:
		return "Ethernet data frame"
	}
}

func discovery(field, value, evidence, packet string) Event {
	return Event{Field: field, Value: value, Evidence: evidence, Packet: packet}
}

func targetSourceMAC(packet gopacket.Packet, ignoreMAC net.HardwareAddr) (net.HardwareAddr, string) {
	layer := packet.Layer(layers.LayerTypeEthernet)
	if layer == nil {
		return nil, ""
	}
	eth, _ := layer.(*layers.Ethernet)
	if eth == nil || !validSourceMAC(eth.SrcMAC, ignoreMAC) {
		return nil, ""
	}
	return append(net.HardwareAddr(nil), eth.SrcMAC...), sourcePacketName(packet, eth)
}

func trafficLogMessage(target Target, packet gopacket.Packet, count int, seen map[string]bool) string {
	summary, _ := PacketSummary(packet)
	if summary == "" {
		return ""
	}
	return fmt.Sprintf("#%d %s/%s %s", count, target.Role, target.Name, summary)
}

func PacketSummary(packet gopacket.Packet) (string, string) {
	layer := packet.Layer(layers.LayerTypeEthernet)
	if layer == nil {
		return "", ""
	}
	eth, _ := layer.(*layers.Ethernet)
	if eth == nil {
		return "", ""
	}
	name := sourcePacketName(packet, eth)
	details := []string{shortPacketName(name), shortMAC(eth.SrcMAC) + ">" + shortMAC(eth.DstMAC)}
	keyParts := []string{name, strings.ToLower(eth.SrcMAC.String()), strings.ToLower(eth.DstMAC.String())}
	if vlanLayer := packet.Layer(layers.LayerTypeDot1Q); vlanLayer != nil {
		vlan, _ := vlanLayer.(*layers.Dot1Q)
		details = append(details, fmt.Sprintf("vlan:%d", vlan.VLANIdentifier))
		keyParts = append(keyParts, fmt.Sprintf("vlan=%d", vlan.VLANIdentifier))
	}
	if eapolLayer := packet.Layer(layers.LayerTypeEAPOL); eapolLayer != nil {
		eapol, _ := eapolLayer.(*layers.EAPOL)
		details = append(details, "eapol:"+strings.ToLower(eapol.Type.String()))
		keyParts = append(keyParts, "eapol="+eapol.Type.String())
	}
	if eth.EthernetType == ethernetTypeMACsec {
		details = append(details, "ether:0x88e5")
		keyParts = append(keyParts, "macsec=0x88e5")
	}
	if arpLayer := packet.Layer(layers.LayerTypeARP); arpLayer != nil {
		arp, _ := arpLayer.(*layers.ARP)
		src := net.IP(arp.SourceProtAddress)
		dst := net.IP(arp.DstProtAddress)
		details = append(details, fmt.Sprintf("arp:%s %s>%s", arpOperationName(arp.Operation), src, dst))
		keyParts = append(keyParts, "arp="+arpOperationName(arp.Operation), src.String(), dst.String())
	}
	if ipv4Layer := packet.Layer(layers.LayerTypeIPv4); ipv4Layer != nil {
		ipv4, _ := ipv4Layer.(*layers.IPv4)
		details = append(details, fmt.Sprintf("%s>%s %s", ipv4.SrcIP, ipv4.DstIP, ipv4.Protocol))
		keyParts = append(keyParts, ipv4.SrcIP.String(), ipv4.DstIP.String(), ipv4.Protocol.String())
	}
	if ipv6Layer := packet.Layer(layers.LayerTypeIPv6); ipv6Layer != nil {
		ipv6, _ := ipv6Layer.(*layers.IPv6)
		details = append(details, fmt.Sprintf("%s>%s %s", ipv6.SrcIP, ipv6.DstIP, ipv6.NextHeader))
		keyParts = append(keyParts, ipv6.SrcIP.String(), ipv6.DstIP.String(), ipv6.NextHeader.String())
	}
	return strings.Join(details, " "), strings.Join(keyParts, "\x00")
}

func shortPacketName(name string) string {
	switch name {
	case "EAPOL / 802.1X":
		return "EAPOL"
	case "MACsec":
		return "MACSEC"
	case "VLAN-tagged traffic":
		return "VLAN"
	case "Ethernet data frame":
		return "ETH"
	default:
		return name
	}
}

func shortMAC(mac net.HardwareAddr) string {
	if len(mac) != 6 {
		return mac.String()
	}
	return fmt.Sprintf("%02x:%02x:%02x", mac[3], mac[4], mac[5])
}

func validSourceMAC(mac net.HardwareAddr, ignore net.HardwareAddr) bool {
	if !validUnicastMAC(mac) {
		return false
	}
	if ignore != nil && macEqual(mac, ignore) {
		return false
	}
	return true
}

func validUnicastMAC(mac net.HardwareAddr) bool {
	if len(mac) != 6 {
		return false
	}
	if mac[0]&1 != 0 {
		return false
	}
	allZero := true
	for _, b := range mac {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		return false
	}
	return true
}

func validMAC(mac net.HardwareAddr) bool {
	if len(mac) != 6 {
		return false
	}
	for _, b := range mac {
		if b != 0 {
			return true
		}
	}
	return false
}

func observableIPv4(ip net.IP) bool {
	ip = ip.To4()
	return ip != nil && !ip.IsUnspecified()
}

func usableIPv4(ip net.IP) bool {
	ip = ip.To4()
	if ip == nil || ip.IsUnspecified() || ip.IsLoopback() || ip.IsMulticast() {
		return false
	}
	return !strings.HasPrefix(ip.String(), "169.254.")
}

func observableIP(ip net.IP) bool {
	return ip != nil && !ip.IsUnspecified()
}

func ethernetTypeName(value layers.EthernetType) string {
	name := value.String()
	if name == "" || strings.HasPrefix(name, "Unknown") {
		return fmt.Sprintf("0x%04x", uint16(value))
	}
	return fmt.Sprintf("0x%04x %s", uint16(value), name)
}

func arpOperationName(operation uint16) string {
	switch operation {
	case 1:
		return "request"
	case 2:
		return "reply"
	default:
		return fmt.Sprintf("%d", operation)
	}
}

func eapCodeName(code layers.EAPCode) string {
	switch code {
	case layers.EAPCodeRequest:
		return "request"
	case layers.EAPCodeResponse:
		return "response"
	case layers.EAPCodeSuccess:
		return "success"
	case layers.EAPCodeFailure:
		return "failure"
	default:
		return fmt.Sprintf("%d", code)
	}
}

func eapTypeName(eapType layers.EAPType) string {
	switch eapType {
	case layers.EAPTypeIdentity:
		return "identity"
	case layers.EAPTypeNotification:
		return "notification"
	case layers.EAPTypeNACK:
		return "nak"
	case layers.EAPTypeOTP:
		return "otp"
	case layers.EAPTypeTokenCard:
		return "token-card"
	default:
		return fmt.Sprintf("%d", eapType)
	}
}

func dedupeEvents(events []Event) []Event {
	var out []Event
	seen := make(map[string]bool)
	for _, event := range events {
		key := event.Field + "\x00" + strings.ToLower(event.Value) + "\x00" + event.Evidence + "\x00" + event.Packet
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, event)
	}
	return out
}

func pcapDir() (string, error) {
	return paths.PcapRunDir()
}

func safeName(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return "unknown"
	}
	replacer := strings.NewReplacer("/", "_", "\\", "_", ":", "_", " ", "_")
	return replacer.Replace(value)
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

func sendEvent(ctx context.Context, events chan<- Event, event Event) {
	select {
	case <-ctx.Done():
	case events <- event:
	default:
	}
}
