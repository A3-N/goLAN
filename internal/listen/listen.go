package listen

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golan/internal/dataplane"
	"golan/internal/inspect"
	"golan/internal/paths"
	"golan/internal/policy"
	"golan/internal/traffic"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
)

const (
	ethernetTypeEAPOL  = layers.EthernetType(0x888e)
	ethernetTypeMACsec = layers.EthernetType(0x88e5)
	arpRequestOp       = 1
)

// EventKind identifies listener lifecycle and packet-analysis events.
type EventKind string

// Listener event kinds identify lifecycle, capture, discovery, and analysis output.
const (
	KindLog       EventKind = "log"
	KindPcap      EventKind = "pcap"
	KindError     EventKind = "error"
	KindStopped   EventKind = "stopped"
	KindTraffic   EventKind = "traffic"
	KindEvidence  EventKind = "evidence"
	KindDecision  EventKind = "decision"
	KindSignal    EventKind = "signal"
	KindDiscovery EventKind = "discovery"
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
	Kind      EventKind
	Message   string
	Adapter   string
	Role      string
	Field     string
	Value     string
	Evidence  string
	Packet    string
	DeviceMAC string
	Path      string
	Err       error
	Frame     traffic.Frame
	Flow      traffic.Flow
	Mode      dataplane.Mode
	Decision  policy.DecisionSummary
}

// Session owns active capture goroutines.
type Session struct {
	Dir    string
	Events <-chan Event
	Engine *policy.Engine

	cancel    context.CancelFunc
	done      chan struct{}
	resultMu  sync.Mutex
	resultErr error
}

// Stop ends all active captures.
func (s *Session) Stop() error {
	if s != nil && s.cancel != nil {
		s.cancel()
	}
	if s == nil || s.done == nil {
		return nil
	}
	timer := time.NewTimer(8 * time.Second)
	defer timer.Stop()
	select {
	case <-s.done:
		s.resultMu.Lock()
		defer s.resultMu.Unlock()
		return s.resultErr
	case <-timer.C:
		return fmt.Errorf("listen stop timed out")
	}
}

// Stopped reports whether every capture goroutine and artifact finalizer has
// completed.
func (s *Session) Stopped() bool {
	if s == nil || s.done == nil {
		return true
	}
	select {
	case <-s.done:
		return true
	default:
		return false
	}
}

// StartWithPolicy begins passive capture through the shared normalized flow
// and policy engine. Enforcement actions are always evaluated in SHADOW for
// Listen and Edge Observe modes.
func StartWithPolicy(targets []Target, mode dataplane.Mode, revision string, rules []policy.Rule) (*Session, error) {
	validated, err := validateTargets(targets)
	if err != nil {
		return nil, err
	}
	targets = validated
	if mode != dataplane.ModeListen && mode != dataplane.ModeEdgeObserve {
		return nil, fmt.Errorf("passive capture mode must be listen or edge-observe")
	}
	engine := policy.NewEngine(8192)
	if len(rules) > 0 {
		if err := engine.Policies.Activate(revision, rules); err != nil {
			return nil, fmt.Errorf("compile passive policy: %w", err)
		}
	}

	dir, err := pcapDir()
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("create pcap dir: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	events := make(chan Event, 128)
	done := make(chan struct{})
	session := &Session{Dir: dir, Events: events, Engine: engine, cancel: cancel, done: done}
	var wg sync.WaitGroup

	for _, target := range targets {
		target := target
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := runCapture(ctx, target, dir, events, engine, dataplane.ForMode(mode)); err != nil {
				session.recordResult(err)
			}
		}()
	}

	go func() {
		defer close(done)
		wg.Wait()
		if err := paths.FinalizeTree(dir); err != nil {
			err = fmt.Errorf("finalize pcaps: %w", err)
			session.recordResult(err)
			finalCtx, cancelFinal := context.WithTimeout(context.Background(), 250*time.Millisecond)
			if sendErr := sendEvent(finalCtx, events, Event{Kind: KindError, Err: err}); sendErr != nil {
				session.recordResult(sendErr)
			}
			cancelFinal()
		}
		close(events)
	}()

	return session, nil
}

// SetPolicy atomically changes the passive session's shadow-evaluation
// revision. A compile error leaves the prior revision active.
func (s *Session) SetPolicy(revision string, rules []policy.Rule) error {
	if s == nil || s.Engine == nil {
		return fmt.Errorf("listen policy engine is unavailable")
	}
	return s.Engine.Policies.Activate(revision, rules)
}

func runCapture(ctx context.Context, target Target, dir string, events chan<- Event, engine *policy.Engine, capabilities dataplane.Capabilities) (resultErr error) {
	if err := sendEvent(ctx, events, Event{Kind: KindLog, Adapter: target.Name, Role: target.Role, Message: "listen init " + target.Role + "/" + target.Name}); err != nil {
		return err
	}
	if err := sendEvent(ctx, events, Event{Kind: KindLog, Adapter: target.Name, Role: target.Role, Message: "listen capture: host side only"}); err != nil {
		return err
	}
	handle, err := pcap.OpenLive(target.Name, 65535, true, pcap.BlockForever)
	if err != nil {
		err = fmt.Errorf("open capture on %s: %w", target.Name, err)
		return errors.Join(err, sendEvent(ctx, events, Event{Kind: KindError, Adapter: target.Name, Role: target.Role, Err: err}))
	}
	defer handle.Close()

	path := filepath.Join(dir, fmt.Sprintf("%s-%s.pcap", paths.SafeFilenamePart(target.Role), paths.SafeFilenamePart(target.Name)))
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		err = fmt.Errorf("create pcap %s: %w", path, err)
		return errors.Join(err, sendEvent(ctx, events, Event{Kind: KindError, Adapter: target.Name, Role: target.Role, Err: err}))
	}
	captureReady := false
	defer func() {
		if syncErr := file.Sync(); syncErr != nil {
			resultErr = errors.Join(resultErr, fmt.Errorf("sync pcap %s: %w", path, syncErr))
		}
		if closeErr := file.Close(); closeErr != nil {
			resultErr = errors.Join(resultErr, fmt.Errorf("close pcap %s: %w", path, closeErr))
		}
		if !captureReady {
			if removeErr := os.Remove(path); removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
				resultErr = errors.Join(resultErr, fmt.Errorf("remove incomplete pcap %s: %w", path, removeErr))
			}
		}
		finalCtx, cancelFinal := context.WithTimeout(context.Background(), 250*time.Millisecond)
		if sendErr := sendEvent(finalCtx, events, Event{Kind: KindStopped, Adapter: target.Name, Role: target.Role, Path: path, Err: resultErr}); sendErr != nil {
			resultErr = errors.Join(resultErr, sendErr)
		}
		cancelFinal()
	}()

	writer := pcapgo.NewWriter(file)
	if err := writer.WriteFileHeader(65535, handle.LinkType()); err != nil {
		err = fmt.Errorf("write pcap header %s: %w", path, err)
		return errors.Join(err, sendEvent(ctx, events, Event{Kind: KindError, Adapter: target.Name, Role: target.Role, Err: err}))
	}
	journalPath := strings.TrimSuffix(path, filepath.Ext(path)) + "." + string(capabilities.Mode()) + ".decisions.jsonl"
	journal, err := policy.OpenJournal(journalPath)
	if err != nil {
		err = fmt.Errorf("open passive decision journal for %s: %w", target.Name, err)
		return errors.Join(err, sendEvent(ctx, events, Event{Kind: KindError, Adapter: target.Name, Role: target.Role, Err: err, Path: path}))
	}
	defer func() {
		if closeErr := journal.Close(); closeErr != nil {
			resultErr = errors.Join(resultErr, fmt.Errorf("close passive decision journal %s: %w", journalPath, closeErr))
		}
	}()
	captureReady = true

	if err := sendEvent(ctx, events, Event{Kind: KindPcap, Adapter: target.Name, Role: target.Role, Path: path}); err != nil {
		return err
	}
	if err := sendEvent(ctx, events, Event{Kind: KindLog, Adapter: target.Name, Role: target.Role, Message: "listen decision journal: " + journalPath}); err != nil {
		return err
	}
	if err := sendEvent(ctx, events, Event{Kind: KindLog, Adapter: target.Name, Role: target.Role, Message: "awaiting host mac on " + target.Name}); err != nil {
		return err
	}

	stopWatcher := make(chan struct{})
	watcherDone := make(chan struct{})
	go func() {
		defer close(watcherDone)
		select {
		case <-ctx.Done():
			handle.Close()
		case <-stopWatcher:
		}
	}()
	defer func() {
		close(stopWatcher)
		<-watcherDone
	}()

	var ignoreMAC net.HardwareAddr
	if target.LocalMAC != "" {
		ignoreMAC, err = net.ParseMAC(target.LocalMAC)
		if err != nil {
			return fmt.Errorf("parse local MAC for %s: %w", target.Name, err)
		}
	}
	inspector := inspect.New()
	source := gopacket.NewPacketSource(handle, handle.LinkType())
	var lockedMAC net.HardwareAddr
	packetCount := 0
	for {
		packet, err := source.NextPacket()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			err = fmt.Errorf("read capture on %s: %w", target.Name, err)
			return errors.Join(err, sendEvent(ctx, events, Event{Kind: KindError, Adapter: target.Name, Role: target.Role, Err: err, Path: path}))
		}
		if packet == nil {
			continue
		}
		if err := writer.WritePacket(packet.Metadata().CaptureInfo, packet.Data()); err != nil {
			err = fmt.Errorf("write pcap for %s: %w", target.Name, err)
			return errors.Join(err, sendEvent(ctx, events, Event{Kind: KindError, Adapter: target.Name, Role: target.Role, Err: err, Path: path}))
		}
		if lockedMAC == nil {
			if mac, source := targetSourceMAC(packet, ignoreMAC); mac != nil {
				lockedMAC = append(net.HardwareAddr(nil), mac...)
				if err := sendEvent(ctx, events, Event{Kind: KindLog, Adapter: target.Name, Role: target.Role, Message: fmt.Sprintf("host mac locked %s via %s", lockedMAC, source)}); err != nil {
					return err
				}
			}
		}
		frame := normalizeObservedPacket(target, packet, lockedMAC, path, capabilities.Mode())
		ordinal := uint64(packetCount + 1)
		result, err := processObservedFrame(engine, capabilities, frame, ordinal, journal)
		if err != nil {
			return errors.Join(fmt.Errorf("evaluate and journal passive policy on %s: %w", target.Name, err), sendEvent(ctx, events, Event{Kind: KindError, Adapter: target.Name, Role: target.Role, Err: err, Path: path}))
		}
		if result.Decision.RuleRevision != "" {
			_ = sendEvent(ctx, events, Event{
				Kind: KindDecision, Adapter: target.Name, Role: target.Role,
				Packet:   string(result.Original.ID),
				Message:  fmt.Sprintf("[%s] %s", result.Decision.Status, result.Decision.Explanation),
				Decision: result.Decision.Summary(),
			})
		}
		packetCount++
		if message := trafficLogMessage(target, packet, packetCount); message != "" {
			_ = sendEvent(ctx, events, Event{
				Kind: KindTraffic, Adapter: target.Name, Role: target.Role,
				Packet: string(result.Original.ID), Message: message,
			})
		}
		_ = sendEvent(ctx, events, Event{
			Kind: KindEvidence, Frame: result.Original, Flow: result.Flow,
			Mode: capabilities.Mode(), Decision: result.Decision.Summary(),
		})
		for _, signal := range inspector.AnalyzePacket(packet) {
			if err := sendEvent(ctx, events, Event{Kind: KindSignal, Adapter: target.Name, Role: target.Role, Message: signal.Encode()}); err != nil {
				return err
			}
		}
		for _, discovery := range AnalyzePacket(packet, ignoreMAC) {
			discovery.Kind = KindDiscovery
			discovery.Adapter = target.Name
			discovery.Role = target.Role
			if err := sendEvent(ctx, events, discovery); err != nil {
				return err
			}
		}
	}
}

func processObservedFrame(engine *policy.Engine, capabilities dataplane.Capabilities, frame traffic.Frame, ordinal uint64, journal *policy.Journal) (policy.Result, error) {
	if engine == nil {
		return policy.Result{}, fmt.Errorf("passive policy engine is unavailable")
	}
	if ordinal == 0 {
		return policy.Result{}, fmt.Errorf("passive capture ordinal is required")
	}
	result := engine.Evaluate(frame, capabilities)
	result.Decision.OriginalCaptureOrdinal = ordinal
	if err := journal.Append(result.Decision); err != nil {
		return result, err
	}
	return result, nil
}

func normalizeObservedPacket(target Target, packet gopacket.Packet, hostMAC net.HardwareAddr, source string, mode dataplane.Mode) traffic.Frame {
	metadata := packet.Metadata().CaptureInfo
	side := traffic.SideHost
	if mode == dataplane.ModeEdgeObserve {
		side = traffic.SideDownstream
	}
	direction := traffic.DirectionUnknown
	if ethernet, ok := packet.Layer(layers.LayerTypeEthernet).(*layers.Ethernet); ok && len(hostMAC) == 6 {
		switch {
		case macEqual(ethernet.SrcMAC, hostMAC):
			direction = traffic.DirectionOutbound
		case macEqual(ethernet.DstMAC, hostMAC):
			direction = traffic.DirectionInbound
		}
	}
	return traffic.Normalize(packet.Data(), traffic.CaptureMetadata{
		Timestamp: metadata.Timestamp, CaptureLength: metadata.CaptureLength,
		OriginalLength: metadata.Length, InterfaceIndex: metadata.InterfaceIndex,
		LinkType: int(layers.LinkTypeEthernet), Source: source,
	}, target.Name, side, direction)
}

// AnalyzePacket extracts assignable values from Layer 2/3 evidence.
func AnalyzePacket(packet gopacket.Packet, ignoreMAC net.HardwareAddr) []Event {
	if packet == nil {
		return nil
	}
	var events []Event
	var eth *layers.Ethernet
	if layer, ok := packet.Layer(layers.LayerTypeEthernet).(*layers.Ethernet); ok {
		eth = layer
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

	if dot1q, ok := packet.Layer(layers.LayerTypeDot1Q).(*layers.Dot1Q); ok {
		if dot1q.VLANIdentifier != 0 {
			events = append(events, discovery("vlan", fmt.Sprintf("%d", dot1q.VLANIdentifier), "802.1Q vlan id", "VLAN-tagged traffic"))
		}
		if dot1q.Type != 0 {
			events = append(events, discovery("vlan_type", ethernetTypeName(dot1q.Type), "inner ether type", "VLAN-tagged traffic"))
		}
	}

	if arp, ok := packet.Layer(layers.LayerTypeARP).(*layers.ARP); ok {
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

	if ipv4, ok := packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4); ok {
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

	if ipv6, ok := packet.Layer(layers.LayerTypeIPv6).(*layers.IPv6); ok {
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

	if dhcp, ok := packet.Layer(layers.LayerTypeDHCPv4).(*layers.DHCPv4); ok {
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

	if eapol, ok := packet.Layer(layers.LayerTypeEAPOL).(*layers.EAPOL); ok {
		events = append(events, discovery("eapol", eapol.Type.String(), "type", "EAPOL / 802.1X"))
		events = append(events, discovery("eapol_type", fmt.Sprintf("%d", eapol.Type), "type number", "EAPOL / 802.1X"))
		events = append(events, discovery("eapol_version", fmt.Sprintf("%d", eapol.Version), "version", "EAPOL / 802.1X"))
	}
	if eth != nil && eth.EthernetType == ethernetTypeMACsec {
		events = append(events, discovery("macsec", "0x88e5", "ether type", "MACsec"))
	}

	if eap, ok := packet.Layer(layers.LayerTypeEAP).(*layers.EAP); ok {
		events = append(events, discovery("eap_code", eapCodeName(eap.Code), "code", "EAPOL / 802.1X"))
		if eap.Type != layers.EAPTypeNone {
			events = append(events, discovery("eap_type", eapTypeName(eap.Type), "method", "EAPOL / 802.1X"))
		}
	}

	deviceMAC := ""
	if eth != nil && validUnicastMAC(eth.SrcMAC) {
		deviceMAC = eth.SrcMAC.String()
	}
	if arp, ok := packet.Layer(layers.LayerTypeARP).(*layers.ARP); ok {
		if candidate := net.HardwareAddr(arp.SourceHwAddress); validUnicastMAC(candidate) {
			deviceMAC = candidate.String()
		}
	}
	if dhcp, ok := packet.Layer(layers.LayerTypeDHCPv4).(*layers.DHCPv4); ok && validUnicastMAC(dhcp.ClientHWAddr) {
		deviceMAC = dhcp.ClientHWAddr.String()
	}
	events = dedupeEvents(events)
	for index := range events {
		events[index].DeviceMAC = deviceMAC
	}
	return events
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
	if packet == nil {
		return nil, ""
	}
	eth, ok := packet.Layer(layers.LayerTypeEthernet).(*layers.Ethernet)
	if !ok || !validSourceMAC(eth.SrcMAC, ignoreMAC) {
		return nil, ""
	}
	return append(net.HardwareAddr(nil), eth.SrcMAC...), sourcePacketName(packet, eth)
}

func trafficLogMessage(target Target, packet gopacket.Packet, count int) string {
	summary, _ := PacketSummary(packet)
	if summary == "" {
		return ""
	}
	return fmt.Sprintf("#%d %s/%s %s", count, target.Role, target.Name, summary)
}

// PacketSummary returns compact display text and a stable traffic key.
func PacketSummary(packet gopacket.Packet) (string, string) {
	if packet == nil {
		return "", ""
	}
	eth, ok := packet.Layer(layers.LayerTypeEthernet).(*layers.Ethernet)
	if !ok {
		return "", ""
	}
	name := sourcePacketName(packet, eth)
	details := []string{shortPacketName(name), shortMAC(eth.SrcMAC) + ">" + shortMAC(eth.DstMAC)}
	keyParts := []string{name, strings.ToLower(eth.SrcMAC.String()), strings.ToLower(eth.DstMAC.String())}
	if vlan, ok := packet.Layer(layers.LayerTypeDot1Q).(*layers.Dot1Q); ok {
		details = append(details, fmt.Sprintf("vlan:%d", vlan.VLANIdentifier))
		keyParts = append(keyParts, fmt.Sprintf("vlan=%d", vlan.VLANIdentifier))
	}
	if eapol, ok := packet.Layer(layers.LayerTypeEAPOL).(*layers.EAPOL); ok {
		details = append(details, "eapol:"+strings.ToLower(eapol.Type.String()))
		keyParts = append(keyParts, "eapol="+eapol.Type.String())
	}
	if eth.EthernetType == ethernetTypeMACsec {
		details = append(details, "ether:0x88e5")
		keyParts = append(keyParts, "macsec=0x88e5")
	}
	if arp, ok := packet.Layer(layers.LayerTypeARP).(*layers.ARP); ok {
		src := net.IP(arp.SourceProtAddress)
		dst := net.IP(arp.DstProtAddress)
		details = append(details, fmt.Sprintf("arp:%s %s>%s", arpOperationName(arp.Operation), src, dst))
		keyParts = append(keyParts, "arp="+arpOperationName(arp.Operation), src.String(), dst.String())
	}
	if ipv4, ok := packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4); ok {
		details = append(details, fmt.Sprintf("%s>%s %s", ipv4.SrcIP, ipv4.DstIP, ipv4.Protocol))
		keyParts = append(keyParts, ipv4.SrcIP.String(), ipv4.DstIP.String(), ipv4.Protocol.String())
	}
	if ipv6, ok := packet.Layer(layers.LayerTypeIPv6).(*layers.IPv6); ok {
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
	return !allZero
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
	case layers.EAPType(4):
		return "md5-challenge"
	case layers.EAPType(5):
		return "otp"
	case layers.EAPType(6):
		return "generic-token-card"
	case layers.EAPType(17):
		return "leap"
	case layers.EAPType(26):
		return "mschapv2"
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

func validateTargets(targets []Target) ([]Target, error) {
	if len(targets) == 0 {
		return nil, fmt.Errorf("no adapter")
	}
	if len(targets) > 2 {
		return nil, fmt.Errorf("at most two adapters may be captured")
	}
	validated := make([]Target, 0, len(targets))
	seen := make(map[string]bool, len(targets))
	for _, target := range targets {
		target.Name = strings.TrimSpace(target.Name)
		target.Role = strings.TrimSpace(target.Role)
		target.LocalMAC = strings.TrimSpace(target.LocalMAC)
		if target.Name == "" {
			return nil, fmt.Errorf("adapter name is required")
		}
		key := strings.ToLower(target.Name)
		if seen[key] {
			return nil, fmt.Errorf("adapter %q is duplicated", target.Name)
		}
		seen[key] = true
		if target.Role == "" {
			return nil, fmt.Errorf("adapter role is required for %s", target.Name)
		}
		if target.LocalMAC != "" {
			mac, err := net.ParseMAC(target.LocalMAC)
			if err != nil || !validUnicastMAC(mac) {
				return nil, fmt.Errorf("local MAC for %s must be a 48-bit unicast address", target.Name)
			}
			target.LocalMAC = mac.String()
		}
		validated = append(validated, target)
	}
	return validated, nil
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

func sendEvent(ctx context.Context, events chan<- Event, event Event) error {
	if event.Kind == KindTraffic || event.Kind == KindEvidence || event.Kind == KindDecision {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case events <- event:
		default:
			// Traffic and decision summaries are explicitly lossy telemetry.
			// The packet capture and in-engine counters remain independent of
			// this bounded TUI channel.
		}
		return nil
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case events <- event:
		return nil
	}
}

func (s *Session) recordResult(err error) {
	if s == nil || err == nil {
		return
	}
	s.resultMu.Lock()
	s.resultErr = errors.Join(s.resultErr, err)
	s.resultMu.Unlock()
}
