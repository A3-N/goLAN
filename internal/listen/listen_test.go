package listen

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golan/internal/dataplane"
	"golan/internal/policy"
	"golan/internal/traffic"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func TestAnalyzePacketHandlesNil(t *testing.T) {
	if events := AnalyzePacket(nil, nil); len(events) != 0 {
		t.Fatalf("events = %+v", events)
	}
	if summary, key := PacketSummary(nil); summary != "" || key != "" {
		t.Fatalf("PacketSummary(nil) = %q, %q", summary, key)
	}
}

func TestValidateTargetsRejectsIncompleteAndDuplicateAdapters(t *testing.T) {
	tests := [][]Target{
		nil,
		{{Name: "", Role: "host"}},
		{{Name: "en11", Role: ""}},
		{{Name: "en11", Role: "host"}, {Name: "EN11", Role: "switch"}},
		{{Name: "en11", Role: "host", LocalMAC: "bad"}},
		{{Name: "en11", Role: "host", LocalMAC: "ff:ff:ff:ff:ff:ff"}},
		{{Name: "en11", Role: "host"}, {Name: "en12", Role: "switch"}, {Name: "en13", Role: "extra"}},
	}
	for _, targets := range tests {
		if _, err := validateTargets(targets); err == nil {
			t.Errorf("validateTargets(%+v) succeeded", targets)
		}
	}
}

func TestValidateTargetsCanonicalizesLocalMAC(t *testing.T) {
	targets, err := validateTargets([]Target{{Name: " en11 ", Role: " host ", LocalMAC: "02-00-00-00-00-11"}})
	if err != nil {
		t.Fatalf("validateTargets: %v", err)
	}
	if len(targets) != 1 || targets[0].Name != "en11" || targets[0].Role != "host" || targets[0].LocalMAC != "02:00:00:00:00:11" {
		t.Fatalf("targets = %+v", targets)
	}
}

func TestSendEventDropsOnlyBoundedTelemetry(t *testing.T) {
	events := make(chan Event, 1)
	events <- Event{Kind: KindLog}

	if err := sendEvent(context.Background(), events, Event{Kind: KindTraffic}); err != nil {
		t.Fatalf("traffic send: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("traffic event was queued despite backpressure: %d", len(events))
	}
	if err := sendEvent(context.Background(), events, Event{Kind: KindEvidence}); err != nil {
		t.Fatalf("evidence send: %v", err)
	}
	if err := sendEvent(context.Background(), events, Event{Kind: KindDecision}); err != nil {
		t.Fatalf("decision send: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := sendEvent(ctx, events, Event{Kind: KindSignal}); !errors.Is(err, context.Canceled) {
		t.Fatalf("critical send error = %v", err)
	}
}

func TestObservedPacketUsesSharedShadowPolicy(t *testing.T) {
	sourceMAC := mac(t, "02:00:00:00:00:11")
	packet := decode(ethernet(sourceMAC, mac(t, "02:00:00:00:00:22"), 0x88b5, make([]byte, 46)))
	packet.Metadata().CaptureInfo = gopacket.CaptureInfo{Timestamp: time.Unix(10, 20).UTC(), CaptureLength: len(packet.Data()), Length: len(packet.Data())}
	frame := normalizeObservedPacket(Target{Name: "en7", Role: "host"}, packet, sourceMAC, "capture.pcap", dataplane.ModeListen)
	if frame.Side != traffic.SideHost || frame.Direction != traffic.DirectionOutbound {
		t.Fatalf("normalized side=%s direction=%s", frame.Side, frame.Direction)
	}
	engine := policy.NewEngine(8)
	if err := engine.Policies.Activate("listen-test", []policy.Rule{{
		ID: "block-outbound", Enabled: true,
		Match:   policy.Match{Directions: []traffic.Direction{traffic.DirectionOutbound}},
		Actions: []policy.Action{{Kind: policy.ActionBlock}},
	}}); err != nil {
		t.Fatal(err)
	}
	result, err := engine.Process(frame, dataplane.ForMode(dataplane.ModeListen))
	if err != nil {
		t.Fatal(err)
	}
	if result.Decision.Status != dataplane.StatusShadow || result.Decision.EffectiveVerdict != policy.VerdictAllow || result.Decision.Verdict != policy.VerdictBlock {
		t.Fatalf("decision = %#v", result.Decision)
	}
}

func TestObservedFrameJournalsExactCaptureOrdinal(t *testing.T) {
	packet := decode(ethernet(
		mac(t, "02:00:00:00:00:11"),
		mac(t, "02:00:00:00:00:22"),
		0x88b5,
		make([]byte, 46),
	))
	packet.Metadata().CaptureInfo = gopacket.CaptureInfo{
		Timestamp:     time.Unix(10, 20).UTC(),
		CaptureLength: len(packet.Data()),
		Length:        len(packet.Data()),
	}
	frame := normalizeObservedPacket(
		Target{Name: "en7", Role: "host"},
		packet,
		nil,
		"host-en7.pcap",
		dataplane.ModeListen,
	)
	path := filepath.Join(t.TempDir(), "host-en7.decisions.jsonl")
	journal, err := policy.OpenJournal(path)
	if err != nil {
		t.Fatal(err)
	}
	result, err := processObservedFrame(
		policy.NewEngine(8),
		dataplane.ForMode(dataplane.ModeListen),
		frame,
		7,
		journal,
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := journal.Close(); err != nil {
		t.Fatal(err)
	}
	if result.Decision.OriginalCaptureOrdinal != 7 ||
		result.Decision.DataPlane != dataplane.ModeListen ||
		result.Decision.EvidenceKind != traffic.EvidencePacket {
		t.Fatalf("decision = %#v", result.Decision)
	}
	input, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer input.Close()
	var decoded policy.Decision
	summary, err := policy.DecodeJournal(
		context.Background(),
		input,
		policy.JournalReadOptions{},
		func(decision policy.Decision) error {
			decoded = decision
			return nil
		},
	)
	if err != nil || summary.Records != 1 || !summary.Complete {
		t.Fatalf("journal summary = %#v, err=%v", summary, err)
	}
	if decoded.PacketID != frame.ID ||
		decoded.OriginalCaptureOrdinal != 7 ||
		decoded.ForwardedPacketID != "" ||
		len(decoded.ForwardedCaptureOrdinals) != 0 {
		t.Fatalf("decoded decision = %#v", decoded)
	}
}

func TestObservedFrameKeepsTransformationsInShadow(t *testing.T) {
	packet := decode(ethernet(
		mac(t, "02:00:00:00:00:11"),
		mac(t, "02:00:00:00:00:22"),
		0x88b5,
		make([]byte, 46),
	))
	packet.Metadata().CaptureInfo = gopacket.CaptureInfo{
		Timestamp:     time.Unix(11, 0).UTC(),
		CaptureLength: len(packet.Data()),
		Length:        len(packet.Data()),
	}
	frame := normalizeObservedPacket(
		Target{Name: "en7", Role: "host"}, packet, nil,
		"host-en7.pcap", dataplane.ModeListen,
	)
	engine := policy.NewEngine(8)
	if err := engine.Policies.Activate("shadow-transform", []policy.Rule{{
		ID: "rewrite-source", Enabled: true,
		Transformations: []policy.Transformation{{
			Kind: policy.TransformField, Field: traffic.FieldSrcMAC,
			Replace: "02:00:00:00:00:33",
		}},
	}}); err != nil {
		t.Fatal(err)
	}
	journal, err := policy.OpenJournal(filepath.Join(t.TempDir(), "shadow.decisions.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	result, err := processObservedFrame(
		engine, dataplane.ForMode(dataplane.ModeListen), frame, 1, journal,
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := journal.Close(); err != nil {
		t.Fatal(err)
	}
	if result.Decision.Status != dataplane.StatusShadow ||
		result.Decision.EffectiveVerdict != policy.VerdictAllow ||
		result.Decision.ForwardedPacketID != "" ||
		result.Forwarded.ID != frame.ID {
		t.Fatalf("shadow result = %#v", result)
	}
}

func TestSessionSetPolicyAtomicallyChangesShadowRevision(t *testing.T) {
	session := &Session{Engine: policy.NewEngine(8)}
	if err := session.SetPolicy("allow", []policy.Rule{{ID: "allow", Enabled: true, Actions: []policy.Action{{Kind: policy.ActionAllow}}}}); err != nil {
		t.Fatal(err)
	}
	if err := session.SetPolicy("invalid", []policy.Rule{{ID: "bad", Enabled: true, Match: policy.Match{Payload: []policy.BytePattern{{Kind: policy.PatternRE2, Value: "("}}}}}); err == nil {
		t.Fatal("invalid policy activated")
	}
	active, ok := session.Engine.Policies.Active()
	if !ok || active.Revision() != "allow" {
		t.Fatalf("active revision = %q, %v", active.Revision(), ok)
	}
}

func TestStopReturnsCaptureResult(t *testing.T) {
	want := errors.New("pcap close failed")
	done := make(chan struct{})
	close(done)
	session := &Session{done: done, resultErr: want}

	if err := session.Stop(); !errors.Is(err, want) {
		t.Fatalf("Stop error = %v", err)
	}
}

func TestStoppedReportsFinalizerCompletion(t *testing.T) {
	done := make(chan struct{})
	session := &Session{done: done}
	if session.Stopped() {
		t.Fatal("open session reported stopped")
	}
	close(done)
	if !session.Stopped() {
		t.Fatal("completed session did not report stopped")
	}
}

func TestAnalyzePacketDiscoversIPv4AndIgnoresLocalMAC(t *testing.T) {
	src := mac(t, "02:00:00:00:00:11")
	packet := decode(ethernet(src, mac(t, "02:00:00:00:00:22"), 0x0800, ipv4(17, net.IPv4(192, 0, 2, 10), net.IPv4(192, 0, 2, 1), nil)))

	events := AnalyzePacket(packet, nil)
	if !hasEvent(events, "mac", src.String(), "IPv4") {
		t.Fatalf("missing IPv4 source mac event: %+v", events)
	}
	if !hasEvent(events, "ether_src", src.String(), "IPv4") {
		t.Fatalf("missing Ethernet source observation: %+v", events)
	}
	if !hasEvent(events, "ether_dst", "02:00:00:00:00:22", "IPv4") {
		t.Fatalf("missing Ethernet destination observation: %+v", events)
	}
	if !hasEvent(events, "ether_type", "0x0800 IPv4", "IPv4") {
		t.Fatalf("missing EtherType observation: %+v", events)
	}
	if !hasEvent(events, "ip", "192.0.2.10", "IPv4") {
		t.Fatalf("missing IPv4 source IP event: %+v", events)
	}
	if !hasEvent(events, "ipv4_dst", "192.0.2.1", "IPv4") {
		t.Fatalf("missing IPv4 destination observation: %+v", events)
	}

	events = AnalyzePacket(packet, src)
	if hasFieldValue(events, "mac", src.String()) {
		t.Fatalf("local adapter mac was not ignored: %+v", events)
	}
	if !hasEvent(events, "ip", "192.0.2.10", "IPv4") {
		t.Fatalf("local mac ignore should not suppress IP evidence: %+v", events)
	}
}

func TestAnalyzePacketDiscoversARP(t *testing.T) {
	src := mac(t, "02:00:00:00:00:33")
	payload := arpRequest(src, net.IPv4(192, 0, 2, 20), net.IPv4(192, 0, 2, 1))
	events := AnalyzePacket(decode(ethernet(src, mac(t, "ff:ff:ff:ff:ff:ff"), 0x0806, payload)), nil)

	if !hasEvent(events, "mac", src.String(), "ARP") {
		t.Fatalf("missing ARP mac event: %+v", events)
	}
	if !hasEvent(events, "ip", "192.0.2.20", "ARP") {
		t.Fatalf("missing ARP sender IP event: %+v", events)
	}
	if !hasEvent(events, "arp_tell", "192.0.2.20", "ARP") {
		t.Fatalf("missing ARP tell observation: %+v", events)
	}
	if !hasEvent(events, "arp_op", "request", "ARP") {
		t.Fatalf("missing ARP operation observation: %+v", events)
	}
	if !hasEvent(events, "arp_who_has", "192.0.2.1", "ARP") {
		t.Fatalf("missing ARP who-has observation: %+v", events)
	}
	if hasFieldValue(events, "gateway", "192.0.2.1") {
		t.Fatalf("ARP who-has target was treated as gateway: %+v", events)
	}
}

func TestAnalyzePacketObservesLinkLocalWithoutAssigningIP(t *testing.T) {
	src := mac(t, "02:00:00:00:00:34")
	payload := arpRequest(src, net.IPv4(169, 254, 10, 20), net.IPv4(169, 254, 10, 1))
	events := AnalyzePacket(decode(ethernet(src, mac(t, "ff:ff:ff:ff:ff:ff"), 0x0806, payload)), nil)

	if !hasEvent(events, "arp_sender_ip", "169.254.10.20", "ARP") {
		t.Fatalf("missing link-local ARP sender observation: %+v", events)
	}
	if !hasEvent(events, "arp_who_has", "169.254.10.1", "ARP") {
		t.Fatalf("missing link-local ARP target observation: %+v", events)
	}
	if hasFieldValue(events, "ip", "169.254.10.20") {
		t.Fatalf("link-local address was treated as assignable host IP: %+v", events)
	}
}

func TestAnalyzePacketDiscoversVLANAndEAPOL(t *testing.T) {
	src := mac(t, "02:00:00:00:00:44")
	inner := ipv4(6, net.IPv4(198, 51, 100, 5), net.IPv4(198, 51, 100, 1), nil)
	vlanPayload := append([]byte{0x00, 0x2a, 0x08, 0x00}, inner...)
	vlanEvents := AnalyzePacket(decode(ethernet(src, mac(t, "02:00:00:00:00:55"), 0x8100, vlanPayload)), nil)
	if !hasEvent(vlanEvents, "mac", src.String(), "VLAN-tagged traffic") {
		t.Fatalf("missing VLAN source mac event: %+v", vlanEvents)
	}
	if !hasEvent(vlanEvents, "vlan", "42", "VLAN-tagged traffic") {
		t.Fatalf("missing VLAN id event: %+v", vlanEvents)
	}

	eapolEvents := AnalyzePacket(decode(ethernet(src, mac(t, "01:80:c2:00:00:03"), 0x888e, []byte{0x01, 0x00, 0x00, 0x00})), nil)
	if !hasEvent(eapolEvents, "mac", src.String(), "EAPOL / 802.1X") {
		t.Fatalf("missing EAPOL source mac event: %+v", eapolEvents)
	}
	if !hasEvent(eapolEvents, "eapol", "EAP", "EAPOL / 802.1X") {
		t.Fatalf("missing EAPOL type observation: %+v", eapolEvents)
	}
	if !hasEvent(eapolEvents, "eapol_type", "0", "EAPOL / 802.1X") {
		t.Fatalf("missing EAPOL numeric type observation: %+v", eapolEvents)
	}

	macsecPacket := decode(ethernet(src, mac(t, "02:00:00:00:00:56"), 0x88e5, []byte{0, 1, 2, 3, 4}))
	macsecEvents := AnalyzePacket(macsecPacket, nil)
	if !hasEvent(macsecEvents, "macsec", "0x88e5", "MACsec") {
		t.Fatalf("missing MACsec observation: %+v", macsecEvents)
	}
	summary, _ := PacketSummary(macsecPacket)
	if !strings.Contains(summary, "MACSEC") || !strings.Contains(summary, "ether:0x88e5") {
		t.Fatalf("MACsec summary = %q", summary)
	}
}

func TestAnalyzePacketDiscoversDHCPOptions(t *testing.T) {
	src := mac(t, "02:00:00:00:00:66")
	dhcp := dhcpPayload(src, net.IPv4(192, 0, 2, 30), net.IPv4(192, 0, 2, 31), net.IPv4(192, 0, 2, 1), net.IPv4(192, 0, 2, 53))
	udp := udpDatagram(68, 67, dhcp)
	ip := ipv4(17, net.IPv4(0, 0, 0, 0), net.IPv4(255, 255, 255, 255), udp)
	events := AnalyzePacket(decode(ethernet(src, mac(t, "ff:ff:ff:ff:ff:ff"), 0x0800, ip)), nil)

	if !hasEvent(events, "mac", src.String(), "DHCP") {
		t.Fatalf("missing DHCP mac event: %+v", events)
	}
	if !hasEvent(events, "ip", "192.0.2.30", "DHCP") || !hasEvent(events, "ip", "192.0.2.31", "DHCP") {
		t.Fatalf("missing DHCP IP events: %+v", events)
	}
	if !hasEvent(events, "gateway", "192.0.2.1", "DHCP") {
		t.Fatalf("missing DHCP router event: %+v", events)
	}
	if !hasEvent(events, "dns", "192.0.2.53", "DHCP") {
		t.Fatalf("missing DHCP DNS event: %+v", events)
	}
	if !hasEvent(events, "dhcp_message", "Request", "DHCP") ||
		!hasEvent(events, "dhcp_server", "192.0.2.2", "DHCP") ||
		!hasEvent(events, "dhcp_hostname", "client-30", "DHCP") {
		t.Fatalf("missing readable DHCP identity events: %+v", events)
	}
}

func TestAnalyzePacketDiscoversLLDPAndSTPRoot(t *testing.T) {
	src := mac(t, "02:00:00:00:00:77")
	lldpPayload := appendLLDPTLV(nil, 1, append([]byte{4}, src...))
	lldpPayload = appendLLDPTLV(lldpPayload, 2, append([]byte{5}, []byte("en7")...))
	lldpPayload = appendLLDPTLV(lldpPayload, 3, []byte{0, 120})
	lldpPayload = appendLLDPTLV(lldpPayload, 5, []byte("access-switch"))
	lldpPayload = appendLLDPTLV(lldpPayload, 0, nil)
	events := AnalyzePacket(decode(ethernet(src, mac(t, "01:80:c2:00:00:0e"), 0x88cc, lldpPayload)), nil)
	if !hasEvent(events, "lldp_chassis", src.String(), "LLDP") ||
		!hasEvent(events, "lldp_port", "en7", "LLDP") ||
		!hasEvent(events, "lldp_system_name", "access-switch", "LLDP") {
		t.Fatalf("missing LLDP infrastructure events: %+v", events)
	}

	rootMAC := mac(t, "02:00:00:00:00:01")
	bpdu := make([]byte, 35)
	binary.BigEndian.PutUint16(bpdu[5:7], 0x8000)
	copy(bpdu[7:13], rootMAC)
	llcBPDU := append([]byte{0x42, 0x42, 0x03}, bpdu...)
	events = AnalyzePacket(decode(ethernet(src, mac(t, "01:80:c2:00:00:00"), uint16(len(llcBPDU)), llcBPDU)), nil)
	if !hasEvent(events, "stp_root", "8000/"+rootMAC.String(), "STP") {
		t.Fatalf("missing STP root event: %+v", events)
	}
}

func decode(data []byte) gopacket.Packet {
	return gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.Default)
}

func mac(t *testing.T, value string) net.HardwareAddr {
	t.Helper()
	out, err := net.ParseMAC(value)
	if err != nil {
		t.Fatalf("ParseMAC(%q): %v", value, err)
	}
	return out
}

func ethernet(src, dst net.HardwareAddr, etherType uint16, payload []byte) []byte {
	out := make([]byte, 14+len(payload))
	copy(out[0:6], dst)
	copy(out[6:12], src)
	out[12] = byte(etherType >> 8)
	out[13] = byte(etherType)
	copy(out[14:], payload)
	return out
}

func ipv4(protocol byte, src, dst net.IP, payload []byte) []byte {
	totalLen := 20 + len(payload)
	out := make([]byte, totalLen)
	out[0] = 0x45
	out[2] = byte(totalLen >> 8)
	out[3] = byte(totalLen)
	out[8] = 64
	out[9] = protocol
	copy(out[12:16], src.To4())
	copy(out[16:20], dst.To4())
	copy(out[20:], payload)
	return out
}

func udpDatagram(srcPort, dstPort uint16, payload []byte) []byte {
	length := 8 + len(payload)
	out := make([]byte, length)
	out[0] = byte(srcPort >> 8)
	out[1] = byte(srcPort)
	out[2] = byte(dstPort >> 8)
	out[3] = byte(dstPort)
	out[4] = byte(length >> 8)
	out[5] = byte(length)
	copy(out[8:], payload)
	return out
}

func arpRequest(src net.HardwareAddr, sourceIP, targetIP net.IP) []byte {
	out := make([]byte, 28)
	out[1] = 1
	out[2] = 0x08
	out[4] = 6
	out[5] = 4
	out[7] = 1
	copy(out[8:14], src)
	copy(out[14:18], sourceIP.To4())
	copy(out[24:28], targetIP.To4())
	return out
}

func dhcpPayload(clientMAC net.HardwareAddr, clientIP, yourIP, routerIP, dnsIP net.IP) []byte {
	out := make([]byte, 240)
	out[0] = 1
	out[1] = 1
	out[2] = 6
	copy(out[12:16], clientIP.To4())
	copy(out[16:20], yourIP.To4())
	copy(out[28:34], clientMAC)
	copy(out[236:240], []byte{99, 130, 83, 99})
	out = append(out, 3, 4)
	out = append(out, routerIP.To4()...)
	out = append(out, 6, 4)
	out = append(out, dnsIP.To4()...)
	out = append(out, 53, 1, 3)
	out = append(out, 54, 4, 192, 0, 2, 2)
	out = append(out, 12, 9)
	out = append(out, []byte("client-30")...)
	out = append(out, 255)
	return out
}

func appendLLDPTLV(destination []byte, kind uint16, value []byte) []byte {
	header := uint16(kind<<9) | uint16(len(value))
	destination = append(destination, byte(header>>8), byte(header))
	return append(destination, value...)
}

func hasEvent(events []Event, field, value, packet string) bool {
	for _, event := range events {
		if event.Field == field && event.Value == value && event.Packet == packet {
			return true
		}
	}
	return false
}

func hasFieldValue(events []Event, field, value string) bool {
	for _, event := range events {
		if event.Field == field && event.Value == value {
			return true
		}
	}
	return false
}
