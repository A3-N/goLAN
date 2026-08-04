package network

import (
	"encoding/json"
	"net"
	"strings"
	"testing"
	"time"

	"golan/internal/dataplane"
	"golan/internal/policy"
	"golan/internal/traffic"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func TestTrackerKeepsUsefulReadableObservationsWithoutPacketHistory(t *testing.T) {
	started := time.Unix(10, 0).UTC()
	tracker := NewTracker("session-1", "listen", started)
	dns := normalizedUDPFrame(t, started.Add(time.Second), 53, &layers.DNS{
		ID: 7, Questions: []layers.DNSQuestion{{
			Name: []byte("Example.Test"), Type: layers.DNSTypeA, Class: layers.DNSClassIN,
		}},
	})
	if !tracker.ObserveFrame(dns, "host", policy.DecisionSummary{}) {
		t.Fatal("DNS observation did not update the device inventory")
	}
	dnsAgain := normalizedUDPFrame(t, started.Add(1200*time.Millisecond), 53, &layers.DNS{
		ID: 7, Questions: []layers.DNSQuestion{{
			Name: []byte("Example.Test"), Type: layers.DNSTypeA, Class: layers.DNSClassIN,
		}},
	})
	if !tracker.ObserveFrame(dnsAgain, "host", policy.DecisionSummary{}) {
		t.Fatal("DNS observation did not update the device inventory")
	}
	dnsResponse := normalizedUDPFrame(t, started.Add(1500*time.Millisecond), 53, &layers.DNS{
		ID: 7, QR: true, Questions: []layers.DNSQuestion{{
			Name: []byte("Example.Test"), Type: layers.DNSTypeA, Class: layers.DNSClassIN,
		}},
	})
	tracker.ObserveFrame(dnsResponse, "host", policy.DecisionSummary{})
	http := normalizedTCPFrame(t, started.Add(2*time.Second), 80,
		[]byte("GET /login?token=private-secret HTTP/1.1\r\nHost: Example.Test\r\n\r\n"))
	tracker.ObserveFrame(http, "host", policy.DecisionSummary{})
	tls := normalizedTCPFrame(t, started.Add(3*time.Second), 443,
		[]byte("\x16\x03\x03private-tls-record"))
	tracker.ObserveFrame(tls, "host", policy.DecisionSummary{})

	session := tracker.Snapshot()
	if len(session.Devices) != 1 {
		t.Fatalf("devices=%#v", session.Devices)
	}
	device := session.Devices[0]
	if device.Key != "en0/02:00:00:00:00:01" || len(device.Observations) != 2 {
		t.Fatalf("device=%#v", device)
	}
	var dnsObservation, httpObservation Observation
	for _, observation := range device.Observations {
		switch observation.Category {
		case CategoryDNS:
			dnsObservation = observation
		case CategoryHTTP:
			httpObservation = observation
		}
	}
	if dnsObservation.Count != 2 || dnsObservation.Summary != "DNS A example.test" {
		t.Fatalf("DNS observation=%#v", dnsObservation)
	}
	if httpObservation.Summary != "HTTP GET example.test/login" {
		t.Fatalf("HTTP observation=%#v", httpObservation)
	}
	encoded, err := json.Marshal(session)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"private-secret", "private-tls-record", "HTTPS", "TCP"} {
		if strings.Contains(string(encoded), forbidden) {
			t.Fatalf("sanitized session retained %q: %s", forbidden, encoded)
		}
	}
}

func TestTrackerRecordsCategoricalRisksDiscoveryAndNotableActions(t *testing.T) {
	tracker := NewTracker("session-2", "controlled-bridge", time.Unix(20, 0))
	if !tracker.ObserveDiscovery(Discovery{
		Adapter: "en7", Role: "host", DeviceMAC: "02:00:00:00:00:01",
		Field: "ip", Value: "192.0.2.7", Packet: "DHCP",
	}) {
		t.Fatal("address discovery was ignored")
	}
	if !tracker.ObserveRisk(Risk{
		Adapter: "en7", Role: "host", DeviceMAC: "02:00:00:00:00:01",
		Protocol: "NTLM", Kind: "authentication",
	}) {
		t.Fatal("categorical risk was ignored")
	}
	frame := normalizedTCPFrame(t, time.Unix(22, 0), 80, []byte("opaque"))
	frame = traffic.Normalize(frame.RawBytes(), frame.Capture, "en7", traffic.SideHost, traffic.DirectionHostToSwitch)
	if !tracker.ObserveFrame(frame, "host", policy.DecisionSummary{
		Status: dataplane.StatusLive, EffectiveVerdict: policy.VerdictBlock, WinningRuleID: "deny-web",
	}) {
		t.Fatal("notable policy action did not update the inventory")
	}

	snapshot := tracker.Snapshot()
	if len(snapshot.Devices) != 1 {
		t.Fatalf("devices=%#v", snapshot.Devices)
	}
	device := snapshot.Devices[0]
	if len(device.IPs) != 2 || device.IPs[0] != "192.0.2.10" || device.IPs[1] != "192.0.2.7" {
		t.Fatalf("addresses=%v", device.IPs)
	}
	categories := make(map[Category]bool)
	for _, observation := range device.Observations {
		categories[observation.Category] = true
	}
	for _, category := range []Category{CategoryAddressing, CategoryRisk, CategoryAction} {
		if !categories[category] {
			t.Fatalf("category %q missing from %#v", category, device.Observations)
		}
	}
	content, err := json.Marshal(device)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"username", "password", "credential", "hash"} {
		if strings.Contains(strings.ToLower(string(content)), forbidden) {
			t.Fatalf("risk inventory retained sensitive field %q: %s", forbidden, content)
		}
	}
}

func TestSessionDecodeIsStrictAndCapturePathsAreDeduplicated(t *testing.T) {
	tracker := NewTracker("strict", "edge-observe", time.Unix(30, 0))
	tracker.ObserveDiscovery(Discovery{
		Adapter: "en1", Role: "downstream", DeviceMAC: "02:00:00:00:00:01",
		Field: "vlan", Value: "23", Packet: "802.1Q",
	})
	tracker.AddCapture(" /tmp/session/original.pcap ")
	tracker.AddCapture("/tmp/session/original.pcap")
	tracker.Finish(time.Unix(40, 0))
	session := tracker.Snapshot()
	content, err := json.Marshal(session)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeSession(content)
	if err != nil {
		t.Fatal(err)
	}
	if len(decoded.CapturePaths) != 1 || decoded.CapturePaths[0] != "/tmp/session/original.pcap" {
		t.Fatalf("capture paths=%v", decoded.CapturePaths)
	}
	withUnknown := append(content[:len(content)-1], []byte(`,"packet_payload":"private"}`)...)
	if _, err := DecodeSession(withUnknown); err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("strict decode err=%v", err)
	}
}

func TestTrackerKeepsStableDiscoveryNumbersWhenOlderDeviceIsActive(t *testing.T) {
	session := Session{
		Version: CurrentVersion, ID: "stable-order", Mode: "listen", StartedAt: time.Unix(1, 0),
		Devices: []Device{
			{Key: "en0/02:00:00:00:00:01", MAC: "02:00:00:00:00:01", Adapter: "en0", FirstSeen: time.Unix(2, 0), LastSeen: time.Unix(2, 0)},
			{Key: "en0/02:00:00:00:00:02", MAC: "02:00:00:00:00:02", Adapter: "en0", FirstSeen: time.Unix(3, 0), LastSeen: time.Unix(3, 0)},
		},
	}
	tracker := LoadTracker(session)
	assertDeviceOrder(t, tracker.Snapshot().Devices,
		[]string{"en0/02:00:00:00:00:02", "en0/02:00:00:00:00:01"},
		[]uint64{2, 1},
	)

	activeOlderDevice := normalizedTCPFrame(t, time.Unix(20, 0), 1234, nil)
	if !tracker.ObserveFrame(activeOlderDevice, "host", policy.DecisionSummary{}) {
		t.Fatal("activity did not update the older device")
	}
	afterActivity := tracker.Snapshot()
	assertDeviceOrder(t, afterActivity.Devices,
		[]string{"en0/02:00:00:00:00:02", "en0/02:00:00:00:00:01"},
		[]uint64{2, 1},
	)
	if !afterActivity.Devices[1].LastSeen.Equal(time.Unix(20, 0)) {
		t.Fatalf("stable row did not receive its live update: last_seen=%s", afterActivity.Devices[1].LastSeen)
	}

	tracker.ObserveDiscovery(Discovery{
		Adapter: "en0", Role: "host", DeviceMAC: "02:00:00:00:00:03",
		Field: "ip", Value: "192.0.2.30", Packet: "DHCP",
	})
	latest := tracker.Snapshot()
	assertDeviceOrder(t, latest.Devices,
		[]string{"en0/02:00:00:00:00:03", "en0/02:00:00:00:00:02", "en0/02:00:00:00:00:01"},
		[]uint64{3, 2, 1},
	)

	content, err := json.Marshal(latest)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(content), `"number"`) {
		t.Fatalf("UI discovery number entered persisted evidence: %s", content)
	}
	decoded, err := DecodeSession(content)
	if err != nil {
		t.Fatal(err)
	}
	assertDeviceOrder(t, LoadTracker(decoded).Snapshot().Devices,
		[]string{"en0/02:00:00:00:00:03", "en0/02:00:00:00:00:02", "en0/02:00:00:00:00:01"},
		[]uint64{3, 2, 1},
	)
}

func TestTrackerBuildsServiceAccessAndPacketFateSummaries(t *testing.T) {
	started := time.Unix(50, 0).UTC()
	tracker := NewTracker("intelligence", "controlled-bridge", started)
	mdns := normalizedUDPPortsFrame(t, started.Add(time.Second), 5353, 5353, &layers.DNS{
		ID: 9, QR: true,
		Answers: []layers.DNSResourceRecord{{
			Name: []byte("_ssh._tcp.local"), Type: layers.DNSTypePTR, Class: layers.DNSClassIN,
			PTR: []byte("workstation._ssh._tcp.local"),
		}},
		Additionals: []layers.DNSResourceRecord{{
			Name: []byte("workstation._ssh._tcp.local"), Type: layers.DNSTypeSRV, Class: layers.DNSClassIN,
			SRV: layers.DNSSRV{Port: 22, Name: []byte("workstation.local")},
		}},
	})
	tracker.ObserveFrame(mdns, "host", policy.DecisionSummary{})
	ssdp := normalizedUDPPortsFrame(t, started.Add(1500*time.Millisecond), 1900, 49152, gopacket.Payload(
		[]byte("HTTP/1.1 200 OK\r\nST: urn:schemas-upnp-org:device:MediaServer:1\r\nServer: Test Device\r\nLocation: http://192.0.2.10/device.xml?token=private#fragment\r\n\r\n"),
	))
	tracker.ObserveFrame(ssdp, "host", policy.DecisionSummary{})
	blocked := normalizedTCPFrame(t, started.Add(2*time.Second), 80, nil)
	tracker.ObserveFrame(blocked, "host", policy.DecisionSummary{
		Status: dataplane.StatusLive, EffectiveVerdict: policy.VerdictBlock, WinningRuleID: "deny-web",
	})
	unresolved := normalizedTCPFrame(t, started.Add(3*time.Second), 443, nil)
	tracker.ObserveFrame(unresolved, "host", policy.DecisionSummary{Status: dataplane.StatusLive})
	shadow := normalizedTCPFrame(t, started.Add(4*time.Second), 22, nil)
	tracker.ObserveFrame(shadow, "host", policy.DecisionSummary{
		Status: dataplane.StatusShadow, Verdict: policy.VerdictBlock, EffectiveVerdict: policy.VerdictAllow, WinningRuleID: "shadow-deny-ssh",
	})
	tracker.ObserveDiscovery(Discovery{
		Adapter: "en0", Role: "host", DeviceMAC: "02:00:00:00:00:01", Field: "eapol", Value: "Start", Packet: "EAPOL",
	})
	tracker.ObserveDiscovery(Discovery{
		Adapter: "en0", Role: "host", DeviceMAC: "02:00:00:00:00:01", Field: "eap_code", Value: "Failure", Packet: "EAPOL",
	})

	session := tracker.Snapshot()
	device, ok := FindDevice(session, "02:00:00:00:00:01")
	if !ok || len(device.Services) == 0 {
		t.Fatalf("device=%#v", device)
	}
	service := device.Services[0]
	if service.Type != "_ssh._tcp" || service.Port != 22 || service.Target != "workstation.local" || service.Protocol != "MDNS" || service.Count != 2 {
		t.Fatalf("service=%#v", service)
	}
	var sawSSDP bool
	for _, candidate := range device.Services {
		if candidate.Protocol == "SSDP" && candidate.Name == "Test Device" && candidate.Target == "http://192.0.2.10/device.xml" {
			sawSSDP = true
		}
	}
	if !sawSSDP {
		t.Fatalf("SSDP service missing or unsafe: %#v", device.Services)
	}
	story := BuildAccessStory(device)
	if story.Result != "failure" || story.Attempts != 1 || len(story.Events) != 2 {
		t.Fatalf("story=%#v", story)
	}
	fates := PacketFatesForDevice(session, device)
	if len(fates) != 2 {
		t.Fatalf("fates=%#v", fates)
	}
	var sawBlocked, sawUnresolved bool
	for _, fate := range fates {
		if fateHasPort(fate, 80) && fate.Blocked == 1 && fate.Confidence == FateExact {
			sawBlocked = true
		}
		if fateHasPort(fate, 443) && fate.Unresolved == 1 && fate.Confidence == FateObserved {
			sawUnresolved = true
		}
	}
	if !sawBlocked || !sawUnresolved {
		t.Fatalf("fates=%#v", fates)
	}
}

func fateHasPort(fate PacketFate, port uint16) bool {
	return fate.EndpointA.Port == port || fate.EndpointB.Port == port
}

func assertDeviceOrder(t *testing.T, devices []Device, keys []string, numbers []uint64) {
	t.Helper()
	if len(devices) != len(keys) || len(keys) != len(numbers) {
		t.Fatalf("devices=%d keys=%d numbers=%d", len(devices), len(keys), len(numbers))
	}
	for index, device := range devices {
		if device.Key != keys[index] || device.Number != numbers[index] {
			t.Fatalf("device[%d]=%s #%d, want %s #%d", index, device.Key, device.Number, keys[index], numbers[index])
		}
	}
}

func normalizedTCPFrame(t *testing.T, timestamp time.Time, destinationPort uint16, payload []byte) traffic.Frame {
	t.Helper()
	ethernet := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0x02, 0, 0, 0, 0, 1},
		DstMAC:       net.HardwareAddr{0x02, 0, 0, 0, 0, 2},
		EthernetType: layers.EthernetTypeIPv4,
	}
	ipv4 := &layers.IPv4{Version: 4, IHL: 5, TTL: 64, Protocol: layers.IPProtocolTCP,
		SrcIP: net.IP{192, 0, 2, 10}, DstIP: net.IP{198, 51, 100, 20}}
	tcp := &layers.TCP{SrcPort: 49152, DstPort: layers.TCPPort(destinationPort), SYN: true}
	if err := tcp.SetNetworkLayerForChecksum(ipv4); err != nil {
		t.Fatal(err)
	}
	buffer := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true},
		ethernet, ipv4, tcp, gopacket.Payload(payload)); err != nil {
		t.Fatal(err)
	}
	return traffic.Normalize(buffer.Bytes(), traffic.CaptureMetadata{Timestamp: timestamp}, "en0", traffic.SideHost, traffic.DirectionHostToSwitch)
}

func normalizedUDPFrame(t *testing.T, timestamp time.Time, destinationPort uint16, payload gopacket.SerializableLayer) traffic.Frame {
	return normalizedUDPPortsFrame(t, timestamp, 49152, destinationPort, payload)
}

func normalizedUDPPortsFrame(t *testing.T, timestamp time.Time, sourcePort, destinationPort uint16, payload gopacket.SerializableLayer) traffic.Frame {
	t.Helper()
	ethernet := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0x02, 0, 0, 0, 0, 1},
		DstMAC:       net.HardwareAddr{0x02, 0, 0, 0, 0, 2},
		EthernetType: layers.EthernetTypeIPv4,
	}
	ipv4 := &layers.IPv4{Version: 4, IHL: 5, TTL: 64, Protocol: layers.IPProtocolUDP,
		SrcIP: net.IP{192, 0, 2, 10}, DstIP: net.IP{198, 51, 100, 53}}
	udp := &layers.UDP{SrcPort: layers.UDPPort(sourcePort), DstPort: layers.UDPPort(destinationPort)}
	if err := udp.SetNetworkLayerForChecksum(ipv4); err != nil {
		t.Fatal(err)
	}
	buffer := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true},
		ethernet, ipv4, udp, payload); err != nil {
		t.Fatal(err)
	}
	return traffic.Normalize(buffer.Bytes(), traffic.CaptureMetadata{Timestamp: timestamp}, "en0", traffic.SideHost, traffic.DirectionHostToSwitch)
}
