package traffic

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"testing"
	"time"
)

func TestNormalizeCopiesBytesAndDecodesVLANIPv4TCP(t *testing.T) {
	raw := syntheticTCPFrame(true)
	frame := Normalize(raw, CaptureMetadata{Timestamp: time.Unix(100, 20), InterfaceIndex: 2}, "en7", SideHost, DirectionHostToSwitch)
	raw[0] = 0

	decoded := frame.Decoded()
	if got, want := decoded.DstMAC, "00:00:5e:00:53:01"; got != want {
		t.Fatalf("destination MAC = %q, want %q", got, want)
	}
	if len(decoded.VLANs) != 1 || decoded.VLANs[0].ID != 42 {
		t.Fatalf("VLANs = %#v", decoded.VLANs)
	}
	if decoded.SrcIP != "192.0.2.10" || decoded.DstIP != "198.51.100.20" {
		t.Fatalf("IP pair = %s > %s", decoded.SrcIP, decoded.DstIP)
	}
	if decoded.SrcPort != 12345 || decoded.DstPort != 80 {
		t.Fatalf("ports = %d > %d", decoded.SrcPort, decoded.DstPort)
	}
	if got := frame.RawBytes()[0]; got != 0x00 {
		t.Fatalf("owned raw byte = %#x", got)
	}
	if got := frame.RawLength(); got != len(raw) {
		t.Fatalf("raw length=%d want=%d", got, len(raw))
	}
	copyBytes := frame.RawBytes()
	copyBytes[1] = 0
	if got := frame.RawBytes()[1]; got != 0x00 {
		t.Fatalf("accessor leaked raw ownership: %#x", got)
	}
	if frame.ID == "" {
		t.Fatal("packet ID is empty")
	}
	if frame.Kind != EvidencePacket {
		t.Fatalf("evidence kind=%q", frame.Kind)
	}
}

func TestNormalizeMalformedDoesNotPanic(t *testing.T) {
	for length := 0; length < 64; length++ {
		frame := Normalize(make([]byte, length), CaptureMetadata{}, "", SideUnknown, DirectionUnknown)
		if length < 14 && !frame.Decoded().Malformed {
			t.Fatalf("length %d not marked malformed", length)
		}
	}
}

func TestTrackerStableBidirectionalFlowAndCopies(t *testing.T) {
	tracker := NewTracker(4)
	forward := Normalize(syntheticTCPFrame(false), CaptureMetadata{Timestamp: time.Unix(1, 0)}, "en1", SideHost, DirectionHostToSwitch)
	identity := CanonicalFlow(forward)
	if identity.ID == "" || identity.EndpointA.IP == "" || identity.EndpointB.IP == "" || identity.Protocol != 6 || identity.Packets != 0 {
		t.Fatalf("canonical flow identity=%#v", identity)
	}
	reverseRaw := syntheticTCPFrame(false)
	copy(reverseRaw[0:6], forward.RawBytes()[6:12])
	copy(reverseRaw[6:12], forward.RawBytes()[0:6])
	copy(reverseRaw[26:30], []byte{198, 51, 100, 20})
	copy(reverseRaw[30:34], []byte{192, 0, 2, 10})
	binary.BigEndian.PutUint16(reverseRaw[34:36], 80)
	binary.BigEndian.PutUint16(reverseRaw[36:38], 12345)
	reverseRaw[47] = 0x12
	reverse := Normalize(reverseRaw, CaptureMetadata{Timestamp: time.Unix(2, 0)}, "en2", SideSwitch, DirectionSwitchToHost)

	first := tracker.Observe(forward)
	second := tracker.Observe(reverse)
	if first.ID != identity.ID || first.ID != second.ID || second.Packets != 2 {
		t.Fatalf("flow snapshots = %#v then %#v", first, second)
	}
	if second.State != FlowStateEstablished {
		t.Fatalf("state = %s", second.State)
	}
	snapshot := tracker.Snapshot()
	if len(snapshot) != 1 || snapshot[0].ID != second.ID {
		t.Fatalf("tracker snapshot=%#v", snapshot)
	}
}

func TestPhysicalPacketIDRetainsLegacyHashContract(t *testing.T) {
	frame := Normalize(
		syntheticTCPFrame(false),
		CaptureMetadata{
			Timestamp: time.Unix(40, 50), InterfaceIndex: 7, Source: "capture-source",
		},
		"en7", SideHost, DirectionHostToSwitch,
	)
	if want := legacyPhysicalPacketID(frame); frame.ID != want {
		t.Fatalf("physical packet ID changed: got=%s want=%s", frame.ID, want)
	}
}

func legacyPhysicalPacketID(frame Frame) PacketID {
	h := sha256.New()
	var number [8]byte
	binary.BigEndian.PutUint64(number[:], uint64(frame.Timestamp.UnixNano()))
	_, _ = h.Write(number[:])
	binary.BigEndian.PutUint64(number[:], uint64(frame.Capture.InterfaceIndex))
	_, _ = h.Write(number[:])
	_, _ = h.Write([]byte(frame.Capture.Source))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write([]byte(frame.Ingress))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write([]byte(frame.Side))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write([]byte(frame.Direction))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write(frame.RawBytes())
	return PacketID(hex.EncodeToString(h.Sum(nil)[:16]))
}

func syntheticTCPFrame(vlan bool) []byte {
	header := 14
	if vlan {
		header += 4
	}
	raw := make([]byte, header+20+20)
	copy(raw[0:6], []byte{0x00, 0x00, 0x5e, 0x00, 0x53, 0x01})
	copy(raw[6:12], []byte{0x00, 0x00, 0x5e, 0x00, 0x53, 0x02})
	ipOffset := 14
	if vlan {
		binary.BigEndian.PutUint16(raw[12:14], 0x8100)
		binary.BigEndian.PutUint16(raw[14:16], 42)
		binary.BigEndian.PutUint16(raw[16:18], 0x0800)
		ipOffset = 18
	} else {
		binary.BigEndian.PutUint16(raw[12:14], 0x0800)
	}
	raw[ipOffset] = 0x45
	binary.BigEndian.PutUint16(raw[ipOffset+2:ipOffset+4], 40)
	raw[ipOffset+8] = 64
	raw[ipOffset+9] = 6
	copy(raw[ipOffset+12:ipOffset+16], []byte{192, 0, 2, 10})
	copy(raw[ipOffset+16:ipOffset+20], []byte{198, 51, 100, 20})
	tcpOffset := ipOffset + 20
	binary.BigEndian.PutUint16(raw[tcpOffset:tcpOffset+2], 12345)
	binary.BigEndian.PutUint16(raw[tcpOffset+2:tcpOffset+4], 80)
	raw[tcpOffset+12] = 5 << 4
	raw[tcpOffset+13] = 0x02
	return raw
}
