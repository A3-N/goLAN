package eapol

import (
	"bytes"
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func TestEAPTypeToMethodMapsMSCHAPv2Type26(t *testing.T) {
	if got := eapTypeToMethod(26); got != MethodMSCHAPv2 {
		t.Fatalf("eapTypeToMethod(26) = %q, want %q", got, MethodMSCHAPv2)
	}
	if got := eapTypeToMethod(29); got != MethodUnknown {
		t.Fatalf("eapTypeToMethod(29) = %q, want %q", got, MethodUnknown)
	}
}

func TestAuthSessionCopiesMACAddresses(t *testing.T) {
	supplicant := net.HardwareAddr{0x02, 0, 0, 0, 0, 0x11}
	session := NewAuthSession(supplicant)
	supplicant[5] = 0xff
	if got := session.Snapshot().SupplicantMAC.String(); got != "02:00:00:00:00:11" {
		t.Fatalf("session MAC = %s", got)
	}

	snapshot := session.Snapshot()
	snapshot.SupplicantMAC[5] = 0xee
	if got := session.Snapshot().SupplicantMAC.String(); got != "02:00:00:00:00:11" {
		t.Fatalf("snapshot aliased session MAC: %s", got)
	}
}

func TestRelaySuppressesLogoff(t *testing.T) {
	supplicant := net.HardwareAddr{0x02, 0, 0, 0, 0, 0x11}
	session := NewAuthSession(supplicant)
	relay := NewRelay("device", "switch", session, nil)
	packet := testEAPOLPacket(t, supplicant, layers.EAPOLTypeLogOff, nil, 0)

	if relay.shouldForward(packet, "device→switch") {
		t.Fatal("suppressed logoff was forwarded")
	}
	if got := session.Snapshot().FramesDropped; got != 1 {
		t.Fatalf("dropped frames = %d", got)
	}

	relay.SetSuppressLogoff(false)
	if !relay.shouldForward(packet, "device→switch") {
		t.Fatal("enabled logoff forwarding was dropped")
	}
}

func TestRelayLearnsAuthenticatorAndSignalsSuccess(t *testing.T) {
	supplicant := net.HardwareAddr{0x02, 0, 0, 0, 0, 0x11}
	authenticator := net.HardwareAddr{0x02, 0, 0, 0, 0, 0x22}
	session := NewAuthSession(supplicant)
	relay := NewRelay("device", "switch", session, nil)
	packet := testEAPOLPacket(t, authenticator, layers.EAPOLTypeEAP, []byte{byte(layers.EAPCodeSuccess), 7, 0, 4}, 0)

	if !relay.shouldForward(packet, "switch→device") {
		t.Fatal("EAP-Success was not forwarded")
	}
	snapshot := session.Snapshot()
	if snapshot.State != StateAuthenticated || snapshot.LastEAPID != 7 {
		t.Fatalf("session snapshot = %+v", snapshot)
	}
	if !bytes.Equal(snapshot.AuthenticatorMAC, authenticator) {
		t.Fatalf("authenticator = %s", snapshot.AuthenticatorMAC)
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	result, err := relay.WaitForAuth(ctx)
	if err != nil {
		t.Fatalf("WaitForAuth: %v", err)
	}
	if !result.Success {
		t.Fatalf("auth result = %+v", result)
	}
}

func TestRelayPinsAuthenticatorVLAN(t *testing.T) {
	supplicant := net.HardwareAddr{0x02, 0, 0, 0, 0, 0x11}
	authenticator := net.HardwareAddr{0x02, 0, 0, 0, 0, 0x22}
	relay := NewRelay("device", "switch", NewAuthSession(supplicant), nil)

	if !relay.shouldForward(testEAPOLPacket(t, authenticator, layers.EAPOLTypeStart, nil, 100), "switch→device") {
		t.Fatal("first VLAN frame was dropped")
	}
	if relay.shouldForward(testEAPOLPacket(t, authenticator, layers.EAPOLTypeStart, nil, 200), "switch→device") {
		t.Fatal("changed VLAN frame was forwarded")
	}
}

func TestRelayDowngradeDropsMKA(t *testing.T) {
	supplicant := net.HardwareAddr{0x02, 0, 0, 0, 0, 0x11}
	session := NewAuthSession(supplicant)
	relay := NewRelay("device", "switch", session, nil)
	relay.SetDowngrade(true)

	packet := testEAPOLPacket(t, supplicant, layers.EAPOLType(5), nil, 0)
	if relay.shouldForward(packet, "device→switch") {
		t.Fatal("MKA frame was forwarded")
	}
	snapshot := session.Snapshot()
	if !snapshot.MACsecDetected || snapshot.FramesDropped != 1 {
		t.Fatalf("session snapshot = %+v", snapshot)
	}
}

func TestDowngraderRejectsMalformedPackets(t *testing.T) {
	downgrader := NewDowngrader()
	if downgrader.ShouldDrop(nil) {
		t.Fatal("nil packet was dropped")
	}
	packet := gopacket.NewPacket([]byte{0, 1, 2}, layers.LayerTypeEthernet, gopacket.Default)
	if downgrader.ShouldDrop(packet) {
		t.Fatal("packet without a decoded EAPOL layer was dropped")
	}
}

func TestRelayValidatesLifecycleInputsBeforeOpeningCapture(t *testing.T) {
	validSession := NewAuthSession(net.HardwareAddr{0x02, 0, 0, 0, 0, 0x11})
	tests := []*Relay{
		NewRelay("", "switch", validSession, nil),
		NewRelay("same", "same", validSession, nil),
		NewRelay("device", "switch", NewAuthSession(nil), nil),
	}
	for _, relay := range tests {
		if err := relay.Start(context.Background()); err == nil {
			t.Errorf("Start(%+v) succeeded", relay)
		}
	}
	var nilContext context.Context
	if err := NewRelay("device", "switch", validSession, nil).Start(nilContext); err == nil {
		t.Fatal("Start accepted a nil context")
	}
	if _, err := NewRelay("device", "switch", validSession, nil).WaitForAuth(nilContext); err == nil {
		t.Fatal("WaitForAuth accepted a nil context")
	}
}

func TestRelayDoesNotLogEAPIdentity(t *testing.T) {
	supplicant := net.HardwareAddr{0x02, 0, 0, 0, 0, 0x11}
	var logs []string
	relay := NewRelay("device", "switch", NewAuthSession(supplicant), func(line string) {
		logs = append(logs, line)
	})
	payload := []byte{byte(layers.EAPCodeResponse), 7, 0, 10, byte(layers.EAPTypeIdentity), 'a', 'l', 'i', 'c', 'e'}
	relay.shouldForward(testEAPOLPacket(t, supplicant, layers.EAPOLTypeEAP, payload, 0), "device→switch")
	if strings.Contains(strings.Join(logs, "\n"), "alice") {
		t.Fatalf("identity leaked in logs: %v", logs)
	}
}

func TestInjectEAPOLStartRejectsZeroMACBeforeOpeningCapture(t *testing.T) {
	if err := InjectEAPOLStartWithVLAN("en11", make(net.HardwareAddr, 6), 0, nil); err == nil {
		t.Fatal("all-zero supplicant MAC was accepted")
	}
}

func TestSetDowngradeToleratesUninitializedSession(t *testing.T) {
	NewRelay("device", "switch", nil, nil).SetDowngrade(true)
}

func TestRelayCallbackRunsOutsideStateLock(t *testing.T) {
	var relay *Relay
	callbackDone := make(chan struct{})
	relay = NewRelay("device", "switch", NewAuthSession(net.HardwareAddr{0x02, 0, 0, 0, 0, 0x11}), func(string) {
		relay.SetInjectStart(false)
		close(callbackDone)
	})

	go relay.SetSuppressLogoff(false)
	select {
	case <-callbackDone:
	case <-time.After(time.Second):
		t.Fatal("log callback deadlocked on relay state lock")
	}
}

func TestAcceptFrameRejectsMalformedInput(t *testing.T) {
	relay := NewRelay("device", "switch", NewAuthSession(net.HardwareAddr{0x02, 0, 0, 0, 0, 0x11}), nil)
	if relay.acceptFrame(nil, nil, "switch→device") {
		t.Fatal("nil frame was accepted")
	}
	if relay.acceptFrame(testEAPOLPacket(t, net.HardwareAddr{0x02, 0, 0, 0, 0, 0x22}, layers.EAPOLTypeStart, nil, 0), &layers.Ethernet{SrcMAC: net.HardwareAddr{2}}, "switch→device") {
		t.Fatal("short source MAC was accepted")
	}
}

func FuzzRelayPacketProcessing(f *testing.F) {
	f.Add([]byte{1, 0x80, 0xc2, 0, 0, 3, 2, 0, 0, 0, 0, 0x11, 0x88, 0x8e, 2, 1, 0, 0})
	f.Fuzz(func(t *testing.T, data []byte) {
		supplicant := net.HardwareAddr{0x02, 0, 0, 0, 0, 0x11}
		relay := NewRelay("device", "switch", NewAuthSession(supplicant), nil)
		packet := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.NoCopy)
		_ = relay.shouldForward(packet, "device→switch")
		_ = relay.shouldForward(packet, "switch→device")
	})
}

func testEAPOLPacket(t *testing.T, src net.HardwareAddr, packetType layers.EAPOLType, payload []byte, vlanID uint16) gopacket.Packet {
	t.Helper()
	if len(src) != 6 {
		t.Fatalf("test source MAC length = %d", len(src))
	}
	raw := make([]byte, 0, 22+len(payload))
	raw = append(raw, paeGroupAddress[:]...)
	raw = append(raw, src...)
	if vlanID != 0 {
		raw = append(raw, 0x81, 0x00, byte(vlanID>>8), byte(vlanID), 0x88, 0x8e)
	} else {
		raw = append(raw, 0x88, 0x8e)
	}
	raw = append(raw, 2, byte(packetType), byte(len(payload)>>8), byte(len(payload)))
	raw = append(raw, payload...)
	return gopacket.NewPacket(raw, layers.LayerTypeEthernet, gopacket.Default)
}
