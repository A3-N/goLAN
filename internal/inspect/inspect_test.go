package inspect

import (
	"encoding/binary"
	"strings"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func TestHTTPBasicSecretIsTransientAndRedactedByDefault(t *testing.T) {
	inspector := New()
	payload := []byte("GET / HTTP/1.1\r\nAuthorization: Basic YWxpY2U6c2VjcmV0\r\n\r\n")
	signals := inspector.AnalyzeFlow("192.0.2.10", 49152, "192.0.2.20", 80, payload, nil)
	if len(signals) != 1 || signals[0].Protocol != "HTTP" || signals[0].Kind != "Basic authentication" || signals[0].Secret != "alice:secret" {
		t.Fatalf("signals = %#v", signals)
	}
	if safe := signals[0].Display(); !strings.Contains(safe, "[REDACTED]") || strings.Contains(safe, "alice:secret") {
		t.Fatalf("safe display = %q", safe)
	}
	if revealed := signals[0].DisplayWithRedaction(false); !strings.Contains(revealed, "[alice:secret]") {
		t.Fatalf("revealed display = %q", revealed)
	}
	decoded, err := DecodeSignal(signals[0].Encode())
	if err != nil || decoded.Secret != "alice:secret" {
		t.Fatalf("transient signal round trip = %#v, %v", decoded, err)
	}
}

func TestCategoricalRiskFamilies(t *testing.T) {
	tests := []struct {
		name    string
		sport   uint16
		dport   uint16
		payload []byte
		want    string
	}{
		{name: "ntlm", dport: 80, payload: []byte("NTLMSSP\x00\x03"), want: "NTLM"},
		{name: "ftp", dport: 21, payload: []byte("PASS example\r\n"), want: "FTP"},
		{name: "smtp", dport: 25, payload: []byte("AUTH LOGIN\r\n"), want: "SMTP"},
		{name: "imap", dport: 143, payload: []byte("a1 LOGIN user value\r\n"), want: "IMAP"},
		{name: "ldap", dport: 389, payload: []byte{0x30, 0x07, 0x02, 0x01, 0x01, 0x60, 0x02}, want: "LDAP"},
		{name: "snmp", dport: 161, payload: []byte{0x30, 0x08, 0x02, 0x01, 0x01, 0x04, 0x03}, want: "SNMP"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			signals := New().AnalyzeFlow("192.0.2.1", test.sport, "192.0.2.2", test.dport, test.payload, nil)
			if len(signals) != 1 || signals[0].Protocol != test.want {
				t.Fatalf("signals = %#v", signals)
			}
		})
	}
}

func TestCardNumbersAreNotDetected(t *testing.T) {
	signals := New().AnalyzeFlow("192.0.2.1", 1234, "192.0.2.2", 443, []byte("4111 1111 1111 1111"), nil)
	if len(signals) != 0 {
		t.Fatalf("card-like content produced signals: %#v", signals)
	}
}

func TestCategoricalEAPMethod(t *testing.T) {
	frame := make([]byte, 14+4+5)
	copy(frame[0:6], []byte{0x02, 0, 0, 0, 0, 2})
	copy(frame[6:12], []byte{0x02, 0, 0, 0, 0, 1})
	frame[12], frame[13] = 0x88, 0x8e
	frame[14], frame[15] = 1, 0
	binary.BigEndian.PutUint16(frame[16:18], 5)
	frame[18], frame[19], frame[22] = 1, 7, 26
	binary.BigEndian.PutUint16(frame[20:22], 5)
	packet := gopacket.NewPacket(frame, layers.LayerTypeEthernet, gopacket.Default)
	signals := New().AnalyzePacket(packet)
	if len(signals) != 1 || signals[0].Kind != "EAP-MSCHAPv2 authentication" {
		t.Fatalf("signals = %#v", signals)
	}
	if strings.Contains(signals[0].Encode(), "hash") {
		t.Fatalf("signal exposed hash semantics: %s", signals[0].Encode())
	}
}

func TestPlaintextSecretExtractionFamilies(t *testing.T) {
	tests := []struct {
		name         string
		sport, dport uint16
		payload      []byte
		wantProtocol string
		wantSecret   string
	}{
		{name: "form", dport: 80, payload: []byte("POST /login HTTP/1.1\r\n\r\nuser=alice&password=s%21cret"), wantProtocol: "HTTP", wantSecret: "s!cret"},
		{name: "ftp", dport: 21, payload: []byte("USER alice\r\nPASS case-Sensitive\r\n"), wantProtocol: "FTP", wantSecret: "case-Sensitive"},
		{name: "smtp plain", dport: 25, payload: []byte("AUTH PLAIN AGFsaWNlAHNtdHAtc2VjcmV0\r\n"), wantProtocol: "SMTP", wantSecret: "smtp-secret"},
		{name: "imap", dport: 143, payload: []byte("a1 LOGIN alice \"imap secret\"\r\n"), wantProtocol: "IMAP", wantSecret: "imap secret"},
		{name: "snmp", dport: 161, payload: []byte{0x30, 0x0d, 0x02, 0x01, 0x01, 0x04, 0x06, 'p', 'u', 'b', 'l', 'i', 'c'}, wantProtocol: "SNMP", wantSecret: "public"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			signals := New().AnalyzeFlow("192.0.2.1", test.sport, "192.0.2.2", test.dport, test.payload, nil)
			if len(signals) != 1 || signals[0].Protocol != test.wantProtocol || signals[0].Secret != test.wantSecret {
				t.Fatalf("signals = %#v", signals)
			}
		})
	}
}

func TestDecodeAcceptsBoundedSecretAndRejectsUnknownFields(t *testing.T) {
	signal, err := DecodeSignal(`{"protocol":"HTTP","kind":"Basic","secret":"value"}`)
	if err != nil || signal.Secret != "value" {
		t.Fatalf("secret signal = %#v, %v", signal, err)
	}
	if _, err := DecodeSignal(`{"protocol":"HTTP","kind":"Basic","raw_payload":"value"}`); err == nil {
		t.Fatal("unknown raw payload field was accepted")
	}
	if _, err := DecodeSignal(`{"protocol":"HTTP","kind":"Basic"} {"protocol":"FTP","kind":"PASS"}`); err == nil {
		t.Fatal("multiple signal values were accepted")
	}
	if _, err := DecodeSignal(strings.Repeat("x", maxEncodedSignal+1)); err == nil {
		t.Fatal("oversized signal was accepted")
	}
}

func FuzzInspectorPacketAndFlow(f *testing.F) {
	f.Add([]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x02, 0, 0, 0, 0, 1, 0x08, 0x00})
	f.Add([]byte("USER synthetic\r\nPASS synthetic-secret\r\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		inspector := New()
		packet := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.NoCopy)
		_ = inspector.AnalyzePacket(packet)
		_ = inspector.AnalyzeFlow("192.0.2.10", 49152, "192.0.2.20", 80, data, data)
	})
}
