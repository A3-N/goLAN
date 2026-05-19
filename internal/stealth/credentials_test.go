package stealth

import (
	"encoding/base64"
	"net"
	"testing"
	"time"

	"github.com/google/gopacket/layers"
)

func TestDetectHTTPBasicCredentialExposureRedactsSecret(t *testing.T) {
	ipv4 := &layers.IPv4{SrcIP: net.IPv4(192, 0, 2, 10), DstIP: net.IPv4(192, 0, 2, 20)}
	token := base64.StdEncoding.EncodeToString([]byte("alice:secret"))
	payload := []byte("GET /admin?ignored=true HTTP/1.1\r\nHost: switch.local\r\nAuthorization: Basic " + token + "\r\n\r\n")

	findings := detectHTTPCredentialExposures(ipv4, 49152, 80, 0, payload)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Username != "alice" {
		t.Fatalf("expected username alice, got %q", findings[0].Username)
	}
	if findings[0].SecretPreview != "[redacted 6 chars]" {
		t.Fatalf("expected redacted secret length, got %q", findings[0].SecretPreview)
	}
	if findings[0].SecretValue != "secret" {
		t.Fatalf("expected raw secret, got %q", findings[0].SecretValue)
	}
	if findings[0].Path != "/admin" {
		t.Fatalf("expected query-stripped path, got %q", findings[0].Path)
	}
}

func TestDetectHTTPFormCredentialExposure(t *testing.T) {
	ipv4 := &layers.IPv4{SrcIP: net.IPv4(192, 0, 2, 10), DstIP: net.IPv4(192, 0, 2, 20)}
	payload := []byte("POST /login HTTP/1.1\r\nHost: router.local\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nusername=bob&password=hunter2")

	findings := detectHTTPCredentialExposures(ipv4, 49152, 80, 0, payload)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Username != "bob" {
		t.Fatalf("expected username bob, got %q", findings[0].Username)
	}
	if findings[0].SecretPreview != "[redacted 7 chars]" {
		t.Fatalf("expected redacted password length, got %q", findings[0].SecretPreview)
	}
	if findings[0].SecretValue != "hunter2" {
		t.Fatalf("expected raw password, got %q", findings[0].SecretValue)
	}
}

func TestFTPUserPassPairing(t *testing.T) {
	observer := &Observer{iface: "test0"}
	nm := NewNetworkMap()
	ipv4 := &layers.IPv4{SrcIP: net.IPv4(192, 0, 2, 10), DstIP: net.IPv4(192, 0, 2, 20)}
	now := time.Now()

	if findings := observer.detectLineCredentialExposures(nm, ipv4, 49152, 21, 0, now, []byte("USER backup\r\n")); len(findings) != 0 {
		t.Fatalf("expected no finding for USER alone, got %d", len(findings))
	}
	findings := observer.detectLineCredentialExposures(nm, ipv4, 49152, 21, 0, now, []byte("PASS plaintext\r\n"))
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Username != "backup" {
		t.Fatalf("expected paired username backup, got %q", findings[0].Username)
	}
	if findings[0].SecretPreview != "[redacted 9 chars]" {
		t.Fatalf("expected redacted password length, got %q", findings[0].SecretPreview)
	}
	if findings[0].SecretValue != "plaintext" {
		t.Fatalf("expected raw password, got %q", findings[0].SecretValue)
	}
}

func TestParseSNMPCommunity(t *testing.T) {
	payload := []byte{
		0x30, 0x0e,
		0x02, 0x01, 0x00,
		0x04, 0x06, 'p', 'u', 'b', 'l', 'i', 'c',
		0xa0, 0x01, 0x00,
	}
	community, ok := parseSNMPCommunity(payload)
	if !ok {
		t.Fatal("expected SNMP community")
	}
	if community != "public" {
		t.Fatalf("expected public, got %q", community)
	}
}

func TestParseLDAPSimpleBind(t *testing.T) {
	payload := []byte{
		0x30, 0x1a,
		0x02, 0x01, 0x01,
		0x60, 0x15,
		0x02, 0x01, 0x03,
		0x04, 0x08, 'c', 'n', '=', 'a', 'd', 'm', 'i', 'n',
		0x80, 0x06, 's', 'e', 'c', 'r', 'e', 't',
	}
	dn, password, ok := parseLDAPSimpleBind(payload)
	if !ok {
		t.Fatal("expected LDAP simple bind")
	}
	if dn != "cn=admin" {
		t.Fatalf("expected cn=admin, got %q", dn)
	}
	if password != "secret" {
		t.Fatalf("expected secret, got %q", password)
	}
}

func TestDetectHTTPNTLMExposure(t *testing.T) {
	ipv4 := &layers.IPv4{SrcIP: net.IPv4(192, 0, 2, 10), DstIP: net.IPv4(192, 0, 2, 20)}
	ntlm := append([]byte("NTLMSSP\x00"), []byte{0x03, 0x00, 0x00, 0x00, 0xaa, 0xbb}...)
	token := base64.StdEncoding.EncodeToString(ntlm)
	payload := []byte("GET / HTTP/1.1\r\nHost: server.local\r\nAuthorization: NTLM " + token + "\r\n\r\n")

	findings := detectHTTPCredentialExposures(ipv4, 49152, 80, 0, payload)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Service != "NTLM" {
		t.Fatalf("expected NTLM service, got %q", findings[0].Service)
	}
	if findings[0].SecretPreview != "[redacted 14 bytes]" {
		t.Fatalf("expected redacted NTLM length, got %q", findings[0].SecretPreview)
	}
}

func TestDetectKerberosEtype23Exposure(t *testing.T) {
	ipv4 := &layers.IPv4{SrcIP: net.IPv4(192, 0, 2, 10), DstIP: net.IPv4(192, 0, 2, 88)}
	payload := []byte{0x6a, 0x06, 0x30, 0x04, 0x02, 0x01, 0x17, 0x00}

	findings := detectKerberosExposure(ipv4, 49152, 88, 0, payload)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Service != "Kerberos" {
		t.Fatalf("expected Kerberos service, got %q", findings[0].Service)
	}
}

func TestFindPaymentCardCandidate(t *testing.T) {
	card, ok := findPaymentCardCandidate([]byte("cc=4111-1111-1111-1111&name=test"))
	if !ok {
		t.Fatal("expected payment card candidate")
	}
	if card != "4111111111111111" {
		t.Fatalf("expected normalized card number, got %q", card)
	}
}

func TestCredentialSnapshotIncludesRawSecret(t *testing.T) {
	observer := &Observer{iface: "test0"}
	nm := NewNetworkMap()
	now := time.Now()
	finding := CredentialExposure{
		Service:       "FTP",
		Protocol:      "FTP",
		SrcIP:         net.IPv4(192, 0, 2, 10),
		DstIP:         net.IPv4(192, 0, 2, 20),
		ServiceIP:     net.IPv4(192, 0, 2, 20),
		SrcPort:       49152,
		DstPort:       21,
		ServicePort:   21,
		Username:      "backup",
		SecretKind:    "password",
		SecretValue:   "plaintext",
		SecretPreview: "[redacted 9 chars]",
		Evidence:      "FTP PASS command",
	}
	observer.addCredentialExposure(nm, finding, now, nil)
	snap := nm.Snapshot()
	if len(snap.CredentialExposures) != 1 {
		t.Fatalf("expected 1 snapshot finding, got %d", len(snap.CredentialExposures))
	}
	if snap.CredentialExposures[0].SecretValue != "plaintext" {
		t.Fatalf("expected raw secret in snapshot, got %q", snap.CredentialExposures[0].SecretValue)
	}
}
