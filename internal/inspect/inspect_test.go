package inspect

import (
	"encoding/base64"
	"encoding/binary"
	"strings"
	"testing"
)

func TestHTTPBasicFindingShowsSecret(t *testing.T) {
	inspector := New()
	token := base64.StdEncoding.EncodeToString([]byte("alice:secret123"))
	findings := inspector.AnalyzeFlow("192.0.2.10", 49152, "192.0.2.20", 80, []byte("GET / HTTP/1.1\r\nAuthorization: Basic "+token+"\r\n\r\n"), nil)

	if len(findings) != 1 {
		t.Fatalf("findings = %+v", findings)
	}
	got := findings[0].Display()
	if !strings.Contains(got, "FOUND HTTP Basic") || !strings.Contains(got, "user=alice") || !strings.Contains(got, "secret=secret123") {
		t.Fatalf("display = %q", got)
	}
	if strings.Contains(got, "redacted") {
		t.Fatalf("secret was redacted: %q", got)
	}
}

func TestHTTPPasswordFieldFindingShowsSecret(t *testing.T) {
	inspector := New()
	payload := []byte("POST /login HTTP/1.1\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nusername=bob&password=hunter2")
	findings := inspector.AnalyzeFlow("192.0.2.10", 49152, "192.0.2.20", 80, payload, nil)

	if len(findings) != 1 {
		t.Fatalf("findings = %+v", findings)
	}
	got := findings[0].Display()
	if !strings.Contains(got, "FOUND HTTP password") || !strings.Contains(got, "secret=hunter2") {
		t.Fatalf("display = %q", got)
	}
}

func TestFTPUserPassFindingKeepsFlowUser(t *testing.T) {
	inspector := New()
	first := inspector.AnalyzeFlow("192.0.2.10", 49152, "192.0.2.20", 21, []byte("USER alice\r\n"), nil)
	second := inspector.AnalyzeFlow("192.0.2.10", 49152, "192.0.2.20", 21, []byte("PASS open-sesame\r\n"), nil)

	if len(first) != 1 || !strings.Contains(first[0].Display(), "user=alice") {
		t.Fatalf("first = %+v", first)
	}
	if len(second) != 1 {
		t.Fatalf("second = %+v", second)
	}
	got := second[0].Display()
	if !strings.Contains(got, "FOUND FTP PASS") || !strings.Contains(got, "user=alice") || !strings.Contains(got, "secret=open-sesame") {
		t.Fatalf("display = %q", got)
	}
}

func TestNTLMv2FindingShowsHash(t *testing.T) {
	inspector := New()
	inspector.AnalyzeFlow("192.0.2.20", 80, "192.0.2.10", 49152, ntlmType2([]byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}), nil)
	findings := inspector.AnalyzeFlow("192.0.2.10", 49152, "192.0.2.20", 80, ntlmType3("alice", "DOMAIN"), nil)

	if len(findings) != 1 {
		t.Fatalf("findings = %+v", findings)
	}
	got := findings[0].Display()
	if !strings.Contains(got, "FOUND NTLM NTLMv2") || !strings.Contains(got, "user=alice") {
		t.Fatalf("display = %q", got)
	}
	if !strings.Contains(got, "secret=alice::DOMAIN:1122334455667788:") {
		t.Fatalf("hash missing challenge: %q", got)
	}
}

func TestKerberosFindingShowsHash(t *testing.T) {
	inspector := New()
	payload := kerberosASREQ("alice", "EXAMPLE")
	findings := inspector.AnalyzeFlow("192.0.2.10", 49152, "192.0.2.20", 88, payload, nil)

	if len(findings) != 1 {
		t.Fatalf("findings = %+v", findings)
	}
	got := findings[0].Display()
	if !strings.Contains(got, "FOUND KERBEROS AS-REQ etype23") || !strings.Contains(got, "user=alice") {
		t.Fatalf("display = %q", got)
	}
	if !strings.Contains(got, "secret=$krb5pa$23$alice$EXAMPLE$dummy$") {
		t.Fatalf("hash missing: %q", got)
	}
}

func TestCardFindingShowsFullNumber(t *testing.T) {
	inspector := New()
	findings := inspector.AnalyzeFlow("192.0.2.10", 49152, "192.0.2.20", 443, []byte("card=4111 1111 1111 1111"), nil)

	if len(findings) != 1 {
		t.Fatalf("findings = %+v", findings)
	}
	got := findings[0].Display()
	if !strings.Contains(got, "FOUND CARD number") || !strings.Contains(got, "secret=4111111111111111") {
		t.Fatalf("display = %q", got)
	}
}

func ntlmType2(challenge []byte) []byte {
	payload := make([]byte, 32)
	copy(payload[:8], []byte("NTLMSSP\x00"))
	binary.LittleEndian.PutUint32(payload[8:12], 2)
	copy(payload[24:32], challenge)
	return payload
}

func ntlmType3(user, domain string) []byte {
	payload := make([]byte, 64)
	copy(payload[:8], []byte("NTLMSSP\x00"))
	binary.LittleEndian.PutUint32(payload[8:12], 3)
	domainBytes := utf16Bytes(domain)
	userBytes := utf16Bytes(user)
	lm := bytesOf(0xaa, 24)
	nt := append(bytesOf(0xbb, 16), bytesOf(0xcc, 24)...)

	offset := 64
	putSecbuf(payload[28:36], len(domainBytes), offset)
	payload = append(payload, domainBytes...)
	offset += len(domainBytes)
	putSecbuf(payload[36:44], len(userBytes), offset)
	payload = append(payload, userBytes...)
	offset += len(userBytes)
	putSecbuf(payload[12:20], len(lm), offset)
	payload = append(payload, lm...)
	offset += len(lm)
	putSecbuf(payload[20:28], len(nt), offset)
	payload = append(payload, nt...)
	return payload
}

func utf16Bytes(value string) []byte {
	out := make([]byte, 0, len(value)*2)
	for _, r := range value {
		out = binary.LittleEndian.AppendUint16(out, uint16(r))
	}
	return out
}

func putSecbuf(field []byte, length, offset int) {
	binary.LittleEndian.PutUint16(field[0:2], uint16(length))
	binary.LittleEndian.PutUint16(field[2:4], uint16(length))
	binary.LittleEndian.PutUint32(field[4:8], uint32(offset))
}

func bytesOf(value byte, count int) []byte {
	out := make([]byte, count)
	for i := range out {
		out[i] = value
	}
	return out
}

func kerberosASREQ(user, domain string) []byte {
	payload := make([]byte, 160)
	payload[17] = 0x0a
	payload[39] = 0x17
	payload[48] = 20
	for i := 0; i < 20; i++ {
		payload[49+i] = byte(i + 1)
	}
	nameOffset := 20 + 97
	payload[nameOffset] = byte(len(user))
	copy(payload[nameOffset+1:], user)
	domainOffset := nameOffset + 1 + len(user) + 3
	payload[domainOffset] = byte(len(domain))
	copy(payload[domainOffset+1:], domain)
	return payload
}
