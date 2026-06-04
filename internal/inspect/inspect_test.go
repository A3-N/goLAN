package inspect

import (
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func TestHTTPBasicFindingShowsSecret(t *testing.T) {
	inspector := New()
	token := base64.StdEncoding.EncodeToString([]byte("alice:secret123"))
	findings := inspector.AnalyzeFlow("192.0.2.10", 49152, "192.0.2.20", 80, []byte("GET / HTTP/1.1\r\nAuthorization: Basic "+token+"\r\n\r\n"), nil)

	if len(findings) != 1 {
		t.Fatalf("findings = %+v", findings)
	}
	got := findings[0].Display()
	if !strings.Contains(got, "HTTP Basic") || !strings.Contains(got, "user=alice") || !strings.Contains(got, "secret=secret123") {
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
	if !strings.Contains(got, "HTTP password") || !strings.Contains(got, "secret=hunter2") {
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
	if !strings.Contains(got, "FTP PASS") || !strings.Contains(got, "user=alice") || !strings.Contains(got, "secret=open-sesame") {
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
	if !strings.Contains(got, "NTLM NTLMv2") || !strings.Contains(got, "user=alice") {
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
	if !strings.Contains(got, "KERBEROS AS-REQ etype23") || !strings.Contains(got, "user=alice") {
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
	if !strings.Contains(got, "CARD number") || !strings.Contains(got, "secret=4111111111111111") {
		t.Fatalf("display = %q", got)
	}
}

func TestEAPMD5FindingShowsHashcat4800(t *testing.T) {
	inspector := New()
	auth := "02:00:00:00:00:02"
	peer := "02:00:00:00:00:01"
	challenge := bytesOf(0x11, 16)
	response, _ := hex.DecodeString("63588113b10df3f656ddd7d8133bda4c")

	request := eapPacket(auth, peer, 1, 0x02, 4, append([]byte{16}, append(challenge, []byte("server")...)...))
	if findings := inspector.AnalyzePacket(request); len(findings) != 0 {
		t.Fatalf("request findings = %+v", findings)
	}
	responseData := append([]byte{16}, append(response, []byte("test")...)...)
	findings := inspector.AnalyzePacket(eapPacket(peer, auth, 2, 0x02, 4, responseData))
	if len(findings) != 1 {
		t.Fatalf("response findings = %+v", findings)
	}
	got := findings[0].Display()
	responseHex := hex.EncodeToString(response)
	challengeHex := hex.EncodeToString(challenge)
	wantSecret := "test:$02$" + challengeHex + "$" + responseHex
	wantHashcat := responseHex + ":" + challengeHex + ":02"
	if !strings.Contains(got, "EAP EAP-MD5 hashcat-4800") ||
		!strings.Contains(got, "user=test") ||
		!strings.Contains(got, "secret="+wantSecret) ||
		!strings.Contains(got, "mode=4800 status=crackable valid=tuple") ||
		!strings.Contains(got, "hashcat="+wantHashcat) {
		t.Fatalf("display = %q", got)
	}

	status := inspector.AnalyzePacket(eapStatusPacket(auth, peer, 4, 0x02))
	if len(status) != 1 || !strings.Contains(status[0].Display(), "status=rejected valid=eap-failure") || !strings.Contains(status[0].Display(), "hashcat="+wantHashcat) {
		t.Fatalf("status findings = %+v", status)
	}
}

func TestEAPMSCHAPv2FindingShowsHashcat5500(t *testing.T) {
	inspector := New()
	auth := "02:00:00:00:00:12"
	peer := "02:00:00:00:00:11"
	authChallenge := bytesOf(0x55, 16)
	peerChallenge := bytesOf(0x77, 16)
	ntResponse := bytesOf(0xcc, 24)
	user := "test"

	inspector.AnalyzePacket(eapPacket(auth, peer, 1, 7, 26, mschapv2Challenge(9, authChallenge, "server")))
	findings := inspector.AnalyzePacket(eapPacket(peer, auth, 2, 7, 26, mschapv2Response(9, peerChallenge, ntResponse, user)))
	if len(findings) != 1 {
		t.Fatalf("findings = %+v", findings)
	}
	chalHash := sha1.Sum(append(append(append([]byte{}, peerChallenge...), authChallenge...), []byte(user)...))
	ntResponseHex := hex.EncodeToString(ntResponse)
	wantSecret := user + "::::" + ntResponseHex + ":" + hex.EncodeToString(peerChallenge) + ":" + hex.EncodeToString(authChallenge)
	wantHashcat := user + "::::" + ntResponseHex + ":" + hex.EncodeToString(chalHash[:8])
	got := findings[0].Display()
	if !strings.Contains(got, "EAP EAP-MSCHAPv2 hashcat-5500") ||
		!strings.Contains(got, "user="+user) ||
		!strings.Contains(got, "secret="+wantSecret) ||
		!strings.Contains(got, "mode=5500 status=crackable valid=tuple") ||
		!strings.Contains(got, "hashcat="+wantHashcat) {
		t.Fatalf("display = %q", got)
	}
}

func TestCiscoLEAPFindingShowsHashcat5500(t *testing.T) {
	inspector := New()
	auth := "02:00:00:00:00:22"
	peer := "02:00:00:00:00:21"
	challenge := bytesOf(0x33, 8)
	response := bytesOf(0xaa, 24)

	inspector.AnalyzePacket(eapPacket(auth, peer, 1, 3, 17, leapData(challenge, "server")))
	findings := inspector.AnalyzePacket(eapPacket(peer, auth, 2, 3, 17, leapData(response, "test")))
	if len(findings) != 1 {
		t.Fatalf("findings = %+v", findings)
	}
	responseHex := hex.EncodeToString(response)
	challengeHex := hex.EncodeToString(challenge)
	wantSecret := "test:" + challengeHex + ":" + responseHex
	wantHashcat := "test::::" + responseHex + ":" + challengeHex
	got := findings[0].Display()
	if !strings.Contains(got, "EAP Cisco LEAP hashcat-5500") ||
		!strings.Contains(got, "user=test") ||
		!strings.Contains(got, "secret="+wantSecret) ||
		!strings.Contains(got, "hashcat="+wantHashcat) {
		t.Fatalf("display = %q", got)
	}
}

func TestEAPResponseUsesRequestMethodForClassification(t *testing.T) {
	inspector := New()
	auth := "02:00:00:00:00:32"
	peer := "02:00:00:00:00:31"

	inspector.AnalyzePacket(eapPacket(auth, peer, 1, 5, 17, leapData(bytesOf(0x44, 8), "server")))
	findings := inspector.AnalyzePacket(eapPacket(peer, auth, 2, 5, 4, leapData(bytesOf(0xbb, 24), "test")))
	if len(findings) != 1 {
		t.Fatalf("LEAP findings = %+v", findings)
	}
	if got := findings[0].Display(); !strings.Contains(got, "Cisco LEAP hashcat-5500") || strings.Contains(got, "hashcat-4800") {
		t.Fatalf("LEAP display = %q", got)
	}

	inspector = New()
	authChallenge := bytesOf(0x55, 16)
	peerChallenge := bytesOf(0x77, 16)
	ntResponse := bytesOf(0xcc, 24)
	inspector.AnalyzePacket(eapPacket(auth, peer, 1, 6, 26, mschapv2Challenge(9, authChallenge, "server")))
	findings = inspector.AnalyzePacket(eapPacket(peer, auth, 2, 6, 4, mschapv2Response(9, peerChallenge, ntResponse, "test")))
	if len(findings) != 1 {
		t.Fatalf("MSCHAPv2 findings = %+v", findings)
	}
	if got := findings[0].Display(); !strings.Contains(got, "EAP-MSCHAPv2 hashcat-5500") || strings.Contains(got, "hashcat-4800") {
		t.Fatalf("MSCHAPv2 display = %q", got)
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

func eapPacket(src, dst string, code, id, eapType byte, typeData []byte) gopacket.Packet {
	eapLen := 5 + len(typeData)
	eap := make([]byte, eapLen)
	eap[0] = code
	eap[1] = id
	binary.BigEndian.PutUint16(eap[2:4], uint16(eapLen))
	eap[4] = eapType
	copy(eap[5:], typeData)
	return eapolPacket(src, dst, eap)
}

func eapStatusPacket(src, dst string, code, id byte) gopacket.Packet {
	eap := make([]byte, 4)
	eap[0] = code
	eap[1] = id
	binary.BigEndian.PutUint16(eap[2:4], 4)
	return eapolPacket(src, dst, eap)
}

func eapolPacket(src, dst string, eap []byte) gopacket.Packet {
	frame := make([]byte, 14+4+len(eap))
	copy(frame[0:6], mustMAC(dst))
	copy(frame[6:12], mustMAC(src))
	frame[12], frame[13] = 0x88, 0x8e
	frame[14], frame[15] = 0x01, 0x00
	binary.BigEndian.PutUint16(frame[16:18], uint16(len(eap)))
	copy(frame[18:], eap)
	return gopacket.NewPacket(frame, layers.LayerTypeEthernet, gopacket.Default)
}

func leapData(value []byte, user string) []byte {
	out := []byte{1, 0, byte(len(value))}
	out = append(out, value...)
	out = append(out, []byte(user)...)
	return out
}

func mschapv2Challenge(id byte, challenge []byte, name string) []byte {
	data := []byte{1, id, 0, 0, byte(len(challenge))}
	data = append(data, challenge...)
	data = append(data, []byte(name)...)
	binary.BigEndian.PutUint16(data[2:4], uint16(len(data)))
	return data
}

func mschapv2Response(id byte, peerChallenge, ntResponse []byte, user string) []byte {
	data := []byte{2, id, 0, 0, 49}
	data = append(data, peerChallenge...)
	data = append(data, bytesOf(0, 8)...)
	data = append(data, ntResponse...)
	data = append(data, 0)
	data = append(data, []byte(user)...)
	binary.BigEndian.PutUint16(data[2:4], uint16(len(data)))
	return data
}

func mustMAC(value string) []byte {
	parts := strings.Split(value, ":")
	out := make([]byte, 6)
	for i, part := range parts {
		decoded, _ := hex.DecodeString(part)
		out[i] = decoded[0]
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
