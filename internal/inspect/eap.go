package inspect

import (
	"crypto/sha1"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
	"unicode"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

const (
	eapTypeMD5Challenge = layers.EAPType(4)
	eapTypeLEAP         = layers.EAPType(17)
	eapTypeMSCHAPv2     = layers.EAPType(26)

	eapMSCHAPv2Challenge = 1
	eapMSCHAPv2Response  = 2
)

type eapChallengeKey struct {
	EAPID uint8
	Auth  string
	Peer  string
}

type eapChallenge struct {
	Method    string
	Mode      int
	EAPID     uint8
	InnerID   uint8
	Auth      string
	Peer      string
	Challenge string
	User      string
}

func (i *Inspector) extractEAP(packet gopacket.Packet, add func(Finding)) {
	if packet == nil {
		return
	}
	ethLayer := packet.Layer(layers.LayerTypeEthernet)
	eapLayer := packet.Layer(layers.LayerTypeEAP)
	if ethLayer == nil || eapLayer == nil {
		return
	}
	eth, _ := ethLayer.(*layers.Ethernet)
	eap, _ := eapLayer.(*layers.EAP)
	if eth == nil || eap == nil {
		return
	}

	src := strings.ToLower(eth.SrcMAC.String())
	dst := strings.ToLower(eth.DstMAC.String())
	switch eap.Code {
	case layers.EAPCodeRequest:
		i.trackEAPRequest(eap, src, dst)
	case layers.EAPCodeResponse:
		if eap.Type == layers.EAPTypeIdentity {
			if user := eapPrintable(eap.TypeData); user != "" {
				i.eapIdentities[src] = user
			}
			return
		}
		i.trackEAPResponse(eap, src, dst, add)
	case layers.EAPCodeSuccess:
		i.emitEAPStatus(src, dst, "accepted", "eap-success", add)
	case layers.EAPCodeFailure:
		i.emitEAPStatus(src, dst, "rejected", "eap-failure", add)
	}
}

func (i *Inspector) trackEAPRequest(eap *layers.EAP, src, dst string) {
	switch eap.Type {
	case eapTypeMD5Challenge:
		value, user, ok := parseSizedValue(eap.TypeData)
		if !ok || len(value) != 16 {
			return
		}
		i.eapChallenges[eapChallengeKey{EAPID: eap.Id, Auth: src, Peer: dst}] = eapChallenge{
			Method:    "EAP-MD5",
			Mode:      4800,
			EAPID:     eap.Id,
			Auth:      src,
			Peer:      dst,
			Challenge: hex.EncodeToString(value),
			User:      user,
		}
	case eapTypeLEAP:
		value, user, ok := parseLEAPValue(eap.TypeData)
		if !ok || len(value) != 8 {
			return
		}
		i.eapChallenges[eapChallengeKey{EAPID: eap.Id, Auth: src, Peer: dst}] = eapChallenge{
			Method:    "Cisco LEAP",
			Mode:      5500,
			EAPID:     eap.Id,
			Auth:      src,
			Peer:      dst,
			Challenge: hex.EncodeToString(value),
			User:      user,
		}
	case eapTypeMSCHAPv2:
		challenge, innerID, user, ok := parseMSCHAPv2Challenge(eap.TypeData)
		if !ok {
			return
		}
		i.eapChallenges[eapChallengeKey{EAPID: eap.Id, Auth: src, Peer: dst}] = eapChallenge{
			Method:    "EAP-MSCHAPv2",
			Mode:      5500,
			EAPID:     eap.Id,
			InnerID:   innerID,
			Auth:      src,
			Peer:      dst,
			Challenge: hex.EncodeToString(challenge),
			User:      user,
		}
	}
}

func (i *Inspector) trackEAPResponse(eap *layers.EAP, src, dst string, add func(Finding)) {
	challenge, ok := i.eapChallenges[eapChallengeKey{EAPID: eap.Id, Auth: dst, Peer: src}]
	if !ok {
		return
	}

	switch challenge.Method {
	case "EAP-MD5":
		value, user, ok := parseSizedValue(eap.TypeData)
		if !ok || len(value) != 16 {
			return
		}
		if user == "" {
			user = i.eapIdentities[src]
		}
		response := hex.EncodeToString(value)
		secret := fmt.Sprintf("%s:$%02x$%s$%s", user, eap.Id, challenge.Challenge, response)
		hashcat := fmt.Sprintf("%s:%s:%02x", response, challenge.Challenge, eap.Id)
		i.emitEAPSecret(src, dst, Finding{
			Protocol: "EAP",
			Kind:     "EAP-MD5 hashcat-4800",
			User:     user,
			Secret:   secret,
			Detail:   eapSecretDetail(4800, "crackable", "tuple", "hashcat="+hashcat),
		}, add)
	case "Cisco LEAP":
		value, user, ok := parseLEAPValue(eap.TypeData)
		if !ok || len(value) != 24 {
			return
		}
		if user == "" {
			user = i.eapIdentities[src]
		}
		response := hex.EncodeToString(value)
		secret := fmt.Sprintf("%s:%s:%s", user, challenge.Challenge, response)
		hashcat := fmt.Sprintf("%s::::%s:%s", user, response, challenge.Challenge)
		i.emitEAPSecret(src, dst, Finding{
			Protocol: "EAP",
			Kind:     "Cisco LEAP hashcat-5500",
			User:     user,
			Secret:   secret,
			Detail:   eapSecretDetail(5500, "crackable", "tuple", "hashcat="+hashcat),
		}, add)
	case "EAP-MSCHAPv2":
		response, ok := parseMSCHAPv2Response(eap.TypeData)
		if !ok {
			return
		}
		if response.InnerID != challenge.InnerID {
			return
		}
		user := response.User
		if user == "" {
			user = i.eapIdentities[src]
		}
		hashUser := mschapHashUser(user)
		if hashUser == "" {
			hashUser = user
		}
		authChallenge := challenge.Challenge
		peerChallenge := hex.EncodeToString(response.PeerChallenge)
		ntResponse := hex.EncodeToString(response.NTResponse)
		challengeHash := mschapv2ChallengeHash(response.PeerChallenge, mustHex(authChallenge), []byte(hashUser))
		secret := fmt.Sprintf("%s::::%s:%s:%s", user, ntResponse, peerChallenge, authChallenge)
		hashcat := fmt.Sprintf("%s::::%s:%s", user, ntResponse, hex.EncodeToString(challengeHash))
		i.emitEAPSecret(src, dst, Finding{
			Protocol: "EAP",
			Kind:     "EAP-MSCHAPv2 hashcat-5500",
			User:     user,
			Secret:   secret,
			Detail:   eapSecretDetail(5500, "crackable", "tuple", "hashcat="+hashcat),
		}, add)
	}
}

func (i *Inspector) emitEAPSecret(src, dst string, finding Finding, add func(Finding)) {
	i.eapLatest[eapPairKey(src, dst)] = finding
	add(finding)
}

func (i *Inspector) emitEAPStatus(src, dst, status, valid string, add func(Finding)) {
	finding, ok := i.eapLatest[eapPairKey(src, dst)]
	if !ok {
		return
	}
	mode := 0
	switch {
	case strings.Contains(finding.Kind, "4800"):
		mode = 4800
	case strings.Contains(finding.Kind, "5500"):
		mode = 5500
	}
	finding.Detail = eapSecretDetail(mode, status, valid, eapDetailExtras(finding.Detail)...)
	add(finding)
}

func parseSizedValue(data []byte) ([]byte, string, bool) {
	if len(data) < 1 {
		return nil, "", false
	}
	size := int(data[0])
	if size < 1 || len(data) < 1+size {
		return nil, "", false
	}
	return append([]byte(nil), data[1:1+size]...), eapPrintable(data[1+size:]), true
}

func parseLEAPValue(data []byte) ([]byte, string, bool) {
	if len(data) < 3 {
		return nil, "", false
	}
	size := int(data[2])
	if size < 1 || len(data) < 3+size {
		return nil, "", false
	}
	return append([]byte(nil), data[3:3+size]...), eapPrintable(data[3+size:]), true
}

func parseMSCHAPv2Challenge(data []byte) ([]byte, uint8, string, bool) {
	if len(data) < 5 || data[0] != eapMSCHAPv2Challenge || data[4] != 16 || len(data) < 21 {
		return nil, 0, "", false
	}
	length := int(binary.BigEndian.Uint16(data[2:4]))
	if length < 21 || length > len(data) {
		return nil, 0, "", false
	}
	data = data[:length]
	return append([]byte(nil), data[5:21]...), data[1], eapPrintable(data[21:]), true
}

type parsedMSCHAPv2Response struct {
	InnerID       uint8
	PeerChallenge []byte
	NTResponse    []byte
	User          string
}

func parseMSCHAPv2Response(data []byte) (parsedMSCHAPv2Response, bool) {
	if len(data) < 54 || data[0] != eapMSCHAPv2Response || data[4] != 49 {
		return parsedMSCHAPv2Response{}, false
	}
	length := int(binary.BigEndian.Uint16(data[2:4]))
	if length < 54 || length > len(data) {
		return parsedMSCHAPv2Response{}, false
	}
	data = data[:length]
	return parsedMSCHAPv2Response{
		InnerID:       data[1],
		PeerChallenge: append([]byte(nil), data[5:21]...),
		NTResponse:    append([]byte(nil), data[29:53]...),
		User:          eapPrintable(data[54:]),
	}, true
}

func mschapv2ChallengeHash(peerChallenge, authChallenge, user []byte) []byte {
	h := sha1.New()
	h.Write(peerChallenge)
	h.Write(authChallenge)
	h.Write(user)
	return h.Sum(nil)[:8]
}

func mschapHashUser(user string) string {
	user = strings.TrimSpace(user)
	if idx := strings.LastIndex(user, `\`); idx >= 0 {
		user = user[idx+1:]
	}
	return user
}

func eapPairKey(a, b string) string {
	if a > b {
		a, b = b, a
	}
	return a + "\x00" + b
}

func eapSecretDetail(mode int, status, valid string, extra ...string) string {
	parts := []string{fmt.Sprintf("mode=%d", mode), "status=" + status, "valid=" + valid}
	parts = append(parts, extra...)
	return strings.Join(parts, " ")
}

func eapDetailExtras(detail string) []string {
	var extra []string
	for _, part := range strings.Fields(detail) {
		if strings.HasPrefix(part, "mode=") ||
			strings.HasPrefix(part, "status=") ||
			strings.HasPrefix(part, "valid=") {
			continue
		}
		extra = append(extra, part)
	}
	return extra
}

func eapPrintable(data []byte) string {
	var out strings.Builder
	for _, b := range data {
		r := rune(b)
		if r == 0 {
			continue
		}
		if r < 0x80 && (unicode.IsPrint(r) || r == '\\') {
			out.WriteByte(b)
		}
	}
	return clean(strings.TrimSpace(out.String()))
}

func mustHex(value string) []byte {
	out, _ := hex.DecodeString(value)
	return out
}
