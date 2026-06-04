package inspect

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"unicode"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

var (
	httpBasicPattern     = regexp.MustCompile(`(?i)Authorization:\s*Basic\s+([A-Za-z0-9+/=]+)`)
	httpNTLMChallengePat = regexp.MustCompile(`(?i)(?:WWW|Proxy)-Authenticate:\s*NTLM\s+([A-Za-z0-9+/=]+)`)
	httpNTLMAuthPat      = regexp.MustCompile(`(?i)(?:Authorization|Proxy-Authorization):\s*NTLM\s+([A-Za-z0-9+/=]+)`)
	passwordFieldPattern = regexp.MustCompile(`(?i)(?:^|[&?;\s])(` +
		`password|pass|_password|passwd|session_password|sessionpassword|` +
		`login_password|loginpassword|form_pw|pw|userpassword|pwd|upassword|` +
		`passwort|passwrd|wppassword|j_password|admin_password|admin_pass|` +
		`secret|api_key|token|key|auth` +
		`)\s*=\s*([^&"\s]+)`)
	cardCandidatePattern = regexp.MustCompile(`(?:\d[ -]?){13,19}`)
)

type Finding struct {
	Protocol string
	Kind     string
	User     string
	Secret   string
	Detail   string
	Src      string
	Sport    uint16
	Dst      string
	Dport    uint16
}

func (f Finding) Key() string {
	return strings.Join([]string{
		strings.ToLower(f.Protocol),
		strings.ToLower(f.Kind),
		strings.ToLower(f.User),
		strings.ToLower(f.Secret),
		strings.ToLower(f.Detail),
		f.Src,
		fmt.Sprintf("%d", f.Sport),
		f.Dst,
		fmt.Sprintf("%d", f.Dport),
	}, "\x00")
}

func (f Finding) Display() string {
	parts := []string{strings.ToUpper(f.Protocol)}
	if f.Kind != "" {
		parts = append(parts, f.Kind)
	}
	if f.User != "" {
		parts = append(parts, "user="+f.User)
	}
	if f.Secret != "" {
		parts = append(parts, "secret="+f.Secret)
	}
	if f.Detail != "" {
		parts = append(parts, f.Detail)
	}
	if f.Src != "" || f.Dst != "" {
		parts = append(parts, fmt.Sprintf("%s:%d>%s:%d", f.Src, f.Sport, f.Dst, f.Dport))
	}
	return strings.Join(parts, " ")
}

func (f Finding) Encode() string {
	data, err := json.Marshal(f)
	if err != nil {
		return ""
	}
	return string(data)
}

func DecodeFinding(value string) (Finding, error) {
	var finding Finding
	err := json.Unmarshal([]byte(value), &finding)
	return finding, err
}

type Inspector struct {
	mu             sync.Mutex
	flowUsers      map[flowKey]string
	ntlmChallenges map[flowKey]string
	eapChallenges  map[eapChallengeKey]eapChallenge
	eapIdentities  map[string]string
	eapLatest      map[string]Finding
	seen           map[string]bool
}

type flowKey struct {
	AIP   string
	APort uint16
	BIP   string
	BPort uint16
}

func New() *Inspector {
	return &Inspector{
		flowUsers:      make(map[flowKey]string),
		ntlmChallenges: make(map[flowKey]string),
		eapChallenges:  make(map[eapChallengeKey]eapChallenge),
		eapIdentities:  make(map[string]string),
		eapLatest:      make(map[string]Finding),
		seen:           make(map[string]bool),
	}
}

func (i *Inspector) AnalyzePacket(packet gopacket.Packet) []Finding {
	i.mu.Lock()
	var findings []Finding
	i.extractEAP(packet, func(f Finding) {
		i.addFinding(&findings, f)
	})
	i.mu.Unlock()

	src, dst, sport, dport, payload, ok := packetFlow(packet)
	if !ok {
		return findings
	}
	return append(findings, i.AnalyzeFlow(src, sport, dst, dport, payload, packet.Data())...)
}

func (i *Inspector) AnalyzeFlow(src string, sport uint16, dst string, dport uint16, payload []byte, raw []byte) []Finding {
	i.mu.Lock()
	defer i.mu.Unlock()

	var findings []Finding
	add := func(f Finding) {
		f.Src, f.Sport, f.Dst, f.Dport = src, sport, dst, dport
		i.addFinding(&findings, f)
	}

	i.extractNTLM(payload, src, sport, dst, dport, add)
	if len(raw) > 0 {
		i.extractNTLM(raw, src, sport, dst, dport, add)
	}
	i.extractHTTP(payload, add)
	i.extractSMTP(payload, src, sport, dst, dport, add)
	i.extractLDAP(payload, sport, dport, add)
	i.extractKerberos(payload, sport, dport, add)
	i.extractCleartext(payload, src, sport, dst, dport, add)
	i.extractCards(payload, add)

	return findings
}

func (i *Inspector) addFinding(findings *[]Finding, f Finding) {
	key := f.Key()
	if i.seen[key] {
		return
	}
	i.seen[key] = true
	*findings = append(*findings, f)
}

func (i *Inspector) extractHTTP(payload []byte, add func(Finding)) {
	payloadStr := string(payload)
	if match := httpBasicPattern.FindStringSubmatch(payloadStr); len(match) == 2 {
		if decoded, err := base64.StdEncoding.DecodeString(match[1]); err == nil {
			if user, secret, ok := strings.Cut(string(decoded), ":"); ok && user != "" && secret != "" {
				add(Finding{Protocol: "HTTP", Kind: "Basic", User: clean(user), Secret: clean(secret)})
			}
		}
	}
	for _, match := range passwordFieldPattern.FindAllStringSubmatch(payloadStr, -1) {
		if len(match) != 3 {
			continue
		}
		field := strings.ToLower(match[1])
		value, _ := url.QueryUnescape(match[2])
		value = clean(value)
		if len(value) > 3 && printable(value) {
			add(Finding{Protocol: "HTTP", Kind: field, Secret: value})
		}
	}
	for _, match := range httpNTLMChallengePat.FindAllStringSubmatch(payloadStr, -1) {
		if len(match) != 2 {
			continue
		}
		blob, err := base64.StdEncoding.DecodeString(match[1])
		if err == nil {
			i.extractNTLM(blob, "", 0, "", 0, add)
		}
	}
	for _, match := range httpNTLMAuthPat.FindAllStringSubmatch(payloadStr, -1) {
		if len(match) != 2 {
			continue
		}
		blob, err := base64.StdEncoding.DecodeString(match[1])
		if err == nil {
			i.extractNTLM(blob, "", 0, "", 0, add)
		}
	}
}

func (i *Inspector) extractNTLM(payload []byte, src string, sport uint16, dst string, dport uint16, add func(Finding)) {
	for pos := 0; pos < len(payload); {
		idx := bytes.Index(payload[pos:], []byte("NTLMSSP\x00"))
		if idx < 0 {
			return
		}
		idx += pos
		blob := payload[idx:]
		if len(blob) < 20 {
			return
		}
		msgType := binary.LittleEndian.Uint32(blob[8:12])
		key := makeFlowKey(src, sport, dst, dport)
		rev := makeFlowKey(dst, dport, src, sport)
		switch msgType {
		case 2:
			if len(blob) >= 32 {
				challenge := strings.ToUpper(hex.EncodeToString(blob[24:32]))
				i.ntlmChallenges[key] = challenge
				i.ntlmChallenges[rev] = challenge
				add(Finding{Protocol: "NTLM", Kind: "challenge", Detail: "type2"})
			}
		case 3:
			if len(blob) >= 64 {
				auth, ok := parseNTLMType3(blob)
				if ok {
					challenge := i.ntlmChallenges[key]
					if challenge == "" {
						challenge = i.ntlmChallenges[rev]
					}
					if challenge == "" {
						challenge = "0000000000000000"
					}
					version := "NTLMv1"
					secret := auth.User + "::" + auth.Domain + ":" + auth.LMResponse + ":" + auth.NTResponse + ":" + challenge
					if auth.NTLen > 24 {
						version = "NTLMv2"
						secret = auth.User + "::" + auth.Domain + ":" + challenge + ":" + auth.NTResponse[:32] + ":" + auth.NTResponse[32:]
					} else if auth.NTLen == 24 {
						secret = auth.User + "::" + auth.Domain + ":" + auth.LMResponse + ":" + auth.NTResponse + ":" + challenge
					}
					detail := "type3"
					if auth.Domain != "" {
						detail = "domain=" + auth.Domain
					}
					add(Finding{Protocol: "NTLM", Kind: version, User: auth.User, Secret: secret, Detail: detail})
				}
			}
		}
		pos = idx + 8
	}
}

type ntlmAuth struct {
	User       string
	Domain     string
	LMResponse string
	NTResponse string
	NTLen      uint16
}

func parseNTLMType3(blob []byte) (ntlmAuth, bool) {
	if len(blob) < 64 {
		return ntlmAuth{}, false
	}
	lmLen := binary.LittleEndian.Uint16(blob[12:14])
	lmOff := binary.LittleEndian.Uint32(blob[16:20])
	ntLen := binary.LittleEndian.Uint16(blob[20:22])
	ntOff := binary.LittleEndian.Uint32(blob[24:28])
	domLen := binary.LittleEndian.Uint16(blob[28:30])
	domOff := binary.LittleEndian.Uint32(blob[32:36])
	userLen := binary.LittleEndian.Uint16(blob[36:38])
	userOff := binary.LittleEndian.Uint32(blob[40:44])
	if !rangeOK(blob, lmOff, lmLen) || !rangeOK(blob, ntOff, ntLen) || !rangeOK(blob, domOff, domLen) || !rangeOK(blob, userOff, userLen) {
		return ntlmAuth{}, false
	}
	domStart := int(domOff)
	domEnd := domStart + int(domLen)
	userStart := int(userOff)
	userEnd := userStart + int(userLen)
	lmStart := int(lmOff)
	lmEnd := lmStart + int(lmLen)
	ntStart := int(ntOff)
	ntEnd := ntStart + int(ntLen)
	domain := decodeUTF16LE(blob[domStart:domEnd])
	user := decodeUTF16LE(blob[userStart:userEnd])
	auth := ntlmAuth{
		User:       clean(user),
		Domain:     clean(domain),
		LMResponse: strings.ToUpper(hex.EncodeToString(blob[lmStart:lmEnd])),
		NTResponse: strings.ToUpper(hex.EncodeToString(blob[ntStart:ntEnd])),
		NTLen:      ntLen,
	}
	if auth.NTLen > 24 && len(auth.NTResponse) < 32 {
		return ntlmAuth{}, false
	}
	return auth, auth.User != "" && auth.NTResponse != ""
}

func rangeOK(payload []byte, off uint32, length uint16) bool {
	if off > uint32(len(payload)) {
		return false
	}
	end := int(off) + int(length)
	return end <= len(payload)
}

func (i *Inspector) extractSMTP(payload []byte, src string, sport uint16, dst string, dport uint16, add func(Finding)) {
	if !portAny(sport, dport, 25, 465, 587) {
		return
	}
	key := makeFlowKey(src, sport, dst, dport)
	for _, line := range splitLines(payload) {
		upper := strings.ToUpper(line)
		switch {
		case strings.HasPrefix(upper, "AUTH PLAIN "):
			decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(line[11:]))
			if err != nil {
				continue
			}
			parts := strings.Split(string(decoded), "\x00")
			if len(parts) >= 3 && parts[1] != "" && parts[2] != "" {
				add(Finding{Protocol: "SMTP", Kind: "AUTH PLAIN", User: clean(parts[1]), Secret: clean(parts[2])})
			}
		case strings.HasPrefix(upper, "AUTH LOGIN"):
			continue
		case i.flowUsers[key] != "":
			decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(line))
			if err == nil && len(decoded) > 0 {
				add(Finding{Protocol: "SMTP", Kind: "AUTH LOGIN", User: i.flowUsers[key], Secret: clean(string(decoded))})
				delete(i.flowUsers, key)
			}
		default:
			decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(line))
			if err == nil && strings.Contains(string(decoded), "@") {
				i.flowUsers[key] = clean(string(decoded))
			}
		}
	}
}

func (i *Inspector) extractLDAP(payload []byte, sport, dport uint16, add func(Finding)) {
	if !portAny(sport, dport, 389, 636) || len(payload) < 10 || payload[0] != 0x30 {
		return
	}
	dn, secret, ok := parseLDAPSimpleBind(payload)
	if ok {
		if secret == "" {
			secret = "(empty)"
		}
		add(Finding{Protocol: "LDAP", Kind: "Simple Bind", User: clean(dn), Secret: clean(secret)})
	}
}

func (i *Inspector) extractKerberos(payload []byte, sport, dport uint16, add func(Finding)) {
	if !portAny(sport, dport, 88) || len(payload) < 50 {
		return
	}
	if payload[17] == 0x0a && payload[39] == 0x17 {
		user, hash, ok := parseKerberosASREQHash(payload)
		if ok {
			add(Finding{Protocol: "Kerberos", Kind: "AS-REQ etype23", User: user, Secret: hash})
		}
	}
}

func parseKerberosASREQHash(payload []byte) (string, string, bool) {
	var hash []byte
	var nameOffset int
	switch {
	case len(payload) >= 198 && (bytes.Equal(payload[40:44], []byte{0xa2, 0x36, 0x04, 0x34}) || bytes.Equal(payload[40:44], []byte{0xa2, 0x35, 0x04, 0x33})):
		hashLen := int(payload[41])
		if hashLen != 53 && hashLen != 54 {
			return "", "", false
		}
		if 44+hashLen > len(payload) {
			return "", "", false
		}
		hash = payload[44 : 44+hashLen]
		nameOffset = 143
		if hashLen == 54 {
			nameOffset = 144
		}
	default:
		if len(payload) <= 49 {
			return "", "", false
		}
		hashLen := int(payload[48])
		if hashLen <= 16 || 49+hashLen > len(payload) {
			return "", "", false
		}
		hash = payload[49 : 49+hashLen]
		nameOffset = hashLen + 97
	}

	if len(hash) <= 16 || nameOffset >= len(payload) {
		return "", "", false
	}
	nameLen := int(payload[nameOffset])
	nameStart := nameOffset + 1
	nameEnd := nameStart + nameLen
	if nameLen <= 0 || nameEnd > len(payload) {
		return "", "", false
	}
	domainOffset := nameEnd + 3
	if domainOffset >= len(payload) {
		return "", "", false
	}
	domainLen := int(payload[domainOffset])
	domainStart := domainOffset + 1
	domainEnd := domainStart + domainLen
	if domainLen <= 0 || domainEnd > len(payload) {
		return "", "", false
	}

	name := clean(string(payload[nameStart:nameEnd]))
	domain := strings.ToUpper(clean(string(payload[domainStart:domainEnd])))
	switched := append([]byte(nil), hash[16:]...)
	switched = append(switched, hash[:16]...)
	hashLine := fmt.Sprintf("$krb5pa$23$%s$%s$dummy$%s", name, domain, strings.ToUpper(hex.EncodeToString(switched)))
	return name, hashLine, name != "" && domain != ""
}

func (i *Inspector) extractCleartext(payload []byte, src string, sport uint16, dst string, dport uint16, add func(Finding)) {
	key := makeFlowKey(src, sport, dst, dport)
	isIRC := portRange(sport, dport, 6660, 6669) || portAny(sport, dport, 6697, 7000)
	lines := splitLines(payload)
	for _, line := range lines {
		upper := strings.ToUpper(line)
		if strings.HasPrefix(upper, "NICK ") || strings.HasPrefix(upper, "JOIN ") {
			isIRC = true
			break
		}
	}
	for _, line := range lines {
		upper := strings.ToUpper(line)
		switch {
		case isIRC && strings.HasPrefix(upper, "USER "):
			user := firstField(line[5:])
			i.flowUsers[key] = user
			add(Finding{Protocol: "IRC", Kind: "USER", User: user})
		case isIRC && strings.HasPrefix(upper, "PASS "):
			add(Finding{Protocol: "IRC", Kind: "PASS", User: i.flowUsers[key], Secret: clean(line[5:])})
			delete(i.flowUsers, key)
		case isIRC && strings.HasPrefix(upper, "NICK "):
			add(Finding{Protocol: "IRC", Kind: "NICK", User: clean(line[5:])})
		case strings.HasPrefix(upper, "USER ") && portAny(sport, dport, 21, 110):
			user := clean(line[5:])
			i.flowUsers[key] = user
			proto := "FTP"
			if portAny(sport, dport, 110) {
				proto = "POP3"
			}
			add(Finding{Protocol: proto, Kind: "USER", User: user})
		case strings.HasPrefix(upper, "PASS ") && portAny(sport, dport, 21, 110):
			proto := "FTP"
			if portAny(sport, dport, 110) {
				proto = "POP3"
			}
			add(Finding{Protocol: proto, Kind: "PASS", User: i.flowUsers[key], Secret: clean(line[5:])})
			delete(i.flowUsers, key)
		case strings.Contains(upper, " LOGIN ") && portAny(sport, dport, 143):
			parts := strings.Fields(line)
			if len(parts) >= 4 && strings.EqualFold(parts[1], "LOGIN") {
				add(Finding{Protocol: "IMAP", Kind: "LOGIN", User: clean(parts[2]), Secret: clean(parts[3])})
			}
		}
	}
	if portAny(sport, dport, 161, 162) {
		if community, version, ok := parseSNMPCommunity(payload); ok {
			add(Finding{Protocol: "SNMP", Kind: version, Secret: clean(community)})
		}
	}
	if portAny(sport, dport, 1433) {
		if user, secret, ok := parseMSSQLLogin(payload); ok {
			add(Finding{Protocol: "MSSQL", Kind: "Login", User: user, Secret: secret})
		}
	}
}

func (i *Inspector) extractCards(payload []byte, add func(Finding)) {
	text := string(payload)
	for _, candidate := range cardCandidatePattern.FindAllString(text, -1) {
		digits := onlyDigits(candidate)
		if len(digits) < 13 || len(digits) > 19 || !luhnValid(digits) {
			continue
		}
		add(Finding{Protocol: "CARD", Kind: "number", Secret: digits})
	}
}

func packetFlow(packet gopacket.Packet) (string, string, uint16, uint16, []byte, bool) {
	var src, dst string
	if layer := packet.Layer(layers.LayerTypeIPv4); layer != nil {
		ip, _ := layer.(*layers.IPv4)
		src, dst = ip.SrcIP.String(), ip.DstIP.String()
	} else if layer := packet.Layer(layers.LayerTypeIPv6); layer != nil {
		ip, _ := layer.(*layers.IPv6)
		src, dst = ip.SrcIP.String(), ip.DstIP.String()
	}
	if layer := packet.Layer(layers.LayerTypeTCP); layer != nil {
		tcp, _ := layer.(*layers.TCP)
		return src, dst, uint16(tcp.SrcPort), uint16(tcp.DstPort), tcp.Payload, true
	}
	if layer := packet.Layer(layers.LayerTypeUDP); layer != nil {
		udp, _ := layer.(*layers.UDP)
		return src, dst, uint16(udp.SrcPort), uint16(udp.DstPort), udp.Payload, true
	}
	return "", "", 0, 0, nil, false
}

func makeFlowKey(src string, sport uint16, dst string, dport uint16) flowKey {
	if sport > dport {
		return flowKey{src, sport, dst, dport}
	}
	return flowKey{dst, dport, src, sport}
}

func splitLines(payload []byte) []string {
	normalized := strings.ReplaceAll(string(payload), "\r\n", "\n")
	normalized = strings.ReplaceAll(normalized, "\r", "\n")
	raw := strings.Split(normalized, "\n")
	lines := make([]string, 0, len(raw))
	for _, line := range raw {
		line = clean(line)
		if line != "" {
			lines = append(lines, line)
		}
	}
	return lines
}

func parseLDAPSimpleBind(payload []byte) (string, string, bool) {
	pos := 1
	if _, ok := readASN1Length(payload, &pos); !ok {
		return "", "", false
	}
	if pos+2 > len(payload) || payload[pos] != 0x02 {
		return "", "", false
	}
	pos += 2 + int(payload[pos+1])
	if pos >= len(payload) || payload[pos] != 0x60 {
		return "", "", false
	}
	pos++
	if _, ok := readASN1Length(payload, &pos); !ok {
		return "", "", false
	}
	if pos+2 > len(payload) || payload[pos] != 0x02 {
		return "", "", false
	}
	pos += 2 + int(payload[pos+1])
	if pos+2 > len(payload) || payload[pos] != 0x04 {
		return "", "", false
	}
	dnLen := int(payload[pos+1])
	pos += 2
	if pos+dnLen > len(payload) {
		return "", "", false
	}
	dn := string(payload[pos : pos+dnLen])
	pos += dnLen
	if pos+2 > len(payload) || payload[pos] != 0x80 {
		return "", "", false
	}
	secretLen := int(payload[pos+1])
	pos += 2
	if pos+secretLen > len(payload) {
		return "", "", false
	}
	return dn, string(payload[pos : pos+secretLen]), true
}

func readASN1Length(payload []byte, pos *int) (int, bool) {
	if *pos >= len(payload) {
		return 0, false
	}
	length := int(payload[*pos])
	*pos = *pos + 1
	if length&0x80 == 0 {
		return length, true
	}
	count := length & 0x7f
	if count == 0 || *pos+count > len(payload) {
		return 0, false
	}
	length = 0
	for j := 0; j < count; j++ {
		length = (length << 8) | int(payload[*pos+j])
	}
	*pos += count
	return length, true
}

func parseSNMPCommunity(payload []byte) (string, string, bool) {
	if len(payload) <= 20 || payload[0] != 0x30 {
		return "", "", false
	}
	snmpv1 := len(payload) > 7 && payload[4] == 0x02 && payload[5] == 0x01 && (payload[6] == 0 || payload[6] == 1)
	snmpv2c := len(payload) > 5 && payload[2] == 0x02 && payload[3] == 0x01 && (payload[4] == 0 || payload[4] == 1)
	start := -1
	version := ""
	if snmpv1 {
		start = bytes.IndexByte(payload[7:], 0x04)
		if start >= 0 {
			start += 7
		}
		version = "SNMPv1"
	} else if snmpv2c {
		start = bytes.IndexByte(payload[5:], 0x04)
		if start >= 0 {
			start += 5
		}
		version = "SNMPv2c"
	}
	if start < 0 || start+2 > len(payload) {
		return "", "", false
	}
	length := int(payload[start+1])
	if length <= 0 || length >= 50 || start+2+length > len(payload) {
		return "", "", false
	}
	community := string(payload[start+2 : start+2+length])
	return community, version, printable(community)
}

func parseMSSQLLogin(payload []byte) (string, string, bool) {
	if len(payload) < 58 || payload[0] != 0x10 || payload[1] != 0x01 {
		return "", "", false
	}
	userOffset := int(binary.LittleEndian.Uint16(payload[36:38]))
	userLen := int(binary.LittleEndian.Uint16(payload[38:40])) * 2
	passOffset := int(binary.LittleEndian.Uint16(payload[40:42]))
	passLen := int(binary.LittleEndian.Uint16(payload[42:44])) * 2
	if userLen <= 0 || passLen <= 0 || userLen > 400 || passLen > 400 {
		return "", "", false
	}
	base := 8
	if base+userOffset+userLen > len(payload) || base+passOffset+passLen > len(payload) {
		return "", "", false
	}
	user := decodeUTF16LE(payload[base+userOffset : base+userOffset+userLen])
	encoded := append([]byte(nil), payload[base+passOffset:base+passOffset+passLen]...)
	for i := range encoded {
		encoded[i] ^= 0xa5
	}
	reverse(encoded)
	secret := decodeUTF16LE(encoded)
	return clean(user), clean(secret), user != "" && secret != ""
}

func decodeUTF16LE(data []byte) string {
	if len(data)%2 != 0 {
		data = data[:len(data)-1]
	}
	runes := make([]rune, 0, len(data)/2)
	for i := 0; i+1 < len(data); i += 2 {
		v := binary.LittleEndian.Uint16(data[i : i+2])
		if v != 0 {
			runes = append(runes, rune(v))
		}
	}
	return string(runes)
}

func reverse(data []byte) {
	for left, right := 0, len(data)-1; left < right; left, right = left+1, right-1 {
		data[left], data[right] = data[right], data[left]
	}
}

func onlyDigits(value string) string {
	var out strings.Builder
	for _, r := range value {
		if r >= '0' && r <= '9' {
			out.WriteRune(r)
		}
	}
	return out.String()
}

func luhnValid(digits string) bool {
	var sum int
	double := false
	for i := len(digits) - 1; i >= 0; i-- {
		n := int(digits[i] - '0')
		if double {
			n *= 2
			if n > 9 {
				n -= 9
			}
		}
		sum += n
		double = !double
	}
	return sum%10 == 0
}

func firstField(value string) string {
	fields := strings.Fields(value)
	if len(fields) == 0 {
		return ""
	}
	return clean(fields[0])
}

func clean(value string) string {
	value = strings.TrimSpace(value)
	value = strings.Trim(value, `"'`)
	return strings.Map(func(r rune) rune {
		if r == 0 || unicode.IsControl(r) {
			return -1
		}
		return r
	}, value)
}

func printable(value string) bool {
	if strings.TrimSpace(value) == "" {
		return false
	}
	for _, r := range value {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}

func portAny(sport, dport uint16, ports ...uint16) bool {
	for _, port := range ports {
		if sport == port || dport == port {
			return true
		}
	}
	return false
}

func portRange(sport, dport uint16, start, end uint16) bool {
	return (sport >= start && sport <= end) || (dport >= start && dport <= end)
}
