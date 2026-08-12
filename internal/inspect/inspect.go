package inspect

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"regexp"
	"strings"
	"sync"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

var (
	httpBasicPattern     = regexp.MustCompile(`(?i)(?:^|\r?\n)(?:proxy-)?authorization:\s*basic\s+`)
	httpNTLMPattern      = regexp.MustCompile(`(?i)(?:^|\r?\n)(?:www-|proxy-)?(?:authenticate|authorization):\s*ntlm(?:\s|$)`)
	passwordFieldPattern = regexp.MustCompile(`(?i)(?:^|[&?;\s])(?:password|pass|passwd|pwd|secret|api_key|token|auth)\s*=`)
	passwordValuePattern = regexp.MustCompile(`(?i)(?:^|[&?;\s])(?:password|pass|passwd|pwd|secret|api_key|token|auth)\s*=\s*([^&;\s\r\n]*)`)
)

const (
	maxSignalEntries   = 8192
	maxInspectionBytes = 1 << 20
	maxEncodedSignal   = 4096
)

// Signal is a protocol-risk result. Secret is a bounded transient live value;
// callers must redact it by default and must never persist it.
type Signal struct {
	Protocol  string `json:"protocol"`
	Kind      string `json:"kind"`
	DeviceMAC string `json:"device_mac,omitempty"`
	Src       string `json:"src,omitempty"`
	Dst       string `json:"dst,omitempty"`
	Secret    string `json:"secret,omitempty"`
}

// Key returns a stable semantic deduplication key.
func (f Signal) Key() string {
	return strings.Join([]string{
		strings.ToLower(f.Protocol), strings.ToLower(f.Kind),
		strings.ToLower(f.DeviceMAC), strings.ToLower(f.Src), strings.ToLower(f.Dst),
	}, "\x00")
}

// Display returns the safe default representation.
func (f Signal) Display() string {
	return f.DisplayWithRedaction(true)
}

// DisplayWithRedaction returns a bounded live-only representation.
func (f Signal) DisplayWithRedaction(redact bool) string {
	parts := []string{strings.ToUpper(cleanLabel(f.Protocol)), cleanLabel(f.Kind), "observed"}
	if secret := cleanSecret(f.Secret); secret != "" {
		if redact {
			secret = "REDACTED"
		}
		parts = append(parts, "["+secret+"]")
	}
	if f.Src != "" || f.Dst != "" {
		parts = append(parts, cleanLabel(f.Src)+" → "+cleanLabel(f.Dst))
	}
	return strings.Join(parts, " ")
}

// Encode serializes the bounded transient signal for an in-process runtime
// event. The result must not be logged or persisted.
func (f Signal) Encode() string {
	f.Protocol = cleanLabel(f.Protocol)
	f.Kind = cleanLabel(f.Kind)
	f.DeviceMAC = cleanLabel(f.DeviceMAC)
	f.Src = cleanLabel(f.Src)
	f.Dst = cleanLabel(f.Dst)
	f.Secret = cleanSecret(f.Secret)
	data, err := json.Marshal(f)
	if err != nil || len(data) > maxEncodedSignal {
		return ""
	}
	return string(data)
}

// DecodeSignal decodes and validates one bounded transient signal.
func DecodeSignal(value string) (Signal, error) {
	if len(value) > maxEncodedSignal {
		return Signal{}, fmt.Errorf("signal exceeds %d bytes", maxEncodedSignal)
	}
	var signal Signal
	decoder := json.NewDecoder(strings.NewReader(value))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&signal); err != nil {
		return Signal{}, err
	}
	var extra json.RawMessage
	if err := decoder.Decode(&extra); err != io.EOF {
		return Signal{}, fmt.Errorf("signal contains multiple values")
	}
	signal.Protocol = cleanLabel(signal.Protocol)
	signal.Kind = cleanLabel(signal.Kind)
	signal.DeviceMAC = cleanLabel(signal.DeviceMAC)
	signal.Src = cleanLabel(signal.Src)
	signal.Dst = cleanLabel(signal.Dst)
	signal.Secret = cleanSecret(signal.Secret)
	if signal.Protocol == "" || signal.Kind == "" {
		return Signal{}, fmt.Errorf("signal category is incomplete")
	}
	return signal, nil
}

// Inspector maintains bounded signal deduplication. It does not retain flow
// payloads; any extracted Secret leaves only in the transient returned Signal.
type Inspector struct {
	mu   sync.Mutex
	seen map[string]bool
}

// New returns an empty categorical inspector.
func New() *Inspector { return &Inspector{seen: make(map[string]bool)} }

// AnalyzePacket detects categorical protocol risks in one decoded packet.
func (i *Inspector) AnalyzePacket(packet gopacket.Packet) []Signal {
	if i == nil || packet == nil {
		return nil
	}
	var signals []Signal
	if signal, ok := categoricalEAPSignal(packet); ok {
		signals = append(signals, signal)
	}
	src, sport, dst, dport, payload, ok := packetFlow(packet)
	if ok {
		signals = append(signals, i.AnalyzeFlow(src, sport, dst, dport, payload, nil)...)
	}
	deviceMAC := ""
	if eth, ok := packet.Layer(layers.LayerTypeEthernet).(*layers.Ethernet); ok {
		deviceMAC = strings.ToLower(eth.SrcMAC.String())
	}
	for index := range signals {
		if signals[index].DeviceMAC == "" {
			signals[index].DeviceMAC = deviceMAC
		}
		if signals[index].Src == "" {
			signals[index].Src = src
		}
		if signals[index].Dst == "" {
			signals[index].Dst = dst
		}
	}
	return i.dedupe(signals)
}

// AnalyzeFlow identifies risky authentication protocols and, where the wire
// format is unambiguously plaintext, returns one bounded transient secret.
func (i *Inspector) AnalyzeFlow(src string, sport uint16, dst string, dport uint16, payload []byte, _ []byte) []Signal {
	if i == nil {
		return nil
	}
	payload = boundedBytes(payload, maxInspectionBytes)
	upper := bytes.ToUpper(payload)
	add := func(signals *[]Signal, protocol, kind, secret string) {
		*signals = append(*signals, Signal{Protocol: protocol, Kind: kind, Src: src, Dst: dst, Secret: cleanSecret(secret)})
	}
	var signals []Signal

	switch {
	case httpBasicPattern.Match(payload):
		add(&signals, "HTTP", "Basic authentication", httpBasicSecret(payload))
	case passwordFieldPattern.Match(payload):
		add(&signals, "HTTP", "plaintext form authentication", httpFormSecret(payload))
	}
	if bytes.Contains(payload, []byte("NTLMSSP\x00")) || httpNTLMPattern.Match(payload) {
		add(&signals, "NTLM", "authentication", "")
	}
	if portEither(sport, dport, 21) && (hasLinePrefix(upper, "USER ") || hasLinePrefix(upper, "PASS ")) {
		add(&signals, "FTP", "plaintext authentication", lineArgument(payload, "PASS "))
	}
	if portEither(sport, dport, 25, 465, 587) && (bytes.Contains(upper, []byte("AUTH PLAIN")) || bytes.Contains(upper, []byte("AUTH LOGIN"))) {
		add(&signals, "SMTP", "plaintext authentication", smtpSecret(payload))
	}
	if portEither(sport, dport, 110, 995) && (hasLinePrefix(upper, "USER ") || hasLinePrefix(upper, "PASS ")) {
		add(&signals, "POP3", "plaintext authentication", lineArgument(payload, "PASS "))
	}
	if portEither(sport, dport, 143, 993) && bytes.Contains(upper, []byte(" LOGIN ")) {
		add(&signals, "IMAP", "plaintext authentication", imapLoginSecret(payload))
	}
	if portEither(sport, dport, 194, 6667, 6697) && (hasLinePrefix(upper, "PASS ") || hasLinePrefix(upper, "USER ")) {
		add(&signals, "IRC", "plaintext authentication", lineArgument(payload, "PASS "))
	}
	if portEither(sport, dport, 389) && looksLikeLDAPSimpleBind(payload) {
		add(&signals, "LDAP", "simple bind", ldapSimpleBindSecret(payload))
	}
	if portEither(sport, dport, 88) && bytes.Contains(payload, []byte{0x17}) {
		add(&signals, "Kerberos", "RC4 pre-authentication", "")
	}
	if portEither(sport, dport, 161, 162) {
		if version, community := snmpDetails(payload); version != "" {
			add(&signals, "SNMP", version, community)
		}
	}
	if portEither(sport, dport, 1433) && len(payload) >= 8 {
		add(&signals, "MSSQL", "login exchange", "")
	}

	return i.dedupe(signals)
}

func (i *Inspector) dedupe(signals []Signal) []Signal {
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.seen == nil {
		i.seen = make(map[string]bool)
	}
	out := signals[:0]
	for _, signal := range signals {
		key := signal.Key()
		if i.seen[key] {
			continue
		}
		if len(i.seen) >= maxSignalEntries {
			clear(i.seen)
		}
		i.seen[key] = true
		out = append(out, signal)
	}
	return out
}

func packetFlow(packet gopacket.Packet) (src string, sport uint16, dst string, dport uint16, payload []byte, ok bool) {
	if ipv4, present := packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4); present {
		src, dst = ipv4.SrcIP.String(), ipv4.DstIP.String()
	} else if ipv6, present := packet.Layer(layers.LayerTypeIPv6).(*layers.IPv6); present {
		src, dst = ipv6.SrcIP.String(), ipv6.DstIP.String()
	} else {
		return "", 0, "", 0, nil, false
	}
	if tcp, present := packet.Layer(layers.LayerTypeTCP).(*layers.TCP); present {
		return src, uint16(tcp.SrcPort), dst, uint16(tcp.DstPort), tcp.Payload, true
	}
	if udp, present := packet.Layer(layers.LayerTypeUDP).(*layers.UDP); present {
		return src, uint16(udp.SrcPort), dst, uint16(udp.DstPort), udp.Payload, true
	}
	return src, 0, dst, 0, nil, false
}

func categoricalEAPSignal(packet gopacket.Packet) (Signal, bool) {
	eap, ok := packet.Layer(layers.LayerTypeEAP).(*layers.EAP)
	if !ok || eap == nil {
		return Signal{}, false
	}
	method := "authentication"
	switch eap.Type {
	case layers.EAPType(4):
		method = "EAP-MD5 authentication"
	case layers.EAPType(17):
		method = "Cisco LEAP authentication"
	case layers.EAPType(26):
		method = "EAP-MSCHAPv2 authentication"
	default:
		return Signal{}, false
	}
	if eap.Code != layers.EAPCodeRequest && eap.Code != layers.EAPCodeResponse {
		return Signal{}, false
	}
	return Signal{Protocol: "EAP", Kind: method}, true
}

func portEither(source, destination uint16, values ...uint16) bool {
	for _, value := range values {
		if source == value || destination == value {
			return true
		}
	}
	return false
}

func hasLinePrefix(payload []byte, prefix string) bool {
	return bytes.HasPrefix(payload, []byte(prefix)) || bytes.Contains(payload, []byte("\n"+prefix))
}

func looksLikeLDAPSimpleBind(payload []byte) bool {
	// LDAP BindRequest is application tag 0. A short bounded structural check
	// is sufficient before the optional bounded authentication-value scan.
	return len(payload) >= 7 && payload[0] == 0x30 && bytes.Contains(payload[:min(len(payload), 64)], []byte{0x60})
}

func snmpDetails(payload []byte) (string, string) {
	// SNMP messages begin with a sequence, INTEGER version, then an OCTET STRING
	// community. Decode only those bounded outer fields.
	if len(payload) < 7 || payload[0] != 0x30 {
		return "", ""
	}
	for index := 2; index+2 < min(len(payload), 12); index++ {
		if payload[index] != 0x02 || payload[index+1] != 0x01 {
			continue
		}
		version := ""
		switch payload[index+2] {
		case 0:
			version = "v1 community authentication"
		case 1:
			version = "v2c community authentication"
		default:
			continue
		}
		communityOffset := index + 3
		if communityOffset >= len(payload) || payload[communityOffset] != 0x04 {
			return version, ""
		}
		length, valueOffset, ok := berValue(payload, communityOffset)
		if !ok || length > 256 {
			return version, ""
		}
		return version, cleanSecret(string(payload[valueOffset : valueOffset+length]))
	}
	return "", ""
}

func httpBasicSecret(payload []byte) string {
	match := httpBasicPattern.FindIndex(payload)
	if match == nil {
		return ""
	}
	encoded := strings.Fields(string(payload[match[1]:]))
	if len(encoded) == 0 || len(encoded[0]) > 1024 {
		return ""
	}
	decoded, err := base64.StdEncoding.DecodeString(encoded[0])
	if err != nil {
		return ""
	}
	return cleanSecret(string(decoded))
}

func httpFormSecret(payload []byte) string {
	match := passwordValuePattern.FindSubmatch(payload)
	if len(match) != 2 {
		return ""
	}
	value, err := url.QueryUnescape(string(match[1]))
	if err != nil {
		return cleanSecret(string(match[1]))
	}
	return cleanSecret(value)
}

func lineArgument(payload []byte, prefix string) string {
	for _, line := range strings.Split(string(payload), "\n") {
		line = strings.TrimSpace(line)
		if len(line) >= len(prefix) && strings.EqualFold(line[:len(prefix)], prefix) {
			return cleanSecret(strings.TrimSpace(line[len(prefix):]))
		}
	}
	return ""
}

func smtpSecret(payload []byte) string {
	upper := strings.ToUpper(string(payload))
	index := strings.Index(upper, "AUTH PLAIN")
	if index < 0 {
		return ""
	}
	fields := strings.Fields(string(payload[index:]))
	if len(fields) < 3 || len(fields[2]) > 1024 {
		return ""
	}
	decoded, err := base64.StdEncoding.DecodeString(fields[2])
	if err != nil {
		return ""
	}
	parts := bytes.Split(decoded, []byte{0})
	if len(parts) == 0 {
		return ""
	}
	return cleanSecret(string(parts[len(parts)-1]))
}

func imapLoginSecret(payload []byte) string {
	for _, line := range strings.Split(string(payload), "\n") {
		fields := quotedFields(strings.TrimSpace(line))
		for index, field := range fields {
			if strings.EqualFold(field, "LOGIN") && index+2 < len(fields) {
				return cleanSecret(fields[index+2])
			}
		}
	}
	return ""
}

func quotedFields(value string) []string {
	var fields []string
	var current strings.Builder
	quoted, escaped := false, false
	flush := func() {
		if current.Len() > 0 {
			fields = append(fields, current.String())
			current.Reset()
		}
	}
	for _, r := range value {
		switch {
		case escaped:
			current.WriteRune(r)
			escaped = false
		case quoted && r == '\\':
			escaped = true
		case r == '"':
			quoted = !quoted
		case !quoted && (r == ' ' || r == '\t' || r == '\r' || r == '\n'):
			flush()
		default:
			current.WriteRune(r)
		}
	}
	flush()
	return fields
}

func ldapSimpleBindSecret(payload []byte) string {
	limit := min(len(payload), 512)
	for index := 0; index < limit; index++ {
		if payload[index] != 0x80 {
			continue
		}
		length, valueOffset, ok := berValue(payload[:limit], index)
		if ok && length <= 256 {
			return cleanSecret(string(payload[valueOffset : valueOffset+length]))
		}
	}
	return ""
}

func berValue(payload []byte, tagOffset int) (length, valueOffset int, ok bool) {
	if tagOffset < 0 || tagOffset+1 >= len(payload) {
		return 0, 0, false
	}
	lengthByte := payload[tagOffset+1]
	valueOffset = tagOffset + 2
	if lengthByte&0x80 == 0 {
		length = int(lengthByte)
	} else {
		count := int(lengthByte & 0x7f)
		if count == 0 || count > 2 || valueOffset+count > len(payload) {
			return 0, 0, false
		}
		length = 0
		for _, value := range payload[valueOffset : valueOffset+count] {
			length = length<<8 | int(value)
		}
		valueOffset += count
	}
	return length, valueOffset, length >= 0 && valueOffset+length <= len(payload)
}

func cleanSecret(value string) string {
	value = strings.TrimSpace(value)
	value = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, value)
	runes := []rune(value)
	if len(runes) > 256 {
		value = string(runes[:256])
	}
	return value
}

func boundedBytes(value []byte, limit int) []byte {
	if len(value) > limit {
		return value[:limit]
	}
	return value
}

func cleanLabel(value string) string {
	value = strings.TrimSpace(value)
	value = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, value)
	runes := []rune(value)
	if len(runes) > 128 {
		value = string(runes[:128])
	}
	return value
}
