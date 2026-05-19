package stealth

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// CredentialExposure records passive evidence that credential or sensitive
// authentication material crossed the bridge and associates it with a service
// endpoint. Cleartext values are stored for operator visibility; hash-oriented
// protocols are recorded as evidence unless a dedicated exporter is added.
type CredentialExposure struct {
	Protocol      string
	Service       string
	SrcIP         net.IP
	DstIP         net.IP
	ServiceIP     net.IP
	SrcPort       uint16
	DstPort       uint16
	ServicePort   uint16
	VLANID        uint16
	Username      string
	SecretKind    string
	SecretValue   string
	SecretPreview string
	Evidence      string
	Host          string
	Path          string
	FirstSeen     time.Time
	LastSeen      time.Time
	Count         int
}

// CredentialExposureSummary is the bounded copy rendered by the TUI.
type CredentialExposureSummary struct {
	Protocol      string
	Service       string
	SrcIP         net.IP
	DstIP         net.IP
	ServiceIP     net.IP
	SrcPort       uint16
	DstPort       uint16
	ServicePort   uint16
	VLANID        uint16
	Username      string
	SecretKind    string
	SecretValue   string
	SecretPreview string
	Evidence      string
	Host          string
	Path          string
	LastSeen      time.Time
	Count         int
}

type credentialSession struct {
	Username string
	Stage    string
	Updated  time.Time
}

const maxCredentialPayloadInspect = 8192

var (
	httpMethods = map[string]bool{
		"GET": true, "POST": true, "PUT": true, "PATCH": true, "DELETE": true,
		"HEAD": true, "OPTIONS": true,
	}
	userFieldNames = map[string]bool{
		"user": true, "username": true, "login": true, "email": true,
		"userid": true, "user_id": true, "account": true, "name": true,
	}
	secretFieldNames = map[string]string{
		"password": "password", "pass": "password", "passwd": "password",
		"pwd": "password", "token": "token", "api_key": "api key",
		"apikey": "api key", "secret": "secret", "access_token": "token",
		"auth_token": "token", "key": "key",
	}
)

func (o *Observer) processCredentialExposure(packet gopacket.Packet, ipv4 *layers.IPv4, vlanID uint16,
	nm *NetworkMap, now time.Time, eventLog func(string)) {
	if packet == nil || ipv4 == nil || nm == nil {
		return
	}

	findings := make([]CredentialExposure, 0, 2)

	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp, _ := tcpLayer.(*layers.TCP)
		if len(tcp.Payload) > 0 {
			payload := boundedPayload(tcp.Payload)
			srcPort := uint16(tcp.SrcPort)
			dstPort := uint16(tcp.DstPort)
			findings = append(findings, detectHTTPCredentialExposures(ipv4, srcPort, dstPort, vlanID, payload)...)
			findings = append(findings, o.detectLineCredentialExposures(nm, ipv4, srcPort, dstPort, vlanID, now, payload)...)
			findings = append(findings, detectNTLMExposure(ipv4, srcPort, dstPort, vlanID, payload)...)
			findings = append(findings, detectMSSQLExposure(ipv4, srcPort, dstPort, vlanID, payload)...)
			findings = append(findings, detectKerberosExposure(ipv4, srcPort, dstPort, vlanID, payload)...)
			findings = append(findings, detectPaymentCardExposure(ipv4, srcPort, dstPort, vlanID, payload, "TCP")...)
			if isLDAPPlaintextBindPort(srcPort, dstPort) && dstPort == 389 {
				if dn, password, ok := parseLDAPSimpleBind(payload); ok {
					findings = append(findings, baseCredentialExposure("LDAP", ipv4, srcPort, dstPort, vlanID, "LDAP Simple Bind").
						withUser(dn).
						withSecret("password", password))
				}
			}
		}
	}

	if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		udp, _ := udpLayer.(*layers.UDP)
		srcPort := uint16(udp.SrcPort)
		dstPort := uint16(udp.DstPort)
		if len(udp.Payload) > 0 && dstPort == 161 {
			if community, ok := parseSNMPCommunity(boundedPayload(udp.Payload)); ok {
				findings = append(findings, baseCredentialExposure("SNMP", ipv4, srcPort, dstPort, vlanID, "SNMP community").
					withSecret("community", community))
			}
		}
		if len(udp.Payload) > 0 {
			payload := boundedPayload(udp.Payload)
			findings = append(findings, detectKerberosExposure(ipv4, srcPort, dstPort, vlanID, payload)...)
			findings = append(findings, detectPaymentCardExposure(ipv4, srcPort, dstPort, vlanID, payload, "UDP")...)
		}
	}

	for _, finding := range findings {
		o.addCredentialExposure(nm, finding, now, eventLog)
	}
}

func boundedPayload(payload []byte) []byte {
	if len(payload) > maxCredentialPayloadInspect {
		return payload[:maxCredentialPayloadInspect]
	}
	return payload
}

func detectHTTPCredentialExposures(ipv4 *layers.IPv4, srcPort, dstPort, vlanID uint16, payload []byte) []CredentialExposure {
	if !looksHTTPRequest(payload) {
		return nil
	}

	head, body := splitHTTPMessage(payload)
	lines := splitProtocolLines(head)
	if len(lines) == 0 {
		return nil
	}

	requestParts := strings.Fields(lines[0])
	if len(requestParts) < 2 {
		return nil
	}

	method := strings.ToUpper(requestParts[0])
	target := requestParts[1]
	host := ""
	contentType := ""
	findings := make([]CredentialExposure, 0, 2)

	for _, line := range lines[1:] {
		name, value, ok := splitHeader(line)
		if !ok {
			continue
		}
		switch strings.ToLower(name) {
		case "host":
			host = sanitizeDisplayString(value)
		case "content-type":
			contentType = strings.ToLower(value)
		case "authorization", "proxy-authorization":
			if user, password, ok := parseHTTPBasic(value); ok {
				evidence := "HTTP Basic Authorization"
				if strings.EqualFold(name, "proxy-authorization") {
					evidence = "HTTP Proxy Basic Authorization"
				}
				finding := baseCredentialExposure("HTTP", ipv4, srcPort, dstPort, vlanID, evidence).
					withUser(user).
					withSecret("password", password)
				finding.Host = host
				finding.Path = sanitizeHTTPPath(target)
				findings = append(findings, finding)
			}
			if authLen, ok := parseHTTPNTLM(value); ok {
				finding := baseCredentialExposure("NTLM", ipv4, srcPort, dstPort, vlanID, "HTTP NTLM authentication material")
				finding.Host = host
				finding.Path = sanitizeHTTPPath(target)
				finding.SecretKind = "ntlm response"
				finding.SecretPreview = redactedBytes(authLen)
				findings = append(findings, finding)
			}
		}
	}

	if values, ok := parseHTTPParamsFromTarget(target); ok {
		findings = append(findings, httpParamFindings(ipv4, srcPort, dstPort, vlanID, host, target, method, "HTTP query field", values)...)
	}
	if len(body) > 0 && (strings.Contains(contentType, "application/x-www-form-urlencoded") || looksLikeFormBody(body)) {
		if values, err := url.ParseQuery(string(body)); err == nil {
			findings = append(findings, httpParamFindings(ipv4, srcPort, dstPort, vlanID, host, target, method, "HTTP form field", values)...)
		}
	}

	return findings
}

func (o *Observer) detectLineCredentialExposures(nm *NetworkMap, ipv4 *layers.IPv4, srcPort, dstPort, vlanID uint16, now time.Time, payload []byte) []CredentialExposure {
	service := lineCredentialService(dstPort)
	if service == "" {
		return nil
	}

	lines := splitProtocolLines(payload)
	findings := make([]CredentialExposure, 0, 1)
	sessionKey := credentialSessionKey(service, ipv4.SrcIP, srcPort, ipv4.DstIP, dstPort)

	for _, line := range lines {
		fields := splitCommandFields(line)
		if len(fields) == 0 {
			continue
		}
		command := strings.ToUpper(fields[0])

		switch service {
		case "FTP", "POP3":
			switch command {
			case "USER":
				if len(fields) >= 2 {
					o.setCredentialSession(nm, sessionKey, credentialSession{Username: fields[1], Updated: now})
				}
			case "PASS":
				if len(fields) >= 2 {
					session := o.getCredentialSession(nm, sessionKey)
					findings = append(findings, baseCredentialExposure(service, ipv4, srcPort, dstPort, vlanID, service+" PASS command").
						withUser(session.Username).
						withSecret("password", fields[1]))
				}
			}
		case "IMAP":
			if len(fields) >= 4 && strings.EqualFold(fields[1], "LOGIN") {
				findings = append(findings, baseCredentialExposure("IMAP", ipv4, srcPort, dstPort, vlanID, "IMAP LOGIN command").
					withUser(fields[2]).
					withSecret("password", fields[3]))
			}
		case "SMTP":
			if command == "AUTH" && len(fields) >= 2 && strings.EqualFold(fields[1], "PLAIN") {
				if len(fields) >= 3 {
					if user, password, ok := decodeSMTPPlain(fields[2]); ok {
						findings = append(findings, baseCredentialExposure("SMTP", ipv4, srcPort, dstPort, vlanID, "SMTP AUTH PLAIN").
							withUser(user).
							withSecret("password", password))
					}
				}
			} else if command == "AUTH" && len(fields) >= 2 && strings.EqualFold(fields[1], "LOGIN") {
				if len(fields) >= 3 {
					if user, ok := decodeBase64Text(fields[2]); ok {
						o.setCredentialSession(nm, sessionKey, credentialSession{Username: user, Stage: "smtp-login-password", Updated: now})
					}
				} else {
					o.setCredentialSession(nm, sessionKey, credentialSession{Stage: "smtp-login-username", Updated: now})
				}
			} else if len(fields) == 1 && looksBase64Token(fields[0]) {
				session := o.getCredentialSession(nm, sessionKey)
				switch session.Stage {
				case "smtp-login-username":
					if user, ok := decodeBase64Text(fields[0]); ok {
						o.setCredentialSession(nm, sessionKey, credentialSession{Username: user, Stage: "smtp-login-password", Updated: now})
					}
				case "smtp-login-password":
					if password, ok := decodeBase64Text(fields[0]); ok {
						findings = append(findings, baseCredentialExposure("SMTP", ipv4, srcPort, dstPort, vlanID, "SMTP AUTH LOGIN").
							withUser(session.Username).
							withSecret("password", password))
					}
				}
			}
		case "IRC":
			switch command {
			case "NICK", "USER":
				if len(fields) >= 2 {
					session := o.getCredentialSession(nm, sessionKey)
					session.Username = fields[1]
					session.Updated = now
					o.setCredentialSession(nm, sessionKey, session)
				}
			case "PASS":
				if len(fields) >= 2 {
					session := o.getCredentialSession(nm, sessionKey)
					findings = append(findings, baseCredentialExposure("IRC", ipv4, srcPort, dstPort, vlanID, "IRC PASS command").
						withUser(session.Username).
						withSecret("password", fields[1]))
				}
			}
		}
	}

	return findings
}

func (o *Observer) addCredentialExposure(nm *NetworkMap, finding CredentialExposure, now time.Time, eventLog func(string)) {
	if finding.Service == "" || len(finding.ServiceIP) == 0 || finding.ServicePort == 0 || finding.SecretKind == "" {
		return
	}
	if finding.SecretPreview == "" {
		finding.SecretPreview = "[redacted]"
	}
	if finding.Username == "" {
		finding.Username = "unknown"
	}
	if finding.FirstSeen.IsZero() {
		finding.FirstSeen = now
	}
	finding.LastSeen = now
	finding.Count = 1

	key := credentialExposureKey(finding)
	secretDisplay := credentialSecretDisplay(finding.SecretPreview, finding.SecretValue)
	summary := fmt.Sprintf("%s %s user=%s secret=%s",
		finding.Service, serviceEndpoint(finding.ServiceIP, finding.ServicePort),
		finding.Username, secretDisplay)
	if finding.Evidence != "" {
		summary = finding.Evidence + " on " + serviceEndpoint(finding.ServiceIP, finding.ServicePort) + " user=" + finding.Username + " secret=" + secretDisplay
	}

	isNew := false
	nm.mu.Lock()
	if existing, ok := nm.CredentialFindings[key]; ok {
		existing.LastSeen = now
		existing.Count++
	} else {
		if len(nm.CredentialFindings) >= nm.maxCredentials {
			pruneOldestCredentialLocked(nm)
		}
		dup := copyCredentialExposure(finding)
		nm.CredentialFindings[key] = &dup
		o.addEventLocked(nm, NACEvent{
			Timestamp: now,
			Kind:      "CRED",
			Interface: o.iface,
			Direction: finding.SrcIP.String() + "→" + finding.DstIP.String(),
			Summary:   summary,
			VLANID:    finding.VLANID,
			SrcIP:     copyIP(finding.SrcIP),
			DstIP:     copyIP(finding.DstIP),
		})
		isNew = true
	}
	nm.mu.Unlock()

	if isNew && eventLog != nil {
		eventLog("[!][AUTH] Cleartext credential exposure: " + summary)
	}
}

func (o *Observer) setCredentialSession(nm *NetworkMap, key string, session credentialSession) {
	if nm == nil || key == "" {
		return
	}
	if session.Updated.IsZero() {
		session.Updated = time.Now()
	}
	session.Username = sanitizeDisplayString(session.Username)
	nm.mu.Lock()
	defer nm.mu.Unlock()
	if len(nm.CredentialSessions) >= nm.maxCredentialSessions {
		pruneCredentialSessionsLocked(nm, session.Updated)
	}
	nm.CredentialSessions[key] = session
}

func (o *Observer) getCredentialSession(nm *NetworkMap, key string) credentialSession {
	if nm == nil || key == "" {
		return credentialSession{}
	}
	nm.mu.RLock()
	defer nm.mu.RUnlock()
	return nm.CredentialSessions[key]
}

func copyCredentialExposure(in CredentialExposure) CredentialExposure {
	out := in
	out.SrcIP = copyIP(in.SrcIP)
	out.DstIP = copyIP(in.DstIP)
	out.ServiceIP = copyIP(in.ServiceIP)
	return out
}

func copyCredentialSummary(in *CredentialExposure) CredentialExposureSummary {
	return CredentialExposureSummary{
		Protocol:      in.Protocol,
		Service:       in.Service,
		SrcIP:         copyIP(in.SrcIP),
		DstIP:         copyIP(in.DstIP),
		ServiceIP:     copyIP(in.ServiceIP),
		SrcPort:       in.SrcPort,
		DstPort:       in.DstPort,
		ServicePort:   in.ServicePort,
		VLANID:        in.VLANID,
		Username:      in.Username,
		SecretKind:    in.SecretKind,
		SecretValue:   in.SecretValue,
		SecretPreview: in.SecretPreview,
		Evidence:      in.Evidence,
		Host:          in.Host,
		Path:          in.Path,
		LastSeen:      in.LastSeen,
		Count:         in.Count,
	}
}

func baseCredentialExposure(service string, ipv4 *layers.IPv4, srcPort, dstPort, vlanID uint16, evidence string) CredentialExposure {
	serviceIP := ipv4.DstIP
	servicePort := dstPort
	if isKnownServicePort(srcPort) && !isKnownServicePort(dstPort) {
		serviceIP = ipv4.SrcIP
		servicePort = srcPort
	}
	return CredentialExposure{
		Protocol:    service,
		Service:     service,
		SrcIP:       copyIP(ipv4.SrcIP),
		DstIP:       copyIP(ipv4.DstIP),
		ServiceIP:   copyIP(serviceIP),
		SrcPort:     srcPort,
		DstPort:     dstPort,
		ServicePort: servicePort,
		VLANID:      vlanID,
		Evidence:    evidence,
	}
}

func (finding CredentialExposure) withUser(username string) CredentialExposure {
	finding.Username = sanitizeDisplayString(username)
	return finding
}

func (finding CredentialExposure) withSecret(kind, secret string) CredentialExposure {
	finding.SecretKind = sanitizeDisplayString(kind)
	finding.SecretValue = sanitizeDisplayString(secret)
	finding.SecretPreview = redactedSecret(secret)
	return finding
}

func credentialExposureKey(finding CredentialExposure) string {
	parts := []string{
		finding.Service,
		finding.ServiceIP.String(),
		strconv.Itoa(int(finding.ServicePort)),
		finding.Username,
		finding.SecretKind,
		finding.Evidence,
		finding.Host,
		finding.Path,
		strconv.Itoa(int(finding.VLANID)),
	}
	if finding.SecretValue != "" {
		parts = append(parts, finding.SecretValue)
	}
	return strings.Join(parts, "|")
}

func credentialSessionKey(service string, clientIP net.IP, clientPort uint16, serverIP net.IP, serverPort uint16) string {
	return strings.Join([]string{
		service,
		clientIP.String(),
		strconv.Itoa(int(clientPort)),
		serverIP.String(),
		strconv.Itoa(int(serverPort)),
	}, "|")
}

func pruneOldestCredentialLocked(nm *NetworkMap) {
	var oldestKey string
	var oldest time.Time
	for key, finding := range nm.CredentialFindings {
		if oldestKey == "" || finding.LastSeen.Before(oldest) {
			oldestKey = key
			oldest = finding.LastSeen
		}
	}
	if oldestKey != "" {
		delete(nm.CredentialFindings, oldestKey)
	}
}

func pruneCredentialSessionsLocked(nm *NetworkMap, now time.Time) {
	cutoff := now.Add(-10 * time.Minute)
	for key, session := range nm.CredentialSessions {
		if session.Updated.Before(cutoff) {
			delete(nm.CredentialSessions, key)
		}
	}
	if len(nm.CredentialSessions) < nm.maxCredentialSessions {
		return
	}

	var oldestKey string
	var oldest time.Time
	for key, session := range nm.CredentialSessions {
		if oldestKey == "" || session.Updated.Before(oldest) {
			oldestKey = key
			oldest = session.Updated
		}
	}
	if oldestKey != "" {
		delete(nm.CredentialSessions, oldestKey)
	}
}

func looksHTTPRequest(payload []byte) bool {
	lineEnd := strings.IndexByte(string(payload), '\n')
	if lineEnd < 0 {
		lineEnd = len(payload)
	}
	firstLine := strings.TrimSpace(string(payload[:lineEnd]))
	fields := strings.Fields(firstLine)
	return len(fields) >= 2 && httpMethods[strings.ToUpper(fields[0])]
}

func splitHTTPMessage(payload []byte) ([]byte, []byte) {
	if idx := strings.Index(string(payload), "\r\n\r\n"); idx >= 0 {
		return payload[:idx], payload[idx+4:]
	}
	if idx := strings.Index(string(payload), "\n\n"); idx >= 0 {
		return payload[:idx], payload[idx+2:]
	}
	return payload, nil
}

func splitProtocolLines(payload []byte) []string {
	raw := strings.ReplaceAll(string(payload), "\r\n", "\n")
	parts := strings.Split(raw, "\n")
	lines := make([]string, 0, len(parts))
	for _, part := range parts {
		line := strings.TrimSpace(part)
		if line != "" {
			lines = append(lines, line)
		}
	}
	return lines
}

func splitHeader(line string) (string, string, bool) {
	idx := strings.IndexByte(line, ':')
	if idx <= 0 {
		return "", "", false
	}
	return strings.TrimSpace(line[:idx]), strings.TrimSpace(line[idx+1:]), true
}

func parseHTTPBasic(value string) (string, string, bool) {
	parts := strings.Fields(value)
	if len(parts) < 2 || !strings.EqualFold(parts[0], "Basic") {
		return "", "", false
	}
	decoded, ok := decodeBase64Bytes(parts[1])
	if !ok {
		return "", "", false
	}
	user, password, ok := strings.Cut(string(decoded), ":")
	if !ok || password == "" {
		return "", "", false
	}
	return user, password, true
}

func parseHTTPNTLM(value string) (int, bool) {
	parts := strings.Fields(value)
	if len(parts) < 2 || !strings.EqualFold(parts[0], "NTLM") {
		return 0, false
	}
	decoded, ok := decodeBase64Bytes(parts[1])
	if !ok || !isNTLMType3(decoded) {
		return 0, false
	}
	return len(decoded), true
}

func parseHTTPParamsFromTarget(target string) (url.Values, bool) {
	idx := strings.IndexByte(target, '?')
	if idx < 0 || idx == len(target)-1 {
		return nil, false
	}
	values, err := url.ParseQuery(target[idx+1:])
	if err != nil || len(values) == 0 {
		return nil, false
	}
	return values, true
}

func httpParamFindings(ipv4 *layers.IPv4, srcPort, dstPort, vlanID uint16, host, target, method, evidence string, values url.Values) []CredentialExposure {
	username := firstCredentialField(values, userFieldNames)
	findings := make([]CredentialExposure, 0, 1)
	for key, vals := range values {
		kind, ok := secretFieldNames[strings.ToLower(key)]
		if !ok {
			continue
		}
		for _, val := range vals {
			if strings.TrimSpace(val) == "" {
				continue
			}
			finding := baseCredentialExposure("HTTP", ipv4, srcPort, dstPort, vlanID, evidence+" "+key).
				withUser(username).
				withSecret(kind, val)
			finding.Host = host
			finding.Path = sanitizeHTTPPath(target)
			if method != "" {
				finding.Evidence = "HTTP " + method + " " + key
			}
			findings = append(findings, finding)
		}
	}
	return findings
}

func firstCredentialField(values url.Values, names map[string]bool) string {
	for key, vals := range values {
		if !names[strings.ToLower(key)] {
			continue
		}
		for _, val := range vals {
			if strings.TrimSpace(val) != "" {
				return val
			}
		}
	}
	return ""
}

func looksLikeFormBody(body []byte) bool {
	s := strings.ToLower(string(body))
	return strings.Contains(s, "password=") || strings.Contains(s, "passwd=") ||
		strings.Contains(s, "token=") || strings.Contains(s, "api_key=")
}

func sanitizeHTTPPath(target string) string {
	if parsed, err := url.Parse(target); err == nil {
		if parsed.Path != "" {
			return truncCredentialText(parsed.Path, 80)
		}
	}
	if idx := strings.IndexByte(target, '?'); idx >= 0 {
		target = target[:idx]
	}
	if target == "" {
		target = "/"
	}
	return truncCredentialText(sanitizeDisplayString(target), 80)
}

func lineCredentialService(dstPort uint16) string {
	switch dstPort {
	case 21:
		return "FTP"
	case 25, 587:
		return "SMTP"
	case 110:
		return "POP3"
	case 143:
		return "IMAP"
	case 6667, 6668, 6669:
		return "IRC"
	default:
		return ""
	}
}

func isLDAPPlaintextBindPort(srcPort, dstPort uint16) bool {
	return srcPort == 389 || dstPort == 389
}

func isKnownServicePort(port uint16) bool {
	switch port {
	case 21, 25, 80, 88, 110, 135, 139, 143, 389, 445, 587, 161, 1433, 8080, 8000, 8888, 6667, 6668, 6669:
		return true
	default:
		return false
	}
}

func detectNTLMExposure(ipv4 *layers.IPv4, srcPort, dstPort, vlanID uint16, payload []byte) []CredentialExposure {
	idx := bytes.Index(payload, []byte("NTLMSSP\x00"))
	if idx < 0 || !isNTLMType3(payload[idx:]) {
		return nil
	}
	finding := baseCredentialExposure("NTLM", ipv4, srcPort, dstPort, vlanID, "NTLMSSP type 3 authentication material")
	finding.SecretKind = "ntlm response"
	finding.SecretPreview = redactedBytes(len(payload) - idx)
	return []CredentialExposure{finding}
}

func isNTLMType3(data []byte) bool {
	if len(data) < 12 || !bytes.Equal(data[:8], []byte("NTLMSSP\x00")) {
		return false
	}
	return binary.LittleEndian.Uint32(data[8:12]) == 3
}

func detectMSSQLExposure(ipv4 *layers.IPv4, srcPort, dstPort, vlanID uint16, payload []byte) []CredentialExposure {
	if dstPort != 1433 || len(payload) < 8 || payload[0] != 0x10 {
		return nil
	}
	finding := baseCredentialExposure("MSSQL", ipv4, srcPort, dstPort, vlanID, "MSSQL TDS login material")
	finding.SecretKind = "tds login"
	finding.SecretPreview = redactedBytes(len(payload))
	return []CredentialExposure{finding}
}

func detectKerberosExposure(ipv4 *layers.IPv4, srcPort, dstPort, vlanID uint16, payload []byte) []CredentialExposure {
	if dstPort != 88 {
		return nil
	}
	kerb := payload
	if len(kerb) > 4 && kerb[0] == 0x00 {
		msgLen := int(binary.BigEndian.Uint32(kerb[:4]))
		if msgLen > 0 && msgLen <= len(kerb)-4 {
			kerb = kerb[4 : 4+msgLen]
		}
	}
	if len(kerb) < 8 || kerb[0] != 0x6a || !bytes.Contains(kerb, []byte{0x02, 0x01, 0x17}) {
		return nil
	}
	finding := baseCredentialExposure("Kerberos", ipv4, srcPort, dstPort, vlanID, "Kerberos AS-REQ etype 23 pre-auth material")
	finding.SecretKind = "kerberos preauth"
	finding.SecretPreview = redactedBytes(len(kerb))
	return []CredentialExposure{finding}
}

func detectPaymentCardExposure(ipv4 *layers.IPv4, srcPort, dstPort, vlanID uint16, payload []byte, transport string) []CredentialExposure {
	card, ok := findPaymentCardCandidate(payload)
	if !ok {
		return nil
	}
	service := transport
	if dstPort == 80 || dstPort == 8080 || dstPort == 8000 || dstPort == 8888 {
		service = "HTTP"
	}
	finding := baseCredentialExposure(service, ipv4, srcPort, dstPort, vlanID, "possible payment card number")
	finding.SecretKind = "payment card"
	finding.SecretValue = card
	finding.SecretPreview = fmt.Sprintf("[redacted %d digits]", len(card))
	return []CredentialExposure{finding}
}

func findPaymentCardCandidate(payload []byte) (string, bool) {
	current := make([]byte, 0, 19)
	flush := func() (string, bool) {
		if len(current) < 13 || len(current) > 19 {
			current = current[:0]
			return "", false
		}
		candidate := string(current)
		current = current[:0]
		if allSameDigit(candidate) || !luhnValid(candidate) {
			return "", false
		}
		return candidate, true
	}

	for _, b := range payload {
		switch {
		case b >= '0' && b <= '9':
			current = append(current, b)
			if len(current) > 19 {
				current = current[:0]
			}
		case b == ' ' || b == '-':
			continue
		default:
			if candidate, ok := flush(); ok {
				return candidate, true
			}
		}
	}
	return flush()
}

func allSameDigit(s string) bool {
	if len(s) == 0 {
		return true
	}
	first := s[0]
	for i := 1; i < len(s); i++ {
		if s[i] != first {
			return false
		}
	}
	return true
}

func luhnValid(s string) bool {
	sum := 0
	double := false
	for i := len(s) - 1; i >= 0; i-- {
		n := int(s[i] - '0')
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

func splitCommandFields(line string) []string {
	fields := make([]string, 0, 4)
	var b strings.Builder
	inQuote := false
	escaped := false
	for _, r := range line {
		switch {
		case escaped:
			b.WriteRune(r)
			escaped = false
		case r == '\\' && inQuote:
			escaped = true
		case r == '"':
			inQuote = !inQuote
		case (r == ' ' || r == '\t') && !inQuote:
			if b.Len() > 0 {
				fields = append(fields, b.String())
				b.Reset()
			}
		default:
			b.WriteRune(r)
		}
	}
	if b.Len() > 0 {
		fields = append(fields, b.String())
	}
	return fields
}

func decodeSMTPPlain(token string) (string, string, bool) {
	decoded, ok := decodeBase64Bytes(token)
	if !ok {
		return "", "", false
	}
	parts := strings.Split(string(decoded), "\x00")
	if len(parts) < 3 || parts[2] == "" {
		return "", "", false
	}
	user := parts[1]
	if user == "" {
		user = parts[0]
	}
	return user, parts[2], true
}

func decodeBase64Text(token string) (string, bool) {
	decoded, ok := decodeBase64Bytes(token)
	if !ok {
		return "", false
	}
	return sanitizeDisplayString(string(decoded)), true
}

func decodeBase64Bytes(token string) ([]byte, bool) {
	token = strings.TrimSpace(token)
	if token == "" {
		return nil, false
	}
	if decoded, err := base64.StdEncoding.DecodeString(token); err == nil {
		return decoded, true
	}
	if decoded, err := base64.RawStdEncoding.DecodeString(token); err == nil {
		return decoded, true
	}
	if rem := len(token) % 4; rem != 0 {
		padded := token + strings.Repeat("=", 4-rem)
		if decoded, err := base64.StdEncoding.DecodeString(padded); err == nil {
			return decoded, true
		}
	}
	return nil, false
}

func looksBase64Token(token string) bool {
	if len(token) < 4 {
		return false
	}
	for _, r := range token {
		if (r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '+' || r == '/' || r == '=' {
			continue
		}
		return false
	}
	return true
}

func parseSNMPCommunity(payload []byte) (string, bool) {
	seq, ok := readBERValue(payload, 0x30)
	if !ok {
		return "", false
	}
	rest := seq
	if _, value, remaining, ok := readBERTLV(rest); !ok || len(value) == 0 {
		return "", false
	} else {
		rest = remaining
	}
	tag, community, _, ok := readBERTLV(rest)
	if !ok || tag != 0x04 || len(community) == 0 || len(community) > 128 {
		return "", false
	}
	return sanitizeDisplayString(string(community)), true
}

func parseLDAPSimpleBind(payload []byte) (string, string, bool) {
	seq, ok := readBERValue(payload, 0x30)
	if !ok {
		return "", "", false
	}
	rest := seq
	if _, _, remaining, ok := readBERTLV(rest); !ok {
		return "", "", false
	} else {
		rest = remaining
	}
	tag, bindReq, _, ok := readBERTLV(rest)
	if !ok || tag != 0x60 {
		return "", "", false
	}
	rest = bindReq
	if _, _, remaining, ok := readBERTLV(rest); !ok {
		return "", "", false
	} else {
		rest = remaining
	}
	tag, name, remaining, ok := readBERTLV(rest)
	if !ok || tag != 0x04 {
		return "", "", false
	}
	rest = remaining
	tag, password, _, ok := readBERTLV(rest)
	if !ok || tag != 0x80 || len(password) == 0 {
		return "", "", false
	}
	return sanitizeDisplayString(string(name)), string(password), true
}

func readBERValue(data []byte, wantTag byte) ([]byte, bool) {
	tag, value, _, ok := readBERTLV(data)
	if !ok || tag != wantTag {
		return nil, false
	}
	return value, true
}

func readBERTLV(data []byte) (byte, []byte, []byte, bool) {
	if len(data) < 2 {
		return 0, nil, nil, false
	}
	tag := data[0]
	lengthByte := data[1]
	offset := 2
	length := int(lengthByte)
	if lengthByte&0x80 != 0 {
		count := int(lengthByte & 0x7f)
		if count == 0 || count > 4 || len(data) < offset+count {
			return 0, nil, nil, false
		}
		length = 0
		for i := 0; i < count; i++ {
			length = (length << 8) | int(data[offset+i])
		}
		offset += count
	}
	if length < 0 || len(data) < offset+length {
		return 0, nil, nil, false
	}
	return tag, data[offset : offset+length], data[offset+length:], true
}

func redactedSecret(secret string) string {
	secret = strings.TrimSpace(secret)
	if secret == "" {
		return "[empty]"
	}
	return fmt.Sprintf("[redacted %d chars]", len([]rune(secret)))
}

func redactedBytes(n int) string {
	if n < 0 {
		n = 0
	}
	return fmt.Sprintf("[redacted %d bytes]", n)
}

func credentialSecretDisplay(preview, value string) string {
	if strings.TrimSpace(value) != "" {
		return value
	}
	return preview
}

func sanitizeDisplayString(s string) string {
	s = strings.Map(func(r rune) rune {
		if r < 32 || r == 127 {
			return -1
		}
		return r
	}, s)
	return truncCredentialText(strings.TrimSpace(s), 120)
}

func truncCredentialText(s string, limit int) string {
	runes := []rune(s)
	if len(runes) <= limit {
		return s
	}
	if limit <= 1 {
		return string(runes[:limit])
	}
	return string(runes[:limit-1]) + "…"
}

func serviceEndpoint(ip net.IP, port uint16) string {
	if len(ip) == 0 {
		return "unknown"
	}
	if port == 0 {
		return ip.String()
	}
	return fmt.Sprintf("%s:%d", ip, port)
}
