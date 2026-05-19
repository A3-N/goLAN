package tui

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/mcrn/goLAN/internal/bridge"
	"github.com/mcrn/goLAN/internal/stealth"
)

const sessionVersion = 1

type SessionStore struct {
	mu   sync.Mutex
	ID   string
	Dir  string
	Path string
	Pcap string
	Data SessionData
}

type SessionData struct {
	ID           string                 `json:"id"`
	Version      int                    `json:"version"`
	CreatedAt    time.Time              `json:"created_at"`
	UpdatedAt    time.Time              `json:"updated_at"`
	Hosts        map[string]SessionHost `json:"hosts"`
	Edges        map[string]SessionEdge `json:"edges"`
	Notes        map[string]string      `json:"notes"`
	CaptureFiles []string               `json:"capture_files"`
	DNSNames     map[string][]string    `json:"dns_names"`
}

type SessionHost struct {
	Key       string    `json:"key"`
	Kind      string    `json:"kind"`
	Label     string    `json:"label"`
	MAC       string    `json:"mac,omitempty"`
	IPs       []string  `json:"ips,omitempty"`
	Names     []string  `json:"names,omitempty"`
	PktCount  uint64    `json:"pkt_count,omitempty"`
	FirstSeen time.Time `json:"first_seen,omitempty"`
	LastSeen  time.Time `json:"last_seen,omitempty"`
}

type SessionEdge struct {
	Key      string    `json:"key"`
	SrcKey   string    `json:"src_key"`
	DstKey   string    `json:"dst_key"`
	Protocol string    `json:"protocol"`
	SrcPort  uint16    `json:"src_port,omitempty"`
	DstPort  uint16    `json:"dst_port,omitempty"`
	VLANID   uint16    `json:"vlan_id,omitempty"`
	Packets  uint64    `json:"packets,omitempty"`
	LastSeen time.Time `json:"last_seen,omitempty"`
}

func NewSessionStore(path string) *SessionStore {
	id, dir, filePath, pcapDir := resolveSessionLocation(path)
	store := &SessionStore{ID: id, Dir: dir, Path: filePath, Pcap: pcapDir}
	store.Data = newSessionData()
	store.Data.ID = id
	if raw, err := os.ReadFile(filePath); err == nil {
		_ = json.Unmarshal(raw, &store.Data)
	}
	store.ensure()
	_ = store.Save()
	return store
}

func newSessionData() SessionData {
	now := time.Now()
	return SessionData{
		Version:   sessionVersion,
		CreatedAt: now,
		UpdatedAt: now,
		Hosts:     make(map[string]SessionHost),
		Edges:     make(map[string]SessionEdge),
		Notes:     make(map[string]string),
		DNSNames:  make(map[string][]string),
	}
}

func resolveSessionLocation(input string) (id, dir, path, pcapDir string) {
	input = strings.TrimSpace(input)
	root := configRootDir()
	if input == "" {
		id = newSessionID()
		dir = filepath.Join(root, "sessions", id)
		return id, dir, filepath.Join(dir, "session.json"), filepath.Join(dir, "pcaps")
	}

	if isSessionPathInput(input) {
		path = input
		if !filepath.IsAbs(path) {
			path, _ = filepath.Abs(path)
		}
		id = sessionIDFromPath(path)
		dir = filepath.Dir(path)
		return id, dir, path, filepath.Join(dir, "pcaps")
	}

	id = sanitizeSessionID(input)
	dir = filepath.Join(root, "sessions", id)
	path = filepath.Join(dir, "session.json")
	if _, err := os.Stat(path); err == nil {
		return id, dir, path, filepath.Join(dir, "pcaps")
	}

	legacy := filepath.Join(root, id+".json")
	if _, err := os.Stat(legacy); err == nil {
		dir = filepath.Dir(legacy)
		return id, dir, legacy, filepath.Join(dir, "pcaps", id)
	}

	return id, dir, path, filepath.Join(dir, "pcaps")
}

func configRootDir() string {
	if override := strings.TrimSpace(os.Getenv("GOLAN_CONFIG_DIR")); override != "" {
		return override
	}
	if sudoUser := strings.TrimSpace(os.Getenv("SUDO_USER")); sudoUser != "" && sudoUser != "root" {
		if account, err := user.Lookup(sudoUser); err == nil && strings.TrimSpace(account.HomeDir) != "" {
			return filepath.Join(account.HomeDir, ".config", "goLAN")
		}
	}
	if home, err := os.UserHomeDir(); err == nil && strings.TrimSpace(home) != "" {
		return filepath.Join(home, ".config", "goLAN")
	}
	if dir, err := os.UserConfigDir(); err == nil && strings.TrimSpace(dir) != "" {
		return filepath.Join(dir, "goLAN")
	}
	return filepath.Join(".config", "goLAN")
}

func isSessionPathInput(input string) bool {
	return filepath.IsAbs(input) ||
		strings.Contains(input, string(os.PathSeparator)) ||
		strings.HasPrefix(input, ".") ||
		strings.HasSuffix(strings.ToLower(input), ".json")
}

func sessionIDFromPath(path string) string {
	base := filepath.Base(path)
	ext := filepath.Ext(base)
	if ext != "" {
		base = strings.TrimSuffix(base, ext)
	}
	if base == "session" {
		base = filepath.Base(filepath.Dir(path))
	}
	return sanitizeSessionID(base)
}

func sanitizeSessionID(value string) string {
	value = strings.TrimSpace(value)
	var b strings.Builder
	for _, r := range value {
		switch {
		case r >= 'a' && r <= 'z':
			b.WriteRune(r)
		case r >= 'A' && r <= 'Z':
			b.WriteRune(r)
		case r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == '-', r == '_', r == '.':
			b.WriteRune(r)
		}
	}
	if b.Len() == 0 {
		return newSessionID()
	}
	return b.String()
}

func newSessionID() string {
	stamp := time.Now().Format("20060102-150405")
	var raw [4]byte
	if _, err := rand.Read(raw[:]); err == nil {
		return stamp + "-" + hex.EncodeToString(raw[:])
	}
	return fmt.Sprintf("%s-%d", stamp, time.Now().UnixNano()%1000000)
}

func (s *SessionStore) ensure() {
	if s == nil {
		return
	}
	if strings.TrimSpace(s.ID) == "" {
		s.ID = firstNonEmpty(s.Data.ID, sessionIDFromPath(s.Path), newSessionID())
	}
	if strings.TrimSpace(s.Dir) == "" {
		s.Dir = filepath.Dir(s.Path)
	}
	if strings.TrimSpace(s.Pcap) == "" {
		s.Pcap = filepath.Join(s.Dir, "pcaps")
	}
	if strings.TrimSpace(s.Data.ID) == "" {
		s.Data.ID = s.ID
	}
	if s.Data.Version == 0 {
		s.Data.Version = sessionVersion
	}
	if s.Data.CreatedAt.IsZero() {
		s.Data.CreatedAt = time.Now()
	}
	if s.Data.Hosts == nil {
		s.Data.Hosts = make(map[string]SessionHost)
	}
	if s.Data.Edges == nil {
		s.Data.Edges = make(map[string]SessionEdge)
	}
	if s.Data.Notes == nil {
		s.Data.Notes = make(map[string]string)
	}
	if s.Data.DNSNames == nil {
		s.Data.DNSNames = make(map[string][]string)
	}
}

func (s *SessionStore) SessionID() string {
	if s == nil {
		return ""
	}
	return s.ID
}

func (s *SessionStore) SessionPath() string {
	if s == nil {
		return ""
	}
	return s.Path
}

func (s *SessionStore) PcapDir() string {
	if s == nil {
		return ""
	}
	return s.Pcap
}

func (s *SessionStore) Save() error {
	if s == nil || strings.TrimSpace(s.Path) == "" {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ensure()
	s.Data.UpdatedAt = time.Now()
	if dir := filepath.Dir(s.Path); dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return err
		}
	}
	if s.Pcap != "" {
		if err := os.MkdirAll(s.Pcap, 0o700); err != nil {
			return err
		}
	}
	raw, err := json.MarshalIndent(s.Data, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.Path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.Path)
}

func NukeSessions() (string, error) {
	root := configRootDir()
	if strings.TrimSpace(root) == "" {
		return "", fmt.Errorf("session config root is empty")
	}
	return root, os.RemoveAll(root)
}

func (s *SessionStore) Note(key string) string {
	if s == nil {
		return ""
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ensure()
	return s.Data.Notes[key]
}

func (s *SessionStore) SetNote(key, note string) {
	if s == nil || strings.TrimSpace(key) == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ensure()
	if strings.TrimSpace(note) == "" {
		delete(s.Data.Notes, key)
		return
	}
	s.Data.Notes[key] = note
}

func (s *SessionStore) Merge(status bridge.BridgeStatus, snap stealth.NetworkMapSnapshot) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ensure()
	now := time.Now()

	for _, path := range status.CaptureFiles {
		s.Data.CaptureFiles = appendUniqueString(s.Data.CaptureFiles, path)
	}

	if status.TargetID != nil {
		host := SessionHost{
			Key:   hostKey(formatMAC(status.TargetID.MAC), formatIP(status.TargetID.IP)),
			Kind:  "target",
			Label: "PC / supplicant",
			MAC:   formatMAC(status.TargetID.MAC),
			IPs:   nonUnknownStrings(formatIP(status.TargetID.IP)),
		}
		s.upsertHostLocked(host, now)
	}

	for _, host := range snap.Hosts {
		ips := ipStrings(host.IPs)
		s.upsertHostLocked(SessionHost{
			Key:       hostKey(formatMAC(host.MAC), firstNonEmpty(ips...)),
			Kind:      "host",
			Label:     "host",
			MAC:       formatMAC(host.MAC),
			IPs:       ips,
			PktCount:  host.PktCount,
			FirstSeen: host.FirstSeen,
			LastSeen:  host.LastSeen,
		}, now)
	}

	if len(snap.Gateway.IP) > 0 || len(snap.Gateway.MAC) > 0 {
		s.upsertHostLocked(SessionHost{
			Key:      hostKey(formatMAC(snap.Gateway.MAC), formatIP(snap.Gateway.IP)),
			Kind:     "gateway",
			Label:    "gateway",
			MAC:      formatMAC(snap.Gateway.MAC),
			IPs:      nonUnknownStrings(formatIP(snap.Gateway.IP)),
			PktCount: snap.Gateway.PktCount,
			LastSeen: now,
		}, now)
	}
	if len(snap.DHCP.ServerIP) > 0 {
		s.upsertHostLocked(SessionHost{Key: hostKey("", formatIP(snap.DHCP.ServerIP)), Kind: "dhcp", Label: "dhcp", IPs: []string{formatIP(snap.DHCP.ServerIP)}, LastSeen: snap.DHCP.LastSeen}, now)
	}
	if len(snap.RADIUS.ServerIP) > 0 {
		s.upsertHostLocked(SessionHost{Key: hostKey("", formatIP(snap.RADIUS.ServerIP)), Kind: "radius", Label: "radius", IPs: []string{formatIP(snap.RADIUS.ServerIP)}, LastSeen: snap.RADIUS.LastSeen}, now)
	}

	for _, dns := range snap.DNSLog {
		for _, response := range dns.Response {
			s.Data.DNSNames[response] = appendUniqueString(s.Data.DNSNames[response], dns.Name)
			key := hostKey("", response)
			host := s.Data.Hosts[key]
			host.Key = key
			host.Kind = firstNonEmpty(host.Kind, "host")
			host.Label = firstNonEmpty(host.Label, "dns")
			host.IPs = appendUniqueString(host.IPs, response)
			host.Names = appendUniqueString(host.Names, dns.Name)
			host.LastSeen = maxTime(host.LastSeen, dns.Timestamp, now)
			s.Data.Hosts[key] = host
		}
	}

	for _, conv := range snap.Conversations {
		src := hostKey(formatMAC(conv.SrcMAC), formatIP(conv.SrcIP))
		dst := hostKey(formatMAC(conv.DstMAC), formatIP(conv.DstIP))
		s.upsertEdgeLocked(SessionEdge{
			Key:      edgeKey(src, dst, conv.Protocol, conv.SrcPort, conv.DstPort, conv.VLANID),
			SrcKey:   src,
			DstKey:   dst,
			Protocol: conv.Protocol,
			SrcPort:  conv.SrcPort,
			DstPort:  conv.DstPort,
			VLANID:   conv.VLANID,
			Packets:  conv.Packets,
			LastSeen: conv.LastSeen,
		})
	}

	targetKey := ""
	if status.TargetID != nil {
		targetKey = hostKey(formatMAC(status.TargetID.MAC), formatIP(status.TargetID.IP))
	}
	if targetKey != "" && len(snap.DHCP.ServerIP) > 0 {
		dhcpKey := hostKey("", formatIP(snap.DHCP.ServerIP))
		s.upsertEdgeLocked(SessionEdge{Key: edgeKey(dhcpKey, targetKey, "DHCP", 67, 68, 0), SrcKey: dhcpKey, DstKey: targetKey, Protocol: "DHCP", LastSeen: snap.DHCP.LastSeen})
	}
	if len(snap.RADIUS.ClientIP) > 0 && len(snap.RADIUS.ServerIP) > 0 {
		src := hostKey("", formatIP(snap.RADIUS.ClientIP))
		dst := hostKey("", formatIP(snap.RADIUS.ServerIP))
		s.upsertEdgeLocked(SessionEdge{Key: edgeKey(src, dst, "RADIUS", 0, 1812, 0), SrcKey: src, DstKey: dst, Protocol: "RADIUS", LastSeen: snap.RADIUS.LastSeen})
	}
}

func (s *SessionStore) Snapshot() SessionData {
	if s == nil {
		return newSessionData()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ensure()
	out := s.Data
	out.Hosts = make(map[string]SessionHost, len(s.Data.Hosts))
	for key, host := range s.Data.Hosts {
		host.IPs = append([]string(nil), host.IPs...)
		host.Names = append([]string(nil), host.Names...)
		out.Hosts[key] = host
	}
	out.Edges = make(map[string]SessionEdge, len(s.Data.Edges))
	for key, edge := range s.Data.Edges {
		out.Edges[key] = edge
	}
	out.Notes = make(map[string]string, len(s.Data.Notes))
	for key, note := range s.Data.Notes {
		out.Notes[key] = note
	}
	out.DNSNames = make(map[string][]string, len(s.Data.DNSNames))
	for key, names := range s.Data.DNSNames {
		out.DNSNames[key] = append([]string(nil), names...)
	}
	out.CaptureFiles = append([]string(nil), s.Data.CaptureFiles...)
	return out
}

func (s *SessionStore) upsertHostLocked(host SessionHost, now time.Time) {
	if host.Key == "" || host.Key == "unknown" {
		return
	}
	existing := s.Data.Hosts[host.Key]
	if existing.Key == "" {
		existing.Key = host.Key
		existing.FirstSeen = firstTime(host.FirstSeen, now)
	}
	existing.Kind = preferKind(existing.Kind, host.Kind)
	existing.Label = firstNonEmpty(existing.Label, host.Label)
	existing.MAC = firstNonUnknown(existing.MAC, host.MAC)
	existing.IPs = appendUniqueStrings(existing.IPs, host.IPs...)
	existing.Names = appendUniqueStrings(existing.Names, host.Names...)
	if host.PktCount > existing.PktCount {
		existing.PktCount = host.PktCount
	}
	existing.FirstSeen = minTime(existing.FirstSeen, host.FirstSeen, now)
	existing.LastSeen = maxTime(existing.LastSeen, host.LastSeen, now)
	s.Data.Hosts[host.Key] = existing
}

func (s *SessionStore) upsertEdgeLocked(edge SessionEdge) {
	if edge.Key == "" || edge.SrcKey == "" || edge.DstKey == "" || edge.SrcKey == edge.DstKey {
		return
	}
	existing := s.Data.Edges[edge.Key]
	if existing.Key == "" {
		existing = edge
	} else {
		existing.Packets = maxUint64(existing.Packets, edge.Packets)
		existing.LastSeen = maxTime(existing.LastSeen, edge.LastSeen)
	}
	s.Data.Edges[edge.Key] = existing
}

func hostKey(mac, ip string) string {
	mac = strings.TrimSpace(strings.ToLower(mac))
	ip = strings.TrimSpace(ip)
	if mac != "" && mac != "unknown" {
		return "mac:" + mac
	}
	if ip != "" && ip != "unknown" {
		return "ip:" + ip
	}
	return ""
}

func edgeKey(src, dst, proto string, srcPort, dstPort, vlan uint16) string {
	return strings.Join([]string{src, dst, proto, portKey(srcPort), portKey(dstPort), portKey(vlan)}, "|")
}

func portKey(v uint16) string {
	if v == 0 {
		return ""
	}
	return fmt.Sprintf("%d", v)
}

func ipStrings(ips []net.IP) []string {
	out := make([]string, 0, len(ips))
	for _, ip := range ips {
		if len(ip) > 0 {
			out = appendUniqueString(out, ip.String())
		}
	}
	sort.Strings(out)
	return out
}

func nonUnknownStrings(values ...string) []string {
	out := make([]string, 0, len(values))
	for _, v := range values {
		if strings.TrimSpace(v) != "" && v != "unknown" {
			out = appendUniqueString(out, v)
		}
	}
	return out
}

func appendUniqueStrings(values []string, more ...string) []string {
	for _, value := range more {
		values = appendUniqueString(values, value)
	}
	sort.Strings(values)
	return values
}

func appendUniqueString(values []string, value string) []string {
	value = strings.TrimSpace(value)
	if value == "" || value == "unknown" {
		return values
	}
	for _, existing := range values {
		if existing == value {
			return values
		}
	}
	return append(values, value)
}

func firstNonUnknown(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" && value != "unknown" {
			return value
		}
	}
	return ""
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func preferKind(existing, candidate string) string {
	rank := map[string]int{"target": 5, "switch": 4, "gateway": 3, "dhcp": 3, "radius": 3, "host": 1}
	if rank[candidate] > rank[existing] {
		return candidate
	}
	return firstNonEmpty(existing, candidate)
}

func firstTime(values ...time.Time) time.Time {
	for _, value := range values {
		if !value.IsZero() {
			return value
		}
	}
	return time.Time{}
}

func minTime(values ...time.Time) time.Time {
	var out time.Time
	for _, value := range values {
		if value.IsZero() {
			continue
		}
		if out.IsZero() || value.Before(out) {
			out = value
		}
	}
	return out
}

func maxTime(values ...time.Time) time.Time {
	var out time.Time
	for _, value := range values {
		if value.IsZero() {
			continue
		}
		if out.IsZero() || value.After(out) {
			out = value
		}
	}
	return out
}

func maxUint64(a, b uint64) uint64 {
	if b > a {
		return b
	}
	return a
}
