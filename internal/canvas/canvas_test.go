package canvas

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golan/internal/inspect"
	"golan/internal/profile"
)

func TestMapOverwritesHostsAndConversations(t *testing.T) {
	m := NewMap()
	if !m.Apply(Observation{Kind: "host", IP: "192.168.1.10", MAC: "02:00:00:00:00:10", Tag: "host"}) {
		t.Fatal("expected first host to change map")
	}
	if m.Apply(Observation{Kind: "host", IP: "192.168.1.10", MAC: "02:00:00:00:00:10", Tag: "host"}) {
		t.Fatal("duplicate host metadata should not create new canvas info")
	}
	m.Apply(Observation{Kind: "host", IP: "192.168.1.1", MAC: "02:00:00:00:00:01", Tag: "gateway"})
	m.Apply(Observation{Kind: "conversation", SrcIP: "192.168.1.10", SrcMAC: "02:00:00:00:00:10", DstIP: "192.168.1.1", DstMAC: "02:00:00:00:00:01", Protocol: "TCP", Port: 443, Service: "https"})
	m.Apply(Observation{Kind: "conversation", SrcIP: "192.168.1.10", SrcMAC: "02:00:00:00:00:10", DstIP: "192.168.1.1", DstMAC: "02:00:00:00:00:01", Protocol: "TCP", Port: 443, Service: "https"})

	canvas := m.JSONCanvas()
	if len(canvas.Edges) != 1 {
		t.Fatalf("edges = %+v", canvas.Edges)
	}
	if !strings.Contains(canvas.Edges[0].Label, "x2") {
		t.Fatalf("edge label = %q", canvas.Edges[0].Label)
	}
}

func TestWriteFileCreatesObsidianCanvas(t *testing.T) {
	m := NewMap()
	m.Apply(Observation{Kind: "host", IP: "192.168.1.10", MAC: "02:00:00:00:00:10", Tag: "host"})
	path := filepath.Join(t.TempDir(), "session.canvas")

	if err := m.WriteFile(path); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	var parsed JSONCanvas
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if len(parsed.Nodes) == 0 {
		t.Fatalf("nodes = %+v", parsed.Nodes)
	}
	if !strings.Contains(string(data), `"nodes"`) || !strings.Contains(string(data), `"edges"`) {
		t.Fatalf("not json canvas: %s", data)
	}
}

func TestFindingAddsSecretToDestinationService(t *testing.T) {
	m := NewMap()
	finding := inspect.Finding{
		Protocol: "HTTP",
		Kind:     "Basic",
		User:     "alice",
		Secret:   "secret123",
		Src:      "192.168.1.10",
		Sport:    49152,
		Dst:      "192.168.1.20",
		Dport:    80,
	}

	if !m.Apply(FromFinding(finding, "en11", "host")) {
		t.Fatal("expected finding to update canvas")
	}
	server := m.Hosts["ip:192.168.1.20"]
	if server == nil {
		t.Fatalf("server missing: %+v", m.Hosts)
	}
	service := server.Services[serviceKey("HTTP", 80, "http Basic")]
	if service == nil {
		t.Fatalf("service missing: %+v", server.Services)
	}
	if !service.Secrets[finding.Display()] {
		t.Fatalf("secret evidence missing: %+v", service.Secrets)
	}
	if len(m.Conversations) != 1 {
		t.Fatalf("conversations = %+v", m.Conversations)
	}
}

func TestConfiguredMACIsSelfAndKeepsLearnedIP(t *testing.T) {
	m := NewMap()
	cfg := profile.AdapterConfig{
		AdapterRole: profile.AdapterRoleHost,
		Name:        "en11",
		CurrentMAC:  "6c:1f:f7:58:b5:fa",
		IP:          "169.254.109.38",
		MAC:         "a0:ad:9f:1c:3c:a5",
		Discovered: []profile.DiscoveredValue{
			{Field: "mac", Value: "a0:ad:9f:1c:3c:a5"},
			{Field: "ip", Value: "169.254.109.38"},
		},
	}

	if !m.ApplyAdapter(cfg) {
		t.Fatal("expected configured adapter to update canvas")
	}
	host := m.Hosts["ip:169.254.109.38"]
	if host == nil {
		t.Fatalf("configured host missing: %+v", m.Hosts)
	}
	if !host.Tags["self"] || !host.Tags["host"] {
		t.Fatalf("configured host tags = %+v", host.Tags)
	}
	if !host.MACs["a0:ad:9f:1c:3c:a5"] {
		t.Fatalf("configured mac missing: %+v", host.MACs)
	}
	text := hostText(host)
	if !strings.Contains(text, "configured+learned mac a0:ad:9f:1c:3c:a5") {
		t.Fatalf("configured mac note missing: %s", text)
	}
	if !strings.Contains(text, "configured+learned ip 169.254.109.38 (internal-link-local)") {
		t.Fatalf("configured ip note missing: %s", text)
	}
	for _, node := range m.JSONCanvas().Nodes {
		if strings.Contains(node.Text, "169.254.109.38") && node.Color != colorSelf {
			t.Fatalf("configured host node color = %s", node.Color)
		}
	}
}

func TestLearnedIPJoinsConfiguredMACSelfHost(t *testing.T) {
	m := NewMap()
	cfg := profile.AdapterConfig{
		AdapterRole: profile.AdapterRoleHost,
		Name:        "en11",
		IP:          "auto",
		MAC:         "a0:ad:9f:1c:3c:a5",
		Discovered: []profile.DiscoveredValue{
			{Field: "arp_sender_ip", Value: "192.168.1.145"},
		},
	}

	if !m.ApplyAdapter(cfg) {
		t.Fatal("expected learned ip to update canvas")
	}
	host := m.Hosts["ip:192.168.1.145"]
	if host == nil {
		t.Fatalf("learned host missing: %+v", m.Hosts)
	}
	if !host.Tags["self"] || !host.MACs["a0:ad:9f:1c:3c:a5"] {
		t.Fatalf("learned host did not inherit self identity: tags=%+v macs=%+v", host.Tags, host.MACs)
	}
	if !strings.Contains(hostText(host), "learned ip 192.168.1.145 (internal-private)") {
		t.Fatalf("learned ip note missing: %s", hostText(host))
	}
}

func TestDNSServiceTagsRouterAndDNS(t *testing.T) {
	m := NewMap()
	m.Apply(Observation{Kind: "service", IP: "192.168.1.1", Protocol: "UDP", Port: 53, Service: "dns"})

	host := m.Hosts["ip:192.168.1.1"]
	if host == nil {
		t.Fatalf("host missing: %+v", m.Hosts)
	}
	for _, tag := range []string{"dns", "router", "gateway"} {
		if !host.Tags[tag] {
			t.Fatalf("tag %q missing: %+v", tag, host.Tags)
		}
	}
	for _, role := range []string{"dns-server", "router", "gateway"} {
		if !host.Roles[role] {
			t.Fatalf("role %q missing: %+v", role, host.Roles)
		}
	}
}

func TestMulticastStaysInInfrastructure(t *testing.T) {
	m := NewMap()
	m.Apply(Observation{Kind: "host", IP: "239.255.255.250", Tag: "host"})

	internal, external, infra := splitHosts(sortedHosts(m.Hosts))
	if len(internal) != 0 || len(external) != 0 || len(infra) != 1 {
		t.Fatalf("internal=%d external=%d infra=%d", len(internal), len(external), len(infra))
	}
	if !infra[0].Tags["multicast"] {
		t.Fatalf("multicast tag missing: %+v", infra[0].Tags)
	}
	if color := hostColor(infra[0]); color != colorInfra {
		t.Fatalf("multicast color = %s", color)
	}
}
