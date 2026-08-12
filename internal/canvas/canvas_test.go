package canvas

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
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
	root := t.TempDir()
	t.Setenv("GOLAN_CONFIG_DIR", root)
	path := filepath.Join(root, "canvases", "session.canvas")

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
	if info, err := os.Stat(path); err != nil {
		t.Fatalf("Stat: %v", err)
	} else if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("canvas mode = %o", got)
	}
}

func TestWriteFileRejectsPathOutsideConfigRoot(t *testing.T) {
	root := t.TempDir()
	t.Setenv("GOLAN_CONFIG_DIR", root)
	path := filepath.Join(t.TempDir(), "session.canvas")

	if err := NewMap().WriteFile(path); err == nil {
		t.Fatal("expected canvas path rejection")
	}
}

func TestValidatePathRequiresCanvasDirectoryAndExtension(t *testing.T) {
	root := t.TempDir()
	t.Setenv("GOLAN_CONFIG_DIR", root)
	for _, path := range []string{
		filepath.Join(root, "session.canvas"),
		filepath.Join(root, "canvases", "session.json"),
		filepath.Join(root, "canvases"),
	} {
		if err := ValidatePath(path); err == nil {
			t.Errorf("ValidatePath(%q) succeeded", path)
		}
	}
	if err := ValidatePath(filepath.Join(root, "canvases", "session.canvas")); err != nil {
		t.Fatalf("ValidatePath: %v", err)
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
