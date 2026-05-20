package tui

import (
	"net"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/charmbracelet/lipgloss"
	"github.com/mcrn/goLAN/internal/bridge"
	"github.com/mcrn/goLAN/internal/stealth"
)

var ansiEscapePattern = regexp.MustCompile(`\x1b\[[0-9;:]*[A-Za-z]`)

func stripANSI(s string) string {
	return ansiEscapePattern.ReplaceAllString(s, "")
}

func assertCompleteCardFrame(t *testing.T, rendered string, width int) {
	t.Helper()
	for i, line := range strings.Split(strings.TrimRight(rendered, "\n"), "\n") {
		plain := stripANSI(line)
		if plain == "" {
			continue
		}
		if got := lipgloss.Width(plain); got != width {
			t.Fatalf("line %d width = %d, want %d: %q", i, got, width, plain)
		}
		runes := []rune(plain)
		first := runes[0]
		last := runes[len(runes)-1]
		switch first {
		case '╭':
			if last != '╮' {
				t.Fatalf("line %d has incomplete top border: %q", i, plain)
			}
		case '╰':
			if last != '╯' {
				t.Fatalf("line %d has incomplete bottom border: %q", i, plain)
			}
		case '│':
			if last != '│' {
				t.Fatalf("line %d has incomplete side border: %q", i, plain)
			}
		default:
			t.Fatalf("line %d is not framed: %q", i, plain)
		}
	}
}

func TestRenderCardUsesOuterWidth(t *testing.T) {
	for _, width := range []int{20, 40, 96} {
		card := renderCard(width, "card body")
		if got := lipgloss.Width(card); got != width {
			t.Fatalf("renderCard(%d) width = %d, want %d", width, got, width)
		}
	}
}

func TestRenderCardHasCompleteFrame(t *testing.T) {
	card := renderCard(40, strings.Repeat("long content ", 12))
	assertCompleteCardFrame(t, card, 40)
}

func TestRenderFixedCardUsesOuterDimensions(t *testing.T) {
	content := strings.Repeat("line\n", 20)
	card := renderFixedCard(48, 12, content)
	if got := lipgloss.Width(card); got != 48 {
		t.Fatalf("renderFixedCard width = %d, want 48", got)
	}
	if got := lipgloss.Height(card); got != 12 {
		t.Fatalf("renderFixedCard height = %d, want 12", got)
	}
}

func TestRenderFixedCardHasCompleteFrame(t *testing.T) {
	card := renderFixedCard(48, 8, strings.Repeat("line\n", 20))
	assertCompleteCardFrame(t, card, 48)
}

func TestRenderFixedCardStackHasCompleteFrames(t *testing.T) {
	stack := renderFixedCardStack(44, 18, []string{
		"one\n" + strings.Repeat("line\n", 8),
		"two\n" + strings.Repeat("line\n", 8),
		"three\n" + strings.Repeat("line\n", 8),
	})
	assertCompleteCardFrame(t, stack, 44)
	if got := lipgloss.Height(stack); got != 18 {
		t.Fatalf("stack height = %d, want 18", got)
	}
}

func TestRenderFramePinsFooterAtTerminalHeight(t *testing.T) {
	m := DashboardModel{width: 80, height: 24}
	frame := m.renderFrame("header", strings.Repeat("body\n", 3), "footer")
	if got := lipgloss.Height(frame); got != 24 {
		t.Fatalf("frame height = %d, want 24", got)
	}
}

func TestRenderFooterUsesTerminalWidth(t *testing.T) {
	m := DashboardModel{width: 80}
	footer := m.renderFooter()
	if got := lipgloss.Width(footer); got != 80 {
		t.Fatalf("footer width = %d, want 80", got)
	}
}

func TestOversizedFramedBodyScrollsInsteadOfSectionError(t *testing.T) {
	m := DashboardModel{width: 80, height: 24}
	body := renderCard(80, strings.Repeat("line\n", 40))
	fit := m.fitBodyHeight(body, 10, 0)
	if strings.Contains(fit, "section exceeds terminal height") {
		t.Fatalf("oversized framed body returned section error: %q", fit)
	}
	if got := lipgloss.Height(fit); got != 10 {
		t.Fatalf("fit body height = %d, want 10", got)
	}
	assertCompleteCardFrame(t, fit, 80)
}

func TestNetworkGraphContentUsesTopologyLanWanModes(t *testing.T) {
	graph := networkGraph{
		Nodes: []networkNode{
			{Key: "local:golan", Kind: "local", Label: "goLAN", IPs: []string{"10.77.0.200"}, MAC: "aa:bb:cc:dd:ee:ff"},
			{Key: "switch:test-switch", Kind: "switch", Label: "Observed network"},
			{Key: "ip:10.77.0.10", Kind: "target", Label: "PC", IPs: []string{"10.77.0.10"}},
			{Key: "ip:10.77.0.20", Kind: "host", Label: "printer", IPs: []string{"10.77.0.20"}},
			{Key: "ip:8.8.8.8", Kind: "external", Label: "dns", IPs: []string{"8.8.8.8"}},
			{Key: "ip:1.1.1.1", Kind: "dns", Label: "DNS server", IPs: []string{"1.1.1.1"}},
			{Key: "ip:169.254.10.20", Kind: "host", Label: "link-local", IPs: []string{"169.254.10.20"}},
		},
		Edges: []networkEdge{
			{SrcKey: "local:golan", DstKey: "switch:test-switch", Protocol: "inline"},
			{SrcKey: "switch:test-switch", DstKey: "ip:10.77.0.10", Protocol: "L2"},
			{SrcKey: "switch:test-switch", DstKey: "ip:10.77.0.20", Protocol: "L2"},
			{SrcKey: "switch:test-switch", DstKey: "ip:8.8.8.8", Protocol: "L2"},
			{SrcKey: "switch:test-switch", DstKey: "ip:169.254.10.20", Protocol: "L2"},
			{SrcKey: "ip:10.77.0.10", DstKey: "ip:10.77.0.20", Protocol: "SNMP", DstPort: 161, Packets: 2, Creds: []string{"cred community=example"}},
			{SrcKey: "ip:10.77.0.10", DstKey: "ip:8.8.8.8", Protocol: "DNS", DstPort: 53, Packets: 3},
		},
		Filters:  networkGraphFilters{ShowLAN: true},
		Selected: 2,
	}

	content, _ := DashboardModel{}.networkGraphContent(filterNetworkGraph(graph), 100)
	plain := stripANSI(content)
	for _, want := range []string{"Network Layout", "==inline==", "==L2==", "SNMP:161", "cred community=example", ">(10.77.0.20)"} {
		if !strings.Contains(plain, want) {
			t.Fatalf("LAN topology missing %q:\n%s", want, plain)
		}
	}
	if strings.Contains(plain, "> (") {
		t.Fatalf("LAN topology should not include a space between arrow and peer:\n%s", plain)
	}
	if strings.Contains(plain, "links:") {
		t.Fatalf("LAN topology should not render links label:\n%s", plain)
	}
	if strings.Contains(plain, ">>") {
		t.Fatalf("selected topology line changed indentation with marker:\n%s", plain)
	}
	if strings.Contains(plain, "WAN DNS:53") {
		t.Fatalf("LAN topology included WAN edge:\n%s", plain)
	}
	if strings.Contains(plain, "8.8.8.8") || strings.Contains(plain, "1.1.1.1") || strings.Contains(plain, "169.254.10.20") {
		t.Fatalf("LAN topology included WAN or link-local node:\n%s", plain)
	}

	graph.Filters = networkGraphFilters{ShowWAN: true}
	content, _ = DashboardModel{}.networkGraphContent(filterNetworkGraph(graph), 100)
	plain = stripANSI(content)
	if !strings.Contains(plain, "DNS:53") || !strings.Contains(plain, ">(8.8.8.8)") || !strings.Contains(plain, "1.1.1.1") {
		t.Fatalf("WAN topology missing WAN edge:\n%s", plain)
	}
	if strings.Contains(plain, "LAN SNMP:161") {
		t.Fatalf("WAN topology included LAN edge:\n%s", plain)
	}
	if strings.Contains(plain, "169.254.10.20") {
		t.Fatalf("WAN topology included link-local node:\n%s", plain)
	}
}

func TestNetworkGraphLabelsOperatorAndPCIPsSeparately(t *testing.T) {
	targetMAC := net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}
	status := bridge.BridgeStatus{
		IfaceB:            "test-switch",
		NATActive:         true,
		NATHiddenIP:       "10.77.0.250",
		NATAnchorMode:     "same-subnet",
		NATAnchorEvidence: "observed DHCP mask 10.77.0.0/255.255.255.0",
		TargetID: &stealth.TargetIdentity{
			MAC: targetMAC,
			IP:  net.IPv4(10, 77, 0, 145),
		},
	}
	graph := DashboardModel{networkShowLAN: true}.buildNetworkGraph(status, stealth.NetworkMapSnapshot{})
	content, _ := DashboardModel{}.networkGraphContent(graph, 120)
	plain := stripANSI(content)
	for _, want := range []string{
		"operator ip: 10.77.0.250",
		"pc ip: 10.77.0.145",
		"same-subnet NAT anchor",
	} {
		if !strings.Contains(plain, want) {
			t.Fatalf("network graph missing %q:\n%s", want, plain)
		}
	}

	detail := stripANSI(DashboardModel{}.nodeDetailContent(graph, graph.Nodes[graph.Selected], 120))
	if strings.Contains(detail, "Operator IP") && strings.Contains(detail, "10.77.0.145") {
		t.Fatalf("node detail confused PC IP with operator IP:\n%s", detail)
	}
}

func TestReconLogWrappingUsesFullCardWidth(t *testing.T) {
	line := "[+][RECON] Target MAC locked: aa:bb:cc:dd:ee:ff. Activating transparent bridge immediately."
	wrapped := wrapReconLogLine(line, 48)
	if len(wrapped) < 2 {
		t.Fatalf("expected wrapped recon log, got %v", wrapped)
	}
	if got := lipgloss.Width(wrapped[0]); got < 44 || got > 48 {
		t.Fatalf("first wrapped line width = %d, want near full 48: %q", got, wrapped[0])
	}
	for i, part := range wrapped {
		if got := lipgloss.Width(part); got > 48 {
			t.Fatalf("wrapped line %d width = %d, want <= 48: %q", i, got, part)
		}
	}
}

func TestReconLogWrappingDoesNotLoopAtNarrowWidths(t *testing.T) {
	line := "[+][RECON] " + strings.Repeat("x", 40)
	wrapped := wrapReconLogLine(line, 4)
	if len(wrapped) == 0 || len(wrapped) > 32 {
		t.Fatalf("narrow wrap produced suspicious line count %d: %v", len(wrapped), wrapped)
	}
	for i, part := range wrapped {
		if got := lipgloss.Width(part); got > 4 {
			t.Fatalf("wrapped line %d width = %d, want <= 4: %q", i, got, part)
		}
	}
}

func TestLayer3DetailContentKeepsPassiveFactsAndDropsNoisyRows(t *testing.T) {
	targetMAC := net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}
	snap := stealth.NetworkMapSnapshot{
		DHCP: stealth.DHCPTelemetry{
			Seen:         true,
			LastType:     "Ack",
			ACKIP:        net.IPv4(10, 77, 0, 145),
			OfferedIP:    net.IPv4(10, 77, 0, 145),
			ServerIP:     net.IPv4(10, 77, 0, 1),
			RouterIP:     net.IPv4(10, 77, 0, 1),
			DNSServers:   []net.IP{net.IPv4(10, 77, 0, 1)},
			Netmask:      net.IPv4Mask(255, 255, 255, 0),
			LeaseSeconds: 3600,
		},
		RADIUS: stealth.RADIUSTelemetry{
			Seen:     true,
			ServerIP: net.IPv4(10, 77, 0, 157),
		},
		Conversations: []stealth.ConversationSummary{
			{
				SrcIP:    net.IPv4(10, 77, 0, 145),
				DstIP:    net.IPv4(8, 8, 8, 8),
				SrcMAC:   targetMAC,
				Protocol: "DNS",
				DstPort:  53,
				Packets:  2,
			},
		},
	}
	status := bridge.BridgeStatus{
		NATActive:       true,
		NATHiddenIP:     "10.77.0.250",
		NATRouteNetwork: "10.77.0.0",
		TargetID: &stealth.TargetIdentity{
			MAC: targetMAC,
			IP:  net.IPv4(10, 77, 0, 145),
		},
	}

	plain := stripANSI(DashboardModel{}.layer3DetailContent(status, snap, 120))
	for _, want := range []string{
		"Target IPs", "10.77.0.145",
		"IP Evidence", "DHCP ACK", "passive traffic",
		"Gateway", "10.77.0.1", "DHCP option 3",
		"DNS Servers", "dhcp-option-6",
		"Netmask", "DHCP option 1",
		"DHCP Lease", "from 10.77.0.1", "1h",
		"Observed LAN", "10.77.0.0/24",
		"External Seen", "yes (1 flow)",
	} {
		if !strings.Contains(plain, want) {
			t.Fatalf("layer 3 detail missing %q:\n%s", want, plain)
		}
	}
	for _, notWant := range []string{"RADIUS", "NAT", "DHCP D/O/R/A/N", "DHCP Offer", "DNS seen"} {
		if strings.Contains(plain, notWant) {
			t.Fatalf("layer 3 detail kept noisy row %q:\n%s", notWant, plain)
		}
	}
}

func TestHostsMapContentKeepsLANNamesAndDropsPublicDNS(t *testing.T) {
	now := time.Now()
	snap := stealth.NetworkMapSnapshot{
		DNSLog: []stealth.DNSQuery{
			{
				Name:      "router.lab.",
				Type:      "A",
				Response:  []string{"10.77.0.1"},
				Timestamp: now,
			},
			{
				Name:      "printer.local",
				Type:      "A",
				Response:  []string{"169.254.10.20"},
				Timestamp: now,
			},
			{
				Name:      "public-looking.example.com",
				Type:      "A",
				Response:  []string{"10.77.2.3"},
				Timestamp: now,
			},
			{
				Name:      "openai.com",
				Type:      "A",
				Response:  []string{"93.184.216.34"},
				Timestamp: now,
			},
			{
				Name:      "fileserver",
				Type:      "A",
				Timestamp: now,
			},
		},
	}

	plain := stripANSI(DashboardModel{}.hostsMapContent(snap, 120))
	for _, want := range []string{"Hosts Map", "router.lab -> 10.77.0.1", "public-looking.example.com -> 10.77.2.3"} {
		if !strings.Contains(plain, want) {
			t.Fatalf("hosts map missing %q:\n%s", want, plain)
		}
	}
	for _, notWant := range []string{"Auth Events", "openai.com", "93.184.216.34", "printer.local", "169.254.10.20", "fileserver"} {
		if strings.Contains(plain, notWant) {
			t.Fatalf("hosts map included public/link-local/auth data %q:\n%s", notWant, plain)
		}
	}
}

func TestNetworkGraphContentKeepsAllObservedServicesStable(t *testing.T) {
	now := time.Now()
	graph := networkGraph{
		Nodes: []networkNode{
			{Key: "local:golan", Kind: "local", Label: "goLAN"},
			{Key: "switch:test-switch", Kind: "switch", Label: "Observed network"},
			{Key: "ip:10.77.0.10", Kind: "target", Label: "PC", IPs: []string{"10.77.0.10"}},
			{Key: "ip:10.77.0.20", Kind: "host", Label: "server", IPs: []string{"10.77.0.20"}},
		},
		Edges: []networkEdge{
			{SrcKey: "local:golan", DstKey: "switch:test-switch", Protocol: "inline"},
			{SrcKey: "switch:test-switch", DstKey: "ip:10.77.0.10", Protocol: "L2"},
			{SrcKey: "switch:test-switch", DstKey: "ip:10.77.0.20", Protocol: "L2"},
			{SrcKey: "ip:10.77.0.10", DstKey: "ip:10.77.0.20", Protocol: "TELNET", DstPort: 23, Packets: 1, LastSeen: now.Add(5 * time.Second)},
			{SrcKey: "ip:10.77.0.10", DstKey: "ip:10.77.0.20", Protocol: "HTTP", DstPort: 80, Packets: 1, LastSeen: now.Add(4 * time.Second)},
			{SrcKey: "ip:10.77.0.10", DstKey: "ip:10.77.0.20", Protocol: "SSH", DstPort: 22, Packets: 1, LastSeen: now.Add(3 * time.Second)},
			{SrcKey: "ip:10.77.0.10", DstKey: "ip:10.77.0.20", Protocol: "SNMP", DstPort: 161, Packets: 1, LastSeen: now.Add(2 * time.Second)},
			{SrcKey: "ip:10.77.0.10", DstKey: "ip:10.77.0.20", Protocol: "DNS", DstPort: 53, Packets: 1, LastSeen: now.Add(time.Second)},
		},
		Filters:  networkGraphFilters{ShowLAN: true},
		Selected: 2,
	}

	content, _ := DashboardModel{}.networkGraphContent(filterNetworkGraph(graph), 120)
	plain := stripANSI(content)
	for _, want := range []string{"DNS:53", "HTTP:80", "SNMP:161", "SSH:22", "TELNET:23"} {
		if !strings.Contains(plain, want) {
			t.Fatalf("stable topology omitted observed service %q:\n%s", want, plain)
		}
	}
	first := strings.Index(plain, "DNS:53")
	last := strings.Index(plain, "TELNET:23")
	if first < 0 || last < 0 || first > last {
		t.Fatalf("stable topology did not sort services deterministically:\n%s", plain)
	}
}

func TestNetworkGraphOnlySelectedNodeExpandsLinksAndScrollsToThem(t *testing.T) {
	graph := networkGraph{
		Nodes: []networkNode{
			{Key: "local:golan", Kind: "local", Label: "goLAN"},
			{Key: "switch:test-switch", Kind: "switch", Label: "Observed network"},
			{Key: "ip:10.77.0.10", Kind: "target", Label: "PC", IPs: []string{"10.77.0.10"}},
			{Key: "ip:10.77.0.20", Kind: "host", Label: "server-a", IPs: []string{"10.77.0.20"}},
			{Key: "ip:10.77.0.30", Kind: "host", Label: "server-b", IPs: []string{"10.77.0.30"}},
			{Key: "ip:10.77.0.40", Kind: "host", Label: "server-c", IPs: []string{"10.77.0.40"}},
		},
		Edges: []networkEdge{
			{SrcKey: "local:golan", DstKey: "switch:test-switch", Protocol: "inline"},
			{SrcKey: "switch:test-switch", DstKey: "ip:10.77.0.10", Protocol: "L2"},
			{SrcKey: "switch:test-switch", DstKey: "ip:10.77.0.20", Protocol: "L2"},
			{SrcKey: "switch:test-switch", DstKey: "ip:10.77.0.30", Protocol: "L2"},
			{SrcKey: "switch:test-switch", DstKey: "ip:10.77.0.40", Protocol: "L2"},
			{SrcKey: "ip:10.77.0.10", DstKey: "ip:10.77.0.20", Protocol: "HTTP", DstPort: 80, Packets: 3},
			{SrcKey: "ip:10.77.0.10", DstKey: "ip:10.77.0.30", Protocol: "DNS", DstPort: 53, Packets: 2},
			{SrcKey: "ip:10.77.0.10", DstKey: "ip:10.77.0.40", Protocol: "SSH", DstPort: 22, Packets: 1},
		},
		Filters:  networkGraphFilters{ShowLAN: true},
		Selected: 5,
	}

	content, selectedLine := DashboardModel{}.networkGraphContent(filterNetworkGraph(graph), 100)
	plain := stripANSI(content)
	if !strings.Contains(plain, "SSH:22") {
		t.Fatalf("selected node link missing:\n%s", plain)
	}
	for _, notWant := range []string{"HTTP:80", "DNS:53"} {
		if strings.Contains(plain, notWant) {
			t.Fatalf("non-selected node link %q should stay collapsed:\n%s", notWant, plain)
		}
	}
	scrolled := stripANSI(scrollNetworkCardContent(content, 8, 0, selectedLine, 100))
	if !strings.Contains(scrolled, "SSH:22") || !strings.Contains(scrolled, "10.77.0.40") {
		t.Fatalf("scroll did not keep selected node links visible:\n%s", scrolled)
	}
}

func TestNetworkGraphAliasesIPOnlyAndMACNodes(t *testing.T) {
	now := time.Now()
	model := DashboardModel{selectedNodeKey: "ip:10.77.0.10"}
	graph := model.buildNetworkGraph(bridge.BridgeStatus{IfaceB: "test-switch"}, stealth.NetworkMapSnapshot{
		Hosts: []stealth.HostSummary{
			{
				MAC:      net.HardwareAddr{0, 1, 2, 3, 4, 5},
				IPs:      []net.IP{net.IPv4(10, 77, 0, 10)},
				PktCount: 9,
				LastSeen: now,
			},
		},
		Conversations: []stealth.ConversationSummary{
			{
				SrcIP:    net.IPv4(10, 77, 0, 10),
				DstIP:    net.IPv4(10, 77, 0, 20),
				Protocol: "SSH",
				DstPort:  22,
				Packets:  2,
				LastSeen: now,
			},
		},
	})

	count10 := 0
	var node10 networkNode
	for _, node := range graph.Nodes {
		if containsString(node.IPs, "10.77.0.10") {
			count10++
			node10 = node
		}
	}
	if count10 != 1 {
		t.Fatalf("expected one canonical .10 node, got %d nodes: %+v", count10, graph.Nodes)
	}
	if node10.MAC != "00:01:02:03:04:05" {
		t.Fatalf("canonical .10 node lost MAC: %+v", node10)
	}
	if graph.selectedNode().Key != node10.Key {
		t.Fatalf("selected alias did not resolve to canonical node: selected=%+v canonical=%+v", graph.selectedNode(), node10)
	}
	for _, edge := range graph.Edges {
		if edge.SrcKey == "ip:10.77.0.10" || edge.DstKey == "ip:10.77.0.10" {
			t.Fatalf("edge kept IP-only alias after canonicalization: %+v", edge)
		}
	}
}

func TestNetworkGraphTargetUsesPassiveIPFromTargetMAC(t *testing.T) {
	now := time.Now()
	targetMAC := net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}
	graph := DashboardModel{}.buildNetworkGraph(bridge.BridgeStatus{
		IfaceB: "test-switch",
		TargetID: &stealth.TargetIdentity{
			MAC: targetMAC,
		},
	}, stealth.NetworkMapSnapshot{
		Hosts: []stealth.HostSummary{
			{MAC: targetMAC, IPs: []net.IP{net.IPv4(10, 77, 0, 145)}, PktCount: 4, LastSeen: now},
		},
	})

	found := false
	for _, node := range graph.Nodes {
		if node.Kind == "target" {
			found = true
			if !containsString(node.IPs, "10.77.0.145") {
				t.Fatalf("target node did not inherit passive IP from target MAC: %+v", node)
			}
		}
	}
	if !found {
		t.Fatalf("target node not found: %+v", graph.Nodes)
	}
}

func TestNetworkGraphCorrelatesDHCPRouterServerAndDNSOnOneIP(t *testing.T) {
	now := time.Now()
	infraIP := net.IPv4(10, 77, 0, 1)
	graph := DashboardModel{}.buildNetworkGraph(bridge.BridgeStatus{IfaceB: "test-switch"}, stealth.NetworkMapSnapshot{
		DHCP: stealth.DHCPTelemetry{
			Seen:       true,
			LastType:   "Ack",
			ACKIP:      infraIP,
			ServerIP:   infraIP,
			RouterIP:   infraIP,
			DNSServers: []net.IP{infraIP},
			LastSeen:   now,
		},
	})

	count := 0
	var infra networkNode
	for _, node := range graph.Nodes {
		if containsString(node.IPs, "10.77.0.1") {
			count++
			infra = node
		}
	}
	if count != 1 {
		t.Fatalf("expected one canonical infrastructure node, got %d nodes: %+v", count, graph.Nodes)
	}
	if infra.Kind != "gateway" {
		t.Fatalf("merged infrastructure node kind = %q, want gateway: %+v", infra.Kind, infra)
	}
	role := displayNodeRole(infra)
	for _, want := range []string{"gateway/router", "DHCP server", "DNS server"} {
		if !strings.Contains(role, want) {
			t.Fatalf("merged infrastructure role missing %q: role=%q node=%+v", want, role, infra)
		}
	}
	label := DashboardModel{}.endpointLabel(bridge.BridgeStatus{}, stealth.NetworkMapSnapshot{
		DHCP: stealth.DHCPTelemetry{
			ServerIP:   infraIP,
			RouterIP:   infraIP,
			DNSServers: []net.IP{infraIP},
		},
	}, infraIP, nil)
	if label != "gateway+dhcp+dns" {
		t.Fatalf("endpoint label = %q, want gateway+dhcp+dns", label)
	}
}

func TestDNSServerEvidenceFromObservedDNSConversationFeedsIntelAndGraph(t *testing.T) {
	now := time.Now()
	dnsIP := net.IPv4(10, 77, 0, 1)
	snap := stealth.NetworkMapSnapshot{
		Conversations: []stealth.ConversationSummary{
			{
				SrcIP:    net.IPv4(10, 77, 0, 145),
				DstIP:    dnsIP,
				Protocol: "DNS",
				SrcPort:  51342,
				DstPort:  53,
				Packets:  2,
				LastSeen: now,
			},
		},
	}

	intel := stripANSI(DashboardModel{}.layer3DetailContent(bridge.BridgeStatus{}, snap, 120))
	if !strings.Contains(intel, "10.77.0.1") || !strings.Contains(intel, "dns-packet") {
		t.Fatalf("page 2 layer 3 detail missing observed DNS conversation:\n%s", intel)
	}

	graph := DashboardModel{networkShowLAN: true}.buildNetworkGraph(bridge.BridgeStatus{IfaceB: "test-switch"}, snap)
	found := false
	for _, node := range graph.Nodes {
		if containsString(node.IPs, "10.77.0.1") {
			found = true
			if displayNodeRole(node) != "DNS server" || !containsString(node.Tags, "dns-query-dst") {
				t.Fatalf("DNS conversation node not tagged as server: %+v role=%q", node, displayNodeRole(node))
			}
		}
	}
	if !found {
		t.Fatalf("DNS server node not found in page 3 graph: %+v", graph.Nodes)
	}
}

func TestDNSServerEvidenceFromDecodedDNSPacketFeedsIntelAndGraph(t *testing.T) {
	now := time.Now()
	dnsIP := net.IPv4(10, 77, 0, 1)
	snap := stealth.NetworkMapSnapshot{
		DNSLog: []stealth.DNSQuery{
			{
				Name:      "router.lab",
				Type:      "A",
				Response:  []string{"10.77.0.1"},
				ClientIP:  net.IPv4(10, 77, 0, 145),
				ServerIP:  dnsIP,
				VLANID:    1,
				Timestamp: now,
			},
		},
	}

	intel := stripANSI(DashboardModel{}.layer3DetailContent(bridge.BridgeStatus{}, snap, 120))
	if !strings.Contains(intel, "10.77.0.1") || !strings.Contains(intel, "dns-packet") || !strings.Contains(intel, "vlan/1") {
		t.Fatalf("page 2 layer 3 detail missing decoded DNS packet:\n%s", intel)
	}

	graph := DashboardModel{networkShowLAN: true}.buildNetworkGraph(bridge.BridgeStatus{IfaceB: "test-switch"}, snap)
	found := false
	for _, node := range graph.Nodes {
		if containsString(node.IPs, "10.77.0.1") {
			found = true
			if displayNodeRole(node) != "DNS server" || !containsString(node.Tags, "dns-packet") || !containsString(node.Tags, "vlan/1") {
				t.Fatalf("decoded DNS packet node not tagged as server: %+v role=%q", node, displayNodeRole(node))
			}
		}
	}
	if !found {
		t.Fatalf("DNS server node not found from decoded packet log: %+v", graph.Nodes)
	}
}

func TestNetworkNodeRoleInferenceTagsServiceCharacteristics(t *testing.T) {
	nodes := []networkNode{
		{Key: "ip:10.77.0.145", Kind: "host", Label: "host", IPs: []string{"10.77.0.145"}},
		{Key: "ip:10.77.0.20", Kind: "host", Label: "host", IPs: []string{"10.77.0.20"}},
		{Key: "ip:10.77.0.53", Kind: "host", Label: "host", IPs: []string{"10.77.0.53"}},
		{Key: "ip:10.77.0.10", Kind: "host", Label: "host", IPs: []string{"10.77.0.10"}},
	}
	edges := []networkEdge{
		{SrcKey: "ip:10.77.0.145", DstKey: "ip:10.77.0.20", Protocol: "JETDIRECT", SrcPort: 49152, DstPort: 9100},
		{SrcKey: "ip:10.77.0.145", DstKey: "ip:10.77.0.53", Protocol: "DNS", SrcPort: 49153, DstPort: 53},
		{SrcKey: "ip:10.77.0.145", DstKey: "ip:10.77.0.10", Protocol: "KERBEROS", SrcPort: 49154, DstPort: 88},
		{SrcKey: "ip:10.77.0.145", DstKey: "ip:10.77.0.10", Protocol: "LDAP", SrcPort: 49155, DstPort: 389},
	}

	inferred := inferNetworkNodeRoles(nodes, edges, bridge.BridgeStatus{}, stealth.NetworkMapSnapshot{})
	byIP := make(map[string]networkNode)
	for _, node := range inferred {
		byIP[node.IPs[0]] = node
	}

	assertNodeRole := func(ip, kind, label, tag string) {
		t.Helper()
		node := byIP[ip]
		if node.Kind != kind || displayNodeRole(node) != label || !containsString(node.Tags, tag) {
			t.Fatalf("node %s role = kind=%q label=%q tags=%v, want kind=%q label=%q tag=%q",
				ip, node.Kind, displayNodeRole(node), node.Tags, kind, label, tag)
		}
	}

	assertNodeRole("10.77.0.20", "printer", "printer", "jetdirect")
	assertNodeRole("10.77.0.53", "dns", "DNS server", "dns-server")
	assertNodeRole("10.77.0.10", "windows", "Windows AD / domain controller", "kerberos+ldap")
}

func TestNetworkNodeRoleInferenceUsesOSFamilySignals(t *testing.T) {
	nodes := []networkNode{
		{Key: "mac:00:11:22:33:44:55", Kind: "host", Label: "host", MAC: "00:11:22:33:44:55", IPs: []string{"10.77.0.25"}},
		{Key: "ip:10.77.0.30", Kind: "host", Label: "host", IPs: []string{"10.77.0.30"}},
		{Key: "ip:10.77.0.40", Kind: "host", Label: "host", IPs: []string{"10.77.0.40"}},
	}
	edges := []networkEdge{
		{SrcKey: "ip:10.77.0.30", DstKey: "ip:10.77.0.40", Protocol: "SSH", DstPort: 22},
		{SrcKey: "ip:10.77.0.30", DstKey: "ip:10.77.0.40", Protocol: "SYSLOG", DstPort: 514},
	}
	snap := stealth.NetworkMapSnapshot{
		DHCP: stealth.DHCPTelemetry{
			ClientMAC:    net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
			ACKIP:        net.IPv4(10, 77, 0, 25),
			VendorClass:  "MSFT 5.0",
			ParamRequest: []byte{1, 3, 6, 15, 44, 46},
		},
		RecentEvents: []stealth.NACEvent{
			{
				Kind:    "LLDP",
				Summary: "sys=edge-sw mgmt=10.77.0.1 caps=bridge,router desc=ExtremeXOS switch",
				SrcMAC:  net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff},
				SrcIP:   net.IPv4(10, 77, 0, 1),
			},
		},
	}

	inferred := inferNetworkNodeRoles(nodes, edges, bridge.BridgeStatus{}, snap)
	byIP := make(map[string]networkNode)
	for _, node := range inferred {
		if len(node.IPs) > 0 {
			byIP[node.IPs[0]] = node
		}
	}

	if node := byIP["10.77.0.25"]; node.Kind != "windows" || displayNodeRole(node) != "Windows" || !containsString(node.Tags, "dhcp-vendor:msft") {
		t.Fatalf("DHCP vendor role = kind=%q label=%q tags=%v", node.Kind, displayNodeRole(node), node.Tags)
	}
	if node := byIP["10.77.0.40"]; node.Kind != "unix" || displayNodeRole(node) != "Unix/Linux" || !containsString(node.Tags, "syslog") {
		t.Fatalf("Unix service role = kind=%q label=%q tags=%v", node.Kind, displayNodeRole(node), node.Tags)
	}
}

func TestNetworkGraphUsesPassiveHostSignalsForNamesAndRoles(t *testing.T) {
	now := time.Now()
	snap := stealth.NetworkMapSnapshot{
		HostSignals: []stealth.HostSignalSummary{
			{
				IP:       net.IPv4(10, 77, 0, 10),
				Kind:     "tcp-fingerprint",
				Value:    "ttl=128 win=64240 mss=1460 opts=mss-nop-wscale-nop-nop-sack",
				Tags:     []string{"tcp-fingerprint", "os-hint:windows", "stack:windows"},
				LastSeen: now,
			},
			{
				IP:       net.IPv4(10, 77, 0, 20),
				Kind:     "tls-sni",
				Value:    "app.internal.example",
				Tags:     []string{"tls", "sni", "web"},
				LastSeen: now,
			},
			{
				IP:       net.IPv4(10, 77, 0, 30),
				Kind:     "ssdp-server",
				Value:    "Linux/5 UPnP/1.0",
				Tags:     []string{"ssdp", "upnp", "iot-discovery"},
				LastSeen: now,
			},
		},
	}

	graph := DashboardModel{networkShowLAN: true}.buildNetworkGraph(bridge.BridgeStatus{IfaceB: "test-switch"}, snap)
	byIP := make(map[string]networkNode)
	for _, node := range graph.Nodes {
		if len(node.IPs) > 0 {
			byIP[node.IPs[0]] = node
		}
	}
	if node := byIP["10.77.0.10"]; node.Kind != "windows" || !containsString(node.Tags, "windows-fingerprint") {
		t.Fatalf("tcp fingerprint did not promote Windows node: %+v role=%q", node, displayNodeRole(node))
	}
	if node := byIP["10.77.0.20"]; node.Kind != "web" || !containsString(node.Names, "app.internal.example") || !containsString(node.Tags, "sni") {
		t.Fatalf("tls sni did not tag/name web node: %+v role=%q", node, displayNodeRole(node))
	}
	if node := byIP["10.77.0.30"]; displayNodeRole(node) != "UPnP / IoT device" || !containsString(node.Tags, "iot") {
		t.Fatalf("ssdp signal did not classify IoT node: %+v role=%q", node, displayNodeRole(node))
	}
}

func TestNetworkGraphPromotesCDPIdentityOverInfraCapabilities(t *testing.T) {
	now := time.Now()
	infraIP := net.IPv4(10, 77, 0, 1)
	infraMAC := net.HardwareAddr{0x00, 0x11, 0xbb, 0x22, 0xcc, 0x33}
	graph := DashboardModel{networkShowLAN: true}.buildNetworkGraph(bridge.BridgeStatus{IfaceB: "test-switch"}, stealth.NetworkMapSnapshot{
		DHCP: stealth.DHCPTelemetry{
			ServerIP:   infraIP,
			RouterIP:   infraIP,
			DNSServers: []net.IP{infraIP},
			LastSeen:   now,
		},
		HostSignals: []stealth.HostSignalSummary{
			{
				MAC:      infraMAC,
				IP:       infraIP,
				Kind:     "cdp",
				Value:    "sys=core-sw platform=Cisco Catalyst 9300 caps=switch,router native-vlan=1",
				Tags:     []string{"cdp", "cisco-discovery", "vendor:cisco", "device:switch", "device:router", "l2-discovery"},
				LastSeen: now,
			},
		},
	})

	node, ok := graph.nodeForIP(infraIP)
	if !ok {
		t.Fatalf("infrastructure node not found: %+v", graph.Nodes)
	}
	if node.Kind != "network" || node.Label != "Cisco switch/router" {
		t.Fatalf("CDP identity did not win primary role: kind=%q label=%q tags=%v", node.Kind, node.Label, node.Tags)
	}
	role := displayNodeRole(node)
	for _, want := range []string{"Cisco switch/router", "gateway/router", "DHCP server", "DNS server"} {
		if !strings.Contains(role, want) {
			t.Fatalf("role missing %q: role=%q node=%+v", want, role, node)
		}
	}
	for _, want := range []string{"vendor:cisco", "identity:cisco", "device:switch"} {
		if !containsString(node.Tags, want) {
			t.Fatalf("CDP evidence tag %q missing from node tags: %+v", want, node.Tags)
		}
	}
}

func TestNetworkGraphDoesNotPromoteOUIOnlyVendorOverService(t *testing.T) {
	now := time.Now()
	dnsIP := net.IPv4(10, 77, 0, 53)
	graph := DashboardModel{networkShowLAN: true}.buildNetworkGraph(bridge.BridgeStatus{IfaceB: "test-switch"}, stealth.NetworkMapSnapshot{
		DNSLog: []stealth.DNSQuery{
			{
				Name:      "host.lab",
				Type:      "A",
				Response:  []string{"10.77.0.50"},
				ClientIP:  net.IPv4(10, 77, 0, 145),
				ServerIP:  dnsIP,
				Timestamp: now,
			},
		},
		HostSignals: []stealth.HostSignalSummary{
			{
				MAC:      net.HardwareAddr{0x00, 0x11, 0xbb, 0xaa, 0xbb, 0xcc},
				IP:       dnsIP,
				Kind:     "oui",
				Value:    "Cisco Systems",
				Tags:     []string{"oui", "vendor:cisco"},
				LastSeen: now,
			},
		},
	})

	node, ok := graph.nodeForIP(dnsIP)
	if !ok {
		t.Fatalf("DNS node not found: %+v", graph.Nodes)
	}
	if node.Kind != "dns" || displayNodeRole(node) != "DNS server" {
		t.Fatalf("OUI-only vendor evidence over-promoted service node: kind=%q role=%q node=%+v",
			node.Kind, displayNodeRole(node), node)
	}
}

func TestNetworkGraphTagsIPScopesAndSuppressesSpecialAddresses(t *testing.T) {
	nodes := tagNetworkNodesByIPScope([]networkNode{
		{
			Key: "mac:02:42:ac:11:00:02",
			MAC: "02:42:ac:11:00:02",
			IPs: []string{"10.77.0.25", "169.254.10.20", "0.0.0.0", "255.255.255.255"},
		},
	})
	nodes = sanitizeNetworkGraphNodes(nodes)
	if len(nodes) != 1 {
		t.Fatalf("expected one sanitized node, got %+v", nodes)
	}
	node := nodes[0]
	if containsString(node.IPs, "169.254.10.20") || containsString(node.IPs, "0.0.0.0") || containsString(node.IPs, "255.255.255.255") {
		t.Fatalf("special IPs should be retained as tags, not displayed as host IPs: %+v", node)
	}
	for _, want := range []string{
		"scope:lan",
		"ip:rfc1918",
		"scope:special",
		"ip:rfc3927-link-local",
		"ip:rfc1122-unspecified",
		"ip:rfc919-broadcast",
		"ip:mixed-private-special",
	} {
		if !containsString(node.Tags, want) {
			t.Fatalf("IP scope tag %q missing from node tags: %+v", want, node.Tags)
		}
	}
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
