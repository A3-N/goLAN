package tui

import (
	"fmt"
	"net"
	"sort"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"
	"github.com/mcrn/goLAN/internal/bridge"
	"github.com/mcrn/goLAN/internal/stealth"
)

type networkGraph struct {
	Nodes    []networkNode
	Edges    []networkEdge
	Selected int
	Filters  networkGraphFilters
}

type networkGraphFilters struct {
	ShowLAN bool
	ShowWAN bool
}

type networkNode struct {
	Key       string
	Kind      string
	Label     string
	MAC       string
	IPs       []string
	Names     []string
	Tags      []string
	PktCount  uint64
	FirstSeen time.Time
	LastSeen  time.Time
}

type networkEdge struct {
	SrcKey   string
	DstKey   string
	Protocol string
	SrcPort  uint16
	DstPort  uint16
	VLANID   uint16
	Packets  uint64
	LastSeen time.Time
	Creds    []string
}

const topologyLinkPrefix = "──"

func (m DashboardModel) renderNetworkPageContent(width, maxHeight int) string {
	status, snap, ok := m.authSnapshot()
	usable, margin := pageContentArea(width)
	if !ok {
		return lipgloss.NewStyle().MarginLeft(margin).Width(usable).MaxWidth(usable).Render(
			renderFixedCard(usable, maxHeight, "Network graph waiting for bridge observer."),
		)
	}
	graph := m.buildNetworkGraph(status, snap)
	content, selectedLine := m.networkGraphContent(graph, usable)
	content = scrollNetworkCardContent(content, maxHeight-2, m.pageScroll, selectedLine, usable)
	return lipgloss.NewStyle().MarginLeft(margin).Width(usable).MaxWidth(usable).Render(
		renderFixedCard(usable, maxHeight, content),
	)
}

func (m DashboardModel) renderNodeDetailPageContent(width, maxHeight int) string {
	status, snap, ok := m.authSnapshot()
	usable, margin := pageContentArea(width)
	if !ok {
		return lipgloss.NewStyle().MarginLeft(margin).Width(usable).MaxWidth(usable).Render(
			renderFixedCard(usable, maxHeight, "Node detail waiting for bridge observer."),
		)
	}
	graph := m.buildNetworkGraph(status, snap)
	node := graph.selectedNode()
	content := m.nodeDetailContent(graph, node, usable)
	return lipgloss.NewStyle().MarginLeft(margin).Width(usable).MaxWidth(usable).Render(
		renderFixedCard(usable, maxHeight, content),
	)
}

func (m DashboardModel) buildNetworkGraph(status bridge.BridgeStatus, snap stealth.NetworkMapSnapshot) networkGraph {
	nodes := make(map[string]networkNode)
	edges := make(map[string]networkEdge)

	addNode := func(node networkNode) {
		if strings.TrimSpace(node.Key) == "" {
			return
		}
		existing := nodes[node.Key]
		if existing.Key == "" {
			existing = node
		} else {
			existing.Kind = preferKind(existing.Kind, node.Kind)
			existing.Label = firstNonEmpty(existing.Label, node.Label)
			existing.MAC = firstNonUnknown(existing.MAC, node.MAC)
			existing.IPs = appendUniqueStrings(existing.IPs, node.IPs...)
			existing.Names = appendUniqueStrings(existing.Names, node.Names...)
			existing.Tags = appendUniqueStrings(existing.Tags, node.Tags...)
			if node.PktCount > existing.PktCount {
				existing.PktCount = node.PktCount
			}
			existing.FirstSeen = minTime(existing.FirstSeen, node.FirstSeen)
			existing.LastSeen = maxTime(existing.LastSeen, node.LastSeen)
		}
		nodes[node.Key] = existing
	}
	addEdge := func(edge networkEdge) {
		if edge.SrcKey == "" || edge.DstKey == "" || edge.SrcKey == edge.DstKey {
			return
		}
		key := edgeKey(edge.SrcKey, edge.DstKey, edge.Protocol, edge.SrcPort, edge.DstPort, edge.VLANID)
		existing := edges[key]
		if existing.SrcKey == "" {
			existing = edge
		} else {
			if edge.Packets > existing.Packets {
				existing.Packets = edge.Packets
			}
			existing.LastSeen = maxTime(existing.LastSeen, edge.LastSeen)
			existing.Creds = appendUniqueStrings(existing.Creds, edge.Creds...)
		}
		edges[key] = existing
	}

	localKey := "local:golan"
	switchKey := "switch:" + status.IfaceB
	if len(snap.EAPOL.AuthenticatorMAC) > 0 {
		switchKey = hostKey(formatMAC(snap.EAPOL.AuthenticatorMAC), "")
	}
	localIPs := nonUnknownStrings(status.NATHiddenIP)
	localNames := []string{"operator access"}
	localTags := []string{"mitm", "operator"}
	if status.NATActive && status.NATAnchorMode != "" {
		localNames = append(localNames, status.NATAnchorMode+" NAT anchor")
		localTags = append(localTags, "nat:"+status.NATAnchorMode)
		if status.NATAnchorEvidence != "" {
			localTags = append(localTags, status.NATAnchorEvidence)
		}
	} else {
		localNames = append(localNames, "operator IP not assigned")
	}
	if status.TargetID != nil && len(status.TargetID.MAC) > 0 {
		localNames = append(localNames, "switch-side MAC "+formatMAC(status.TargetID.MAC))
	}
	addNode(networkNode{Key: localKey, Kind: "local", Label: "goLAN", IPs: localIPs, Names: localNames, Tags: localTags})
	addNode(networkNode{Key: switchKey, Kind: "switch", Label: "Observed network", MAC: formatMAC(snap.EAPOL.AuthenticatorMAC), Names: nonUnknownStrings(status.IfaceB)})
	addEdge(networkEdge{SrcKey: localKey, DstKey: switchKey, Protocol: "inline"})

	targetKey := ""
	if status.TargetID != nil {
		targetIPs := ipStringCandidates(targetIPCandidates(status, snap))
		targetKey = hostKey(formatMAC(status.TargetID.MAC), firstNonEmpty(targetIPs...))
		addNode(networkNode{
			Key:   targetKey,
			Kind:  "target",
			Label: "PC / supplicant",
			MAC:   formatMAC(status.TargetID.MAC),
			IPs:   targetIPs,
			Names: []string{"downstream supplicant"},
			Tags:  []string{"pc-ip", "target-identity"},
		})
		addEdge(networkEdge{SrcKey: targetKey, DstKey: switchKey, Protocol: "L2"})
	}

	for _, host := range snap.Hosts {
		ips := ipStrings(host.IPs)
		key := hostKey(formatMAC(host.MAC), firstNonEmpty(ips...))
		addNode(networkNode{
			Key:       key,
			Kind:      classifyHostKind(ips),
			Label:     classifyHostKind(ips),
			MAC:       formatMAC(host.MAC),
			IPs:       ips,
			PktCount:  host.PktCount,
			FirstSeen: host.FirstSeen,
			LastSeen:  host.LastSeen,
		})
		addEdge(networkEdge{SrcKey: switchKey, DstKey: key, Protocol: "L2", Packets: host.PktCount, LastSeen: host.LastSeen})
	}

	for _, signal := range snap.HostSignals {
		ips := nonUnknownStrings(formatIP(signal.IP))
		key := hostKey(formatMAC(signal.MAC), firstNonEmpty(ips...))
		if key == "" {
			continue
		}
		tags := signalNodeTags(signal)
		addNode(networkNode{
			Key:      key,
			Kind:     classifyHostKind(ips),
			Label:    classifyHostKind(ips),
			MAC:      formatMAC(signal.MAC),
			IPs:      ips,
			Names:    signalNodeNames(signal),
			Tags:     tags,
			PktCount: signal.Count,
			LastSeen: signal.LastSeen,
		})
		addEdge(networkEdge{SrcKey: switchKey, DstKey: key, Protocol: "L2", Packets: signal.Count, LastSeen: signal.LastSeen})
	}

	for _, event := range snap.RecentEvents {
		if event.Kind != "LLDP" && event.Kind != "CDP" {
			continue
		}
		key := hostKey(formatMAC(event.SrcMAC), formatIP(event.SrcIP))
		if key == "" {
			continue
		}
		addNode(networkNode{
			Key:      key,
			Kind:     "network",
			Label:    "network device",
			MAC:      formatMAC(event.SrcMAC),
			IPs:      nonUnknownStrings(formatIP(event.SrcIP)),
			Names:    nonUnknownStrings(event.Summary),
			Tags:     []string{strings.ToLower(event.Kind), "l2-discovery"},
			LastSeen: event.Timestamp,
		})
		addEdge(networkEdge{SrcKey: switchKey, DstKey: key, Protocol: event.Kind, VLANID: event.VLANID, LastSeen: event.Timestamp})
	}

	for _, dns := range snap.DNSLog {
		for _, response := range dns.Response {
			key := hostKey("", response)
			addNode(networkNode{Key: key, Kind: classifyHostKind([]string{response}), Label: "dns", IPs: []string{response}, Names: []string{dns.Name}, LastSeen: dns.Timestamp})
		}
	}
	if len(snap.Gateway.IP) > 0 || len(snap.Gateway.MAC) > 0 {
		key := hostKey(formatMAC(snap.Gateway.MAC), formatIP(snap.Gateway.IP))
		addNode(networkNode{Key: key, Kind: "gateway", Label: "gateway/router", MAC: formatMAC(snap.Gateway.MAC), IPs: nonUnknownStrings(formatIP(snap.Gateway.IP)), Tags: []string{"default-gateway", "router", "arp-heavy"}, PktCount: snap.Gateway.PktCount})
		addEdge(networkEdge{SrcKey: switchKey, DstKey: key, Protocol: "L2", Packets: snap.Gateway.PktCount})
	}
	if len(snap.DHCP.RouterIP) > 0 {
		key := hostKey("", formatIP(snap.DHCP.RouterIP))
		addNode(networkNode{Key: key, Kind: "gateway", Label: "gateway/router", IPs: []string{formatIP(snap.DHCP.RouterIP)}, Tags: []string{"default-gateway", "dhcp-router"}, LastSeen: snap.DHCP.LastSeen})
		addEdge(networkEdge{SrcKey: switchKey, DstKey: key, Protocol: "DHCP-ROUTER", LastSeen: snap.DHCP.LastSeen})
	}
	dhcpServerKey := ""
	if len(snap.DHCP.ServerIP) > 0 {
		dhcpServerKey = hostKey("", formatIP(snap.DHCP.ServerIP))
		addNode(networkNode{Key: dhcpServerKey, Kind: "dhcp", Label: "DHCP server", IPs: []string{formatIP(snap.DHCP.ServerIP)}, Tags: []string{"dhcp-server", "udp/67", "offers/acks", "lease/router/netmask"}, LastSeen: snap.DHCP.LastSeen})
		addEdge(networkEdge{SrcKey: switchKey, DstKey: dhcpServerKey, Protocol: "DHCP-SERVER", LastSeen: snap.DHCP.LastSeen})
		if targetKey != "" {
			addEdge(networkEdge{SrcKey: dhcpServerKey, DstKey: targetKey, Protocol: "DHCP", SrcPort: 67, DstPort: 68, LastSeen: snap.DHCP.LastSeen})
		}
	}
	for _, leaseIP := range ipStringCandidates([]net.IP{snap.DHCP.ACKIP, snap.DHCP.OfferedIP}) {
		key := hostKey("", leaseIP)
		addNode(networkNode{Key: key, Kind: "host", Label: "DHCP lease", IPs: []string{leaseIP}, Tags: []string{"dhcp-lease"}, LastSeen: snap.DHCP.LastSeen})
		if dhcpServerKey != "" {
			addEdge(networkEdge{SrcKey: dhcpServerKey, DstKey: key, Protocol: "DHCP", SrcPort: 67, DstPort: 68, LastSeen: snap.DHCP.LastSeen})
		} else {
			addEdge(networkEdge{SrcKey: switchKey, DstKey: key, Protocol: "DHCP-LEASE", LastSeen: snap.DHCP.LastSeen})
		}
	}
	dnsEvidence := dnsServerEvidence(snap)
	for _, dnsIP := range dnsServerCandidates(snap) {
		ip := formatIP(dnsIP)
		key := hostKey("", ip)
		tags := appendUniqueStrings([]string{"dns-server", "name-resolution"}, dnsEvidence[ip]...)
		lastSeen := dnsServerLastSeen(snap, dnsIP)
		addNode(networkNode{Key: key, Kind: "dns", Label: "DNS server", IPs: []string{ip}, Tags: tags, LastSeen: lastSeen})
		tagMap := tagSet(tags)
		if tagMap["dhcp-option-6"] {
			addEdge(networkEdge{SrcKey: switchKey, DstKey: key, Protocol: "DHCP-DNS", DstPort: 53, LastSeen: maxTime(snap.DHCP.LastSeen, lastSeen)})
		}
		if tagMap["dns-conversation"] || tagMap["dns-query-dst"] || tagMap["dns-response-src"] {
			addEdge(networkEdge{SrcKey: switchKey, DstKey: key, Protocol: "DNS-EVIDENCE", DstPort: 53, LastSeen: lastSeen})
		}
	}
	if len(snap.RADIUS.ServerIP) > 0 {
		server := hostKey("", formatIP(snap.RADIUS.ServerIP))
		client := hostKey("", formatIP(snap.RADIUS.ClientIP))
		addNode(networkNode{Key: server, Kind: "radius", Label: "RADIUS server", IPs: []string{formatIP(snap.RADIUS.ServerIP)}, Tags: []string{"radius-server", "udp/1812", "aaa", "nac-control-plane"}, LastSeen: snap.RADIUS.LastSeen})
		if client != "" {
			addNode(networkNode{Key: client, Kind: "nas", Label: "NAS / RADIUS client", IPs: []string{formatIP(snap.RADIUS.ClientIP)}, Tags: []string{"radius-client", "nas", "switch-control-plane"}, LastSeen: snap.RADIUS.LastSeen})
			addEdge(networkEdge{SrcKey: client, DstKey: server, Protocol: "RADIUS", DstPort: 1812, LastSeen: snap.RADIUS.LastSeen})
		}
		if len(snap.RADIUS.NASIPAddress) > 0 {
			nas := hostKey("", formatIP(snap.RADIUS.NASIPAddress))
			addNode(networkNode{Key: nas, Kind: "nas", Label: "NAS / RADIUS client", IPs: []string{formatIP(snap.RADIUS.NASIPAddress)}, Tags: []string{"radius-client", "nas", "switch-control-plane"}, LastSeen: snap.RADIUS.LastSeen})
			addEdge(networkEdge{SrcKey: nas, DstKey: server, Protocol: "RADIUS", DstPort: 1812, LastSeen: snap.RADIUS.LastSeen})
		}
	}

	for _, conv := range snap.Conversations {
		src := hostKey(formatMAC(conv.SrcMAC), formatIP(conv.SrcIP))
		dst := hostKey(formatMAC(conv.DstMAC), formatIP(conv.DstIP))
		addNode(networkNode{Key: src, Kind: classifyHostKind([]string{formatIP(conv.SrcIP)}), Label: classifyHostKind([]string{formatIP(conv.SrcIP)}), MAC: formatMAC(conv.SrcMAC), IPs: nonUnknownStrings(formatIP(conv.SrcIP)), LastSeen: conv.LastSeen})
		addNode(networkNode{Key: dst, Kind: classifyHostKind([]string{formatIP(conv.DstIP)}), Label: classifyHostKind([]string{formatIP(conv.DstIP)}), MAC: formatMAC(conv.DstMAC), IPs: nonUnknownStrings(formatIP(conv.DstIP)), LastSeen: conv.LastSeen})
		addEdge(networkEdge{SrcKey: src, DstKey: dst, Protocol: conv.Protocol, SrcPort: conv.SrcPort, DstPort: conv.DstPort, VLANID: conv.VLANID, Packets: conv.Packets, LastSeen: conv.LastSeen})
	}
	for _, finding := range snap.CredentialExposures {
		src := hostKey("", formatIP(finding.SrcIP))
		dst := hostKey("", formatIP(finding.ServiceIP))
		addNode(networkNode{Key: src, Kind: classifyHostKind([]string{formatIP(finding.SrcIP)}), Label: "client", IPs: nonUnknownStrings(formatIP(finding.SrcIP)), LastSeen: finding.LastSeen})
		addNode(networkNode{Key: dst, Kind: "service", Label: finding.Service, IPs: nonUnknownStrings(formatIP(finding.ServiceIP)), Names: nonUnknownStrings(finding.Host), LastSeen: finding.LastSeen})
		addEdge(networkEdge{SrcKey: src, DstKey: dst, Protocol: finding.Service, DstPort: finding.ServicePort, VLANID: finding.VLANID, Packets: uint64(finding.Count), LastSeen: finding.LastSeen, Creds: []string{credentialEdgeLabel(finding)}})
	}

	list := make([]networkNode, 0, len(nodes))
	for _, node := range nodes {
		list = append(list, node)
	}
	list = tagNetworkNodesByIPScope(list)
	edgeList := make([]networkEdge, 0, len(edges))
	for _, edge := range edges {
		edgeList = append(edgeList, edge)
	}
	aliasByKey := map[string]string{}
	list, edgeList, aliasByKey = canonicalizeNetworkGraphAliases(list, edgeList)
	edgeList = annotateCredentialEdges(edgeList, list, snap.CredentialExposures)
	list = inferNetworkNodeRoles(list, edgeList, status, snap)
	sort.Slice(list, func(i, j int) bool {
		ri, rj := nodeRank(list[i].Kind), nodeRank(list[j].Kind)
		if ri != rj {
			return ri > rj
		}
		return nodeTitle(list[i]) < nodeTitle(list[j])
	})
	sort.Slice(edgeList, func(i, j int) bool {
		if edgeList[i].LastSeen.Equal(edgeList[j].LastSeen) {
			return edgeList[i].Packets > edgeList[j].Packets
		}
		return edgeList[i].LastSeen.After(edgeList[j].LastSeen)
	})

	selected := 0
	selectedKey := firstNonEmpty(aliasByKey[m.selectedNodeKey], m.selectedNodeKey)
	for i, node := range list {
		if node.Key == selectedKey {
			selected = i
			break
		}
	}
	graph := networkGraph{
		Nodes:    list,
		Edges:    edgeList,
		Selected: selected,
		Filters: networkGraphFilters{
			ShowLAN: m.networkShowLAN,
			ShowWAN: m.networkShowWAN,
		},
	}
	return filterNetworkGraph(graph)
}

func canonicalizeNetworkGraphAliases(nodes []networkNode, edges []networkEdge) ([]networkNode, []networkEdge, map[string]string) {
	parent := make(map[string]string, len(nodes))
	byIP := make(map[string]string)
	byMAC := make(map[string]string)

	find := func(key string) string {
		if key == "" {
			return ""
		}
		if parent[key] == "" {
			parent[key] = key
			return key
		}
		root := key
		for parent[root] != root {
			root = parent[root]
		}
		for parent[key] != key {
			next := parent[key]
			parent[key] = root
			key = next
		}
		return root
	}
	union := func(a, b string) {
		ra, rb := find(a), find(b)
		if ra == "" || rb == "" || ra == rb {
			return
		}
		parent[rb] = ra
	}

	for _, node := range nodes {
		if !nodeAliasMergeEligible(node) {
			continue
		}
		find(node.Key)
		for _, ip := range node.IPs {
			if parsed := net.ParseIP(ip); parsed != nil {
				key := parsed.String()
				if existing := byIP[key]; existing != "" {
					union(existing, node.Key)
				} else {
					byIP[key] = node.Key
				}
			}
		}
		if node.MAC != "" && node.MAC != "unknown" {
			key := strings.ToLower(node.MAC)
			if existing := byMAC[key]; existing != "" {
				union(existing, node.Key)
			} else {
				byMAC[key] = node.Key
			}
		}
	}

	groups := make(map[string][]networkNode)
	aliasByKey := make(map[string]string, len(nodes))
	for _, node := range nodes {
		root := node.Key
		if nodeAliasMergeEligible(node) {
			root = find(node.Key)
		}
		groups[root] = append(groups[root], node)
	}

	mergedByRoot := make(map[string]networkNode, len(groups))
	for root, group := range groups {
		canonicalKey := preferredCanonicalNodeKey(group)
		merged := networkNode{Key: canonicalKey}
		for _, node := range group {
			aliasByKey[node.Key] = canonicalKey
			merged = mergeNetworkNode(merged, node)
		}
		merged.Key = canonicalKey
		mergedByRoot[root] = merged
	}

	outNodes := make([]networkNode, 0, len(mergedByRoot))
	for _, node := range mergedByRoot {
		outNodes = append(outNodes, node)
	}

	edgeMap := make(map[string]networkEdge, len(edges))
	for _, edge := range edges {
		edge.SrcKey = firstNonEmpty(aliasByKey[edge.SrcKey], edge.SrcKey)
		edge.DstKey = firstNonEmpty(aliasByKey[edge.DstKey], edge.DstKey)
		if edge.SrcKey == "" || edge.DstKey == "" || edge.SrcKey == edge.DstKey {
			continue
		}
		key := edgeKey(edge.SrcKey, edge.DstKey, edge.Protocol, edge.SrcPort, edge.DstPort, edge.VLANID)
		existing := edgeMap[key]
		if existing.SrcKey == "" {
			edge.Creds = appendUniqueStrings(nil, edge.Creds...)
			edgeMap[key] = edge
			continue
		}
		if edge.Packets > existing.Packets {
			existing.Packets = edge.Packets
		}
		existing.LastSeen = maxTime(existing.LastSeen, edge.LastSeen)
		existing.Creds = appendUniqueStrings(existing.Creds, edge.Creds...)
		edgeMap[key] = existing
	}
	outEdges := make([]networkEdge, 0, len(edgeMap))
	for _, edge := range edgeMap {
		outEdges = append(outEdges, edge)
	}

	return outNodes, outEdges, aliasByKey
}

func signalNodeTags(signal stealth.HostSignalSummary) []string {
	tags := appendUniqueStrings([]string{"signal:" + strings.ToLower(strings.TrimSpace(signal.Kind))}, signal.Tags...)
	value := strings.ToLower(strings.TrimSpace(signal.Value))
	switch signal.Kind {
	case "oui":
		if value != "" {
			tags = appendUniqueString(tags, "oui")
		}
	case "cdp", "lldp":
		tags = appendUniqueStrings(tags, strings.ToLower(signal.Kind), "l2-discovery", "network-discovery")
	case "ssh-banner":
		tags = appendUniqueStrings(tags, "ssh", "server-banner")
	case "http-host", "http-server":
		tags = appendUniqueStrings(tags, "http", "web")
	case "tls-sni":
		tags = appendUniqueStrings(tags, "tls", "sni", "web")
	case "ssdp-server", "ssdp-type":
		tags = appendUniqueStrings(tags, "ssdp", "upnp")
	case "ws-discovery":
		tags = appendUniqueStrings(tags, "ws-discovery", "windows")
	case "llmnr", "netbios":
		tags = appendUniqueStrings(tags, "windows-name-resolution", "windows")
	case "dns-name", "dhcp-hostname":
		tags = appendUniqueString(tags, "name-evidence")
	}
	return tags
}

func signalNodeNames(signal stealth.HostSignalSummary) []string {
	value := strings.TrimSpace(signal.Value)
	if value == "" {
		return nil
	}
	switch signal.Kind {
	case "dns-name", "dhcp-hostname", "http-host", "tls-sni":
		return []string{value}
	case "cdp", "lldp":
		return nonUnknownStrings(l2SignalField(value, "sys"))
	default:
		return nil
	}
}

func l2SignalField(value string, field string) string {
	value = strings.TrimSpace(value)
	field = strings.TrimSpace(field)
	if value == "" || field == "" {
		return ""
	}
	prefix := field + "="
	idx := strings.Index(value, prefix)
	if idx < 0 {
		return ""
	}
	start := idx + len(prefix)
	end := len(value)
	for _, marker := range []string{" sys=", " port=", " mgmt=", " caps=", " desc=", " platform=", " version=", " native-vlan="} {
		if markerIdx := strings.Index(value[start:], marker); markerIdx >= 0 && start+markerIdx < end {
			end = start + markerIdx
		}
	}
	return strings.TrimSpace(value[start:end])
}

func nodeAliasMergeEligible(node networkNode) bool {
	if node.Key == "" || strings.HasPrefix(node.Key, "local:") {
		return false
	}
	return true
}

func preferredCanonicalNodeKey(nodes []networkNode) string {
	best := ""
	bestRank := -1
	for _, node := range nodes {
		rank := 0
		switch {
		case node.Kind == "target":
			rank = 100
		case node.Kind == "switch":
			rank = 90
		case strings.HasPrefix(node.Key, "mac:"):
			rank = 80
		case node.Kind == "gateway" || node.Kind == "dhcp" || node.Kind == "radius" || node.Kind == "nas":
			rank = 70
		case strings.HasPrefix(node.Key, "ip:"):
			rank = 60
		default:
			rank = 10
		}
		if rank > bestRank || (rank == bestRank && (best == "" || node.Key < best)) {
			best = node.Key
			bestRank = rank
		}
	}
	return best
}

func mergeNetworkNode(existing, node networkNode) networkNode {
	if existing.Key == "" {
		existing.Key = node.Key
	}
	existing.Kind = preferKind(existing.Kind, node.Kind)
	existing.Label = firstNonEmpty(existing.Label, node.Label)
	existing.MAC = firstNonUnknown(existing.MAC, node.MAC)
	existing.IPs = appendUniqueStrings(existing.IPs, node.IPs...)
	existing.Names = appendUniqueStrings(existing.Names, node.Names...)
	existing.Tags = appendUniqueStrings(existing.Tags, node.Tags...)
	if node.PktCount > existing.PktCount {
		existing.PktCount = node.PktCount
	}
	existing.FirstSeen = minTime(existing.FirstSeen, node.FirstSeen)
	existing.LastSeen = maxTime(existing.LastSeen, node.LastSeen)
	return existing
}

func (g networkGraph) selectedNode() networkNode {
	if len(g.Nodes) == 0 {
		return networkNode{}
	}
	if g.Selected < 0 || g.Selected >= len(g.Nodes) {
		return g.Nodes[0]
	}
	return g.Nodes[g.Selected]
}

func (g networkGraph) firstNodeByKind(kind string) (int, networkNode) {
	for i, node := range g.Nodes {
		if node.Kind == kind {
			return i, node
		}
	}
	return -1, networkNode{}
}

type topologyBranch struct {
	Index int
	Node  networkNode
}

func (g networkGraph) topologyBranches() []topologyBranch {
	out := make([]topologyBranch, 0, len(g.Nodes))
	for i, node := range g.Nodes {
		switch node.Kind {
		case "local", "switch":
			continue
		default:
			out = append(out, topologyBranch{Index: i, Node: node})
		}
	}
	return out
}

func (g networkGraph) trafficModeLabel() string {
	if g.Filters.ShowWAN {
		return "WAN / internet"
	}
	return "LAN / internal"
}

func (g networkGraph) shortTrafficModeLabel() string {
	if g.Filters.ShowWAN {
		return "WAN"
	}
	return "LAN"
}

func filterNetworkGraph(graph networkGraph) networkGraph {
	if !graph.Filters.ShowLAN && !graph.Filters.ShowWAN {
		graph.Filters.ShowLAN = true
	}
	graph.Nodes = sanitizeNetworkGraphNodes(graph.Nodes)

	nodeByKey := make(map[string]networkNode, len(graph.Nodes))
	visibleNodes := make(map[string]bool, len(graph.Nodes))
	for _, node := range graph.Nodes {
		nodeByKey[node.Key] = node
		if isAlwaysVisibleNode(node) || (isAnchorNode(node) && nodeVisibleInTrafficMode(node, graph.Filters)) {
			visibleNodes[node.Key] = true
		}
	}

	visibleEdges := make([]networkEdge, 0, len(graph.Edges))
	for _, edge := range graph.Edges {
		if edgeHasSuppressedSpecial(edge, nodeByKey) {
			continue
		}
		external := edgeIsExternal(edge, nodeByKey)
		if (external && !graph.Filters.ShowWAN) || (!external && !graph.Filters.ShowLAN) {
			continue
		}
		visibleEdges = append(visibleEdges, edge)
		visibleNodes[edge.SrcKey] = true
		visibleNodes[edge.DstKey] = true
	}

	visibleList := make([]networkNode, 0, len(graph.Nodes))
	for _, node := range graph.Nodes {
		if visibleNodes[node.Key] {
			visibleList = append(visibleList, node)
		}
	}

	selected := 0
	for i, node := range visibleList {
		if node.Key == graph.selectedNode().Key {
			selected = i
			break
		}
	}
	graph.Nodes = visibleList
	graph.Edges = visibleEdges
	graph.Selected = selected
	return graph
}

func sanitizeNetworkGraphNodes(nodes []networkNode) []networkNode {
	out := make([]networkNode, 0, len(nodes))
	for _, node := range nodes {
		filteredIPs := make([]string, 0, len(node.IPs))
		for _, ip := range node.IPs {
			if ipStringIsSuppressedSpecial(ip) {
				continue
			}
			filteredIPs = appendUniqueString(filteredIPs, ip)
		}
		node.IPs = filteredIPs
		if keyLooksSuppressedSpecial(node.Key) && len(node.IPs) == 0 && !isAlwaysVisibleNode(node) {
			continue
		}
		out = append(out, node)
	}
	return out
}

func tagNetworkNodesByIPScope(nodes []networkNode) []networkNode {
	out := append([]networkNode(nil), nodes...)
	for i := range out {
		tags := out[i].Tags
		seenPrivate := false
		seenSpecial := false
		seenWAN := false
		for _, value := range out[i].IPs {
			scopeTags := ipScopeTags(value)
			if len(scopeTags) == 0 {
				continue
			}
			tags = appendUniqueStrings(tags, scopeTags...)
			scopeSet := tagSet(scopeTags)
			seenPrivate = seenPrivate || scopeSet["ip:rfc1918"]
			seenSpecial = seenSpecial || scopeSet["scope:special"]
			seenWAN = seenWAN || scopeSet["scope:wan"]
		}
		if ip := ipFromHostKey(out[i].Key); ip != "" {
			scopeTags := ipScopeTags(ip)
			tags = appendUniqueStrings(tags, scopeTags...)
			scopeSet := tagSet(scopeTags)
			seenPrivate = seenPrivate || scopeSet["ip:rfc1918"]
			seenSpecial = seenSpecial || scopeSet["scope:special"]
			seenWAN = seenWAN || scopeSet["scope:wan"]
		}
		if seenPrivate && seenSpecial {
			tags = appendUniqueStrings(tags, "ip:mixed-private-special")
		}
		if seenPrivate && seenWAN {
			tags = appendUniqueStrings(tags, "ip:mixed-lan-wan")
		}
		out[i].Tags = tags
	}
	return out
}

func isAlwaysVisibleNode(node networkNode) bool {
	switch node.Kind {
	case "local", "switch", "target":
		return true
	default:
		return false
	}
}

func isAnchorNode(node networkNode) bool {
	switch node.Kind {
	case "gateway", "dhcp", "dns", "radius", "nas":
		return true
	default:
		return false
	}
}

func nodeVisibleInTrafficMode(node networkNode, filters networkGraphFilters) bool {
	external := nodeIsExternal(node) || keyLooksExternal(node.Key)
	if external {
		return filters.ShowWAN
	}
	return filters.ShowLAN
}

func edgeIsExternal(edge networkEdge, nodes map[string]networkNode) bool {
	return nodeIsExternal(nodes[edge.SrcKey]) || nodeIsExternal(nodes[edge.DstKey]) || keyLooksExternal(edge.SrcKey) || keyLooksExternal(edge.DstKey)
}

func edgeIsLinkLocal(edge networkEdge, nodes map[string]networkNode) bool {
	return nodeHasLinkLocalOnly(nodes[edge.SrcKey]) || nodeHasLinkLocalOnly(nodes[edge.DstKey]) || keyLooksLinkLocal(edge.SrcKey) || keyLooksLinkLocal(edge.DstKey)
}

func edgeHasSuppressedSpecial(edge networkEdge, nodes map[string]networkNode) bool {
	return nodeHasSuppressedSpecialOnly(nodes[edge.SrcKey]) || nodeHasSuppressedSpecialOnly(nodes[edge.DstKey]) ||
		keyLooksSuppressedSpecial(edge.SrcKey) || keyLooksSuppressedSpecial(edge.DstKey)
}

func nodeIsExternal(node networkNode) bool {
	if node.Kind == "external" {
		return true
	}
	for _, ip := range node.IPs {
		parsed := net.ParseIP(ip)
		if parsed == nil {
			continue
		}
		if !parsed.IsPrivate() && !parsed.IsLinkLocalUnicast() && !parsed.IsLoopback() && !parsed.IsMulticast() && !parsed.IsUnspecified() {
			return true
		}
	}
	return false
}

func nodeHasLinkLocalOnly(node networkNode) bool {
	if node.Key == "" {
		return false
	}
	if keyLooksLinkLocal(node.Key) {
		return true
	}
	if len(node.IPs) == 0 {
		return false
	}
	for _, ip := range node.IPs {
		if !ipStringIsLinkLocal(ip) {
			return false
		}
	}
	return true
}

func nodeHasSuppressedSpecialOnly(node networkNode) bool {
	if node.Key == "" {
		return false
	}
	if keyLooksSuppressedSpecial(node.Key) {
		return true
	}
	if len(node.IPs) == 0 {
		return false
	}
	for _, ip := range node.IPs {
		if !ipStringIsSuppressedSpecial(ip) {
			return false
		}
	}
	return true
}

func keyLooksExternal(key string) bool {
	if !strings.HasPrefix(key, "ip:") {
		return false
	}
	ip := net.ParseIP(strings.TrimPrefix(key, "ip:"))
	if ip == nil {
		return false
	}
	return !ip.IsPrivate() && !ip.IsLinkLocalUnicast() && !ip.IsLoopback() && !ip.IsMulticast() && !ip.IsUnspecified()
}

func keyLooksLinkLocal(key string) bool {
	if !strings.HasPrefix(key, "ip:") {
		return false
	}
	return ipStringIsLinkLocal(strings.TrimPrefix(key, "ip:"))
}

func ipStringIsLinkLocal(value string) bool {
	ip := net.ParseIP(value)
	return ip != nil && ip.IsLinkLocalUnicast()
}

func keyLooksSuppressedSpecial(key string) bool {
	if !strings.HasPrefix(key, "ip:") {
		return false
	}
	return ipStringIsSuppressedSpecial(strings.TrimPrefix(key, "ip:"))
}

func ipStringIsSuppressedSpecial(value string) bool {
	ip := net.ParseIP(value)
	if ip == nil {
		return false
	}
	return ip.IsUnspecified() || ip.IsLoopback() || ip.IsMulticast() || ip.IsLinkLocalUnicast() || ipIsLimitedBroadcast(ip) || ipIsReservedNonHost(ip)
}

func ipScopeTags(value string) []string {
	ip := net.ParseIP(strings.TrimSpace(value))
	if ip == nil {
		return nil
	}
	var tags []string
	switch {
	case ip.IsUnspecified():
		tags = appendUniqueStrings(tags, "scope:special", "ip:rfc1122-unspecified")
	case ipIsLimitedBroadcast(ip):
		tags = appendUniqueStrings(tags, "scope:special", "ip:rfc919-broadcast")
	case ip.IsLoopback():
		tags = appendUniqueStrings(tags, "scope:special", "ip:rfc1122-loopback")
	case ip.IsLinkLocalUnicast():
		tags = appendUniqueStrings(tags, "scope:special", "ip:rfc3927-link-local")
	case ip.IsLinkLocalMulticast():
		tags = appendUniqueStrings(tags, "scope:special", "ip:link-local-multicast")
	case ip.IsMulticast():
		tags = appendUniqueStrings(tags, "scope:special", "ip:rfc5771-multicast")
	case ip.IsPrivate():
		tags = appendUniqueStrings(tags, "scope:lan", "ip:rfc1918")
	case ipIsCarrierGradeNAT(ip):
		tags = appendUniqueStrings(tags, "scope:special", "ip:rfc6598-shared")
	case ipIsDocumentation(ip):
		tags = appendUniqueStrings(tags, "scope:special", "ip:rfc5737-documentation")
	case ipIsBenchmark(ip):
		tags = appendUniqueStrings(tags, "scope:special", "ip:rfc2544-benchmark")
	case ipIsReservedNonHost(ip):
		tags = appendUniqueStrings(tags, "scope:special", "ip:rfc6890-reserved")
	case ip.IsGlobalUnicast():
		tags = appendUniqueStrings(tags, "scope:wan", "ip:global-unicast")
	default:
		tags = appendUniqueStrings(tags, "scope:special", "ip:rfc6890-special")
	}
	return tags
}

func ipIsLimitedBroadcast(ip net.IP) bool {
	ip4 := ip.To4()
	return ip4 != nil && ip4[0] == 255 && ip4[1] == 255 && ip4[2] == 255 && ip4[3] == 255
}

func ipIsCarrierGradeNAT(ip net.IP) bool {
	ip4 := ip.To4()
	return ip4 != nil && ip4[0] == 100 && ip4[1]&0xc0 == 64
}

func ipIsDocumentation(ip net.IP) bool {
	ip4 := ip.To4()
	if ip4 != nil {
		return (ip4[0] == 192 && ip4[1] == 0 && ip4[2] == 2) ||
			(ip4[0] == 198 && ip4[1] == 51 && ip4[2] == 100) ||
			(ip4[0] == 203 && ip4[1] == 0 && ip4[2] == 113)
	}
	return strings.EqualFold(ip.String(), "2001:db8::") || strings.HasPrefix(strings.ToLower(ip.String()), "2001:db8:")
}

func ipIsBenchmark(ip net.IP) bool {
	ip4 := ip.To4()
	return ip4 != nil && ip4[0] == 198 && (ip4[1] == 18 || ip4[1] == 19)
}

func ipIsReservedNonHost(ip net.IP) bool {
	ip4 := ip.To4()
	if ip4 == nil {
		return false
	}
	return ip4[0] >= 240
}

func (m DashboardModel) networkGraphContent(graph networkGraph, width int) (string, int) {
	var sb strings.Builder
	selectedLine := -1
	lineNo := 0
	writeLine := func(line string) {
		sb.WriteString(line + "\n")
		lineNo++
	}
	writeSelected := func(line string, selected bool) {
		if selected && selectedLine == -1 {
			selectedLine = lineNo
		}
		writeLine(line)
	}

	sb.WriteString(styleLabel.Render("Network Layout") + "\n")
	lineNo++
	sb.WriteString(styleDim.Render("Use arrows to select a node, Enter for detail. L/W selects LAN or WAN comms.") + "\n")
	lineNo++
	writeLine(styleDim.Render("Traffic mode: " + graph.trafficModeLabel()))

	localIdx, localNode := graph.firstNodeByKind("local")
	switchIdx, switchNode := graph.firstNodeByKind("switch")
	leftWidth, rightWidth, gap := topologyColumnWidths(width)
	addBlock := func(left []string, right []string, selectedLeftLine int) {
		lines := len(left)
		if len(right) > lines {
			lines = len(right)
		}
		for i := 0; i < lines; i++ {
			leftLine := ""
			if i < len(left) {
				leftLine = left[i]
			}
			rightLine := ""
			if i < len(right) {
				rightLine = right[i]
			}
			writeSelected(joinTopologyColumns(leftLine, rightLine, leftWidth, rightWidth, gap), i == selectedLeftLine)
		}
	}

	localHeader := topologyNodeHeader(localIdx, localNode, width-8)
	if localNode.Key == "" {
		localHeader = "[MitM goLAN]"
	}
	localLine := trunc("   "+localHeader, leftWidth)
	if graph.Selected == localIdx {
		localLine = styleWarning.Render(localLine)
	} else {
		localLine = styleSuccess.Render(localLine)
	}
	localBlock := []string{localLine}
	for _, meta := range topologyNodeMeta(localNode, width-10) {
		localBlock = append(localBlock, styleDim.Render(trunc("   │  "+meta, leftWidth)))
	}
	addBlock(localBlock, []string{
		styleLabel.Render(trunc("Traffic Links", rightWidth)),
		styleDim.Render(trunc("mode: "+graph.trafficModeLabel(), rightWidth)),
	}, selectedTopologyLine(graph.Selected == localIdx))

	center := topologyNodeHeader(switchIdx, switchNode, width-20)
	if switchNode.Key == "" {
		center = "[NET observed network]"
	}
	centerLine := trunc(fmt.Sprintf("   └─==inline== %s", center), leftWidth)
	if graph.Selected == switchIdx {
		centerLine = styleWarning.Render(centerLine)
	} else {
		centerLine = styleIfaceNameSwitch.Render(centerLine)
	}
	switchBlock := []string{centerLine}
	for _, meta := range topologyNodeMeta(switchNode, width-18) {
		switchBlock = append(switchBlock, styleDim.Render(trunc("      │  "+meta, leftWidth)))
	}
	addBlock(switchBlock, []string{styleDim.Render(trunc("observed conversations by endpoint", rightWidth))}, selectedTopologyLine(graph.Selected == switchIdx))

	branches := graph.topologyBranches()
	if len(branches) == 0 {
		addBlock([]string{styleDim.Render("      └─ no hosts match current traffic mode yet")}, nil, -1)
		return sb.String(), selectedLine
	}

	for branchIndex, item := range branches {
		connector := "├─"
		childConnector := "│ "
		if branchIndex == len(branches)-1 {
			connector = "└─"
			childConnector = "  "
		}
		line := trunc(fmt.Sprintf("      %s==L2== %s", connector, topologyNodeHeader(item.Index, item.Node, leftWidth-16)), leftWidth)
		if item.Index == graph.Selected {
			line = styleWarning.Render(line)
		} else {
			line = styleVal.Render(line)
		}
		leftBlock := []string{line}

		for _, meta := range topologyNodeMeta(item.Node, width-22) {
			leftBlock = append(leftBlock, styleDim.Render(trunc("      "+childConnector+"       "+meta, leftWidth)))
		}
		rightBlock := make([]string, len(leftBlock))
		selectedBranch := item.Index == graph.Selected
		if selectedBranch {
			leftBlock, rightBlock = graph.appendTopologyCommRows(item.Node.Key, childConnector, leftWidth, rightWidth, leftBlock, rightBlock)
		}
		selectedLineInBlock := selectedTopologyLine(selectedBranch)
		if selectedBranch && len(leftBlock) > 0 {
			selectedLineInBlock = len(leftBlock) - 1
		}
		addBlock(leftBlock, rightBlock, selectedLineInBlock)
	}
	return sb.String(), selectedLine
}

func selectedTopologyLine(selected bool) int {
	if selected {
		return 0
	}
	return -1
}

func topologyColumnWidths(width int) (int, int, int) {
	width = safeWidth(width)
	if width < 56 {
		return width, 0, 0
	}
	gap := 2
	left := (width - gap) / 2
	right := width - left - gap
	if right < 18 {
		return width, 0, 0
	}
	return left, right, gap
}

func joinTopologyColumns(left, right string, leftWidth, rightWidth, gap int) string {
	if rightWidth <= 0 {
		return left
	}
	pad := leftWidth - lipgloss.Width(left)
	if pad < 0 {
		pad = 0
	}
	bridge := strings.Repeat(" ", pad+gap)
	switch {
	case strings.Contains(right, "══"):
		bridge = strings.Repeat("═", pad+gap)
	case strings.Contains(right, topologyLinkPrefix):
		bridge = strings.Repeat("─", pad+gap)
	}
	return left + bridge + right
}

func topologyNodeHeader(index int, node networkNode, width int) string {
	if node.Key == "" {
		return ""
	}
	title := nodeTitle(node)
	if title == node.Key {
		title = firstNonEmpty(node.Label, node.Key)
	}
	parts := []string{title}
	if role := displayNodeRole(node); role != "" {
		parts = append(parts, role)
	}
	prefix := fmt.Sprintf("[%02d %s ", index+1, nodeKindGlyph(node.Kind))
	if index < 0 {
		prefix = "[" + nodeKindGlyph(node.Kind) + " "
	}
	return trunc(prefix+strings.Join(parts, "  ")+"]", width)
}

func topologyNodeMeta(node networkNode, width int) []string {
	if node.Key == "" {
		return nil
	}
	var meta []string
	ipLabel := "ip"
	switch node.Kind {
	case "local":
		ipLabel = "operator ip"
	case "target":
		ipLabel = "pc ip"
	}
	if len(node.IPs) > 0 {
		meta = append(meta, ipLabel+": "+strings.Join(node.IPs, ", "))
	} else {
		meta = append(meta, ipLabel+": unknown")
	}
	if node.MAC != "" && node.MAC != "unknown" {
		meta = append(meta, "mac: "+node.MAC)
	}
	if len(node.Names) > 0 {
		meta = append(meta, "name: "+strings.Join(node.Names, ", "))
	}
	if len(node.Tags) > 0 {
		meta = append(meta, "tags: "+strings.Join(limitStrings(node.Tags, 8), ", "))
	}
	if node.PktCount > 0 {
		meta = append(meta, fmt.Sprintf("seen: %d pkt", node.PktCount))
	}
	for i, value := range meta {
		meta[i] = trunc(value, width)
	}
	return meta
}

func scrollNetworkCardContent(content string, maxLines int, scroll int, selectedLine int, width int) string {
	content = strings.TrimRight(content, "\n")
	if maxLines <= 0 || content == "" {
		return ""
	}
	lines := strings.Split(content, "\n")
	if len(lines) <= maxLines {
		return content
	}
	if maxLines == 1 {
		return styleDim.Render(trunc("resize terminal", width-4))
	}

	visibleHeight := maxLines - 1
	if scroll < 0 {
		scroll = 0
	}
	maxScroll := len(lines) - visibleHeight
	if maxScroll < 0 {
		maxScroll = 0
	}
	if selectedLine >= 0 {
		if selectedLine < scroll {
			scroll = selectedLine
		}
		if selectedLine >= scroll+visibleHeight {
			scroll = selectedLine - visibleHeight + 1
		}
	}
	if scroll > maxScroll {
		scroll = maxScroll
	}

	end := scroll + visibleHeight
	if end > len(lines) {
		end = len(lines)
	}
	visible := append([]string(nil), lines[scroll:end]...)
	marker := fmt.Sprintf("showing %d-%d/%d  selection scrolls with ↑↓", scroll+1, end, len(lines))
	visible = append(visible, styleDim.Render(trunc(marker, width-4)))
	return strings.Join(visible, "\n")
}

func (m DashboardModel) nodeDetailContent(graph networkGraph, node networkNode, width int) string {
	var sb strings.Builder
	if node.Key == "" {
		sb.WriteString("No node selected.\n")
		return sb.String()
	}
	sb.WriteString(styleLabel.Render("Node Detail") + " " + styleWarning.Render(nodeTitle(node)) + "\n")
	sb.WriteString(renderKeyValue("Kind", node.Kind) + "\n")
	sb.WriteString(renderKeyValue("Role", emptyText(displayNodeRole(node))) + "\n")
	sb.WriteString(renderKeyValue("Tags", emptyText(strings.Join(node.Tags, ", "))) + "\n")
	sb.WriteString(renderKeyValue("MAC", emptyText(node.MAC)) + "\n")
	ipLabel := "IPs"
	switch node.Kind {
	case "local":
		ipLabel = "Operator IP"
	case "target":
		ipLabel = "PC IPs"
	}
	sb.WriteString(renderKeyValue(ipLabel, emptyText(strings.Join(node.IPs, ", "))) + "\n")
	sb.WriteString(renderKeyValue("DNS/Names", emptyText(strings.Join(node.Names, ", "))) + "\n")
	sb.WriteString(renderKeyValue("Packets", fmt.Sprintf("%d", node.PktCount)) + "\n")
	if !node.LastSeen.IsZero() {
		sb.WriteString(renderKeyValue("Last seen", ageString(node.LastSeen)) + "\n")
	}
	sb.WriteString(styleLabel.Render("Inbound") + "\n")
	for _, edge := range graph.EdgesFor(node.Key, false) {
		sb.WriteString(styleDim.Render(trunc(edgeLine(edge, graph), width-4)) + "\n")
	}
	sb.WriteString(styleLabel.Render("Outbound") + "\n")
	for _, edge := range graph.EdgesFor(node.Key, true) {
		sb.WriteString(styleDim.Render(trunc(edgeLine(edge, graph), width-4)) + "\n")
	}
	return sb.String()
}

func (g networkGraph) EdgesFor(key string, outbound bool) []networkEdge {
	out := make([]networkEdge, 0, 8)
	for _, edge := range g.Edges {
		if outbound && edge.SrcKey == key {
			out = append(out, edge)
		}
		if !outbound && edge.DstKey == key {
			out = append(out, edge)
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		return topologyEdgeSortKey(out[i], g, key) < topologyEdgeSortKey(out[j], g, key)
	})
	if len(out) > 12 {
		out = out[:12]
	}
	return out
}

func (g networkGraph) topologyCommsFor(key string, limit int) []networkEdge {
	out := make([]networkEdge, 0, limit)
	for _, edge := range g.Edges {
		if edge.Protocol == "inline" || edge.Protocol == "L2" || edge.Protocol == "DHCP-OPT" {
			continue
		}
		if edge.SrcKey != key && edge.DstKey != key {
			continue
		}
		out = append(out, edge)
	}
	sort.SliceStable(out, func(i, j int) bool {
		return topologyEdgeSortKey(out[i], g, key) < topologyEdgeSortKey(out[j], g, key)
	})
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out
}

func (g networkGraph) appendTopologyCommRows(key, childConnector string, leftWidth, rightWidth int, leftBlock, rightBlock []string) ([]string, []string) {
	if key == "" {
		return leftBlock, rightBlock
	}
	comms := g.topologyCommsFor(key, 0)
	if len(comms) == 0 {
		left := fmt.Sprintf("      %s       no %s links", childConnector, g.shortTrafficModeLabel())
		leftBlock = append(leftBlock, styleDim.Render(trunc(left, leftWidth)))
		rightBlock = append(rightBlock, "")
		return leftBlock, rightBlock
	}
	for i, edge := range comms {
		connector := "├─"
		if i == len(comms)-1 {
			connector = "└─"
		}
		left := fmt.Sprintf("      %s       %s %s", childConnector, connector, edgeLabel(edge))
		leftBlock = append(leftBlock, styleDim.Render(trunc(left, leftWidth)))
		rightBlock = append(rightBlock, styleDim.Render(trunc(topologyPeerOnlyLine(edge, g, key), rightWidth)))
		packets := fmt.Sprintf("      %s          %d pkt", childConnector, edge.Packets)
		leftBlock = append(leftBlock, styleDim.Render(trunc(packets, leftWidth)))
		rightBlock = append(rightBlock, "")
	}
	return leftBlock, rightBlock
}

func topologyEdgeSortKey(edge networkEdge, graph networkGraph, perspective string) string {
	peer := edge.DstKey
	direction := "out"
	if edge.DstKey == perspective {
		peer = edge.SrcKey
		direction = "in"
	}
	return strings.Join([]string{
		direction,
		graph.nodeShort(peer),
		strings.ToUpper(edge.Protocol),
		fmt.Sprintf("%05d", edge.DstPort),
		fmt.Sprintf("%05d", edge.SrcPort),
		fmt.Sprintf("%05d", edge.VLANID),
	}, "|")
}

func edgeLine(edge networkEdge, graph networkGraph) string {
	label := edge.Protocol
	if edge.DstPort != 0 {
		label += fmt.Sprintf(":%d", edge.DstPort)
	}
	if edge.VLANID != 0 {
		label += fmt.Sprintf("/vlan%d", edge.VLANID)
	}
	return fmt.Sprintf("%s --%s--> %s  %d pkt", graph.nodeShort(edge.SrcKey), label, graph.nodeShort(edge.DstKey), edge.Packets)
}

func topologyPeerOnlyLine(edge networkEdge, graph networkGraph, perspective string) string {
	peer := edge.DstKey
	outbound := true
	if edge.DstKey == perspective {
		peer = edge.SrcKey
		outbound = false
	}
	peerLabel := "(" + graph.nodeShort(peer) + ")"
	credential := edgeCredentialMarker(edge)
	if graph.edgeIsExternal(edge) {
		if outbound {
			return connectorWithEdgeLabel("══", ">", credential) + peerLabel
		}
		return connectorWithEdgeLabel("══", "<", credential) + peerLabel
	}
	if outbound {
		return connectorWithEdgeLabel("──", ">", credential) + peerLabel
	}
	return connectorWithEdgeLabel("──", "<", credential) + peerLabel
}

func connectorWithEdgeLabel(line, arrow, label string) string {
	if label == "" {
		if arrow == "<" {
			return "<" + line
		}
		return line + arrow
	}
	label = "[" + label + "]"
	if arrow == "<" {
		return "<" + line + label + line
	}
	return line + label + line + arrow
}

func edgeCredentialMarker(edge networkEdge) string {
	for _, value := range edge.Creds {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func annotateCredentialEdges(edges []networkEdge, nodes []networkNode, findings []stealth.CredentialExposureSummary) []networkEdge {
	if len(edges) == 0 || len(findings) == 0 {
		return edges
	}
	out := append([]networkEdge(nil), edges...)
	nodeByKey := make(map[string]networkNode, len(nodes))
	for _, node := range nodes {
		nodeByKey[node.Key] = node
	}
	for i := range out {
		for _, finding := range findings {
			if edgeMatchesCredential(out[i], nodeByKey, finding) {
				out[i].Creds = appendUniqueStrings(out[i].Creds, credentialEdgeLabel(finding))
			}
		}
		out[i].Creds = limitStrings(out[i].Creds, 3)
	}
	return out
}

func edgeMatchesCredential(edge networkEdge, nodes map[string]networkNode, finding stealth.CredentialExposureSummary) bool {
	if finding.ServicePort != 0 && edge.SrcPort != finding.ServicePort && edge.DstPort != finding.ServicePort {
		return false
	}
	if finding.VLANID != 0 && edge.VLANID != 0 && finding.VLANID != edge.VLANID {
		return false
	}
	if finding.Service != "" && edge.Protocol != "" && edge.Protocol != "TCP" && edge.Protocol != "UDP" &&
		!strings.EqualFold(edge.Protocol, finding.Service) {
		return false
	}

	src := nodes[edge.SrcKey]
	dst := nodes[edge.DstKey]
	serviceIP := formatIP(finding.ServiceIP)
	srcIP := formatIP(finding.SrcIP)
	dstIP := formatIP(finding.DstIP)
	serviceOnSrc := nodeHasIP(src, serviceIP)
	serviceOnDst := nodeHasIP(dst, serviceIP)
	if !serviceOnSrc && !serviceOnDst {
		return false
	}
	if srcIP == "unknown" && dstIP == "unknown" {
		return true
	}
	return (nodeHasIP(src, srcIP) && nodeHasIP(dst, dstIP)) ||
		(nodeHasIP(src, dstIP) && nodeHasIP(dst, srcIP)) ||
		(serviceOnSrc && (nodeHasIP(dst, srcIP) || nodeHasIP(dst, dstIP))) ||
		(serviceOnDst && (nodeHasIP(src, srcIP) || nodeHasIP(src, dstIP)))
}

func nodeHasIP(node networkNode, ip string) bool {
	if ip == "" || ip == "unknown" {
		return false
	}
	for _, value := range node.IPs {
		if value == ip {
			return true
		}
	}
	if strings.TrimPrefix(node.Key, "ip:") == ip {
		return true
	}
	return false
}

func credentialEdgeLabel(finding stealth.CredentialExposureSummary) string {
	secret := strings.TrimSpace(finding.SecretValue)
	if secret == "" {
		return ""
	}
	user := strings.TrimSpace(finding.Username)
	if user != "" && !strings.EqualFold(user, "unknown") {
		return trunc("cred "+user+":"+secret, 42)
	}
	if kind := strings.TrimSpace(finding.SecretKind); kind != "" {
		return trunc("cred "+kind+"="+secret, 42)
	}
	return trunc("cred "+secret, 42)
}

func edgeLabel(edge networkEdge) string {
	label := edge.Protocol
	if edge.DstPort != 0 {
		label += fmt.Sprintf(":%d", edge.DstPort)
	}
	if edge.VLANID != 0 {
		label += fmt.Sprintf("/vlan%d", edge.VLANID)
	}
	return label
}

func (g networkGraph) edgeIsExternal(edge networkEdge) bool {
	nodes := make(map[string]networkNode, len(g.Nodes))
	for _, node := range g.Nodes {
		nodes[node.Key] = node
	}
	return edgeIsExternal(edge, nodes)
}

func (g networkGraph) nodeShort(key string) string {
	for _, node := range g.Nodes {
		if node.Key == key {
			return nodeTitle(node)
		}
	}
	return strings.TrimPrefix(strings.TrimPrefix(key, "mac:"), "ip:")
}

func nodeSummary(node networkNode, width int) string {
	parts := []string{nodeTitle(node)}
	if role := displayNodeRole(node); role != "" {
		parts = append(parts, role)
	}
	if node.MAC != "" && node.MAC != "unknown" {
		parts = append(parts, node.MAC)
	}
	if len(node.Names) > 0 {
		parts = append(parts, strings.Join(node.Names, ","))
	}
	return trunc(strings.Join(parts, "  "), width)
}

func nodeTitle(node networkNode) string {
	if len(node.IPs) > 0 {
		return node.IPs[0]
	}
	if len(node.Names) > 0 {
		return node.Names[0]
	}
	if node.MAC != "" && node.MAC != "unknown" {
		return node.MAC
	}
	return firstNonEmpty(node.Label, node.Key)
}

func nodeKindGlyph(kind string) string {
	switch kind {
	case "local":
		return "MitM"
	case "target":
		return "PC"
	case "switch":
		return "NET"
	case "gateway":
		return "GW"
	case "dhcp":
		return "DH"
	case "radius":
		return "RA"
	case "nas":
		return "NAS"
	case "dns":
		return "DNS"
	case "printer":
		return "PRN"
	case "dc":
		return "AD"
	case "windows":
		return "WIN"
	case "unix":
		return "UNX"
	case "apple":
		return "APL"
	case "network":
		return "NET"
	case "phone":
		return "PHN"
	case "web":
		return "WEB"
	case "ntp":
		return "NTP"
	case "service":
		return "SVC"
	case "external":
		return "EX"
	default:
		return "IP"
	}
}

func onOff(enabled bool) string {
	if enabled {
		return "on"
	}
	return "off"
}

func nodeRank(kind string) int {
	switch kind {
	case "local":
		return 100
	case "switch":
		return 90
	case "target":
		return 80
	case "gateway":
		return 70
	case "dhcp", "radius", "nas", "dns", "dc", "network":
		return 60
	case "printer", "windows", "unix", "apple", "phone", "web", "ntp", "service":
		return 45
	case "external":
		return 20
	default:
		return 30
	}
}

func classifyHostKind(ips []string) string {
	for _, value := range ips {
		ip := net.ParseIP(value)
		if ip == nil {
			continue
		}
		if ip.IsPrivate() || ip.IsLinkLocalUnicast() {
			return "host"
		}
		return "external"
	}
	return "host"
}
