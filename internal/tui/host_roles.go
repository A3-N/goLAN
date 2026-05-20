package tui

import (
	"fmt"
	"net"
	"sort"
	"strings"

	"github.com/mcrn/goLAN/internal/bridge"
	"github.com/mcrn/goLAN/internal/stealth"
)

type nodeRoleUpdate struct {
	Kind  string
	Label string
	Score int
	Tags  []string
}

func inferNetworkNodeRoles(nodes []networkNode, edges []networkEdge, status bridge.BridgeStatus, snap stealth.NetworkMapSnapshot) []networkNode {
	out := append([]networkNode(nil), nodes...)
	scores := make([]int, len(out))
	byKey := make(map[string][]int, len(out))
	byIP := make(map[string][]int, len(out))
	byMAC := make(map[string][]int, len(out))

	for i, node := range out {
		scores[i] = baseNodeRoleScore(node.Kind)
		byKey[node.Key] = append(byKey[node.Key], i)
		for _, ip := range node.IPs {
			if parsed := net.ParseIP(ip); parsed != nil {
				byIP[parsed.String()] = append(byIP[parsed.String()], i)
			}
		}
		if node.MAC != "" && node.MAC != "unknown" {
			byMAC[strings.ToLower(node.MAC)] = append(byMAC[strings.ToLower(node.MAC)], i)
		}
	}

	applyIndex := func(i int, update nodeRoleUpdate) {
		if i < 0 || i >= len(out) {
			return
		}
		node := out[i]
		node.Tags = appendUniqueStrings(node.Tags, update.Tags...)
		if update.Score >= scores[i] && roleCanPromote(node.Kind) {
			node.Kind = firstNonEmpty(update.Kind, node.Kind)
			node.Label = firstNonEmpty(update.Label, node.Label)
			scores[i] = update.Score
		} else if isGenericNodeLabel(node.Label) && update.Label != "" {
			node.Label = update.Label
		}
		out[i] = node
	}
	applyIndexes := func(indexes []int, update nodeRoleUpdate) {
		for _, i := range indexes {
			applyIndex(i, update)
		}
	}
	applyKey := func(key string, update nodeRoleUpdate) {
		applyIndexes(byKey[key], update)
		if ip := ipFromHostKey(key); ip != "" {
			applyIndexes(byIP[ip], update)
		}
	}
	applyIP := func(ip net.IP, update nodeRoleUpdate) {
		if ip == nil {
			return
		}
		applyIndexes(byIP[ip.String()], update)
	}
	applyMAC := func(mac net.HardwareAddr, update nodeRoleUpdate) {
		if len(mac) == 0 {
			return
		}
		applyIndexes(byMAC[strings.ToLower(mac.String())], update)
	}

	if len(snap.Gateway.IP) > 0 || len(snap.Gateway.MAC) > 0 {
		update := nodeRoleUpdate{Kind: "gateway", Label: "gateway/router", Score: 95, Tags: []string{"default-gateway", "router", "arp-heavy"}}
		applyIP(snap.Gateway.IP, update)
		applyMAC(snap.Gateway.MAC, update)
	}
	if len(snap.DHCP.RouterIP) > 0 {
		applyIP(snap.DHCP.RouterIP, nodeRoleUpdate{Kind: "gateway", Label: "gateway/router", Score: 94, Tags: []string{"dhcp-router", "default-gateway"}})
	}
	if len(snap.DHCP.ServerIP) > 0 {
		applyIP(snap.DHCP.ServerIP, nodeRoleUpdate{Kind: "dhcp", Label: "DHCP server", Score: 92, Tags: []string{"dhcp-server", "udp/67", "offers/acks", "lease/router/netmask"}})
	}
	for ipText, evidence := range dnsServerEvidence(snap) {
		if ip := net.ParseIP(ipText); ip != nil {
			tags := appendUniqueStrings([]string{"dns-server", "name-resolution"}, evidence...)
			applyIP(ip, nodeRoleUpdate{Kind: "dns", Label: "DNS server", Score: 84, Tags: tags})
		}
	}
	if dhcpRole, ok := inferRoleFromDHCPVendor(snap.DHCP.VendorClass, snap.DHCP.ParamRequest); ok {
		applyMAC(snap.DHCP.ClientMAC, dhcpRole)
		applyIP(firstIP(snap.DHCP.ACKIP, snap.DHCP.OfferedIP), dhcpRole)
	}
	if len(snap.RADIUS.ServerIP) > 0 {
		applyIP(snap.RADIUS.ServerIP, nodeRoleUpdate{Kind: "radius", Label: "RADIUS server", Score: 92, Tags: []string{"radius-server", "udp/1812", "aaa", "nac-control-plane"}})
	}
	if len(snap.RADIUS.ClientIP) > 0 {
		applyIP(snap.RADIUS.ClientIP, nodeRoleUpdate{Kind: "nas", Label: "NAS / RADIUS client", Score: 88, Tags: []string{"radius-client", "nas", "switch-control-plane"}})
	}
	if status.TargetID != nil {
		applyMAC(status.TargetID.MAC, nodeRoleUpdate{Score: 0, Tags: []string{"supplicant", "connecting-device"}})
	}

	for _, edge := range edges {
		inferServiceRoleForEndpoint(edge.SrcKey, edge.Protocol, edge.SrcPort, applyKey)
		inferServiceRoleForEndpoint(edge.DstKey, edge.Protocol, edge.DstPort, applyKey)
	}
	for _, event := range snap.RecentEvents {
		if update, ok := inferRoleFromL2Event(event); ok {
			applyMAC(event.SrcMAC, update)
			applyIP(event.SrcIP, update)
		}
	}

	for i, node := range out {
		if nameRole, ok := inferRoleFromNames(node.Names); ok {
			applyIndex(i, nameRole)
		}
		tags := tagSet(out[i].Tags)
		if identityRole, ok := inferRoleFromIdentityTags(tags); ok {
			applyIndex(i, identityRole)
			tags = tagSet(out[i].Tags)
		}
		switch {
		case tags["kerberos/kdc"] && tags["ldap"]:
			applyIndex(i, nodeRoleUpdate{Kind: "windows", Label: "Windows AD / domain controller", Score: 96, Tags: []string{"active-directory", "directory", "kerberos+ldap", "windows"}})
		case tags["jetdirect"] || tags["ipp"] || tags["lpd"] || tags["printer-name"] || (tags["snmp-agent"] && tags["ws-discovery"]):
			applyIndex(i, nodeRoleUpdate{Kind: "printer", Label: "printer", Score: 84, Tags: []string{"print-service"}})
		case tags["smb"] && (tags["rdp"] || tags["winrm"] || tags["netbios"] || tags["ms-rpc"] || tags["llmnr"] || tags["ws-discovery"]):
			applyIndex(i, nodeRoleUpdate{Kind: "windows", Label: "Windows", Score: 72, Tags: []string{"windows-services"}})
		case tags["os-hint:windows"] || tags["stack:windows"] || tags["dhcp-vendor:msft"]:
			applyIndex(i, nodeRoleUpdate{Kind: "windows", Label: "Windows", Score: 66, Tags: []string{"windows-fingerprint"}})
		case tags["ssh"] && (tags["syslog"] || tags["nfs"] || tags["rpcbind"] || tags["dhcp-vendor:unix"]):
			applyIndex(i, nodeRoleUpdate{Kind: "unix", Label: "Unix/Linux", Score: 72, Tags: []string{"unix-like-services"}})
		case tags["os-hint:unix"] || tags["stack:unix"] || tags["dhcp-vendor:unix"]:
			applyIndex(i, nodeRoleUpdate{Kind: "unix", Label: "Unix/Linux", Score: 64, Tags: []string{"unix-fingerprint"}})
		case tags["os-hint:apple"] || tags["dhcp-vendor:apple"] || (tags["bonjour"] && tags["mdns"]):
			applyIndex(i, nodeRoleUpdate{Kind: "apple", Label: "Apple/Bonjour", Score: 64, Tags: []string{"apple-fingerprint"}})
		case tags["upnp"] || tags["iot-discovery"]:
			applyIndex(i, nodeRoleUpdate{Kind: "service", Label: "UPnP / IoT device", Score: 52, Tags: []string{"iot"}})
		case tags["web"] && (tags["http-server"] || tags["tls"] || tags["sni"]):
			applyIndex(i, nodeRoleUpdate{Kind: "web", Label: "web service", Score: 54, Tags: []string{"web-identity"}})
		case tags["cdp"] || tags["lldp"] || tags["bridge"] || tags["router"] || tags["snmp-agent"]:
			applyIndex(i, nodeRoleUpdate{Kind: "network", Label: "network device", Score: 68, Tags: []string{"infrastructure-signal"}})
		}
		out[i].Tags = limitStrings(out[i].Tags, 12)
	}

	return out
}

func inferServiceRoleForEndpoint(key string, proto string, port uint16, apply func(string, nodeRoleUpdate)) {
	if key == "" {
		return
	}
	if update, ok := roleForServicePort(port); ok {
		apply(key, update)
		return
	}
	if port == 0 {
		if update, ok := roleForProtocol(proto); ok {
			apply(key, update)
		}
	}
}

func roleForServicePort(port uint16) (nodeRoleUpdate, bool) {
	switch port {
	case 53:
		return nodeRoleUpdate{Kind: "dns", Label: "DNS server", Score: 74, Tags: []string{"dns-server", "udp/tcp-53", "name-resolution"}}, true
	case 67:
		return nodeRoleUpdate{Kind: "dhcp", Label: "DHCP server", Score: 90, Tags: []string{"dhcp-server", "udp/67"}}, true
	case 68:
		return nodeRoleUpdate{Kind: "host", Label: "DHCP client", Score: 25, Tags: []string{"dhcp-client", "udp/68"}}, true
	case 88, 464:
		return nodeRoleUpdate{Kind: "windows", Label: "Windows", Score: 78, Tags: []string{"kerberos/kdc", "directory-auth", fmt.Sprintf("port/%d", port)}}, true
	case 123:
		return nodeRoleUpdate{Kind: "ntp", Label: "NTP server", Score: 65, Tags: []string{"ntp", "time-service"}}, true
	case 135:
		return nodeRoleUpdate{Kind: "windows", Label: "Windows", Score: 58, Tags: []string{"ms-rpc", "windows"}}, true
	case 137, 138, 139:
		return nodeRoleUpdate{Kind: "windows", Label: "Windows", Score: 60, Tags: []string{"netbios", "windows"}}, true
	case 161:
		return nodeRoleUpdate{Kind: "network", Label: "network device", Score: 56, Tags: []string{"snmp-agent", "udp/161", "network-managed"}}, true
	case 162:
		return nodeRoleUpdate{Kind: "service", Label: "SNMP trap receiver", Score: 52, Tags: []string{"snmp-trap", "udp/162"}}, true
	case 389, 636, 3268, 3269:
		return nodeRoleUpdate{Kind: "service", Label: "directory server", Score: 62, Tags: []string{"ldap", "directory", fmt.Sprintf("port/%d", port)}}, true
	case 445:
		return nodeRoleUpdate{Kind: "windows", Label: "Windows", Score: 64, Tags: []string{"smb", "windows", "file-sharing"}}, true
	case 515:
		return nodeRoleUpdate{Kind: "printer", Label: "printer", Score: 82, Tags: []string{"lpd", "printer"}}, true
	case 631:
		return nodeRoleUpdate{Kind: "printer", Label: "printer", Score: 82, Tags: []string{"ipp", "printer"}}, true
	case 9100:
		return nodeRoleUpdate{Kind: "printer", Label: "printer", Score: 84, Tags: []string{"jetdirect", "raw-print", "printer"}}, true
	case 1812, 1813:
		return nodeRoleUpdate{Kind: "radius", Label: "RADIUS server", Score: 90, Tags: []string{"radius-server", fmt.Sprintf("udp/%d", port), "aaa"}}, true
	case 3389:
		return nodeRoleUpdate{Kind: "windows", Label: "Windows", Score: 66, Tags: []string{"rdp", "windows"}}, true
	case 5353:
		return nodeRoleUpdate{Kind: "apple", Label: "Bonjour/mDNS host", Score: 46, Tags: []string{"mdns", "bonjour"}}, true
	case 5355:
		return nodeRoleUpdate{Kind: "windows", Label: "Windows", Score: 50, Tags: []string{"llmnr", "windows-name-resolution"}}, true
	case 5985, 5986:
		return nodeRoleUpdate{Kind: "windows", Label: "Windows", Score: 68, Tags: []string{"winrm", "windows"}}, true
	case 8080, 8443:
		return nodeRoleUpdate{Kind: "web", Label: "web service", Score: 52, Tags: []string{"http-alt", fmt.Sprintf("port/%d", port)}}, true
	case 1900:
		return nodeRoleUpdate{Kind: "service", Label: "SSDP / UPnP", Score: 44, Tags: []string{"ssdp", "upnp", "iot-discovery"}}, true
	case 3702:
		return nodeRoleUpdate{Kind: "windows", Label: "Windows", Score: 50, Tags: []string{"ws-discovery", "windows", "printer-discovery"}}, true
	}

	switch {
	case port == 22:
		return nodeRoleUpdate{Kind: "unix", Label: "Unix/Linux", Score: 56, Tags: []string{"ssh", "unix-like", "port/22"}}, true
	case port == 21 || port == 23 || port == 69:
		labels := map[uint16]string{21: "FTP service", 23: "Telnet service", 69: "TFTP service"}
		return nodeRoleUpdate{Kind: "service", Label: labels[port], Score: 46, Tags: []string{strings.ToLower(strings.Fields(labels[port])[0]), fmt.Sprintf("port/%d", port)}}, true
	case port == 25 || port == 465 || port == 587 || port == 110 || port == 143 || port == 993 || port == 995:
		return nodeRoleUpdate{Kind: "service", Label: "mail service", Score: 50, Tags: []string{"mail", fmt.Sprintf("port/%d", port)}}, true
	case port == 80 || port == 443:
		return nodeRoleUpdate{Kind: "web", Label: "web service", Score: 50, Tags: []string{"http", fmt.Sprintf("port/%d", port)}}, true
	case port == 514:
		return nodeRoleUpdate{Kind: "unix", Label: "Unix/Linux", Score: 58, Tags: []string{"syslog", "logging", "unix-like"}}, true
	case port == 111:
		return nodeRoleUpdate{Kind: "unix", Label: "Unix/Linux", Score: 56, Tags: []string{"rpcbind", "unix-like", "port/111"}}, true
	case port == 2049:
		return nodeRoleUpdate{Kind: "unix", Label: "Unix/Linux", Score: 62, Tags: []string{"nfs", "unix-like", "port/2049"}}, true
	}
	return nodeRoleUpdate{}, false
}

func roleForProtocol(proto string) (nodeRoleUpdate, bool) {
	switch strings.ToUpper(strings.TrimSpace(proto)) {
	case "DNS", "MDNS":
		return nodeRoleUpdate{Kind: "dns", Label: "DNS server", Score: 60, Tags: []string{"dns-observed"}}, true
	case "DHCP":
		return nodeRoleUpdate{Kind: "dhcp", Label: "DHCP server/client", Score: 55, Tags: []string{"dhcp-observed"}}, true
	case "RADIUS":
		return nodeRoleUpdate{Kind: "radius", Label: "RADIUS endpoint", Score: 70, Tags: []string{"radius-observed"}}, true
	case "SNMP":
		return nodeRoleUpdate{Kind: "network", Label: "network device", Score: 50, Tags: []string{"snmp-observed", "network-managed"}}, true
	case "SMB", "MSRPC", "RDP", "WINRM", "NBNS", "LLMNR", "WSD":
		return nodeRoleUpdate{Kind: "windows", Label: "Windows", Score: 56, Tags: []string{strings.ToLower(strings.TrimSpace(proto)), "windows"}}, true
	case "SSH":
		return nodeRoleUpdate{Kind: "unix", Label: "Unix/Linux", Score: 52, Tags: []string{"ssh", "unix-like"}}, true
	case "NFS", "RPCBIND", "SYSLOG":
		return nodeRoleUpdate{Kind: "unix", Label: "Unix/Linux", Score: 58, Tags: []string{strings.ToLower(strings.TrimSpace(proto)), "unix-like"}}, true
	case "IPP", "LPD", "JETDIRECT":
		return nodeRoleUpdate{Kind: "printer", Label: "printer", Score: 75, Tags: []string{"print-service"}}, true
	default:
		return nodeRoleUpdate{}, false
	}
}

func inferRoleFromNames(names []string) (nodeRoleUpdate, bool) {
	joined := strings.ToLower(strings.Join(names, " "))
	switch {
	case strings.Contains(joined, "printer") || strings.Contains(joined, "_ipp") || strings.Contains(joined, "airprint") ||
		strings.Contains(joined, "xerox") || strings.Contains(joined, "brother") || strings.Contains(joined, "canon") ||
		strings.Contains(joined, "laserjet") || strings.Contains(joined, "officejet"):
		return nodeRoleUpdate{Kind: "printer", Label: "printer", Score: 86, Tags: []string{"printer-name"}}, true
	case strings.Contains(joined, "wpad"):
		return nodeRoleUpdate{Kind: "web", Label: "WPAD / proxy", Score: 72, Tags: []string{"wpad", "proxy-discovery"}}, true
	case strings.Contains(joined, "_ldap") || strings.Contains(joined, "_kerberos") || strings.Contains(joined, "domaincontroller"):
		return nodeRoleUpdate{Kind: "windows", Label: "Windows AD / domain controller", Score: 88, Tags: []string{"ad-dns-name", "windows"}}, true
	case strings.Contains(joined, "windows") || strings.Contains(joined, "msft") || strings.Contains(joined, "workgroup") || strings.Contains(joined, "_smb"):
		return nodeRoleUpdate{Kind: "windows", Label: "Windows", Score: 62, Tags: []string{"windows-name"}}, true
	case strings.Contains(joined, "ubuntu") || strings.Contains(joined, "debian") || strings.Contains(joined, "linux") ||
		strings.Contains(joined, "freebsd") || strings.Contains(joined, "openbsd") || strings.Contains(joined, "centos") ||
		strings.Contains(joined, "redhat") || strings.Contains(joined, "raspberrypi"):
		return nodeRoleUpdate{Kind: "unix", Label: "Unix/Linux", Score: 66, Tags: []string{"unix-name"}}, true
	case strings.Contains(joined, "airplay") || strings.Contains(joined, "airdrop") || strings.Contains(joined, "airport") ||
		strings.Contains(joined, "apple") || strings.Contains(joined, "macbook") || strings.Contains(joined, "iphone") ||
		strings.Contains(joined, "ipad"):
		return nodeRoleUpdate{Kind: "apple", Label: "Apple/Bonjour", Score: 66, Tags: []string{"apple-name", "bonjour"}}, true
	case strings.Contains(joined, "cisco") || strings.Contains(joined, "juniper") || strings.Contains(joined, "extreme") ||
		strings.Contains(joined, "aruba") || strings.Contains(joined, "fortinet") || strings.Contains(joined, "mikrotik"):
		return nodeRoleUpdate{Kind: "network", Label: "network device", Score: 76, Tags: []string{"network-vendor-name"}}, true
	default:
		return nodeRoleUpdate{}, false
	}
}

func inferRoleFromDHCPVendor(vendor string, params []byte) (nodeRoleUpdate, bool) {
	value := strings.ToLower(strings.TrimSpace(vendor))
	switch {
	case strings.Contains(value, "msft") || strings.Contains(value, "microsoft"):
		return nodeRoleUpdate{Kind: "windows", Label: "Windows", Score: 68, Tags: []string{"dhcp-vendor:msft", "windows", "dhcp-option-60"}}, true
	case strings.Contains(value, "android"):
		return nodeRoleUpdate{Kind: "unix", Label: "Android/Linux", Score: 64, Tags: []string{"dhcp-vendor:android", "unix-like", "dhcp-option-60"}}, true
	case strings.Contains(value, "dhcpcd") || strings.Contains(value, "udhcp") || strings.Contains(value, "busybox") ||
		strings.Contains(value, "linux") || strings.Contains(value, "systemd"):
		return nodeRoleUpdate{Kind: "unix", Label: "Unix/Linux", Score: 66, Tags: []string{"dhcp-vendor:unix", "unix-like", "dhcp-option-60"}}, true
	case strings.Contains(value, "apple") || strings.Contains(value, "darwin"):
		return nodeRoleUpdate{Kind: "apple", Label: "Apple/Bonjour", Score: 64, Tags: []string{"dhcp-vendor:apple", "bonjour", "dhcp-option-60"}}, true
	case strings.Contains(value, "pxeclient"):
		return nodeRoleUpdate{Kind: "service", Label: "PXE boot client", Score: 50, Tags: []string{"pxe", "dhcp-option-60"}}, true
	}
	paramSet := dhcpParamSet(params)
	if len(paramSet) > 0 && paramSet[44] && paramSet[46] {
		return nodeRoleUpdate{Kind: "windows", Label: "Windows", Score: 45, Tags: []string{"dhcp-netbios-request", "windows"}}, true
	}
	return nodeRoleUpdate{}, false
}

func inferRoleFromIdentityTags(tags map[string]bool) (nodeRoleUpdate, bool) {
	if len(tags) == 0 {
		return nodeRoleUpdate{}, false
	}
	vendor := canonicalVendorFromTags(tags)
	device := deviceClassFromTags(tags)
	strongL2 := tags["cdp"] || tags["lldp"] || tags["l2-discovery"] || tags["network-discovery"]

	if vendor != "" {
		score := 58
		if strongL2 {
			score = 97
		}
		// OUI-only vendor evidence is useful as a tag, but it should not
		// replace a service or infrastructure role by itself.
		if score < 90 && device == "" {
			return nodeRoleUpdate{}, false
		}
		label := vendorDeviceLabel(vendor, device)
		kind := kindForDeviceClass(device)
		if kind == "" {
			kind = "network"
		}
		return nodeRoleUpdate{
			Kind:  kind,
			Label: label,
			Score: score,
			Tags:  []string{"identity:" + vendor, "vendor:" + vendor},
		}, true
	}

	if strongL2 {
		switch device {
		case "phone":
			return nodeRoleUpdate{Kind: "phone", Label: "IP phone", Score: 90, Tags: []string{"identity:phone", "phone"}}, true
		case "switch", "router", "switch/router", "ap", "firewall":
			return nodeRoleUpdate{Kind: "network", Label: genericDeviceLabel(device), Score: 88, Tags: []string{"identity:network-device", "infrastructure-signal"}}, true
		}
	}
	return nodeRoleUpdate{}, false
}

func canonicalVendorFromTags(tags map[string]bool) string {
	for tag := range tags {
		switch {
		case tag == "cisco" || tag == "vendor:cisco" || strings.Contains(tag, "cisco"):
			return "cisco"
		case tag == "extreme" || tag == "vendor:extreme" || strings.Contains(tag, "extreme"):
			return "extreme"
		case tag == "juniper" || tag == "vendor:juniper" || strings.Contains(tag, "juniper") || strings.Contains(tag, "junos"):
			return "juniper"
		case tag == "aruba" || tag == "vendor:aruba" || strings.Contains(tag, "aruba"):
			return "aruba"
		case tag == "hpe" || tag == "vendor:hpe" || strings.Contains(tag, "hewlett") || strings.Contains(tag, "procurve"):
			return "hpe"
		case tag == "fortinet" || tag == "vendor:fortinet" || strings.Contains(tag, "fortinet") || strings.Contains(tag, "fortigate"):
			return "fortinet"
		case tag == "mikrotik" || tag == "vendor:mikrotik" || strings.Contains(tag, "mikrotik") || strings.Contains(tag, "routeros"):
			return "mikrotik"
		case tag == "ubiquiti" || tag == "vendor:ubiquiti" || strings.Contains(tag, "ubiquiti") || strings.Contains(tag, "unifi"):
			return "ubiquiti"
		case tag == "ruckus" || tag == "vendor:ruckus" || strings.Contains(tag, "ruckus"):
			return "ruckus"
		case tag == "brocade" || tag == "vendor:brocade" || strings.Contains(tag, "brocade"):
			return "brocade"
		case tag == "dell" || tag == "vendor:dell" || strings.Contains(tag, "dell") || strings.Contains(tag, "powerconnect"):
			return "dell"
		case tag == "huawei" || tag == "vendor:huawei" || strings.Contains(tag, "huawei"):
			return "huawei"
		case tag == "paloalto" || tag == "vendor:paloalto" || strings.Contains(tag, "paloalto"):
			return "paloalto"
		case tag == "checkpoint" || tag == "vendor:checkpoint" || strings.Contains(tag, "checkpoint"):
			return "checkpoint"
		case tag == "netgear" || tag == "vendor:netgear" || strings.Contains(tag, "netgear"):
			return "netgear"
		case tag == "sonicwall" || tag == "vendor:sonicwall" || strings.Contains(tag, "sonicwall"):
			return "sonicwall"
		case tag == "tplink" || tag == "vendor:tplink" || strings.Contains(tag, "tp-link") || strings.Contains(tag, "tplink"):
			return "tplink"
		case tag == "openwrt" || tag == "vendor:openwrt" || strings.Contains(tag, "openwrt"):
			return "openwrt"
		}
	}
	return ""
}

func deviceClassFromTags(tags map[string]bool) string {
	hasSwitch := tags["device:switch"] || tags["switch"] || tags["bridge"]
	hasRouter := tags["device:router"] || tags["router"]
	switch {
	case tags["device:phone"] || tags["phone"]:
		return "phone"
	case tags["device:ap"] || tags["wireless-ap"] || tags["wlan-ap"]:
		return "ap"
	case tags["device:firewall"] || tags["firewall"]:
		return "firewall"
	case hasSwitch && hasRouter:
		return "switch/router"
	case hasSwitch:
		return "switch"
	case hasRouter:
		return "router"
	case tags["device:network"]:
		return "network device"
	default:
		return ""
	}
}

func kindForDeviceClass(device string) string {
	switch device {
	case "phone":
		return "phone"
	case "switch", "router", "switch/router", "ap", "firewall", "network device":
		return "network"
	default:
		return ""
	}
}

func vendorDeviceLabel(vendor string, device string) string {
	vendorName := vendorDisplayName(vendor)
	if vendorName == "" {
		return genericDeviceLabel(device)
	}
	switch device {
	case "phone":
		return vendorName + " IP phone"
	case "ap":
		return vendorName + " access point"
	case "firewall":
		return vendorName + " firewall"
	case "switch":
		return vendorName + " switch"
	case "router":
		return vendorName + " router"
	case "switch/router":
		return vendorName + " switch/router"
	case "network device", "":
		return vendorName + " network device"
	default:
		return vendorName + " " + device
	}
}

func genericDeviceLabel(device string) string {
	switch device {
	case "phone":
		return "IP phone"
	case "ap":
		return "access point"
	case "firewall":
		return "firewall"
	case "switch":
		return "switch"
	case "router":
		return "router"
	case "switch/router":
		return "switch/router"
	default:
		return "network device"
	}
}

func vendorDisplayName(vendor string) string {
	switch vendor {
	case "cisco":
		return "Cisco"
	case "extreme":
		return "Extreme"
	case "juniper":
		return "Juniper"
	case "aruba":
		return "Aruba"
	case "hpe":
		return "HPE"
	case "fortinet":
		return "Fortinet"
	case "mikrotik":
		return "MikroTik"
	case "ubiquiti":
		return "Ubiquiti"
	case "ruckus":
		return "Ruckus"
	case "brocade":
		return "Brocade"
	case "dell":
		return "Dell"
	case "huawei":
		return "Huawei"
	case "paloalto":
		return "Palo Alto"
	case "checkpoint":
		return "Check Point"
	case "netgear":
		return "Netgear"
	case "sonicwall":
		return "SonicWall"
	case "tplink":
		return "TP-Link"
	case "openwrt":
		return "OpenWrt"
	default:
		return ""
	}
}

func identityTagsFromText(value string) []string {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		return nil
	}
	var tags []string
	for _, entry := range []struct {
		vendor  string
		matches []string
	}{
		{"cisco", []string{"cisco", "ios-xe", "ios xr", "nx-os", "meraki"}},
		{"extreme", []string{"extreme", "extremexos", "exos", "voss"}},
		{"juniper", []string{"juniper", "junos"}},
		{"aruba", []string{"aruba", "procurve"}},
		{"hpe", []string{"hewlett packard", "hewlett-packard", "hpe ", "hp "}},
		{"fortinet", []string{"fortinet", "fortigate", "fortios"}},
		{"mikrotik", []string{"mikrotik", "routeros"}},
		{"ubiquiti", []string{"ubiquiti", "unifi", "edgeos"}},
		{"ruckus", []string{"ruckus", "brocade icx"}},
		{"brocade", []string{"brocade"}},
		{"dell", []string{"dell ", "powerconnect", "force10", "os10"}},
		{"huawei", []string{"huawei"}},
		{"paloalto", []string{"palo alto", "pan-os", "panos"}},
		{"checkpoint", []string{"checkpoint", "check point", "gaia"}},
		{"netgear", []string{"netgear"}},
		{"sonicwall", []string{"sonicwall"}},
		{"tplink", []string{"tp-link", "tplink"}},
		{"openwrt", []string{"openwrt"}},
	} {
		for _, match := range entry.matches {
			if strings.Contains(value, match) {
				tags = appendUniqueStrings(tags, "vendor:"+entry.vendor, entry.vendor)
				break
			}
		}
	}
	switch {
	case strings.Contains(value, "ip phone") || strings.Contains(value, "phone"):
		tags = appendUniqueStrings(tags, "phone", "device:phone")
	case strings.Contains(value, "access point") || strings.Contains(value, "aironet") ||
		strings.Contains(value, "air-ap") || strings.Contains(value, "wlan-ap") ||
		strings.Contains(value, "wifi") || strings.Contains(value, "unifi ap"):
		tags = appendUniqueStrings(tags, "wireless-ap", "device:ap")
	}
	if strings.Contains(value, "firewall") || strings.Contains(value, "fortigate") ||
		strings.Contains(value, "pan-os") || strings.Contains(value, "sonicwall") ||
		strings.Contains(value, "checkpoint") || strings.Contains(value, "check point") {
		tags = appendUniqueStrings(tags, "firewall", "device:firewall")
	}
	if strings.Contains(value, "switch") || strings.Contains(value, "catalyst") ||
		strings.Contains(value, "nexus") || strings.Contains(value, "procurve") ||
		strings.Contains(value, "powerconnect") || strings.Contains(value, "icx") {
		tags = appendUniqueStrings(tags, "switch", "bridge", "device:switch")
	}
	if strings.Contains(value, "router") || strings.Contains(value, "isr") || strings.Contains(value, "asr") {
		tags = appendUniqueStrings(tags, "router", "device:router")
	}
	return tags
}

func inferRoleFromL2Event(event stealth.NACEvent) (nodeRoleUpdate, bool) {
	summary := strings.ToLower(event.Summary)
	tags := []string{strings.ToLower(event.Kind), "l2-discovery"}
	score := 74
	switch event.Kind {
	case "LLDP":
		tags = append(tags, "lldp")
	case "CDP":
		tags = append(tags, "cdp", "cisco-discovery", "vendor:cisco", "cisco")
	default:
		return nodeRoleUpdate{}, false
	}
	tags = appendUniqueStrings(tags, identityTagsFromText(summary)...)
	if identityRole, ok := inferRoleFromIdentityTags(tagSet(tags)); ok {
		identityRole.Tags = appendUniqueStrings(identityRole.Tags, tags...)
		return identityRole, true
	}
	if strings.Contains(summary, "phone") {
		return nodeRoleUpdate{Kind: "phone", Label: "IP phone", Score: score, Tags: append(tags, "phone")}, true
	}
	if strings.Contains(summary, "bridge") || strings.Contains(summary, "switch") || strings.Contains(summary, "router") ||
		strings.Contains(summary, "native-vlan") || strings.Contains(summary, "cisco") || strings.Contains(summary, "extreme") ||
		strings.Contains(summary, "juniper") || strings.Contains(summary, "aruba") {
		return nodeRoleUpdate{Kind: "network", Label: "network device", Score: score, Tags: append(tags, "bridge", "router")}, true
	}
	if strings.Contains(summary, "windows") {
		return nodeRoleUpdate{Kind: "windows", Label: "Windows", Score: 64, Tags: append(tags, "windows")}, true
	}
	if strings.Contains(summary, "linux") || strings.Contains(summary, "ubuntu") || strings.Contains(summary, "debian") ||
		strings.Contains(summary, "freebsd") || strings.Contains(summary, "openbsd") {
		return nodeRoleUpdate{Kind: "unix", Label: "Unix/Linux", Score: 64, Tags: append(tags, "unix-like")}, true
	}
	return nodeRoleUpdate{Kind: "network", Label: "network device", Score: 58, Tags: tags}, true
}

func dhcpParamSet(params []byte) map[byte]bool {
	out := make(map[byte]bool, len(params))
	for _, param := range params {
		out[param] = true
	}
	return out
}

func roleCanPromote(kind string) bool {
	switch kind {
	case "local", "target", "switch":
		return false
	default:
		return true
	}
}

func baseNodeRoleScore(kind string) int {
	switch kind {
	case "local":
		return 100
	case "target":
		return 98
	case "switch":
		return 96
	case "gateway":
		return 95
	case "dhcp", "radius":
		return 90
	case "nas":
		return 88
	case "dc":
		return 86
	case "printer":
		return 82
	case "dns":
		return 74
	case "network", "phone":
		return 68
	case "windows", "unix", "apple", "web", "ntp", "service":
		return 50
	default:
		return 0
	}
}

func displayNodeRole(node networkNode) string {
	roles := displayNodeRoles(node)
	if len(roles) > 0 {
		return strings.Join(roles, " + ")
	}
	return ""
}

func displayNodeRoles(node networkNode) []string {
	tags := tagSet(node.Tags)
	roles := make([]string, 0, 4)
	addRole := func(role string) {
		role = strings.TrimSpace(role)
		if role == "" {
			return
		}
		for _, existing := range roles {
			if strings.EqualFold(existing, role) {
				return
			}
		}
		roles = append(roles, role)
	}

	label := strings.TrimSpace(node.Label)
	if !isGenericNodeLabel(label) {
		addRole(label)
	}
	if node.Kind == "gateway" || tags["default-gateway"] || tags["dhcp-router"] || tags["router"] {
		if !roleLabelCovered("gateway/router", roles) {
			addRole("gateway/router")
		}
	}
	if node.Kind == "dhcp" || tags["dhcp-server"] {
		if !roleLabelCovered("DHCP server", roles) {
			addRole("DHCP server")
		}
	}
	if node.Kind == "dns" || tags["dns-server"] {
		if !roleLabelCovered("DNS server", roles) {
			addRole("DNS server")
		}
	}
	if node.Kind == "radius" || tags["radius-server"] {
		if !roleLabelCovered("RADIUS server", roles) {
			addRole("RADIUS server")
		}
	}
	if node.Kind == "nas" || tags["radius-client"] {
		if !roleLabelCovered("NAS / RADIUS client", roles) {
			addRole("NAS / RADIUS client")
		}
	}
	return roles
}

func roleLabelCovered(label string, roles []string) bool {
	lower := strings.ToLower(strings.TrimSpace(label))
	for _, role := range roles {
		roleLower := strings.ToLower(role)
		if lower == roleLower {
			return true
		}
		if strings.Contains(lower, "dhcp") && strings.Contains(roleLower, "dhcp") {
			return true
		}
		if strings.Contains(lower, "dns") && strings.Contains(roleLower, "dns") {
			return true
		}
		if strings.Contains(lower, "gateway") && strings.Contains(roleLower, "gateway") {
			return true
		}
		if lower == "router" && roleLower == "router" {
			return true
		}
		if strings.Contains(lower, "radius") && strings.Contains(roleLower, "radius") {
			return true
		}
	}
	return false
}

func isGenericNodeLabel(label string) bool {
	switch strings.ToLower(strings.TrimSpace(label)) {
	case "", "host", "external", "client", "service", "dns", "ip":
		return true
	default:
		return false
	}
}

func ipFromHostKey(key string) string {
	if strings.HasPrefix(key, "ip:") {
		return strings.TrimPrefix(key, "ip:")
	}
	return ""
}

func tagSet(tags []string) map[string]bool {
	out := make(map[string]bool, len(tags))
	for _, tag := range tags {
		out[tag] = true
	}
	return out
}

func limitStrings(values []string, limit int) []string {
	if limit <= 0 || len(values) <= limit {
		return values
	}
	out := append([]string(nil), values...)
	sort.SliceStable(out, func(i, j int) bool {
		pi, pj := limitedStringPriority(out[i]), limitedStringPriority(out[j])
		if pi != pj {
			return pi < pj
		}
		return out[i] < out[j]
	})
	return out[:limit]
}

func limitedStringPriority(value string) int {
	value = strings.ToLower(strings.TrimSpace(value))
	switch {
	case strings.HasPrefix(value, "identity:"), strings.HasPrefix(value, "vendor:"), strings.HasPrefix(value, "device:"),
		value == "cdp", value == "lldp", value == "cisco-discovery", value == "l2-discovery", value == "network-discovery":
		return 0
	case value == "default-gateway", value == "dhcp-router", value == "dhcp-server", value == "dns-server",
		value == "radius-server", value == "radius-client", value == "router", value == "switch", value == "bridge",
		value == "snmp-agent":
		return 1
	default:
		return 2
	}
}

func (g networkGraph) nodeForIP(ip net.IP) (networkNode, bool) {
	if ip == nil {
		return networkNode{}, false
	}
	needle := ip.String()
	for _, node := range g.Nodes {
		for _, value := range node.IPs {
			if value == needle {
				return node, true
			}
		}
	}
	return networkNode{}, false
}
