package canvas

import (
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"strings"
)

func convLabel(conv *Conversation) string {
	parts := []string{conv.Protocol}
	if conv.Service != "" {
		parts = append(parts, conv.Service)
	}
	if conv.Port != 0 {
		parts = append(parts, strconv.Itoa(int(conv.Port)))
	}
	if conv.Count > 1 {
		parts = append(parts, fmt.Sprintf("x%d", conv.Count))
	}
	return strings.Join(parts, " ")
}

func sortedHosts(hosts map[string]*Host) []*Host {
	out := make([]*Host, 0, len(hosts))
	for _, host := range hosts {
		out = append(out, host)
	}
	sort.Slice(out, func(i, j int) bool { return hostSortLabel(out[i]) < hostSortLabel(out[j]) })
	return out
}

func hostSortLabel(host *Host) string {
	if ip := firstSorted(host.IPs); ip != "" {
		return "0:" + ip
	}
	return "1:" + firstSorted(host.MACs)
}

func sortedConversations(conversations map[string]*Conversation) []*Conversation {
	out := make([]*Conversation, 0, len(conversations))
	for _, conversation := range conversations {
		out = append(out, conversation)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out
}

func sortedServices(services map[string]*Service) []*Service {
	out := make([]*Service, 0, len(services))
	for _, service := range services {
		out = append(out, service)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Protocol == out[j].Protocol {
			return out[i].Port < out[j].Port
		}
		return out[i].Protocol < out[j].Protocol
	})
	return out
}

func sortedKeys(values map[string]bool) []string {
	out := make([]string, 0, len(values))
	for value := range values {
		if strings.TrimSpace(value) != "" {
			out = append(out, value)
		}
	}
	sort.Strings(out)
	return out
}

func firstSorted(values map[string]bool) string {
	valuesInOrder := sortedKeys(values)
	if len(valuesInOrder) == 0 {
		return ""
	}
	return valuesInOrder[0]
}

func copyBoolMap(destination, source map[string]bool) {
	for key, value := range source {
		if value {
			destination[key] = true
		}
	}
}

func serviceName(protocol string, port uint16) string {
	switch strings.ToUpper(protocol) {
	case "TCP":
		switch port {
		case 21:
			return "ftp"
		case 22:
			return "ssh"
		case 25:
			return "smtp"
		case 53:
			return "dns"
		case 80:
			return "http"
		case 110:
			return "pop3"
		case 143:
			return "imap"
		case 389:
			return "ldap"
		case 443:
			return "https"
		case 445:
			return "smb"
		case 587:
			return "submission"
		case 636:
			return "ldaps"
		case 1433:
			return "mssql"
		}
	case "UDP":
		switch port {
		case 53:
			return "dns"
		case 67, 68:
			return "dhcp"
		case 88:
			return "kerberos"
		case 123:
			return "ntp"
		case 161, 162:
			return "snmp"
		}
	}
	return ""
}

func cleanIP(value string) string {
	value = strings.TrimSpace(value)
	if isAuto(value) {
		return ""
	}
	if ip, err := netip.ParseAddr(strings.Trim(value, "[]")); err == nil && !ip.IsUnspecified() {
		return ip.String()
	}
	return ""
}

func cleanMAC(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	if isAuto(value) {
		return ""
	}
	mac, err := net.ParseMAC(value)
	if err != nil || !validUnicastMAC(mac) {
		return ""
	}
	return mac.String()
}
