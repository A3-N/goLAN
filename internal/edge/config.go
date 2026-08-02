package edge

import (
	"fmt"
	"net/netip"
	"strings"
)

// Mode selects passive observation or IPv4 routing.
type Mode string

// Edge modes never advertise or route IPv6 in the initial implementation.
const (
	ModeObserve Mode = "observe"
	ModeRoute   Mode = "route"
)

// Route is one discovered routing-table candidate.
type Route struct {
	Interface string       `json:"interface"`
	Gateway   netip.Addr   `json:"gateway"`
	Prefix    netip.Prefix `json:"prefix"`
	Default   bool         `json:"default"`
}

// PortForward permits one explicit unsolicited inbound mapping.
type PortForward struct {
	Protocol   string     `json:"protocol"`
	ListenPort uint16     `json:"listen_port"`
	TargetIP   netip.Addr `json:"target_ip"`
	TargetPort uint16     `json:"target_port"`
}

// Config is a validated edge session request.
type Config struct {
	Mode         Mode          `json:"mode"`
	Downstream   string        `json:"downstream"`
	Upstream     string        `json:"upstream"`
	Subnet       netip.Prefix  `json:"subnet"`
	DNS          []netip.Addr  `json:"dns,omitempty"`
	PortForwards []PortForward `json:"port_forwards,omitempty"`
}

// Lease is the deterministic one-host DHCPv4 addressing plan.
type Lease struct {
	Subnet   netip.Prefix `json:"subnet"`
	ServerIP netip.Addr   `json:"server_ip"`
	ClientIP netip.Addr   `json:"client_ip"`
	Gateway  netip.Addr   `json:"gateway"`
	DNS      []netip.Addr `json:"dns"`
}

// SelectSubnet returns the first conflict-free /24 in 10.77.0.0/16.
func SelectSubnet(occupied []netip.Prefix) (netip.Prefix, error) {
	for third := 0; third <= 255; third++ {
		candidate := netip.PrefixFrom(netip.AddrFrom4([4]byte{10, 77, byte(third), 0}), 24)
		conflict := false
		for _, prefix := range occupied {
			if !prefix.IsValid() {
				continue
			}
			prefix = prefix.Masked()
			if prefix.Contains(candidate.Addr()) || candidate.Contains(prefix.Addr()) {
				conflict = true
				break
			}
		}
		if !conflict {
			return candidate, nil
		}
	}
	return netip.Prefix{}, fmt.Errorf("no conflict-free /24 remains in 10.77.0.0/16")
}

// LeaseForSubnet returns .1 for goLAN and the single .2 DHCP lease.
func LeaseForSubnet(subnet netip.Prefix, dns []netip.Addr) (Lease, error) {
	if !subnet.IsValid() || !subnet.Addr().Is4() || subnet.Bits() != 24 {
		return Lease{}, fmt.Errorf("edge subnet must be an IPv4 /24")
	}
	base := subnet.Masked().Addr().As4()
	server := base
	server[3] = 1
	client := base
	client[3] = 2
	cleanDNS := make([]netip.Addr, 0, len(dns))
	for _, address := range dns {
		if !address.Is4() || address.IsUnspecified() || address.IsMulticast() {
			return Lease{}, fmt.Errorf("DNS address %s is not usable IPv4", address)
		}
		cleanDNS = append(cleanDNS, address)
	}
	if len(cleanDNS) == 0 {
		cleanDNS = append(cleanDNS, netip.AddrFrom4(server))
	}
	return Lease{Subnet: subnet.Masked(), ServerIP: netip.AddrFrom4(server), ClientIP: netip.AddrFrom4(client), Gateway: netip.AddrFrom4(server), DNS: cleanDNS}, nil
}

// ValidateConfig validates every value before a privileged edge mutation.
func ValidateConfig(config Config) error {
	switch config.Mode {
	case ModeObserve, ModeRoute:
	default:
		return fmt.Errorf("edge mode must be observe or route")
	}
	if !validInterfaceName(config.Downstream) {
		return fmt.Errorf("downstream adapter name is invalid")
	}
	if config.Mode == ModeObserve {
		return nil
	}
	if !validInterfaceName(config.Upstream) || strings.EqualFold(config.Downstream, config.Upstream) {
		return fmt.Errorf("upstream adapter must be valid and differ from downstream")
	}
	if !config.Subnet.IsValid() || !config.Subnet.Addr().Is4() || config.Subnet.Bits() != 24 {
		return fmt.Errorf("edge subnet must be an IPv4 /24")
	}
	seen := make(map[string]bool)
	for _, forward := range config.PortForwards {
		protocol := strings.ToLower(forward.Protocol)
		if protocol != "tcp" && protocol != "udp" {
			return fmt.Errorf("port forward protocol must be TCP or UDP")
		}
		if forward.ListenPort == 0 || forward.TargetPort == 0 || !forward.TargetIP.Is4() {
			return fmt.Errorf("port forward addresses and ports must be explicit IPv4 values")
		}
		key := fmt.Sprintf("%s/%d", protocol, forward.ListenPort)
		if seen[key] {
			return fmt.Errorf("port forward %s is duplicated", key)
		}
		seen[key] = true
	}
	return nil
}

func validInterfaceName(name string) bool {
	name = strings.TrimSpace(name)
	if name == "" || len(name) > 15 {
		return false
	}
	for index, char := range name {
		if char >= 'a' && char <= 'z' || char >= 'A' && char <= 'Z' || char >= '0' && char <= '9' {
			continue
		}
		if index > 0 && (char == '-' || char == '_' || char == '.' || char == ':') {
			continue
		}
		return false
	}
	return true
}
