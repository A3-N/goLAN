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

// EgressMode selects how routed client traffic leaves the Mac. System egress
// follows the Mac's ordinary IPv4 routing table. VPN egress forces permitted
// client destinations through one already-connected tunnel interface while
// leaving locally originated Mac traffic on its existing routes.
type EgressMode string

const (
	EgressSystem EgressMode = "system"
	EgressVPN    EgressMode = "vpn"
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
	Mode            Mode           `json:"mode"`
	Downstream      string         `json:"downstream"`
	Upstream        string         `json:"upstream"`
	Egress          EgressMode     `json:"egress"`
	VPNDestinations []netip.Prefix `json:"vpn_destinations,omitempty"`
	VPNRouteAddress netip.Addr     `json:"vpn_route_address,omitempty"`
	EgressMTU       int            `json:"egress_mtu,omitempty"`
	Subnet          netip.Prefix   `json:"subnet"`
	DNS             []netip.Addr   `json:"dns,omitempty"`
	PortForwards    []PortForward  `json:"port_forwards,omitempty"`
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
	egress := config.Egress
	if egress == "" {
		egress = EgressSystem
	}
	if egress != EgressSystem && egress != EgressVPN {
		return fmt.Errorf("edge egress must be system or vpn")
	}
	if !config.Subnet.IsValid() || !config.Subnet.Addr().Is4() || config.Subnet.Bits() != 24 {
		return fmt.Errorf("edge subnet must be an IPv4 /24")
	}
	if config.EgressMTU != 0 && (config.EgressMTU < 576 || config.EgressMTU > 65535) {
		return fmt.Errorf("edge egress MTU must be between 576 and 65535")
	}
	seenDNS := make(map[netip.Addr]bool, len(config.DNS))
	for _, dns := range config.DNS {
		if !dns.Is4() || dns.IsUnspecified() || dns.IsMulticast() {
			return fmt.Errorf("DNS address %s is not usable IPv4", dns)
		}
		if seenDNS[dns] {
			return fmt.Errorf("DNS address %s is duplicated", dns)
		}
		seenDNS[dns] = true
	}
	if egress == EgressSystem && len(config.VPNDestinations) != 0 {
		return fmt.Errorf("VPN destinations require vpn egress")
	}
	if egress == EgressVPN {
		if !config.VPNRouteAddress.Is4() || config.VPNRouteAddress.IsUnspecified() || config.VPNRouteAddress.IsMulticast() {
			return fmt.Errorf("vpn egress requires a usable IPv4 route address")
		}
		if len(config.VPNDestinations) == 0 {
			return fmt.Errorf("vpn egress requires at least one destination or all")
		}
		seenDestinations := make(map[netip.Prefix]bool, len(config.VPNDestinations))
		all := false
		for _, destination := range config.VPNDestinations {
			if !destination.IsValid() || !destination.Addr().Is4() {
				return fmt.Errorf("VPN destination %s must be an IPv4 prefix", destination)
			}
			destination = destination.Masked()
			if seenDestinations[destination] {
				return fmt.Errorf("VPN destination %s is duplicated", destination)
			}
			seenDestinations[destination] = true
			all = all || destination.Bits() == 0
		}
		if all && len(seenDestinations) != 1 {
			return fmt.Errorf("VPN destination all cannot be combined with other prefixes")
		}
		if len(config.DNS) == 0 {
			return fmt.Errorf("vpn egress requires at least one IPv4 DNS server")
		}
		for _, dns := range config.DNS {
			// A loopback resolver is consumed by goLAN's downstream DNS relay;
			// the client never routes 127/8 into the VPN destination set.
			if dns.IsLoopback() {
				continue
			}
			contained := false
			for destination := range seenDestinations {
				if destination.Contains(dns) {
					contained = true
					break
				}
			}
			if !contained {
				return fmt.Errorf("VPN DNS address %s is outside the permitted VPN destinations", dns)
			}
		}
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
		lease, leaseErr := LeaseForSubnet(config.Subnet, config.DNS)
		if leaseErr != nil || forward.TargetIP != lease.ClientIP {
			return fmt.Errorf("port forward target must be the deterministic Edge client %s", lease.ClientIP)
		}
		key := fmt.Sprintf("%s/%d", protocol, forward.ListenPort)
		if seen[key] {
			return fmt.Errorf("port forward %s is duplicated", key)
		}
		seen[key] = true
	}
	return nil
}

// EffectiveEgress returns the backward-compatible system default when older
// callers omit the egress field.
func (config Config) EffectiveEgress() EgressMode {
	if config.Egress == "" {
		return EgressSystem
	}
	return config.Egress
}

// ValidInterfaceName reports whether a staged physical or logical interface
// name is safe to pass as one argv value to macOS networking commands.
func ValidInterfaceName(name string) bool { return validInterfaceName(name) }

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
