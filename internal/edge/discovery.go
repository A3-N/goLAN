package edge

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	"golan/internal/pfutil"
)

const commandTimeout = 5 * time.Second

// AutoOptions describes one non-mutating Edge route plan. VPN egress uses an
// already-connected point-to-point IPv4 interface and never starts, stops, or
// reconfigures the VPN itself.
type AutoOptions struct {
	Downstream      string
	Upstream        string
	Mode            Mode
	Egress          EgressMode
	VPNDestinations []netip.Prefix
	DNS             []netip.Addr
}

// DNSResolver is one IPv4 resolver described by macOS SystemConfiguration.
// Interface is populated for interface-scoped resolvers such as VPN utun
// resolvers. Domains is non-empty for split-DNS resolver entries.
type DNSResolver struct {
	Nameservers []netip.Addr
	Domains     []string
	Interface   string
	Order       int
	Scoped      bool
}

// DiscoverDefaultRoute reads the current macOS IPv4 default route without
// changing routing state.
func DiscoverDefaultRoute(ctx context.Context) (Route, error) {
	return discoverRoute(ctx, pfutil.ExecRunner{}, "")
}

func discoverRoute(ctx context.Context, runner pfutil.Runner, requestedInterface string) (Route, error) {
	commandCtx, cancel := context.WithTimeout(ctx, commandTimeout)
	defer cancel()
	args := []string{"-n", "get", "default"}
	if strings.TrimSpace(requestedInterface) != "" && !strings.EqualFold(requestedInterface, "auto") {
		if !validInterfaceName(requestedInterface) {
			return Route{}, fmt.Errorf("upstream adapter name is invalid")
		}
		args = []string{"-n", "get", "-ifscope", requestedInterface, "default"}
	}
	output, err := runner.Run(commandCtx, "route", args, "")
	if err != nil {
		return Route{}, pfutil.CommandError("read IPv4 default route", output, err)
	}
	var route Route
	for _, line := range strings.Split(output, "\n") {
		key, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		switch strings.ToLower(strings.TrimSpace(key)) {
		case "interface":
			route.Interface = strings.TrimSpace(value)
		case "gateway":
			address, parseErr := netip.ParseAddr(strings.TrimSpace(value))
			if parseErr == nil && address.Is4() {
				route.Gateway = address
			}
		}
	}
	if !validInterfaceName(route.Interface) || !route.Gateway.Is4() {
		return Route{}, fmt.Errorf("IPv4 default route output is incomplete")
	}
	route.Default = true
	return route, nil
}

// AutoConfig resolves an upstream route, conflict-free subnet, and DNS plan
// for one downstream adapter without mutating the host.
func AutoConfig(ctx context.Context, downstream, requestedUpstream string, mode Mode) (Config, error) {
	return AutoConfigWithOptions(ctx, AutoOptions{
		Downstream: downstream, Upstream: requestedUpstream, Mode: mode, Egress: EgressSystem,
	})
}

// AutoConfigWithOptions resolves one system or VPN egress plan without
// mutating the host. System mode follows the selected default route. VPN mode
// validates an explicit live tunnel and relies on PF route-to for client-only
// egress selection.
func AutoConfigWithOptions(ctx context.Context, options AutoOptions) (Config, error) {
	downstream := strings.TrimSpace(options.Downstream)
	if !validInterfaceName(downstream) {
		return Config{}, fmt.Errorf("downstream adapter name is invalid")
	}
	egress := options.Egress
	if egress == "" {
		egress = EgressSystem
	}
	if egress != EgressSystem && egress != EgressVPN {
		return Config{}, fmt.Errorf("edge egress must be system or vpn")
	}

	upstream := strings.TrimSpace(options.Upstream)
	var route Route
	var vpnRouteAddress netip.Addr
	var egressMTU int
	var err error
	if egress == EgressVPN {
		if isAutoUpstream(upstream) {
			return Config{}, fmt.Errorf("vpn egress requires an explicit tunnel interface")
		}
		vpnRouteAddress, err = VPNRouteAddress(upstream)
		if err != nil {
			return Config{}, err
		}
		egressMTU, err = interfaceMTU(upstream)
		if err != nil {
			return Config{}, err
		}
	} else {
		route, err = discoverRoute(ctx, pfutil.ExecRunner{}, upstream)
		if err != nil {
			return Config{}, err
		}
		upstream = route.Interface
		egressMTU, err = interfaceMTU(upstream)
		if err != nil {
			return Config{}, err
		}
	}
	if strings.EqualFold(upstream, downstream) {
		return Config{}, fmt.Errorf("downstream adapter cannot also be upstream")
	}
	occupied, err := OccupiedIPv4Prefixes()
	if err != nil {
		return Config{}, err
	}
	subnet, err := SelectSubnet(occupied)
	if err != nil {
		return Config{}, err
	}
	dns := append([]netip.Addr(nil), options.DNS...)
	if len(dns) == 0 {
		dnsInterface := ""
		if egress == EgressVPN {
			dnsInterface = upstream
		}
		dns, err = discoverMacOSDNS(ctx, pfutil.ExecRunner{}, dnsInterface)
		if err != nil && egress == EgressVPN {
			return Config{}, err
		}
	}
	// resolv.conf is only a compatibility fallback. macOS VPN and split-DNS
	// state is represented by SystemConfiguration and is read above.
	if len(dns) == 0 && egress == EgressSystem {
		if content, readErr := os.ReadFile("/etc/resolv.conf"); readErr == nil {
			dns = SystemDNS(string(content))
		}
	}
	if len(dns) == 0 && egress == EgressSystem && route.Gateway.Is4() {
		dns = []netip.Addr{route.Gateway}
	}
	destinations := make([]netip.Prefix, 0, len(options.VPNDestinations))
	for _, destination := range options.VPNDestinations {
		destinations = append(destinations, destination.Masked())
	}
	config := Config{
		Mode: options.Mode, Downstream: downstream, Upstream: upstream, Egress: egress,
		VPNDestinations: destinations, VPNRouteAddress: vpnRouteAddress, EgressMTU: egressMTU, Subnet: subnet, DNS: dns,
	}
	if err := ValidateConfig(config); err != nil {
		return Config{}, err
	}
	return config, nil
}

// DiscoverMacOSDNS returns the active default IPv4 resolvers, or resolvers
// scoped to interfaceName when it is non-empty. It uses scutil because
// /etc/resolv.conf does not represent macOS supplemental and scoped resolvers.
func DiscoverMacOSDNS(ctx context.Context, interfaceName string) ([]netip.Addr, error) {
	return discoverMacOSDNS(ctx, pfutil.ExecRunner{}, interfaceName)
}

func discoverMacOSDNS(ctx context.Context, runner pfutil.Runner, interfaceName string) ([]netip.Addr, error) {
	interfaceName = strings.TrimSpace(interfaceName)
	if interfaceName != "" && !validInterfaceName(interfaceName) {
		return nil, fmt.Errorf("DNS resolver interface name is invalid")
	}
	commandCtx, cancel := context.WithTimeout(ctx, commandTimeout)
	defer cancel()
	output, err := runner.Run(commandCtx, "scutil", []string{"--dns"}, "")
	if err != nil {
		return nil, pfutil.CommandError("read macOS DNS configuration", output, err)
	}
	resolvers := ParseSCDNS(output)
	var selected []DNSResolver
	if interfaceName != "" {
		for _, resolver := range resolvers {
			if resolver.Interface == interfaceName && len(resolver.Nameservers) > 0 {
				selected = append(selected, resolver)
			}
		}
		if len(selected) == 0 {
			return nil, fmt.Errorf("macOS has no IPv4 DNS resolver scoped to VPN interface %s; set edge dns explicitly", interfaceName)
		}
	} else {
		// The first unscoped, non-supplemental resolver is macOS's default
		// resolver. Do not combine split-DNS servers and advertise them as a
		// flat DHCP list because their domain matching semantics would be lost.
		for _, resolver := range resolvers {
			if !resolver.Scoped && len(resolver.Domains) == 0 && len(resolver.Nameservers) > 0 {
				selected = []DNSResolver{resolver}
				break
			}
		}
		if len(selected) == 0 {
			return nil, fmt.Errorf("macOS has no usable default IPv4 DNS resolver")
		}
	}
	return resolverAddresses(selected), nil
}

// ParseSCDNS parses the stable key/value shape printed by `scutil --dns`.
// Unknown fields and non-IPv4 nameservers are intentionally ignored.
func ParseSCDNS(output string) []DNSResolver {
	var result []DNSResolver
	var current *DNSResolver
	flush := func() {
		if current == nil {
			return
		}
		if len(current.Nameservers) > 0 {
			result = append(result, *current)
		}
		current = nil
	}
	for _, raw := range strings.Split(output, "\n") {
		line := strings.TrimSpace(raw)
		if strings.HasPrefix(line, "resolver #") {
			flush()
			current = &DNSResolver{}
			continue
		}
		if current == nil {
			continue
		}
		key, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		key, value = strings.TrimSpace(key), strings.TrimSpace(value)
		switch {
		case strings.HasPrefix(key, "nameserver["):
			address, parseErr := netip.ParseAddr(value)
			if parseErr == nil && usableDNSAddress(address) {
				current.Nameservers = appendUniqueAddr(current.Nameservers, address)
			}
		case key == "domain":
			if value != "" && value != "." && !slices.Contains(current.Domains, value) {
				current.Domains = append(current.Domains, value)
			}
		case key == "if_index":
			if open := strings.IndexByte(value, '('); open >= 0 {
				if close := strings.IndexByte(value[open+1:], ')'); close >= 0 {
					candidate := strings.TrimSpace(value[open+1 : open+1+close])
					if validInterfaceName(candidate) {
						current.Interface = candidate
					}
				}
			}
		case key == "flags":
			current.Scoped = strings.Contains(strings.ToLower(value), "scoped")
		case key == "order":
			current.Order, _ = strconv.Atoi(value)
		}
	}
	flush()
	return result
}

func resolverAddresses(resolvers []DNSResolver) []netip.Addr {
	var result []netip.Addr
	for _, resolver := range resolvers {
		for _, address := range resolver.Nameservers {
			result = appendUniqueAddr(result, address)
		}
	}
	return result
}

func appendUniqueAddr(values []netip.Addr, candidate netip.Addr) []netip.Addr {
	if slices.Contains(values, candidate) {
		return values
	}
	return append(values, candidate)
}

func usableDNSAddress(address netip.Addr) bool {
	return address.Is4() && !address.IsUnspecified() && !address.IsMulticast()
}

func isAutoUpstream(value string) bool {
	value = strings.TrimSpace(value)
	return value == "" || strings.EqualFold(value, "auto")
}

// VPNRouteAddress confirms that name currently identifies an up,
// point-to-point interface and returns its deterministic usable IPv4 address.
// macOS PF requires that address as the route-to next hop for utun rules.
func VPNRouteAddress(name string) (netip.Addr, error) {
	name = strings.TrimSpace(name)
	if !validInterfaceName(name) {
		return netip.Addr{}, fmt.Errorf("VPN tunnel interface name is invalid")
	}
	networkInterface, err := net.InterfaceByName(name)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("VPN tunnel interface %s is unavailable: %w", name, err)
	}
	if networkInterface.Flags&net.FlagUp == 0 {
		return netip.Addr{}, fmt.Errorf("VPN tunnel interface %s is down", name)
	}
	if networkInterface.Flags&net.FlagRunning == 0 {
		return netip.Addr{}, fmt.Errorf("VPN tunnel interface %s is not running", name)
	}
	if networkInterface.Flags&net.FlagPointToPoint == 0 {
		return netip.Addr{}, fmt.Errorf("VPN egress interface %s is not point-to-point", name)
	}
	commandCtx, cancel := context.WithTimeout(context.Background(), commandTimeout)
	output, commandErr := (pfutil.ExecRunner{}).Run(commandCtx, "ifconfig", []string{name}, "")
	cancel()
	if commandErr == nil {
		if peer, ok := parsePointToPointPeer(output); ok {
			return peer, nil
		}
	}
	addresses, err := networkInterface.Addrs()
	if err != nil {
		return netip.Addr{}, fmt.Errorf("read VPN tunnel addresses on %s: %w", name, err)
	}
	var usable []netip.Addr
	for _, raw := range addresses {
		prefix, parseErr := netip.ParsePrefix(raw.String())
		if parseErr == nil && prefix.Addr().Is4() && !prefix.Addr().IsUnspecified() && !prefix.Addr().IsLinkLocalUnicast() {
			usable = append(usable, prefix.Addr())
		}
	}
	if len(usable) == 0 {
		return netip.Addr{}, fmt.Errorf("VPN tunnel interface %s has no usable IPv4 address", name)
	}
	slices.SortFunc(usable, func(left, right netip.Addr) int { return left.Compare(right) })
	return usable[0], nil
}

func parsePointToPointPeer(output string) (netip.Addr, bool) {
	for _, raw := range strings.Split(output, "\n") {
		fields := strings.Fields(strings.TrimSpace(raw))
		if len(fields) < 4 || fields[0] != "inet" || fields[2] != "-->" {
			continue
		}
		peer, err := netip.ParseAddr(fields[3])
		if err == nil && peer.Is4() && !peer.IsUnspecified() && !peer.IsMulticast() {
			return peer, true
		}
	}
	return netip.Addr{}, false
}

func interfaceMTU(name string) (int, error) {
	networkInterface, err := net.InterfaceByName(name)
	if err != nil {
		return 0, fmt.Errorf("egress interface %s is unavailable: %w", name, err)
	}
	if networkInterface.MTU < 576 {
		return 0, fmt.Errorf("egress interface %s has unusable IPv4 MTU %d", name, networkInterface.MTU)
	}
	return networkInterface.MTU, nil
}

// InterfaceMTU returns the live IPv4-capable egress MTU for a validated
// interface without changing it.
func InterfaceMTU(name string) (int, error) {
	name = strings.TrimSpace(name)
	if !validInterfaceName(name) {
		return 0, fmt.Errorf("egress interface name is invalid")
	}
	return interfaceMTU(name)
}

// ValidateVPNInterface retains the liveness-only API for callers that do not
// need the route-to address.
func ValidateVPNInterface(name string) error {
	_, err := VPNRouteAddress(name)
	return err
}

// OccupiedIPv4Prefixes snapshots configured IPv4 interface networks.
func OccupiedIPv4Prefixes() ([]netip.Prefix, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("list interfaces: %w", err)
	}
	var prefixes []netip.Prefix
	for _, networkInterface := range interfaces {
		addresses, addressErr := networkInterface.Addrs()
		if addressErr != nil {
			return nil, fmt.Errorf("list addresses on %s: %w", networkInterface.Name, addressErr)
		}
		for _, raw := range addresses {
			prefix, parseErr := netip.ParsePrefix(raw.String())
			if parseErr == nil && prefix.Addr().Is4() {
				prefixes = append(prefixes, prefix.Masked())
			}
		}
	}
	return prefixes, nil
}

// SystemDNS returns usable IPv4 nameservers from resolv.conf. An empty result
// is valid; callers may use the upstream gateway as a conservative fallback.
func SystemDNS(content string) []netip.Addr {
	var result []netip.Addr
	seen := make(map[netip.Addr]bool)
	scanner := bufio.NewScanner(strings.NewReader(content))
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 2 || !strings.EqualFold(fields[0], "nameserver") {
			continue
		}
		address, err := netip.ParseAddr(fields[1])
		if err == nil && usableDNSAddress(address) && !seen[address] {
			seen[address] = true
			result = append(result, address)
		}
	}
	return result
}
