package edge

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strings"
	"time"

	"golan/internal/pfutil"
)

const commandTimeout = 5 * time.Second

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
	downstream = strings.TrimSpace(downstream)
	if !validInterfaceName(downstream) {
		return Config{}, fmt.Errorf("downstream adapter name is invalid")
	}
	route, err := discoverRoute(ctx, pfutil.ExecRunner{}, requestedUpstream)
	if err != nil {
		return Config{}, err
	}
	if strings.EqualFold(route.Interface, downstream) {
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
	var dns []netip.Addr
	if content, readErr := os.ReadFile("/etc/resolv.conf"); readErr == nil {
		dns = SystemDNS(string(content))
	}
	if len(dns) == 0 && route.Gateway.Is4() {
		dns = []netip.Addr{route.Gateway}
	}
	config := Config{
		Mode: mode, Downstream: downstream, Upstream: route.Interface, Subnet: subnet, DNS: dns,
	}
	if err := ValidateConfig(config); err != nil {
		return Config{}, err
	}
	return config, nil
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
		if err == nil && address.Is4() && !address.IsUnspecified() && !address.IsMulticast() && !seen[address] {
			seen[address] = true
			result = append(result, address)
		}
	}
	return result
}
