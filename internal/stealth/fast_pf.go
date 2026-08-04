package stealth

import (
	"context"
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"time"

	"golan/internal/pfutil"
	"golan/internal/policy"
	"golan/internal/traffic"
)

const (
	// FastBridgePFAnchor is the isolated PF child anchor used only for IP
	// packets traversing goLAN's fast kernel bridge.
	FastBridgePFAnchor = "com.apple/golan.bridge"
	fastPFTimeout      = 5 * time.Second
	etherTypeIPv4      = 0x0800
	etherTypeIPv6      = 0x86dd
)

var fastBridgePFOperations = pfutil.AnchorOperations{
	Anchor: FastBridgePFAnchor, FlushKind: "rules", Timeout: fastPFTimeout,
	ValidateOperation: "validate fast bridge anchor",
	LoadOperation:     "load fast bridge anchor",
	FlushOperation:    "flush fast bridge anchor",
	RulesError:        "fast bridge PF rules are empty",
	RunnerError:       "fast bridge PF runner is required",
}

// CompileFastBridgePF returns deterministic IPv4/IPv6 filter rules for the
// bridge member PF hooks. Rules outside the exact PF boundary remain SHADOW.
// A revision mixing PF rules with Layer 2 terminal rules that can also match IP
// is rejected because separate kernel filters cannot preserve first-match
// ordering for overlapping traffic.
func CompileFastBridgePF(hostInterface, switchInterface, revision string, rules []policy.Rule) (string, error) {
	if err := validateInterfaceName(hostInterface); err != nil {
		return "", fmt.Errorf("host interface: %w", err)
	}
	if err := validateInterfaceName(switchInterface); err != nil {
		return "", fmt.Errorf("switch interface: %w", err)
	}
	hostInterface = strings.TrimSpace(hostInterface)
	switchInterface = strings.TrimSpace(switchInterface)
	if strings.EqualFold(hostInterface, switchInterface) {
		return "", fmt.Errorf("fast bridge PF interfaces must differ")
	}
	if len(rules) == 0 {
		return "", nil
	}
	compiled, err := policy.Compile(revision, rules)
	if err != nil {
		return "", fmt.Errorf("compile fast bridge PF policy: %w", err)
	}
	ordered := compiled.Rules()
	hasPF := false
	for _, rule := range ordered {
		if rule.Enabled && policy.FastBridgePFCompatible(rule) {
			hasPF = true
			break
		}
	}
	if !hasPF {
		return "", nil
	}
	for _, rule := range ordered {
		if !rule.Enabled || policy.FastBridgePFCompatible(rule) || !policy.FastBridgeL2Compatible(rule) || !hasTerminalVerdict(rule) {
			continue
		}
		if l2RuleMayMatchIP(rule) {
			return "", fmt.Errorf("fast bridge policy mixes PF rule(s) with overlapping Layer 2 rule %s; use one kernel boundary or controlled bridge", rule.ID)
		}
	}

	var lines []string
	for _, rule := range ordered {
		if !rule.Enabled || !policy.FastBridgePFCompatible(rule) {
			continue
		}
		verdict := fastPFVerdict(rule)
		if verdict == "" {
			continue
		}
		interfaces := fastPFIngressInterfaces(rule.Match, hostInterface, switchInterface)
		families, err := fastPFFamilies(rule.Match)
		if err != nil {
			return "", fmt.Errorf("rule %s: %w", rule.ID, err)
		}
		for _, interfaceName := range interfaces {
			for _, family := range families {
				parts := []string{verdict, "in", "quick", "on", interfaceName, family.keyword}
				if protocols := fastPFProtocols(rule.Match); protocols != "" {
					parts = append(parts, "proto", protocols)
				}
				parts = append(parts, "from", fastPFAddresses(rule.Match.SrcCIDRs, family.version))
				if ports := pfutil.Ports(rule.Match.SrcPorts); ports != "" {
					parts = append(parts, "port", ports)
				}
				parts = append(parts, "to", fastPFAddresses(rule.Match.DstCIDRs, family.version))
				if ports := pfutil.Ports(rule.Match.DstPorts); ports != "" {
					parts = append(parts, "port", ports)
				}
				if verdict == "pass" {
					parts = append(parts, "keep", "state")
				}
				lines = append(lines, strings.Join(parts, " "))
			}
		}
	}
	if len(lines) == 0 {
		return "", nil
	}
	return strings.Join(lines, "\n") + "\n", nil
}

// CompileNATPF returns the complete IPv4 endpoint policy for a bridge
// whose authenticated identity has moved into the local kernel. It preserves
// outbound state, permits DHCP acquisition, blocks unsolicited inbound IPv4,
// and blocks IPv6 on only the nat interface. Exactly representable
// allow/block rules precede those defaults in shared policy order.
func CompileNATPF(interfaceName, revision string, rules []policy.Rule) (string, error) {
	if err := validateInterfaceName(interfaceName); err != nil {
		return "", fmt.Errorf("nat interface: %w", err)
	}
	interfaceName = strings.TrimSpace(interfaceName)
	lines := []string{
		fmt.Sprintf("pass out quick on %s inet proto udp from any port 68 to any port 67 keep state", interfaceName),
		fmt.Sprintf("pass in quick on %s inet proto udp from any port 67 to any port 68 keep state", interfaceName),
		fmt.Sprintf("block drop quick on %s inet6 all", interfaceName),
	}
	if len(rules) > 0 {
		compiled, err := policy.Compile(revision, rules)
		if err != nil {
			return "", fmt.Errorf("compile nat PF policy: %w", err)
		}
		for _, rule := range compiled.Rules() {
			if !rule.Enabled || !policy.NATPFCompatible(rule) {
				continue
			}
			verdict := fastPFVerdict(rule)
			if verdict == "" {
				continue
			}
			for _, direction := range natPFDirections(rule.Match.Directions) {
				parts := []string{verdict, direction, "quick", "on", interfaceName, "inet"}
				if protocols := fastPFProtocols(rule.Match); protocols != "" {
					parts = append(parts, "proto", protocols)
				}
				parts = append(parts, "from", fastPFAddresses(rule.Match.SrcCIDRs, 4))
				if ports := pfutil.Ports(rule.Match.SrcPorts); ports != "" {
					parts = append(parts, "port", ports)
				}
				parts = append(parts, "to", fastPFAddresses(rule.Match.DstCIDRs, 4))
				if ports := pfutil.Ports(rule.Match.DstPorts); ports != "" {
					parts = append(parts, "port", ports)
				}
				if verdict == "pass" {
					parts = append(parts, "keep", "state")
				}
				lines = append(lines, strings.Join(parts, " "))
			}
		}
	}
	lines = append(lines,
		fmt.Sprintf("pass out quick on %s inet from any to any keep state", interfaceName),
		fmt.Sprintf("block drop in quick on %s inet all", interfaceName),
	)
	return strings.Join(lines, "\n") + "\n", nil
}

func natPFDirections(values []traffic.Direction) []string {
	seen := make(map[string]bool)
	for _, value := range values {
		switch value {
		case traffic.DirectionOutbound:
			seen["out"] = true
		case traffic.DirectionInbound:
			seen["in"] = true
		}
	}
	if len(seen) == 0 {
		seen["out"] = true
		seen["in"] = true
	}
	var result []string
	for _, direction := range []string{"out", "in"} {
		if seen[direction] {
			result = append(result, direction)
		}
	}
	return result
}

func hasTerminalVerdict(rule policy.Rule) bool {
	return fastPFVerdict(rule) != ""
}

func fastPFVerdict(rule policy.Rule) string {
	for _, action := range rule.Actions {
		switch action.Kind {
		case policy.ActionAllow:
			return "pass"
		case policy.ActionBlock:
			return "block drop"
		}
	}
	return ""
}

func l2RuleMayMatchIP(rule policy.Rule) bool {
	if strings.HasPrefix(rule.ID, "builtin-eapol-") {
		return false
	}
	if len(rule.Match.EtherTypes) == 0 {
		return true
	}
	for _, etherType := range rule.Match.EtherTypes {
		if etherType == etherTypeIPv4 || etherType == etherTypeIPv6 {
			return true
		}
	}
	return false
}

func fastPFIngressInterfaces(match policy.Match, hostInterface, switchInterface string) []string {
	allowed := map[string]bool{hostInterface: true, switchInterface: true}
	intersect := func(values map[string]bool) {
		for interfaceName := range allowed {
			if !values[interfaceName] {
				delete(allowed, interfaceName)
			}
		}
	}
	if len(match.Directions) > 0 {
		values := make(map[string]bool)
		for _, direction := range match.Directions {
			switch direction {
			case traffic.DirectionOutbound, traffic.DirectionHostToSwitch:
				values[hostInterface] = true
			case traffic.DirectionInbound, traffic.DirectionSwitchToHost:
				values[switchInterface] = true
			}
		}
		intersect(values)
	}
	if len(match.Topologies) > 0 {
		values := make(map[string]bool)
		for _, side := range match.Topologies {
			switch side {
			case traffic.SideHost, traffic.SideDownstream:
				values[hostInterface] = true
			case traffic.SideSwitch, traffic.SideUpstream:
				values[switchInterface] = true
			}
		}
		intersect(values)
	}
	if len(match.Egress) > 0 {
		values := make(map[string]bool)
		for _, side := range match.Egress {
			switch side {
			case traffic.SideSwitch, traffic.SideUpstream:
				values[hostInterface] = true
			case traffic.SideHost, traffic.SideDownstream:
				values[switchInterface] = true
			}
		}
		intersect(values)
	}
	var result []string
	for _, interfaceName := range []string{hostInterface, switchInterface} {
		if allowed[interfaceName] {
			result = append(result, interfaceName)
		}
	}
	return result
}

type fastPFFamily struct {
	version uint8
	keyword string
}

func fastPFFamilies(match policy.Match) ([]fastPFFamily, error) {
	allowed := map[uint8]bool{4: true, 6: true}
	intersect := func(values map[uint8]bool) {
		for version := range allowed {
			if !values[version] {
				delete(allowed, version)
			}
		}
	}
	if len(match.IPVersions) > 0 {
		values := make(map[uint8]bool)
		for _, version := range match.IPVersions {
			if version != 4 && version != 6 {
				return nil, fmt.Errorf("IP version %d cannot be compiled into PF", version)
			}
			values[version] = true
		}
		intersect(values)
	}
	for _, cidrs := range [][]string{match.SrcCIDRs, match.DstCIDRs} {
		if len(cidrs) == 0 {
			continue
		}
		values := make(map[uint8]bool)
		for _, value := range cidrs {
			prefix, err := netip.ParsePrefix(strings.TrimSpace(value))
			if err != nil {
				return nil, fmt.Errorf("parse CIDR %q: %w", value, err)
			}
			if prefix.Addr().Is4() {
				values[4] = true
			} else {
				values[6] = true
			}
		}
		intersect(values)
	}
	var result []fastPFFamily
	if allowed[4] {
		result = append(result, fastPFFamily{version: 4, keyword: "inet"})
	}
	if allowed[6] {
		result = append(result, fastPFFamily{version: 6, keyword: "inet6"})
	}
	return result, nil
}

func fastPFProtocols(match policy.Match) string {
	values := append([]uint8(nil), match.Protocols...)
	if len(values) == 0 && (hasPortMatch(match.SrcPorts) || hasPortMatch(match.DstPorts)) {
		return "{ tcp, udp }"
	}
	if len(values) == 0 {
		return ""
	}
	sort.Slice(values, func(i, j int) bool { return values[i] < values[j] })
	items := make([]string, 0, len(values))
	seen := make(map[uint8]bool)
	for _, value := range values {
		if seen[value] {
			continue
		}
		seen[value] = true
		switch value {
		case 6:
			items = append(items, "tcp")
		case 17:
			items = append(items, "udp")
		default:
			items = append(items, strconv.Itoa(int(value)))
		}
	}
	return pfutil.List(items)
}

func hasPortMatch(set policy.PortSet) bool {
	return len(set.Values) > 0 || len(set.Ranges) > 0
}

func fastPFAddresses(values []string, version uint8) string {
	var items []string
	seen := make(map[string]bool)
	for _, value := range values {
		prefix, err := netip.ParsePrefix(strings.TrimSpace(value))
		if err != nil || prefix.Addr().Is4() != (version == 4) {
			continue
		}
		item := prefix.Masked().String()
		if !seen[item] {
			seen[item] = true
			items = append(items, item)
		}
	}
	if len(values) == 0 {
		return "any"
	}
	sort.Strings(items)
	return pfutil.List(items)
}

// FastBridgePFBackend owns only the fast-bridge child anchor and an optional
// PF enable token. Restore never flushes global or unrelated PF state.
type FastBridgePFBackend struct {
	backend *pfutil.Backend
}

// NewFastBridgePFBackend creates an isolated fast-bridge PF backend.
func NewFastBridgePFBackend() *FastBridgePFBackend {
	return newFastBridgePFBackend(pfutil.ExecRunner{})
}

func newFastBridgePFBackend(runner pfutil.Runner) *FastBridgePFBackend {
	return &FastBridgePFBackend{backend: pfutil.NewBackend(fastBridgePFOperations, runner)}
}

// Apply validates a complete anchor before enabling PF or replacing the owned
// child anchor. A partial load remains marked for cleanup.
func (p *FastBridgePFBackend) Apply(ctx context.Context, rules string) error {
	if p == nil {
		return fmt.Errorf("fast bridge PF backend is nil")
	}
	if p.backend == nil {
		return fmt.Errorf("fast bridge PF runner is required")
	}
	return p.backend.Apply(ctx, rules)
}

// Restore flushes only the owned child anchor and releases only the enable
// token acquired by this backend. Failed steps remain retryable.
func (p *FastBridgePFBackend) Restore(ctx context.Context) error {
	if p == nil {
		return nil
	}
	if p.backend == nil {
		return fmt.Errorf("fast bridge PF runner is required")
	}
	return p.backend.Restore(ctx)
}
