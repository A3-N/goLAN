package edge

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
	// PFAnchor is a dedicated child of macOS's pre-wired com.apple wildcard.
	// Using that existing namespace activates translation and filtering without
	// rewriting /etc/pf.conf or changing unrelated anchors.
	PFAnchor              = "com.apple/golan.edge"
	pfTimeout             = 5 * time.Second
	pfVPNDestinationTable = "<golan_edge_vpn_destinations>"
)

var edgePFOperations = pfutil.AnchorOperations{
	Anchor: PFAnchor, FlushKind: "all", Timeout: pfTimeout,
	ValidateOperation: "validate dedicated anchor",
	LoadOperation:     "load dedicated anchor",
	FlushOperation:    "flush dedicated anchor",
	RulesError:        "PF rules are empty",
	RunnerError:       "PF runner is required",
}

// CompilePF returns a deterministic dedicated-anchor rule set. It contains no
// global flush or /etc/pf.conf mutation commands.
func CompilePF(config Config) (string, error) {
	return compilePF(config, nil)
}

// CompilePFWithPolicy adds exactly representable first-match policy rules to
// the dedicated anchor. Incompatible rules remain SHADOW in the shared engine.
func CompilePFWithPolicy(config Config, revision string, rules []policy.Rule) (string, error) {
	filters, err := compilePolicyFilters(config, revision, rules)
	if err != nil {
		return "", err
	}
	return compilePF(config, filters)
}

func compilePF(config Config, policyFilters []string) (string, error) {
	if err := ValidateConfig(config); err != nil {
		return "", err
	}
	if config.Mode == ModeObserve {
		return "", nil
	}
	subnet := config.Subnet.Masked().String()
	server := config.Subnet.Masked().Addr().Next().String()
	destinations := "any"
	var definitions []string
	if config.EffectiveEgress() == EgressVPN {
		if entries := pfVPNDestinationEntries(config.VPNDestinations); len(entries) > 0 {
			definitions = append(definitions, fmt.Sprintf("table %s const { %s }", pfVPNDestinationTable, strings.Join(entries, ", ")))
			destinations = pfVPNDestinationTable
		}
	}
	if config.EgressMTU >= 576 {
		definitions = append(definitions, fmt.Sprintf(
			"scrub in on %s inet proto tcp max-mss %d",
			config.Downstream, config.EgressMTU-40,
		))
	}
	translations := []string{
		fmt.Sprintf("nat on %s inet from %s to %s -> (%s)", config.Upstream, subnet, destinations, config.Upstream),
	}
	forwards := append([]PortForward(nil), config.PortForwards...)
	sort.Slice(forwards, func(i, j int) bool {
		if forwards[i].Protocol == forwards[j].Protocol {
			return forwards[i].ListenPort < forwards[j].ListenPort
		}
		return forwards[i].Protocol < forwards[j].Protocol
	})
	for _, forward := range forwards {
		protocol := strings.ToLower(forward.Protocol)
		translations = append(translations,
			fmt.Sprintf("rdr pass on %s inet proto %s from any to (%s) port %d -> %s port %d", config.Upstream, protocol, config.Upstream, forward.ListenPort, forward.TargetIP, forward.TargetPort),
		)
	}
	filters := []string{
		fmt.Sprintf("block drop quick on %s inet6 all", config.Downstream),
		fmt.Sprintf("pass in quick on %s inet proto udp from any port 68 to { 255.255.255.255, %s } port 67", config.Downstream, server),
		fmt.Sprintf("pass out quick on %s inet proto udp from %s port 67 to any port 68", config.Downstream, server),
		fmt.Sprintf("block in quick on %s inet from ! %s to any", config.Downstream, subnet),
	}
	if requiresDNSRelay(config.DNS) {
		filters = append(filters, fmt.Sprintf(
			"pass in quick on %s inet proto { tcp, udp } from %s to %s port 53 keep state",
			config.Downstream, subnet, server,
		))
	}
	// The downstream device is untrusted. Permit the owned DHCP/DNS endpoints
	// above, then prevent it from reaching any other address hosted by the Mac.
	filters = append(filters, fmt.Sprintf("block in quick on %s inet from %s to self", config.Downstream, subnet))
	if config.EffectiveEgress() == EgressVPN && destinations != "any" {
		filters = append(filters, fmt.Sprintf("block in quick on %s inet from %s to ! %s", config.Downstream, subnet, destinations))
	}
	filters = append(filters, policyFilters...)
	if config.EffectiveEgress() == EgressVPN {
		routeTarget := fmt.Sprintf("(%s %s)", config.Upstream, config.VPNRouteAddress)
		filters = append(filters,
			fmt.Sprintf("pass in quick on %s route-to %s inet from %s to %s keep state", config.Downstream, routeTarget, subnet, destinations),
			fmt.Sprintf("pass out quick on %s inet from %s to %s keep state", config.Upstream, subnet, destinations),
			fmt.Sprintf("pass out quick on %s inet from any to %s keep state", config.Downstream, subnet),
			fmt.Sprintf("block out quick inet from %s to any", subnet),
			fmt.Sprintf("block in quick on %s inet from any to %s", config.Upstream, subnet),
			fmt.Sprintf("block in quick on %s inet from %s to any", config.Downstream, subnet),
		)
	} else {
		filters = append(filters,
			fmt.Sprintf("pass in quick on %s inet from %s to any keep state", config.Downstream, subnet),
			fmt.Sprintf("pass out quick on %s inet from %s to any keep state", config.Upstream, subnet),
			fmt.Sprintf("pass out quick on %s inet from any to %s keep state", config.Downstream, subnet),
			fmt.Sprintf("block in quick on %s inet from any to %s", config.Upstream, subnet),
		)
	}
	lines := append(definitions, translations...)
	lines = append(lines, filters...)
	return strings.Join(lines, "\n") + "\n", nil
}

func pfVPNDestinationEntries(values []netip.Prefix) []string {
	items := make([]string, 0, len(values))
	for _, value := range values {
		value = value.Masked()
		if value.Bits() == 0 {
			return nil
		}
		items = append(items, value.String())
	}
	sort.Strings(items)
	return items
}

func compilePolicyFilters(config Config, revision string, rules []policy.Rule) ([]string, error) {
	if len(rules) == 0 {
		return nil, nil
	}
	compiled, err := policy.Compile(revision, rules)
	if err != nil {
		return nil, fmt.Errorf("compile edge policy: %w", err)
	}
	var lines []string
	for _, rule := range compiled.Rules() {
		if !rule.Enabled || !policy.EdgeRouteCompatible(rule) {
			continue
		}
		verdict := ""
		for _, action := range rule.Actions {
			switch action.Kind {
			case policy.ActionAllow:
				verdict = "pass"
			case policy.ActionBlock:
				verdict = "block drop"
			}
		}
		if verdict == "" {
			continue
		}
		directions := policyDirections(rule.Match.Directions)
		for _, direction := range directions {
			interfaceName := config.Downstream
			destinations := pfAddresses(rule.Match.DstCIDRs)
			if direction == traffic.DirectionInbound {
				interfaceName = config.Upstream
				scopedDestinations, scopeErr := pfScopedPolicyDestinations(config.Subnet, rule.Match.DstCIDRs)
				if scopeErr != nil {
					return nil, fmt.Errorf("scope edge policy rule %s: %w", rule.ID, scopeErr)
				}
				if len(scopedDestinations) == 0 {
					continue
				}
				destinations = pfutil.List(scopedDestinations)
			}
			parts := []string{verdict, "in", "quick", "on", interfaceName}
			if verdict == "pass" && direction == traffic.DirectionOutbound && config.EffectiveEgress() == EgressVPN {
				parts = append(parts, "route-to", fmt.Sprintf("(%s %s)", config.Upstream, config.VPNRouteAddress))
			}
			parts = append(parts, "inet")
			protocols := pfProtocols(rule.Match.Protocols, rule.Match.SrcPorts, rule.Match.DstPorts)
			if protocols != "" {
				parts = append(parts, "proto", protocols)
			}
			parts = append(parts, "from", pfAddresses(rule.Match.SrcCIDRs))
			if ports := pfutil.Ports(rule.Match.SrcPorts); ports != "" {
				parts = append(parts, "port", ports)
			}
			parts = append(parts, "to", destinations)
			if ports := pfutil.Ports(rule.Match.DstPorts); ports != "" {
				parts = append(parts, "port", ports)
			}
			if verdict == "pass" {
				parts = append(parts, "keep", "state")
			}
			lines = append(lines, strings.Join(parts, " "))
		}
	}
	return lines, nil
}

// pfScopedPolicyDestinations keeps rules entering the upstream interface
// inside Edge's client subnet. Without this intersection, an inbound Edge
// policy using "to any" could also filter traffic addressed to the Mac itself.
func pfScopedPolicyDestinations(subnet netip.Prefix, values []string) ([]string, error) {
	subnet = subnet.Masked()
	if len(values) == 0 {
		return []string{subnet.String()}, nil
	}
	seen := make(map[netip.Prefix]bool, len(values))
	for _, value := range values {
		prefix, err := netip.ParsePrefix(strings.TrimSpace(value))
		if err != nil {
			return nil, err
		}
		prefix = prefix.Masked()
		var intersection netip.Prefix
		switch {
		case prefix.Contains(subnet.Addr()):
			intersection = subnet
		case subnet.Contains(prefix.Addr()):
			intersection = prefix
		default:
			continue
		}
		seen[intersection] = true
	}
	result := make([]string, 0, len(seen))
	for prefix := range seen {
		result = append(result, prefix.String())
	}
	sort.Strings(result)
	return result, nil
}

func policyDirections(values []traffic.Direction) []traffic.Direction {
	seen := make(map[traffic.Direction]bool)
	for _, value := range values {
		switch value {
		case traffic.DirectionOutbound, traffic.DirectionHostToSwitch:
			seen[traffic.DirectionOutbound] = true
		case traffic.DirectionInbound, traffic.DirectionSwitchToHost:
			seen[traffic.DirectionInbound] = true
		}
	}
	if len(seen) == 0 {
		seen[traffic.DirectionOutbound] = true
		seen[traffic.DirectionInbound] = true
	}
	result := make([]traffic.Direction, 0, len(seen))
	for _, direction := range []traffic.Direction{traffic.DirectionOutbound, traffic.DirectionInbound} {
		if seen[direction] {
			result = append(result, direction)
		}
	}
	return result
}

func pfProtocols(values []uint8, source, destination policy.PortSet) string {
	if len(values) == 0 && (len(source.Values) > 0 || len(source.Ranges) > 0 || len(destination.Values) > 0 || len(destination.Ranges) > 0) {
		return "{ tcp, udp }"
	}
	if len(values) == 0 {
		return ""
	}
	items := make([]string, 0, len(values))
	for _, value := range values {
		switch value {
		case 1:
			items = append(items, "icmp")
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

func pfAddresses(values []string) string {
	if len(values) == 0 {
		return "any"
	}
	return pfutil.List(append([]string(nil), values...))
}

// PFBackend owns only the dedicated anchor and an optional pf enable token.
type PFBackend struct {
	backend *pfutil.Backend
}

// PFState is a payload-free snapshot of the dedicated edge anchor ownership.
// EnableTokenOwned reports only whether this backend owns a restoration token;
// the token value is intentionally never exposed.
type PFState struct {
	Anchor           string `json:"anchor"`
	Loaded           bool   `json:"loaded"`
	EnableTokenOwned bool   `json:"enable_token_owned"`
}

// NewPFBackend creates a dedicated-anchor backend.
func NewPFBackend() *PFBackend {
	return newPFBackend(pfutil.ExecRunner{})
}

func newPFBackend(runner pfutil.Runner) *PFBackend {
	return &PFBackend{backend: pfutil.NewBackend(edgePFOperations, runner)}
}

// State returns a concurrency-safe payload-free ownership snapshot.
func (p *PFBackend) State() PFState {
	state := PFState{Anchor: PFAnchor}
	if p == nil {
		return state
	}
	if p.backend == nil {
		return state
	}
	owned := p.backend.State()
	state.Loaded = owned.Loaded
	state.EnableTokenOwned = owned.EnableTokenOwned
	return state
}

// Apply validates syntax before enabling PF or loading the anchor.
func (p *PFBackend) Apply(ctx context.Context, rules string) error {
	if p == nil {
		return fmt.Errorf("PF backend is nil")
	}
	if p.backend == nil {
		return fmt.Errorf("PF runner is required")
	}
	return p.backend.Apply(ctx, rules)
}

// Restore flushes only goLAN's anchor and releases only goLAN's enable token.
// Failed steps remain retryable.
func (p *PFBackend) Restore(ctx context.Context) error {
	if p == nil {
		return nil
	}
	if p.backend == nil {
		return fmt.Errorf("PF runner is required")
	}
	return p.backend.Restore(ctx)
}
