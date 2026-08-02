package edge

import (
	"context"
	"fmt"
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
	PFAnchor  = "com.apple/golan.edge"
	pfTimeout = 5 * time.Second
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
	translations := []string{
		fmt.Sprintf("nat on %s inet from %s to any -> (%s)", config.Upstream, subnet, config.Upstream),
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
		"block drop quick inet6 all",
		fmt.Sprintf("pass in quick on %s inet proto udp from any port 68 to 255.255.255.255 port 67", config.Downstream),
		fmt.Sprintf("pass out quick on %s inet proto udp from %s port 67 to any port 68", config.Downstream, config.Subnet.Masked().Addr().Next()),
	}
	filters = append(filters, policyFilters...)
	filters = append(filters,
		fmt.Sprintf("pass in quick on %s inet from %s to any keep state", config.Downstream, subnet),
		fmt.Sprintf("pass out quick on %s inet from %s to any keep state", config.Upstream, subnet),
		fmt.Sprintf("pass out quick on %s inet from any to %s keep state", config.Downstream, subnet),
		fmt.Sprintf("block in quick on %s inet all", config.Upstream),
	)
	lines := append(translations, filters...)
	return strings.Join(lines, "\n") + "\n", nil
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
			if direction == traffic.DirectionInbound {
				interfaceName = config.Upstream
			}
			parts := []string{verdict, "in", "quick", "on", interfaceName, "inet"}
			protocols := pfProtocols(rule.Match.Protocols, rule.Match.SrcPorts, rule.Match.DstPorts)
			if protocols != "" {
				parts = append(parts, "proto", protocols)
			}
			parts = append(parts, "from", pfAddresses(rule.Match.SrcCIDRs))
			if ports := pfutil.Ports(rule.Match.SrcPorts); ports != "" {
				parts = append(parts, "port", ports)
			}
			parts = append(parts, "to", pfAddresses(rule.Match.DstCIDRs))
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
