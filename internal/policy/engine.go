package policy

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"net"
	"net/netip"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"golan/internal/dataplane"
	"golan/internal/traffic"
)

const (
	maxRules         = 4096
	maxPatternLength = 64 << 10
	maxRevisions     = 64
)

// RuleSet is an immutable, fully compiled policy revision.
type RuleSet struct {
	revision     string
	created      time.Time
	rules        []compiledRule
	warningCache *diagnosticCache
}

type compiledRule struct {
	source Rule
	order  int
	match  compiledMatch
}

type compiledMatch struct {
	srcCIDRs   []netip.Prefix
	dstCIDRs   []netip.Prefix
	dnsNames   []compiledPattern
	httpHosts  []compiledPattern
	httpPaths  []compiledPattern
	httpHeader []compiledHeader
	payload    []compiledPattern
}

type compiledHeader struct {
	name    string
	pattern compiledPattern
}

type compiledPattern struct {
	kind    PatternKind
	literal []byte
	re2     *regexp.Regexp
	value   []byte
	mask    []byte
}

// Compile validates an entire revision before returning it. Callers can retain
// their prior RuleSet unchanged when Compile returns an error.
func Compile(revision string, rules []Rule) (RuleSet, error) {
	revision = strings.TrimSpace(revision)
	if revision == "" {
		return RuleSet{}, fmt.Errorf("policy revision is required")
	}
	if len(rules) > maxRules {
		return RuleSet{}, fmt.Errorf("policy contains %d rules; maximum is %d", len(rules), maxRules)
	}
	seen := make(map[string]bool, len(rules))
	compiled := make([]compiledRule, 0, len(rules))
	for index, source := range rules {
		source = cloneRule(source)
		source.ID = strings.TrimSpace(source.ID)
		source.Name = strings.TrimSpace(source.Name)
		if source.ID == "" {
			return RuleSet{}, fmt.Errorf("rule %d: id is required", index+1)
		}
		if len(source.ID) > 128 || strings.ContainsAny(source.ID, "\x00\r\n") {
			return RuleSet{}, fmt.Errorf("rule %s: id is invalid", source.ID)
		}
		if seen[source.ID] {
			return RuleSet{}, fmt.Errorf("rule id %s is duplicated", source.ID)
		}
		seen[source.ID] = true
		if source.Name == "" {
			source.Name = source.ID
		}
		if err := validateRule(source); err != nil {
			return RuleSet{}, fmt.Errorf("rule %s: %w", source.ID, err)
		}
		matcher, err := compileMatch(source.Match)
		if err != nil {
			return RuleSet{}, fmt.Errorf("rule %s: %w", source.ID, err)
		}
		compiled = append(compiled, compiledRule{source: source, order: index, match: matcher})
	}
	sort.SliceStable(compiled, func(i, j int) bool {
		if compiled[i].source.Priority == compiled[j].source.Priority {
			return compiled[i].order < compiled[j].order
		}
		return compiled[i].source.Priority > compiled[j].source.Priority
	})
	return RuleSet{revision: revision, created: time.Now().UTC(), rules: compiled, warningCache: newDiagnosticCache()}, nil
}

// Revision returns the immutable revision name.
func (r RuleSet) Revision() string {
	return r.revision
}

// CreatedAt returns when this in-memory revision was compiled.
func (r RuleSet) CreatedAt() time.Time {
	return r.created
}

// Rules returns a deep copy in evaluation order.
func (r RuleSet) Rules() []Rule {
	out := make([]Rule, 0, len(r.rules))
	for _, rule := range r.rules {
		out = append(out, cloneRule(rule.source))
	}
	return out
}

// Evaluate applies ordered first-match terminal semantics. Log and tag actions
// from earlier matching rules remain in the decision path.
func (r RuleSet) Evaluate(frame traffic.Frame, flow traffic.Flow, capabilities dataplane.Capabilities) Decision {
	evaluatedAt := frame.Timestamp
	if evaluatedAt.IsZero() {
		evaluatedAt = time.Now().UTC()
	}
	decision := Decision{
		PacketID:         frame.ID,
		DataPlane:        capabilities.Mode(),
		EvidenceKind:     frame.Kind,
		RuleRevision:     r.revision,
		Verdict:          VerdictAllow,
		EffectiveVerdict: VerdictAllow,
		Status:           dataplane.StatusLive,
		Explanation:      "default allow; no terminal rule matched",
		EvaluatedAt:      evaluatedAt,
	}
	mode := capabilities.Mode()
	for _, rule := range r.rules {
		if !rule.source.Enabled || !rule.matches(frame, flow, mode) {
			continue
		}
		decision.MatchingRuleIDs = append(decision.MatchingRuleIDs, rule.source.ID)
		for _, action := range rule.source.Actions {
			switch action.Kind {
			case ActionTag:
				decision.Tags = appendUnique(decision.Tags, action.Value)
			}
		}
		terminal, ok := terminalAction(rule.source.Actions)
		if !ok && len(rule.source.Transformations) == 0 {
			continue
		}
		decision.WinningRuleID = rule.source.ID
		decision.Transformations = cloneTransformations(rule.source.Transformations)
		decision.Actions = append([]Action(nil), rule.source.Actions...)
		if ok {
			decision.Verdict = actionVerdict(terminal.Kind)
		}
		required, reason := requiredCapability(rule.source, terminal, ok, frame, mode)
		decision.RequiredCapability = required
		decision.Status = capabilities.Support(required)
		if required == "" {
			decision.Status = dataplane.StatusLive
		}
		if reason != "" {
			decision.Status = dataplane.StatusUnsupported
			decision.Explanation = fmt.Sprintf("rule %s matched but is unsupported: %s", rule.source.ID, reason)
		} else {
			decision.Explanation = fmt.Sprintf("rule %s matched; requires %s (%s)", rule.source.ID, required, decision.Status)
		}
		if mode == dataplane.ModeFastBridge && !FastBridgeCompatible(rule.source) {
			decision.Status = dataplane.StatusShadow
			decision.Explanation = fmt.Sprintf("rule %s matched but requires controlled bridge evaluation (SHADOW)", rule.source.ID)
		}
		if mode == dataplane.ModeTakeover && !TakeoverPFCompatible(rule.source) {
			decision.Status = dataplane.StatusShadow
			decision.Explanation = fmt.Sprintf("rule %s matched but is outside the takeover endpoint PF boundary (SHADOW)", rule.source.ID)
		} else if mode == dataplane.ModeTakeover && frame.Decoded().IPVersion != 4 {
			decision.Status = dataplane.StatusShadow
			decision.Explanation = fmt.Sprintf("rule %s matched outside the takeover IPv4 endpoint PF boundary (SHADOW)", rule.source.ID)
		}
		if mode == dataplane.ModeEdgeRoute && !EdgeRouteCompatible(rule.source) {
			decision.Status = dataplane.StatusShadow
			decision.Explanation = fmt.Sprintf("rule %s matched but cannot be compiled into the edge PF anchor (SHADOW)", rule.source.ID)
		}
		if decision.Status != dataplane.StatusLive {
			decision.EffectiveVerdict = VerdictAllow
		} else {
			decision.EffectiveVerdict = decision.Verdict
		}
		return decision
	}
	return decision
}

// Compatibility reports the static capability status a rule would have in a
// mode. Packet-specific restrictions such as TLS remain part of Decision.
func Compatibility(rule Rule, capabilities dataplane.Capabilities) (dataplane.Status, dataplane.Capability, string) {
	if !containsMode(rule.Match.Modes, capabilities.Mode()) {
		return dataplane.StatusUnsupported, "", "rule does not apply to this mode"
	}
	terminal, hasTerminal := terminalAction(rule.Actions)
	required, reason := requiredCapability(rule, terminal, hasTerminal, traffic.Frame{}, capabilities.Mode())
	if reason != "" {
		return dataplane.StatusUnsupported, required, reason
	}
	if capabilities.Mode() == dataplane.ModeFastBridge && !FastBridgeCompatible(rule) {
		return dataplane.StatusShadow, required, "rule requires controlled bridge evaluation"
	}
	if capabilities.Mode() == dataplane.ModeTakeover && !TakeoverPFCompatible(rule) {
		return dataplane.StatusShadow, required, "rule is outside the takeover endpoint PF boundary"
	}
	if capabilities.Mode() == dataplane.ModeEdgeRoute && !EdgeRouteCompatible(rule) {
		return dataplane.StatusShadow, required, "rule cannot be compiled into the edge PF anchor"
	}
	if required == "" {
		required = dataplane.CapabilityObserve
	}
	return capabilities.Support(required), required, ""
}

// EdgeRouteCompatible reports whether a rule can be represented exactly by
// the dedicated IPv4 PF anchor. Other rules remain visible in SHADOW.
func EdgeRouteCompatible(rule Rule) bool {
	return endpointPFCompatible(rule, dataplane.ModeEdgeRoute)
}

// TakeoverPFCompatible reports whether a rule can be represented exactly by
// the IPv4 PF boundary on the authenticated bridge endpoint. Link-layer,
// topology, application-message, and transformation rules remain visible in
// SHADOW instead of being silently approximated.
func TakeoverPFCompatible(rule Rule) bool {
	if !endpointPFCompatible(rule, dataplane.ModeTakeover) {
		return false
	}
	m := rule.Match
	return len(m.IPVersions) > 0 || len(m.SrcCIDRs) > 0 || len(m.DstCIDRs) > 0 || len(m.Protocols) > 0 ||
		len(m.SrcPorts.Values) > 0 || len(m.SrcPorts.Ranges) > 0 ||
		len(m.DstPorts.Values) > 0 || len(m.DstPorts.Ranges) > 0
}

func endpointPFCompatible(rule Rule, modes ...dataplane.Mode) bool {
	m := rule.Match
	if len(m.Modes) > 0 {
		matches := false
		for _, mode := range modes {
			if containsMode(m.Modes, mode) {
				matches = true
				break
			}
		}
		if !matches {
			return false
		}
	}
	if len(m.Topologies) > 0 || len(m.Ingress) > 0 || len(m.Egress) > 0 ||
		len(m.SrcMAC) > 0 || len(m.DstMAC) > 0 || len(m.EtherTypes) > 0 || len(m.VLANs) > 0 ||
		len(m.DSCP) > 0 || len(m.TTL) > 0 || m.TCPFlagMask != 0 || len(m.ICMPTypes) > 0 ||
		len(m.ICMPCodes) > 0 || len(m.EAPOLTypes) > 0 || len(m.DNSNames) > 0 || len(m.DNSTypes) > 0 ||
		len(m.HTTPMethods) > 0 || len(m.HTTPStatuses) > 0 || len(m.HTTPHosts) > 0 || len(m.HTTPPaths) > 0 ||
		len(m.HTTPHeaders) > 0 || len(m.Payload) > 0 ||
		len(rule.Transformations) > 0 {
		return false
	}
	for _, version := range m.IPVersions {
		if version != 4 {
			return false
		}
	}
	for _, direction := range m.Directions {
		switch direction {
		case traffic.DirectionOutbound, traffic.DirectionInbound:
		default:
			return false
		}
	}
	hasTerminal := false
	for _, action := range rule.Actions {
		switch action.Kind {
		case ActionAllow, ActionBlock:
			if hasTerminal {
				return false
			}
			hasTerminal = true
		case ActionTag:
		default:
			return false
		}
	}
	return hasTerminal
}

// FastBridgeCompatible reports whether a rule can be enforced by the macOS
// bridge-local Layer 2 filter, the bridge member PF path, or the existing
// EAPOL relay.
func FastBridgeCompatible(rule Rule) bool {
	return FastBridgeL2Compatible(rule) || FastBridgePFCompatible(rule)
}

// FastBridgeL2Compatible reports whether a rule can be represented by a
// bridge-local Layer 2 filter or the existing EAPOL relay.
func FastBridgeL2Compatible(rule Rule) bool {
	if strings.HasPrefix(rule.ID, "builtin-eapol-") {
		return true
	}
	m := rule.Match
	if len(m.Modes) > 0 && !containsMode(m.Modes, dataplane.ModeFastBridge) {
		return false
	}
	if len(m.Ingress) > 0 || len(m.VLANs) > 0 || len(m.IPVersions) > 0 || len(m.SrcCIDRs) > 0 ||
		len(m.DstCIDRs) > 0 || len(m.Protocols) > 0 || len(m.DSCP) > 0 || len(m.TTL) > 0 ||
		len(m.SrcPorts.Values) > 0 || len(m.SrcPorts.Ranges) > 0 || m.SrcPorts.Negate ||
		len(m.DstPorts.Values) > 0 || len(m.DstPorts.Ranges) > 0 || m.DstPorts.Negate ||
		m.TCPFlagMask != 0 || len(m.ICMPTypes) > 0 || len(m.ICMPCodes) > 0 ||
		len(m.DNSNames) > 0 || len(m.DNSTypes) > 0 || len(m.HTTPMethods) > 0 || len(m.HTTPStatuses) > 0 ||
		len(m.HTTPHosts) > 0 || len(m.HTTPPaths) > 0 || len(m.HTTPHeaders) > 0 ||
		len(m.Payload) > 0 ||
		len(rule.Transformations) > 0 {
		return false
	}
	for _, action := range rule.Actions {
		switch action.Kind {
		case ActionAllow, ActionBlock, ActionTag:
		default:
			return false
		}
	}
	return true
}

// FastBridgePFCompatible reports whether a rule can be represented exactly by
// the IPv4/IPv6 PF hooks on macOS bridge member interfaces. A rule must contain
// an IP-layer constraint; otherwise PF could not enforce it for non-IP frames.
func FastBridgePFCompatible(rule Rule) bool {
	if strings.HasPrefix(rule.ID, "builtin-eapol-") {
		return false
	}
	m := rule.Match
	if len(m.Modes) > 0 && !containsMode(m.Modes, dataplane.ModeFastBridge) {
		return false
	}
	if len(m.Ingress) > 0 || len(m.SrcMAC) > 0 || len(m.DstMAC) > 0 || len(m.EtherTypes) > 0 || len(m.VLANs) > 0 ||
		len(m.DSCP) > 0 || len(m.TTL) > 0 || m.TCPFlagMask != 0 || len(m.ICMPTypes) > 0 || len(m.ICMPCodes) > 0 ||
		len(m.EAPOLTypes) > 0 || len(m.DNSNames) > 0 || len(m.DNSTypes) > 0 || len(m.HTTPMethods) > 0 ||
		len(m.HTTPStatuses) > 0 || len(m.HTTPHosts) > 0 || len(m.HTTPPaths) > 0 || len(m.HTTPHeaders) > 0 ||
		len(m.Payload) > 0 || len(rule.Transformations) > 0 {
		return false
	}
	if len(m.IPVersions) == 0 && len(m.SrcCIDRs) == 0 && len(m.DstCIDRs) == 0 && len(m.Protocols) == 0 &&
		len(m.SrcPorts.Values) == 0 && len(m.SrcPorts.Ranges) == 0 &&
		len(m.DstPorts.Values) == 0 && len(m.DstPorts.Ranges) == 0 {
		return false
	}
	for _, side := range m.Topologies {
		switch side {
		case traffic.SideHost, traffic.SideSwitch, traffic.SideDownstream, traffic.SideUpstream:
		default:
			return false
		}
	}
	for _, side := range m.Egress {
		switch side {
		case traffic.SideHost, traffic.SideSwitch, traffic.SideDownstream, traffic.SideUpstream:
		default:
			return false
		}
	}
	for _, direction := range m.Directions {
		switch direction {
		case traffic.DirectionOutbound, traffic.DirectionInbound, traffic.DirectionHostToSwitch, traffic.DirectionSwitchToHost:
		default:
			return false
		}
	}
	for _, version := range m.IPVersions {
		if version != 4 && version != 6 {
			return false
		}
	}
	hasPorts := len(m.SrcPorts.Values) > 0 || len(m.SrcPorts.Ranges) > 0 ||
		len(m.DstPorts.Values) > 0 || len(m.DstPorts.Ranges) > 0
	if hasPorts {
		for _, protocol := range m.Protocols {
			if protocol != 6 && protocol != 17 {
				return false
			}
		}
	}
	hasTerminal := false
	for _, action := range rule.Actions {
		switch action.Kind {
		case ActionAllow, ActionBlock:
			if hasTerminal {
				return false
			}
			hasTerminal = true
		case ActionTag:
		default:
			return false
		}
	}
	return hasTerminal
}

func (r compiledRule) matches(frame traffic.Frame, _ traffic.Flow, mode dataplane.Mode) bool {
	m := r.source.Match
	d := frame.Decoded()
	if !containsMode(m.Modes, mode) || !containsSide(m.Topologies, frame.Side) ||
		!containsStringFold(m.Ingress, frame.Ingress) || !containsSide(m.Egress, frameEgress(frame.Direction)) ||
		!containsDirection(m.Directions, frame.Direction) || !containsStringFold(m.SrcMAC, d.SrcMAC) ||
		!containsStringFold(m.DstMAC, d.DstMAC) || !containsUint16(m.EtherTypes, d.EtherType) ||
		!containsAnyVLAN(m.VLANs, d.VLANs) || !containsUint8(m.IPVersions, d.IPVersion) ||
		!containsUint8(m.Protocols, d.IPProtocol) || !containsUint8(m.DSCP, d.DSCP) ||
		!containsUint8(m.TTL, d.TTL) || !matchPortSet(m.SrcPorts, d.SrcPort) ||
		!matchPortSet(m.DstPorts, d.DstPort) || !containsUint8(m.ICMPTypes, d.ICMPType) ||
		!containsUint8(m.ICMPCodes, d.ICMPCode) || !containsUint8(m.EAPOLTypes, d.EAPOLType) ||
		!containsUint16(m.DNSTypes, d.DNSType) ||
		!containsStringFold(m.HTTPMethods, d.HTTPMethod) || !containsUint16(m.HTTPStatuses, d.HTTPStatus) {
		return false
	}
	if m.TCPFlagMask != 0 && d.TCPFlags&m.TCPFlagMask != m.TCPFlags&m.TCPFlagMask {
		return false
	}
	if !matchPrefixes(r.match.srcCIDRs, d.SrcIP) || !matchPrefixes(r.match.dstCIDRs, d.DstIP) {
		return false
	}
	if !matchAnyStringPattern(r.match.dnsNames, d.DNSNames) || !matchStringPattern(r.match.httpHosts, d.HTTPHost) ||
		!matchStringPattern(r.match.httpPaths, d.HTTPPath) || !matchHeaders(r.match.httpHeader, d.HTTPHeader) {
		return false
	}
	if len(r.match.payload) > 0 {
		ranges := frame.Ranges(traffic.FieldPayload)
		if len(ranges) != 1 {
			return false
		}
		raw := frame.RawBytes()
		if ranges[0].Start < 0 || ranges[0].End > len(raw) || ranges[0].Start > ranges[0].End {
			return false
		}
		for _, pattern := range r.match.payload {
			if !pattern.matches(raw[ranges[0].Start:ranges[0].End]) {
				return false
			}
		}
	}
	return true
}

// RevisionSummary describes one retained immutable policy revision.
type RevisionSummary struct {
	Revision  string
	CreatedAt time.Time
	RuleCount int
	Active    bool
}

// Store atomically owns the active immutable policy revision and a bounded
// history used for explicit comparison and rollback.
type Store struct {
	mu        sync.RWMutex
	active    RuleSet
	has       bool
	history   []RuleSet
	revisions map[string]int
}

// Activate compiles and atomically replaces the active revision. Compilation
// failure leaves the prior revision untouched.
func (s *Store) Activate(revision string, rules []Rule) error {
	next, err := Compile(revision, rules)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.installLocked(next, true)
}

// Register validates and retains a revision without changing the active
// revision. It is used when loading named project history.
func (s *Store) Register(revision string, rules []Rule) error {
	next, err := Compile(revision, rules)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.installLocked(next, false)
}

func (s *Store) installLocked(next RuleSet, activate bool) error {
	if s.revisions == nil {
		s.revisions = make(map[string]int)
	}
	if index, ok := s.revisions[next.revision]; ok {
		existing := s.history[index]
		if !reflect.DeepEqual(existing.Rules(), next.Rules()) {
			return fmt.Errorf("policy revision %q already exists with different rules", next.revision)
		}
		if activate {
			s.active = existing
			s.has = true
		}
		return nil
	}
	if len(s.history) == maxRevisions {
		evict := 0
		if s.has && s.history[evict].revision == s.active.revision {
			for index := 1; index < len(s.history); index++ {
				if s.history[index].revision != s.active.revision {
					evict = index
					break
				}
			}
		}
		delete(s.revisions, s.history[evict].revision)
		s.history = append(s.history[:evict], s.history[evict+1:]...)
		for index := range s.history {
			s.revisions[s.history[index].revision] = index
		}
	}
	s.revisions[next.revision] = len(s.history)
	s.history = append(s.history, next)
	if activate {
		s.active = next
		s.has = true
	}
	return nil
}

// Active returns the current immutable revision.
func (s *Store) Active() (RuleSet, bool) {
	if s == nil {
		return RuleSet{}, false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.active, s.has
}

// Revision returns one retained immutable revision by name.
func (s *Store) Revision(revision string) (RuleSet, bool) {
	if s == nil {
		return RuleSet{}, false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	index, ok := s.revisions[strings.TrimSpace(revision)]
	if !ok {
		return RuleSet{}, false
	}
	return s.history[index], true
}

// ActivateRevision atomically rolls back to a retained, already-compiled
// revision. No mutable rule slice is shared with the caller.
func (s *Store) ActivateRevision(revision string) error {
	if s == nil {
		return fmt.Errorf("policy store is unavailable")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	index, ok := s.revisions[strings.TrimSpace(revision)]
	if !ok {
		return fmt.Errorf("policy revision %q is not retained", strings.TrimSpace(revision))
	}
	s.active = s.history[index]
	s.has = true
	return nil
}

// History returns newest-first immutable revision summaries.
func (s *Store) History() []RevisionSummary {
	if s == nil {
		return nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]RevisionSummary, 0, len(s.history))
	for index := len(s.history) - 1; index >= 0; index-- {
		revision := s.history[index]
		result = append(result, RevisionSummary{
			Revision: revision.revision, CreatedAt: revision.created,
			RuleCount: len(revision.rules), Active: s.has && revision.revision == s.active.revision,
		})
	}
	return result
}

func validateRule(rule Rule) error {
	terminalCount := 0
	for _, action := range rule.Actions {
		switch action.Kind {
		case ActionAllow, ActionBlock:
			terminalCount++
		case ActionRedirect, ActionNAT, ActionPortForward:
			return fmt.Errorf("%s is a session-level network setting, not a policy action", action.Kind)
		case ActionTag:
			if strings.TrimSpace(action.Value) == "" {
				return fmt.Errorf("%s action value is required", action.Kind)
			}
		case ActionDelay, ActionJitter:
			if action.Duration < 0 {
				return fmt.Errorf("%s duration must not be negative", action.Kind)
			}
		case ActionBandwidth:
			if action.Rate == 0 {
				return fmt.Errorf("bandwidth rate is required")
			}
		case ActionLoss, ActionDuplicate:
			if action.Percent < 0 || action.Percent > 100 {
				return fmt.Errorf("%s percent must be between 0 and 100", action.Kind)
			}
		default:
			return fmt.Errorf("unknown action %q", action.Kind)
		}
	}
	if terminalCount > 1 {
		return fmt.Errorf("multiple terminal actions are not allowed")
	}
	for _, transform := range rule.Transformations {
		if err := validateTransformation(transform); err != nil {
			return err
		}
	}
	for _, portSet := range []PortSet{rule.Match.SrcPorts, rule.Match.DstPorts} {
		for _, portRange := range portSet.Ranges {
			if portRange.First > portRange.Last {
				return fmt.Errorf("port range %d-%d is reversed", portRange.First, portRange.Last)
			}
		}
	}
	for _, value := range rule.Match.DSCP {
		if value > 63 {
			return fmt.Errorf("DSCP %d is outside 0-63", value)
		}
	}
	for _, value := range rule.Match.HTTPStatuses {
		if value < 100 || value > 599 {
			return fmt.Errorf("HTTP status %d is outside 100-599", value)
		}
	}
	return nil
}

func validateTransformation(transform Transformation) error {
	switch transform.Kind {
	case TransformField:
		if transform.Field == "" {
			return fmt.Errorf("field transformation requires a field")
		}
		if transform.Replace == "" {
			return fmt.Errorf("field transformation requires a replacement value")
		}
		if err := validateFieldReplacement(transform.Field, transform.Replace); err != nil {
			return err
		}
	case TransformLiteral, TransformRE2, TransformMasked:
		if transform.Search == "" {
			return fmt.Errorf("%s transformation requires a search value", transform.Kind)
		}
		if transform.Kind == TransformRE2 {
			if _, err := regexp.Compile(transform.Search); err != nil {
				return fmt.Errorf("compile replacement RE2: %w", err)
			}
		}
		if transform.Kind == TransformMasked {
			search, _, err := parseMasked(transform.Search)
			if err != nil {
				return fmt.Errorf("masked replacement: %w", err)
			}
			replacement, err := decodeHexBytes(transform.Replace)
			if err != nil {
				return fmt.Errorf("masked replacement: %w", err)
			}
			if len(search) != len(replacement) {
				return fmt.Errorf("masked replacement must preserve frame length")
			}
		}
		if transform.Kind == TransformLiteral && len([]byte(transform.Search)) != len([]byte(transform.Replace)) {
			return fmt.Errorf("literal replacement must preserve frame length")
		}
	default:
		return fmt.Errorf("unknown transformation %q", transform.Kind)
	}
	if len(transform.Search) > maxPatternLength || len(transform.Replace) > maxPatternLength {
		return fmt.Errorf("transformation exceeds %d bytes", maxPatternLength)
	}
	switch transform.Occurrence {
	case "", OccurrenceFirst, OccurrenceAll:
	default:
		return fmt.Errorf("unknown occurrence %q", transform.Occurrence)
	}
	return nil
}

func validateFieldReplacement(field traffic.Field, replacement string) error {
	switch field {
	case traffic.FieldSrcMAC, traffic.FieldDstMAC:
		mac, err := net.ParseMAC(strings.TrimSpace(replacement))
		if err != nil || len(mac) != 6 {
			return fmt.Errorf("replacement MAC %q is invalid", replacement)
		}
	case traffic.FieldSrcIP, traffic.FieldDstIP:
		if _, err := netip.ParseAddr(strings.TrimSpace(replacement)); err != nil {
			return fmt.Errorf("replacement IP %q is invalid", replacement)
		}
	case traffic.FieldSrcPort, traffic.FieldDstPort, traffic.FieldEtherType:
		if _, err := parseUint(replacement, 16); err != nil {
			return err
		}
	case traffic.FieldTTL:
		if _, err := parseUint(replacement, 8); err != nil {
			return err
		}
	case traffic.FieldDSCP:
		if _, err := parseUint(replacement, 6); err != nil {
			return fmt.Errorf("replacement DSCP %q is outside 0-63", replacement)
		}
	case traffic.FieldVLAN:
		if _, err := parseUint(replacement, 12); err != nil {
			return fmt.Errorf("replacement VLAN %q is outside 0-4095", replacement)
		}
	default:
		return fmt.Errorf("field %s is not safely rewritable", field)
	}
	return nil
}

func compileMatch(match Match) (compiledMatch, error) {
	var out compiledMatch
	var err error
	if out.srcCIDRs, err = compilePrefixes(match.SrcCIDRs); err != nil {
		return compiledMatch{}, fmt.Errorf("source CIDR: %w", err)
	}
	if out.dstCIDRs, err = compilePrefixes(match.DstCIDRs); err != nil {
		return compiledMatch{}, fmt.Errorf("destination CIDR: %w", err)
	}
	if out.dnsNames, err = compilePatterns(match.DNSNames); err != nil {
		return compiledMatch{}, fmt.Errorf("DNS name: %w", err)
	}
	if out.httpHosts, err = compilePatterns(match.HTTPHosts); err != nil {
		return compiledMatch{}, fmt.Errorf("HTTP host: %w", err)
	}
	if out.httpPaths, err = compilePatterns(match.HTTPPaths); err != nil {
		return compiledMatch{}, fmt.Errorf("HTTP path: %w", err)
	}
	if out.payload, err = compilePatterns(match.Payload); err != nil {
		return compiledMatch{}, fmt.Errorf("payload: %w", err)
	}
	for _, header := range match.HTTPHeaders {
		name := strings.ToLower(strings.TrimSpace(header.Name))
		if name == "" {
			return compiledMatch{}, fmt.Errorf("HTTP header name is required")
		}
		pattern, err := compilePattern(header.Value)
		if err != nil {
			return compiledMatch{}, fmt.Errorf("HTTP header %s: %w", name, err)
		}
		out.httpHeader = append(out.httpHeader, compiledHeader{name: name, pattern: pattern})
	}
	for _, macs := range [][]string{match.SrcMAC, match.DstMAC} {
		for _, value := range macs {
			mac, err := net.ParseMAC(value)
			if err != nil || len(mac) != 6 {
				return compiledMatch{}, fmt.Errorf("MAC %q is invalid", value)
			}
		}
	}
	return out, nil
}

func compilePrefixes(values []string) ([]netip.Prefix, error) {
	out := make([]netip.Prefix, 0, len(values))
	for _, value := range values {
		prefix, err := netip.ParsePrefix(strings.TrimSpace(value))
		if err != nil {
			return nil, fmt.Errorf("parse %q: %w", value, err)
		}
		out = append(out, prefix.Masked())
	}
	return out, nil
}

func compilePatterns(values []BytePattern) ([]compiledPattern, error) {
	out := make([]compiledPattern, 0, len(values))
	for _, value := range values {
		pattern, err := compilePattern(value)
		if err != nil {
			return nil, err
		}
		out = append(out, pattern)
	}
	return out, nil
}

func compilePattern(pattern BytePattern) (compiledPattern, error) {
	if pattern.Kind == "" {
		pattern.Kind = PatternLiteral
	}
	if pattern.Value == "" {
		return compiledPattern{}, fmt.Errorf("pattern is empty")
	}
	if len(pattern.Value) > maxPatternLength {
		return compiledPattern{}, fmt.Errorf("pattern exceeds %d bytes", maxPatternLength)
	}
	switch pattern.Kind {
	case PatternLiteral:
		return compiledPattern{kind: pattern.Kind, literal: []byte(pattern.Value)}, nil
	case PatternRE2:
		expression, err := regexp.Compile(pattern.Value)
		if err != nil {
			return compiledPattern{}, fmt.Errorf("compile RE2: %w", err)
		}
		return compiledPattern{kind: pattern.Kind, re2: expression}, nil
	case PatternMasked:
		value, mask, err := parseMasked(pattern.Value)
		if err != nil {
			return compiledPattern{}, err
		}
		return compiledPattern{kind: pattern.Kind, value: value, mask: mask}, nil
	default:
		return compiledPattern{}, fmt.Errorf("unknown pattern kind %q", pattern.Kind)
	}
}

func parseMasked(value string) ([]byte, []byte, error) {
	tokens := strings.Fields(strings.ReplaceAll(value, ":", " "))
	if len(tokens) == 0 || len(tokens) > maxPatternLength {
		return nil, nil, fmt.Errorf("masked pattern size is invalid")
	}
	values := make([]byte, len(tokens))
	masks := make([]byte, len(tokens))
	for i, token := range tokens {
		if token == "??" || token == "**" {
			continue
		}
		decoded, err := hex.DecodeString(token)
		if err != nil || len(decoded) != 1 {
			return nil, nil, fmt.Errorf("masked byte %q is invalid", token)
		}
		values[i] = decoded[0]
		masks[i] = 0xff
	}
	return values, masks, nil
}

func (p compiledPattern) matches(value []byte) bool {
	switch p.kind {
	case PatternLiteral:
		return bytes.Contains(value, p.literal)
	case PatternRE2:
		return p.re2.Match(value)
	case PatternMasked:
		return maskedIndex(value, p.value, p.mask) >= 0
	default:
		return false
	}
}

func maskedIndex(data, value, mask []byte) int {
	if len(value) == 0 || len(value) != len(mask) || len(value) > len(data) {
		return -1
	}
	for start := 0; start+len(value) <= len(data); start++ {
		matched := true
		for i := range value {
			if data[start+i]&mask[i] != value[i]&mask[i] {
				matched = false
				break
			}
		}
		if matched {
			return start
		}
	}
	return -1
}

func requiredCapability(rule Rule, terminal Action, hasTerminal bool, frame traffic.Frame, mode dataplane.Mode) (dataplane.Capability, string) {
	required := dataplane.Capability("")
	if hasTerminal {
		switch terminal.Kind {
		case ActionAllow, ActionBlock:
			if mode == dataplane.ModeTakeover || mode == dataplane.ModeEdgeRoute {
				required = dataplane.CapabilityStatefulFilter
			} else {
				required = dataplane.CapabilityFrameFilter
			}
		}
	}
	for _, action := range rule.Actions {
		switch action.Kind {
		case ActionDelay, ActionJitter, ActionBandwidth, ActionLoss, ActionDuplicate:
			required = combineCapability(required, dataplane.CapabilityTrafficShape)
		}
	}
	d := frame.Decoded()
	for _, transform := range rule.Transformations {
		capability := transformationCapability(transform)
		if (d.SrcPort == 443 || d.DstPort == 443) && capability == dataplane.CapabilityRewritePayload {
			return capability, "TLS payload is encrypted"
		}
		required = combineCapability(required, capability)
	}
	return required, ""
}

func transformationCapability(transform Transformation) dataplane.Capability {
	switch transform.Kind {
	case TransformField:
		switch transform.Field {
		case traffic.FieldSrcMAC, traffic.FieldDstMAC, traffic.FieldVLAN, traffic.FieldEtherType:
			return dataplane.CapabilityRewriteEthernet
		case traffic.FieldSrcIP, traffic.FieldDstIP, traffic.FieldTTL, traffic.FieldDSCP:
			return dataplane.CapabilityRewriteIP
		case traffic.FieldSrcPort, traffic.FieldDstPort:
			return dataplane.CapabilityRewriteTransport
		default:
			return dataplane.CapabilityRewritePayload
		}
	case TransformLiteral, TransformRE2, TransformMasked:
		return dataplane.CapabilityRewritePayload
	default:
		return dataplane.CapabilityObserve
	}
}

func combineCapability(current, next dataplane.Capability) dataplane.Capability {
	if current == "" || current == dataplane.CapabilityObserve {
		return next
	}
	if next == "" || next == dataplane.CapabilityObserve || next == current {
		return current
	}
	// One Decision exposes the strongest requirement. Composite capability
	// diagnostics remain visible in rule validation and transformation lists.
	rank := map[dataplane.Capability]int{
		dataplane.CapabilityObserve: 0, dataplane.CapabilityFrameFilter: 1,
		dataplane.CapabilityStatefulFilter: 2, dataplane.CapabilityRewriteEthernet: 3,
		dataplane.CapabilityRewriteIP: 4, dataplane.CapabilityRewriteTransport: 5,
		dataplane.CapabilityRewritePayload: 6, dataplane.CapabilityTrafficShape: 7,
		dataplane.CapabilityRedirect: 8,
		dataplane.CapabilityNAT:      9, dataplane.CapabilityPortForward: 10,
	}
	if rank[next] > rank[current] {
		return next
	}
	return current
}

func cloneRule(rule Rule) Rule {
	rule.Match = cloneMatch(rule.Match)
	rule.Actions = append([]Action(nil), rule.Actions...)
	rule.Transformations = cloneTransformations(rule.Transformations)
	if rule.LastMatch != nil {
		value := *rule.LastMatch
		rule.LastMatch = &value
	}
	if rule.Metadata != nil {
		metadata := make(map[string]string, len(rule.Metadata))
		for key, value := range rule.Metadata {
			metadata[key] = value
		}
		rule.Metadata = metadata
	}
	return rule
}

func cloneMatch(match Match) Match {
	match.Modes = append([]dataplane.Mode(nil), match.Modes...)
	match.Topologies = append([]traffic.TopologySide(nil), match.Topologies...)
	match.Ingress = append([]string(nil), match.Ingress...)
	match.Egress = append([]traffic.TopologySide(nil), match.Egress...)
	match.Directions = append([]traffic.Direction(nil), match.Directions...)
	match.SrcMAC = append([]string(nil), match.SrcMAC...)
	match.DstMAC = append([]string(nil), match.DstMAC...)
	match.EtherTypes = append([]uint16(nil), match.EtherTypes...)
	match.VLANs = append([]uint16(nil), match.VLANs...)
	match.IPVersions = append([]uint8(nil), match.IPVersions...)
	match.SrcCIDRs = append([]string(nil), match.SrcCIDRs...)
	match.DstCIDRs = append([]string(nil), match.DstCIDRs...)
	match.Protocols = append([]uint8(nil), match.Protocols...)
	match.DSCP = append([]uint8(nil), match.DSCP...)
	match.TTL = append([]uint8(nil), match.TTL...)
	match.SrcPorts.Values = append([]uint16(nil), match.SrcPorts.Values...)
	match.SrcPorts.Ranges = append([]PortRange(nil), match.SrcPorts.Ranges...)
	match.DstPorts.Values = append([]uint16(nil), match.DstPorts.Values...)
	match.DstPorts.Ranges = append([]PortRange(nil), match.DstPorts.Ranges...)
	match.ICMPTypes = append([]uint8(nil), match.ICMPTypes...)
	match.ICMPCodes = append([]uint8(nil), match.ICMPCodes...)
	match.EAPOLTypes = append([]uint8(nil), match.EAPOLTypes...)
	match.DNSNames = append([]BytePattern(nil), match.DNSNames...)
	match.DNSTypes = append([]uint16(nil), match.DNSTypes...)
	match.HTTPMethods = append([]string(nil), match.HTTPMethods...)
	match.HTTPStatuses = append([]uint16(nil), match.HTTPStatuses...)
	match.HTTPHosts = append([]BytePattern(nil), match.HTTPHosts...)
	match.HTTPPaths = append([]BytePattern(nil), match.HTTPPaths...)
	match.HTTPHeaders = append([]HeaderMatch(nil), match.HTTPHeaders...)
	match.Payload = append([]BytePattern(nil), match.Payload...)
	return match
}

func cloneTransformations(values []Transformation) []Transformation {
	return append([]Transformation(nil), values...)
}

func terminalAction(actions []Action) (Action, bool) {
	for _, action := range actions {
		switch action.Kind {
		case ActionAllow, ActionBlock:
			return action, true
		}
	}
	return Action{}, false
}

func actionVerdict(kind ActionKind) Verdict {
	switch kind {
	case ActionBlock:
		return VerdictBlock
	default:
		return VerdictAllow
	}
}

func containsMode(values []dataplane.Mode, got dataplane.Mode) bool {
	if len(values) == 0 {
		return true
	}
	for _, value := range values {
		if value == got {
			return true
		}
	}
	return false
}

func containsSide(values []traffic.TopologySide, got traffic.TopologySide) bool {
	if len(values) == 0 {
		return true
	}
	for _, value := range values {
		if value == got {
			return true
		}
	}
	return false
}

func containsDirection(values []traffic.Direction, got traffic.Direction) bool {
	if len(values) == 0 {
		return true
	}
	for _, value := range values {
		if value == got {
			return true
		}
	}
	return false
}

func containsStringFold(values []string, got string) bool {
	if len(values) == 0 {
		return true
	}
	for _, value := range values {
		if strings.EqualFold(strings.TrimSpace(value), got) {
			return true
		}
	}
	return false
}

func containsUint8(values []uint8, got uint8) bool {
	if len(values) == 0 {
		return true
	}
	for _, value := range values {
		if value == got {
			return true
		}
	}
	return false
}

func containsUint16(values []uint16, got uint16) bool {
	if len(values) == 0 {
		return true
	}
	for _, value := range values {
		if value == got {
			return true
		}
	}
	return false
}

func containsAnyVLAN(values []uint16, got []traffic.VLAN) bool {
	if len(values) == 0 {
		return true
	}
	for _, tag := range got {
		if containsUint16(values, tag.ID) {
			return true
		}
	}
	return false
}

func matchPortSet(set PortSet, got uint16) bool {
	if len(set.Values) == 0 && len(set.Ranges) == 0 {
		return true
	}
	matched := containsUint16(set.Values, got) && len(set.Values) > 0
	for _, value := range set.Ranges {
		if got >= value.First && got <= value.Last {
			matched = true
			break
		}
	}
	if set.Negate {
		return !matched
	}
	return matched
}

func matchPrefixes(prefixes []netip.Prefix, value string) bool {
	if len(prefixes) == 0 {
		return true
	}
	address, err := netip.ParseAddr(value)
	if err != nil {
		return false
	}
	for _, prefix := range prefixes {
		if prefix.Contains(address) {
			return true
		}
	}
	return false
}

func matchAnyStringPattern(patterns []compiledPattern, values []string) bool {
	if len(patterns) == 0 {
		return true
	}
	for _, pattern := range patterns {
		for _, value := range values {
			if pattern.matches([]byte(value)) {
				return true
			}
		}
	}
	return false
}

func matchStringPattern(patterns []compiledPattern, value string) bool {
	if len(patterns) == 0 {
		return true
	}
	for _, pattern := range patterns {
		if pattern.matches([]byte(value)) {
			return true
		}
	}
	return false
}

func matchHeaders(patterns []compiledHeader, headers map[string][]string) bool {
	for _, expected := range patterns {
		matched := false
		for name, values := range headers {
			if !strings.EqualFold(name, expected.name) {
				continue
			}
			for _, value := range values {
				if expected.pattern.matches([]byte(value)) {
					matched = true
					break
				}
			}
		}
		if !matched {
			return false
		}
	}
	return true
}

func frameEgress(direction traffic.Direction) traffic.TopologySide {
	switch direction {
	case traffic.DirectionHostToSwitch:
		return traffic.SideSwitch
	case traffic.DirectionSwitchToHost:
		return traffic.SideHost
	case traffic.DirectionOutbound:
		return traffic.SideUpstream
	case traffic.DirectionInbound:
		return traffic.SideDownstream
	default:
		return traffic.SideUnknown
	}
}

func appendUnique(values []string, value string) []string {
	value = strings.TrimSpace(value)
	if value == "" {
		return values
	}
	for _, existing := range values {
		if existing == value {
			return values
		}
	}
	return append(values, value)
}
