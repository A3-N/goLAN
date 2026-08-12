package policy

import (
	"bytes"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strings"
	"sync"

	"golan/internal/dataplane"
	"golan/internal/traffic"
)

// DiagnosticKind identifies one static policy warning category.
type DiagnosticKind string

// Policy diagnostic kinds are stable values used by the Workbench.
const (
	DiagnosticCapability  DiagnosticKind = "capability"
	DiagnosticConflict    DiagnosticKind = "conflict"
	DiagnosticUnreachable DiagnosticKind = "unreachable"
	DiagnosticExposure    DiagnosticKind = "exposure"
)

// Diagnostic describes one deterministic, payload-free policy warning.
type Diagnostic struct {
	Kind          DiagnosticKind
	RuleID        string
	RelatedRuleID string
	Mode          dataplane.Mode
	Status        dataplane.Status
	Message       string
}

type diagnosticCache struct {
	mu     sync.Mutex
	byMode map[string][]Diagnostic
}

const maxDiagnosticCacheEntries = 16

func newDiagnosticCache() *diagnosticCache {
	return &diagnosticCache{byMode: make(map[string][]Diagnostic)}
}

// String returns a compact stable warning suitable for logs and terminal rows.
func (d Diagnostic) String() string {
	parts := []string{"WARN", string(d.Kind), "rule=" + d.RuleID}
	if d.RelatedRuleID != "" {
		parts = append(parts, "related="+d.RelatedRuleID)
	}
	if d.Mode != "" {
		parts = append(parts, "mode="+string(d.Mode))
	}
	if d.Status != "" {
		parts = append(parts, "status="+string(d.Status))
	}
	if d.Message != "" {
		parts = append(parts, d.Message)
	}
	return strings.Join(parts, " ")
}

// Diagnostics returns bounded warnings in policy evaluation order. It never
// changes the compiled revision and does not reject an otherwise valid policy.
func (r RuleSet) Diagnostics(capabilities dataplane.Capabilities) []Diagnostic {
	if r.warningCache == nil {
		return r.computeDiagnostics(capabilities)
	}
	key := string(capabilities.Mode()) + "|" + strings.Join(capabilities.Summary(), ",")
	r.warningCache.mu.Lock()
	cached, ok := r.warningCache.byMode[key]
	r.warningCache.mu.Unlock()
	if ok {
		return cloneDiagnostics(cached)
	}
	computed := r.computeDiagnostics(capabilities)
	r.warningCache.mu.Lock()
	if cached, ok = r.warningCache.byMode[key]; !ok {
		if len(r.warningCache.byMode) < maxDiagnosticCacheEntries {
			r.warningCache.byMode[key] = cloneDiagnostics(computed)
		}
		cached = computed
	}
	r.warningCache.mu.Unlock()
	return cloneDiagnostics(cached)
}

// DiagnosticsForRule returns warnings caused by or directly affecting one
// rule without recomputing unrelated all-pairs diagnostics. It is intended for
// responsive draft previews and remains advisory like Diagnostics.
func (r RuleSet) DiagnosticsForRule(capabilities dataplane.Capabilities, ruleID string) []Diagnostic {
	ruleID = strings.TrimSpace(ruleID)
	if ruleID == "" {
		return nil
	}
	targetIndex := -1
	for index := range r.rules {
		if r.rules[index].source.ID == ruleID {
			targetIndex = index
			break
		}
	}
	if targetIndex < 0 || !r.rules[targetIndex].source.Enabled {
		return nil
	}
	target := r.rules[targetIndex]
	mode := capabilities.Mode()
	diagnostics := make([]Diagnostic, 0, 4)
	status, required, reason := Compatibility(target.source, capabilities)
	if status != dataplane.StatusLive {
		diagnostics = append(diagnostics, Diagnostic{
			Kind: DiagnosticCapability, RuleID: target.source.ID,
			Mode: mode, Status: status,
			Message: diagnosticCapabilityMessage(target.source, mode, status, required, reason),
		})
	}
	if !containsMode(target.source.Match.Modes, mode) {
		return diagnostics
	}
	if impossibleReason := diagnosticImpossibleReason(target); impossibleReason != "" {
		return append(diagnostics, Diagnostic{
			Kind: DiagnosticUnreachable, RuleID: target.source.ID,
			Mode: mode, Message: "rule cannot match: " + impossibleReason,
		})
	}
	if exposure := diagnosticExposure(target.source); exposure != "" {
		diagnostics = append(diagnostics, Diagnostic{
			Kind: DiagnosticExposure, RuleID: target.source.ID,
			Mode: mode, Message: exposure,
		})
	}

	covered := false
	for index := 0; index < targetIndex; index++ {
		earlier := r.rules[index]
		if !diagnosticRuleParticipates(earlier, mode) || !diagnosticDecisive(earlier.source) {
			continue
		}
		if diagnosticMatchContains(earlier, target) {
			diagnostics = append(diagnostics, Diagnostic{
				Kind: DiagnosticUnreachable, RuleID: target.source.ID,
				RelatedRuleID: earlier.source.ID, Mode: mode,
				Message: "an earlier decisive rule covers every possible match",
			})
			covered = true
			break
		}
	}
	if !covered {
		for index := 0; index < targetIndex; index++ {
			earlier := r.rules[index]
			if !diagnosticRuleParticipates(earlier, mode) {
				continue
			}
			if message, conflict := diagnosticConflictMessage(earlier, target); conflict {
				diagnostics = append(diagnostics, Diagnostic{
					Kind: DiagnosticConflict, RuleID: target.source.ID,
					RelatedRuleID: earlier.source.ID, Mode: mode, Message: message,
				})
				break
			}
		}
	}
	if covered || !diagnosticDecisive(target.source) {
		return diagnostics
	}
	for index := targetIndex + 1; index < len(r.rules); index++ {
		later := r.rules[index]
		if !diagnosticRuleParticipates(later, mode) {
			continue
		}
		if diagnosticMatchContains(target, later) {
			diagnostics = append(diagnostics, Diagnostic{
				Kind: DiagnosticUnreachable, RuleID: later.source.ID,
				RelatedRuleID: target.source.ID, Mode: mode,
				Message: "the draft decisive rule covers every possible match",
			})
			continue
		}
		if message, conflict := diagnosticConflictMessage(target, later); conflict {
			diagnostics = append(diagnostics, Diagnostic{
				Kind: DiagnosticConflict, RuleID: later.source.ID,
				RelatedRuleID: target.source.ID, Mode: mode, Message: message,
			})
		}
	}
	return diagnostics
}

func (r RuleSet) computeDiagnostics(capabilities dataplane.Capabilities) []Diagnostic {
	mode := capabilities.Mode()
	diagnostics := make([]Diagnostic, 0, len(r.rules))
	prior := make([]compiledRule, 0, len(r.rules))
	candidateIndex := newDiagnosticCandidateIndex()
	for _, current := range r.rules {
		if !current.source.Enabled {
			continue
		}
		status, required, reason := Compatibility(current.source, capabilities)
		if status != dataplane.StatusLive {
			message := diagnosticCapabilityMessage(current.source, mode, status, required, reason)
			diagnostics = append(diagnostics, Diagnostic{
				Kind: DiagnosticCapability, RuleID: current.source.ID,
				Mode: mode, Status: status, Message: message,
			})
		}
		if !containsMode(current.source.Match.Modes, mode) {
			continue
		}
		if impossibleReason := diagnosticImpossibleReason(current); impossibleReason != "" {
			diagnostics = append(diagnostics, Diagnostic{
				Kind: DiagnosticUnreachable, RuleID: current.source.ID,
				Mode: mode, Message: "rule cannot match: " + impossibleReason,
			})
			continue
		}
		if exposure := diagnosticExposure(current.source); exposure != "" {
			diagnostics = append(diagnostics, Diagnostic{
				Kind: DiagnosticExposure, RuleID: current.source.ID,
				Mode: mode, Message: exposure,
			})
		}

		candidates, filtered := candidateIndex.candidates(current.source.Match)
		covered := false
		if earlier, found := diagnosticCoveringCandidate(prior, candidates, filtered, current); found {
			diagnostics = append(diagnostics, Diagnostic{
				Kind: DiagnosticUnreachable, RuleID: current.source.ID,
				RelatedRuleID: earlier.source.ID, Mode: mode,
				Message: "an earlier decisive rule covers every possible match",
			})
			covered = true
		}
		if !covered {
			if earlier, message, found := diagnosticConflictingCandidate(prior, candidates, filtered, current); found {
				diagnostics = append(diagnostics, Diagnostic{
					Kind: DiagnosticConflict, RuleID: current.source.ID,
					RelatedRuleID: earlier.source.ID, Mode: mode, Message: message,
				})
			}
		}
		candidateIndex.add(len(prior), current.source.Match)
		prior = append(prior, current)
	}
	return diagnostics
}

func diagnosticCoveringCandidate(prior []compiledRule, candidates []int, filtered bool, current compiledRule) (compiledRule, bool) {
	check := func(earlier compiledRule) bool {
		return diagnosticDecisive(earlier.source) && diagnosticMatchContains(earlier, current)
	}
	if filtered {
		for _, index := range candidates {
			if index >= 0 && index < len(prior) && check(prior[index]) {
				return prior[index], true
			}
		}
		return compiledRule{}, false
	}
	for _, earlier := range prior {
		if check(earlier) {
			return earlier, true
		}
	}
	return compiledRule{}, false
}

func diagnosticConflictingCandidate(prior []compiledRule, candidates []int, filtered bool, current compiledRule) (compiledRule, string, bool) {
	check := func(earlier compiledRule) (string, bool) {
		return diagnosticConflictMessage(earlier, current)
	}
	if filtered {
		for _, index := range candidates {
			if index < 0 || index >= len(prior) {
				continue
			}
			if message, conflict := check(prior[index]); conflict {
				return prior[index], message, true
			}
		}
		return compiledRule{}, "", false
	}
	for _, earlier := range prior {
		if message, conflict := check(earlier); conflict {
			return earlier, message, true
		}
	}
	return compiledRule{}, "", false
}

func diagnosticConflictMessage(earlier, current compiledRule) (string, bool) {
	earlierTerminal, earlierOK := terminalAction(earlier.source.Actions)
	currentTerminal, currentOK := terminalAction(current.source.Actions)
	if !earlierOK || !currentOK || earlierTerminal == currentTerminal || !diagnosticMatchesOverlap(earlier, current) {
		return "", false
	}
	if earlier.source.Priority != current.source.Priority &&
		diagnosticSpecificity(earlier.source.Match) > diagnosticSpecificity(current.source.Match) {
		// A more-specific exception before a broader fallback is an
		// intentional first-match pattern, not an unresolved conflict.
		return "", false
	}
	return fmt.Sprintf("terminal action %s may overlap earlier action %s", currentTerminal.Kind, earlierTerminal.Kind), true
}

func diagnosticRuleParticipates(rule compiledRule, mode dataplane.Mode) bool {
	return rule.source.Enabled && containsMode(rule.source.Match.Modes, mode) && diagnosticImpossibleReason(rule) == ""
}

func cloneDiagnostics(values []Diagnostic) []Diagnostic {
	return append([]Diagnostic(nil), values...)
}

func diagnosticCapabilityMessage(rule Rule, current dataplane.Mode, status dataplane.Status, required dataplane.Capability, reason string) string {
	parts := make([]string, 0, 3)
	if required != "" {
		parts = append(parts, "requires "+string(required))
	}
	if reason != "" {
		parts = append(parts, reason)
	}
	if live := diagnosticLiveModes(rule, current); len(live) > 0 {
		values := make([]string, len(live))
		for index, mode := range live {
			values[index] = string(mode)
		}
		parts = append(parts, "LIVE in "+strings.Join(values, ","))
	} else {
		parts = append(parts, "no live alternative in the current rule scope")
	}
	if len(parts) == 0 {
		return string(status)
	}
	return strings.Join(parts, "; ")
}

func diagnosticLiveModes(rule Rule, current dataplane.Mode) []dataplane.Mode {
	modes := dataplane.Modes()
	result := make([]dataplane.Mode, 0, len(modes))
	for _, mode := range modes {
		if mode == current {
			continue
		}
		status, _, _ := Compatibility(rule, dataplane.ForMode(mode))
		if status == dataplane.StatusLive {
			result = append(result, mode)
		}
	}
	return result
}

func diagnosticDecisive(rule Rule) bool {
	_, terminal := terminalAction(rule.Actions)
	return terminal || len(rule.Transformations) > 0
}

func diagnosticImpossibleReason(rule compiledRule) string {
	match := rule.source.Match
	if diagnosticDirectionMask(match) == 0 {
		return "direction and egress constraints do not intersect"
	}
	if diagnosticIPFamilyMask(rule) == 0 {
		return "IP-version, CIDR, and EtherType families do not intersect"
	}
	if diagnosticPortConstrained(match.SrcPorts) && len(normalizedPortIntervals(match.SrcPorts)) == 0 {
		return "source-port condition excludes every port"
	}
	if diagnosticPortConstrained(match.DstPorts) && len(normalizedPortIntervals(match.DstPorts)) == 0 {
		return "destination-port condition excludes every port"
	}
	if match.TCPFlagMask != 0 && match.TCPFlags&match.TCPFlagMask != 0 &&
		len(match.Protocols) > 0 && !uint8SetContains(match.Protocols, 6) {
		return "TCP flags require TCP protocol 6"
	}
	if diagnosticRequiresHTTP(rule) && len(match.Protocols) > 0 && !uint8SetContains(match.Protocols, 6) {
		return "HTTP conditions require TCP protocol 6"
	}
	if diagnosticRequiresDNS(rule) && len(match.Protocols) > 0 &&
		!uint8SetContains(match.Protocols, 6) && !uint8SetContains(match.Protocols, 17) {
		return "DNS conditions require TCP or UDP"
	}
	if diagnosticRequiresICMP(match) && len(match.Protocols) > 0 &&
		!uint8SetContains(match.Protocols, 1) && !uint8SetContains(match.Protocols, 58) {
		return "ICMP conditions require protocol 1 or 58"
	}
	if diagnosticRequiresEAPOL(match) {
		if diagnosticRequiresIP(rule) {
			return "EAPOL and IP constraints cannot match the same frame"
		}
		if len(match.EtherTypes) > 0 && !uint16SetContains(match.EtherTypes, 0x888e) {
			return "EAPOL types require EtherType 0x888e"
		}
	}
	return ""
}

func diagnosticHasHTTP(match Match) bool {
	return len(match.HTTPMethods) > 0 || len(match.HTTPStatuses) > 0 || len(match.HTTPHosts) > 0 ||
		len(match.HTTPPaths) > 0 || len(match.HTTPHeaders) > 0
}

func diagnosticHasDNS(match Match) bool {
	return len(match.DNSNames) > 0 || len(match.DNSTypes) > 0
}

func diagnosticRequiresHTTP(rule compiledRule) bool {
	match := rule.source.Match
	methodRequired := len(match.HTTPMethods) > 0 && !stringSliceContainsEmpty(match.HTTPMethods)
	if methodRequired || len(match.HTTPStatuses) > 0 || len(match.HTTPHeaders) > 0 {
		return true
	}
	if len(rule.match.httpHosts) > 0 && !matchStringPattern(rule.match.httpHosts, "") {
		return true
	}
	return len(rule.match.httpPaths) > 0 && !matchStringPattern(rule.match.httpPaths, "")
}

func diagnosticRequiresDNS(rule compiledRule) bool {
	typeRequired := len(rule.source.Match.DNSTypes) > 0 && !uint16SetContains(rule.source.Match.DNSTypes, 0)
	return len(rule.match.dnsNames) > 0 || typeRequired
}

func diagnosticRequiresICMP(match Match) bool {
	typeRequired := len(match.ICMPTypes) > 0 && !uint8SetContains(match.ICMPTypes, 0)
	codeRequired := len(match.ICMPCodes) > 0 && !uint8SetContains(match.ICMPCodes, 0)
	return typeRequired || codeRequired
}

func diagnosticRequiresEAPOL(match Match) bool {
	return len(match.EAPOLTypes) > 0 && !uint8SetContains(match.EAPOLTypes, 0)
}

func diagnosticRequiresIP(rule compiledRule) bool {
	match := rule.source.Match
	protocolRequired := len(match.Protocols) > 0 && !uint8SetContains(match.Protocols, 0)
	sourcePortRequired := diagnosticPortConstrained(match.SrcPorts) && !matchPortSet(match.SrcPorts, 0)
	destinationPortRequired := diagnosticPortConstrained(match.DstPorts) && !matchPortSet(match.DstPorts, 0)
	tcpRequired := match.TCPFlagMask != 0 && match.TCPFlags&match.TCPFlagMask != 0
	return len(match.IPVersions) > 0 || len(rule.match.srcCIDRs) > 0 || len(rule.match.dstCIDRs) > 0 ||
		protocolRequired || sourcePortRequired || destinationPortRequired || tcpRequired ||
		diagnosticRequiresICMP(match) || diagnosticRequiresHTTP(rule) || diagnosticRequiresDNS(rule)
}

func diagnosticIPFamilyMask(rule compiledRule) uint8 {
	match := rule.source.Match
	if !diagnosticRequiresIP(rule) {
		return 0b11
	}
	mask := uint8(0b11)
	if len(match.IPVersions) > 0 {
		versions := uint8(0)
		for _, version := range match.IPVersions {
			switch version {
			case 4:
				versions |= 0b01
			case 6:
				versions |= 0b10
			}
		}
		mask &= versions
	}
	for _, prefixes := range [][]netip.Prefix{rule.match.srcCIDRs, rule.match.dstCIDRs} {
		if len(prefixes) == 0 {
			continue
		}
		families := uint8(0)
		for _, prefix := range prefixes {
			if prefix.Addr().Is4() {
				families |= 0b01
			} else {
				families |= 0b10
			}
		}
		mask &= families
	}
	if len(match.EtherTypes) > 0 {
		families := uint8(0)
		if uint16SetContains(match.EtherTypes, 0x0800) {
			families |= 0b01
		}
		if uint16SetContains(match.EtherTypes, 0x86dd) {
			families |= 0b10
		}
		mask &= families
	}
	return mask
}

func diagnosticDirectionMask(match Match) uint8 {
	directions := []traffic.Direction{
		traffic.DirectionOutbound,
		traffic.DirectionInbound,
		traffic.DirectionHostToSwitch,
		traffic.DirectionSwitchToHost,
		traffic.DirectionUnknown,
	}
	var mask uint8
	for index, direction := range directions {
		if containsDirection(match.Directions, direction) && containsSide(match.Egress, frameEgress(direction)) {
			mask |= 1 << index
		}
	}
	return mask
}

func diagnosticExposure(rule Rule) string {
	terminal, ok := terminalAction(rule.Actions)
	if !ok {
		return ""
	}
	match := rule.Match
	sourceBounded := len(match.SrcMAC) > 0 || len(match.SrcCIDRs) > 0
	switch terminal.Kind {
	case ActionAllow:
		directions := diagnosticDirectionMask(match)
		const inboundMask = 1<<1 | 1<<3
		const outboundMask = 1<<0 | 1<<2
		if directions&inboundMask != 0 && !sourceBounded {
			return "allow scope includes inbound traffic from any source identity or CIDR"
		}
		if directions&outboundMask != 0 && !diagnosticDestinationBounded(match) {
			return "allow scope has no outbound destination or service boundary"
		}
	}
	return ""
}

func diagnosticDestinationBounded(match Match) bool {
	return len(match.DstMAC) > 0 || len(match.DstCIDRs) > 0 || len(match.EtherTypes) > 0 || len(match.VLANs) > 0 ||
		len(match.Protocols) > 0 || diagnosticPortConstrained(match.DstPorts) || len(match.EAPOLTypes) > 0 ||
		diagnosticHasDNS(match) || diagnosticHasHTTP(match) || len(match.Payload) > 0
}

func diagnosticMatchContains(outer, inner compiledRule) bool {
	a, b := outer.source.Match, inner.source.Match
	return comparableSetContains(a.Modes, b.Modes) &&
		comparableSetContains(a.Topologies, b.Topologies) &&
		stringSetContains(a.Ingress, b.Ingress) &&
		comparableSetContains(a.Egress, b.Egress) &&
		comparableSetContains(a.Directions, b.Directions) &&
		macSetContains(a.SrcMAC, b.SrcMAC) && macSetContains(a.DstMAC, b.DstMAC) &&
		comparableSetContains(a.EtherTypes, b.EtherTypes) &&
		comparableSetContains(a.VLANs, b.VLANs) &&
		comparableSetContains(a.IPVersions, b.IPVersions) &&
		prefixSetContains(outer.match.srcCIDRs, inner.match.srcCIDRs) &&
		prefixSetContains(outer.match.dstCIDRs, inner.match.dstCIDRs) &&
		comparableSetContains(a.Protocols, b.Protocols) &&
		comparableSetContains(a.DSCP, b.DSCP) && comparableSetContains(a.TTL, b.TTL) &&
		portSetContains(a.SrcPorts, b.SrcPorts) && portSetContains(a.DstPorts, b.DstPorts) &&
		tcpFlagsContain(a.TCPFlagMask, a.TCPFlags, b.TCPFlagMask, b.TCPFlags) &&
		comparableSetContains(a.ICMPTypes, b.ICMPTypes) && comparableSetContains(a.ICMPCodes, b.ICMPCodes) &&
		comparableSetContains(a.EAPOLTypes, b.EAPOLTypes) &&
		patternORContains(outer.match.dnsNames, inner.match.dnsNames) &&
		comparableSetContains(a.DNSTypes, b.DNSTypes) &&
		stringSetContains(a.HTTPMethods, b.HTTPMethods) &&
		comparableSetContains(a.HTTPStatuses, b.HTTPStatuses) &&
		patternORContains(outer.match.httpHosts, inner.match.httpHosts) &&
		patternORContains(outer.match.httpPaths, inner.match.httpPaths) &&
		headerSetContains(outer.match.httpHeader, inner.match.httpHeader) &&
		patternANDContains(outer.match.payload, inner.match.payload)
}

func diagnosticMatchesOverlap(left, right compiledRule) bool {
	a, b := left.source.Match, right.source.Match
	return comparableSetsOverlap(a.Modes, b.Modes) &&
		comparableSetsOverlap(a.Topologies, b.Topologies) &&
		stringSetsOverlap(a.Ingress, b.Ingress) &&
		comparableSetsOverlap(a.EtherTypes, b.EtherTypes) &&
		macSetsOverlap(a.SrcMAC, b.SrcMAC) && macSetsOverlap(a.DstMAC, b.DstMAC) &&
		comparableSetsOverlap(a.IPVersions, b.IPVersions) &&
		prefixSetsOverlap(left.match.srcCIDRs, right.match.srcCIDRs) &&
		prefixSetsOverlap(left.match.dstCIDRs, right.match.dstCIDRs) &&
		comparableSetsOverlap(a.Protocols, b.Protocols) &&
		comparableSetsOverlap(a.DSCP, b.DSCP) && comparableSetsOverlap(a.TTL, b.TTL) &&
		portSetsOverlap(a.SrcPorts, b.SrcPorts) && portSetsOverlap(a.DstPorts, b.DstPorts) &&
		tcpFlagsOverlap(a.TCPFlagMask, a.TCPFlags, b.TCPFlagMask, b.TCPFlags) &&
		comparableSetsOverlap(a.ICMPTypes, b.ICMPTypes) && comparableSetsOverlap(a.ICMPCodes, b.ICMPCodes) &&
		comparableSetsOverlap(a.EAPOLTypes, b.EAPOLTypes) &&
		comparableSetsOverlap(a.DNSTypes, b.DNSTypes) &&
		stringSetsOverlap(a.HTTPMethods, b.HTTPMethods) &&
		comparableSetsOverlap(a.HTTPStatuses, b.HTTPStatuses) &&
		diagnosticDirectionMask(a)&diagnosticDirectionMask(b) != 0 &&
		diagnosticIPFamilyMask(left)&diagnosticIPFamilyMask(right) != 0
}

func diagnosticSpecificity(match Match) int {
	count := 0
	for _, constrained := range []bool{
		len(match.Topologies) > 0, len(match.Ingress) > 0, len(match.Egress) > 0,
		len(match.Directions) > 0, len(match.SrcMAC) > 0, len(match.DstMAC) > 0,
		len(match.EtherTypes) > 0, len(match.VLANs) > 0, len(match.IPVersions) > 0,
		len(match.SrcCIDRs) > 0, len(match.DstCIDRs) > 0, len(match.Protocols) > 0,
		len(match.DSCP) > 0, len(match.TTL) > 0, diagnosticPortConstrained(match.SrcPorts),
		diagnosticPortConstrained(match.DstPorts), match.TCPFlagMask != 0,
		len(match.ICMPTypes) > 0, len(match.ICMPCodes) > 0, len(match.EAPOLTypes) > 0,
		len(match.DNSNames) > 0, len(match.DNSTypes) > 0, len(match.HTTPMethods) > 0,
		len(match.HTTPStatuses) > 0, len(match.HTTPHosts) > 0, len(match.HTTPPaths) > 0,
		len(match.HTTPHeaders) > 0,
		len(match.Payload) > 0,
	} {
		if constrained {
			count++
		}
	}
	return count
}

type diagnosticCandidateIndex struct {
	count         int
	ingressAny    []int
	ingress       map[string][]int
	topologyAny   []int
	topology      map[traffic.TopologySide][]int
	egressAny     []int
	egress        map[traffic.TopologySide][]int
	directionAny  []int
	direction     map[traffic.Direction][]int
	sourceMACAny  []int
	sourceMAC     map[string][]int
	destMACAny    []int
	destMAC       map[string][]int
	etherTypeAny  []int
	etherType     map[uint16][]int
	ipVersionAny  []int
	ipVersion     map[uint8][]int
	protocolAny   []int
	protocol      map[uint8][]int
	sourcePortAny []int
	sourcePort    map[uint16][]int
	destPortAny   []int
	destPort      map[uint16][]int
}

func newDiagnosticCandidateIndex() *diagnosticCandidateIndex {
	return &diagnosticCandidateIndex{
		ingress: make(map[string][]int), topology: make(map[traffic.TopologySide][]int),
		egress: make(map[traffic.TopologySide][]int), direction: make(map[traffic.Direction][]int),
		sourceMAC: make(map[string][]int), destMAC: make(map[string][]int),
		etherType: make(map[uint16][]int), ipVersion: make(map[uint8][]int),
		protocol: make(map[uint8][]int), sourcePort: make(map[uint16][]int), destPort: make(map[uint16][]int),
	}
}

func (i *diagnosticCandidateIndex) add(index int, match Match) {
	addDiagnosticDimension(index, normalizedDiagnosticStrings(match.Ingress), &i.ingressAny, i.ingress)
	addDiagnosticDimension(index, match.Topologies, &i.topologyAny, i.topology)
	addDiagnosticDimension(index, match.Egress, &i.egressAny, i.egress)
	addDiagnosticDimension(index, match.Directions, &i.directionAny, i.direction)
	addDiagnosticDimension(index, normalizedDiagnosticMACs(match.SrcMAC), &i.sourceMACAny, i.sourceMAC)
	addDiagnosticDimension(index, normalizedDiagnosticMACs(match.DstMAC), &i.destMACAny, i.destMAC)
	addDiagnosticDimension(index, match.EtherTypes, &i.etherTypeAny, i.etherType)
	addDiagnosticDimension(index, match.IPVersions, &i.ipVersionAny, i.ipVersion)
	addDiagnosticDimension(index, match.Protocols, &i.protocolAny, i.protocol)
	if values, exact := diagnosticExactPorts(match.SrcPorts); exact {
		addDiagnosticDimension(index, values, &i.sourcePortAny, i.sourcePort)
	} else {
		i.sourcePortAny = append(i.sourcePortAny, index)
	}
	if values, exact := diagnosticExactPorts(match.DstPorts); exact {
		addDiagnosticDimension(index, values, &i.destPortAny, i.destPort)
	} else {
		i.destPortAny = append(i.destPortAny, index)
	}
	i.count++
}

func (i *diagnosticCandidateIndex) candidates(match Match) ([]int, bool) {
	var best diagnosticCandidateOption
	hasBest := false
	consider := func(option diagnosticCandidateOption, constrained bool) {
		if !constrained || hasBest && option.estimate >= best.estimate {
			return
		}
		best = option
		hasBest = true
	}
	consider(newDiagnosticCandidateOption(i.ingressAny, i.ingress, normalizedDiagnosticStrings(match.Ingress)))
	consider(newDiagnosticCandidateOption(i.topologyAny, i.topology, match.Topologies))
	consider(newDiagnosticCandidateOption(i.egressAny, i.egress, match.Egress))
	consider(newDiagnosticCandidateOption(i.directionAny, i.direction, match.Directions))
	consider(newDiagnosticCandidateOption(i.sourceMACAny, i.sourceMAC, normalizedDiagnosticMACs(match.SrcMAC)))
	consider(newDiagnosticCandidateOption(i.destMACAny, i.destMAC, normalizedDiagnosticMACs(match.DstMAC)))
	consider(newDiagnosticCandidateOption(i.etherTypeAny, i.etherType, match.EtherTypes))
	consider(newDiagnosticCandidateOption(i.ipVersionAny, i.ipVersion, match.IPVersions))
	consider(newDiagnosticCandidateOption(i.protocolAny, i.protocol, match.Protocols))
	if values, exact := diagnosticExactPorts(match.SrcPorts); exact {
		consider(newDiagnosticCandidateOption(i.sourcePortAny, i.sourcePort, values))
	}
	if values, exact := diagnosticExactPorts(match.DstPorts); exact {
		consider(newDiagnosticCandidateOption(i.destPortAny, i.destPort, values))
	}
	if !hasBest || best.estimate >= i.count {
		return nil, false
	}
	return best.indices(), true
}

type diagnosticCandidateOption struct {
	lists    [][]int
	estimate int
}

func newDiagnosticCandidateOption[T comparable](wildcard []int, buckets map[T][]int, values []T) (diagnosticCandidateOption, bool) {
	if len(values) == 0 {
		return diagnosticCandidateOption{}, false
	}
	option := diagnosticCandidateOption{lists: make([][]int, 0, len(values)+1), estimate: len(wildcard)}
	if len(wildcard) > 0 {
		option.lists = append(option.lists, wildcard)
	}
	seen := make(map[T]bool, len(values))
	for _, value := range values {
		if seen[value] {
			continue
		}
		seen[value] = true
		bucket := buckets[value]
		option.estimate += len(bucket)
		if len(bucket) > 0 {
			option.lists = append(option.lists, bucket)
		}
	}
	return option, true
}

func (o diagnosticCandidateOption) indices() []int {
	if len(o.lists) == 0 {
		return nil
	}
	if len(o.lists) == 1 {
		return o.lists[0]
	}
	seen := make(map[int]bool, o.estimate)
	result := make([]int, 0, o.estimate)
	for _, list := range o.lists {
		for _, index := range list {
			if seen[index] {
				continue
			}
			seen[index] = true
			result = append(result, index)
		}
	}
	sort.Ints(result)
	return result
}

func addDiagnosticDimension[T comparable](index int, values []T, wildcard *[]int, buckets map[T][]int) {
	if len(values) == 0 {
		*wildcard = append(*wildcard, index)
		return
	}
	seen := make(map[T]bool, len(values))
	for _, value := range values {
		if seen[value] {
			continue
		}
		seen[value] = true
		buckets[value] = append(buckets[value], index)
	}
}

func normalizedDiagnosticStrings(values []string) []string {
	result := make([]string, len(values))
	for index, value := range values {
		result[index] = strings.ToLower(strings.TrimSpace(value))
	}
	return result
}

func normalizedDiagnosticMACs(values []string) []string {
	result := make([]string, len(values))
	for index, value := range values {
		result[index] = diagnosticMAC(value)
	}
	return result
}

func diagnosticExactPorts(set PortSet) ([]uint16, bool) {
	if set.Negate || len(set.Ranges) > 0 || len(set.Values) == 0 {
		return nil, false
	}
	return set.Values, true
}

func comparableSetContains[T comparable](outer, inner []T) bool {
	if len(outer) == 0 {
		return true
	}
	if len(inner) == 0 {
		return false
	}
	for _, candidate := range inner {
		found := false
		for _, allowed := range outer {
			if candidate == allowed {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

func comparableSetsOverlap[T comparable](left, right []T) bool {
	if len(left) == 0 || len(right) == 0 {
		return true
	}
	for _, a := range left {
		for _, b := range right {
			if a == b {
				return true
			}
		}
	}
	return false
}

func stringSetContains(outer, inner []string) bool {
	if len(outer) == 0 {
		return true
	}
	if len(inner) == 0 {
		return false
	}
	for _, candidate := range inner {
		found := false
		for _, allowed := range outer {
			if strings.EqualFold(strings.TrimSpace(candidate), strings.TrimSpace(allowed)) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

func stringSetsOverlap(left, right []string) bool {
	if len(left) == 0 || len(right) == 0 {
		return true
	}
	for _, a := range left {
		for _, b := range right {
			if strings.EqualFold(strings.TrimSpace(a), strings.TrimSpace(b)) {
				return true
			}
		}
	}
	return false
}

func macSetContains(outer, inner []string) bool {
	if len(outer) == 0 {
		return true
	}
	if len(inner) == 0 {
		return false
	}
	allowed := make(map[string]bool, len(outer))
	for _, value := range outer {
		allowed[diagnosticMAC(value)] = true
	}
	for _, value := range inner {
		if !allowed[diagnosticMAC(value)] {
			return false
		}
	}
	return true
}

func macSetsOverlap(left, right []string) bool {
	if len(left) == 0 || len(right) == 0 {
		return true
	}
	values := make(map[string]bool, len(left))
	for _, value := range left {
		values[diagnosticMAC(value)] = true
	}
	for _, value := range right {
		if values[diagnosticMAC(value)] {
			return true
		}
	}
	return false
}

func diagnosticMAC(value string) string {
	parsed, err := net.ParseMAC(strings.TrimSpace(value))
	if err != nil {
		return strings.ToLower(strings.TrimSpace(value))
	}
	return parsed.String()
}

func prefixSetContains(outer, inner []netip.Prefix) bool {
	if len(outer) == 0 {
		return true
	}
	if len(inner) == 0 {
		return false
	}
	for _, candidate := range inner {
		found := false
		for _, allowed := range outer {
			if allowed.Bits() <= candidate.Bits() && allowed.Contains(candidate.Addr()) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

func prefixSetsOverlap(left, right []netip.Prefix) bool {
	if len(left) == 0 || len(right) == 0 {
		return true
	}
	for _, a := range left {
		for _, b := range right {
			if a.Contains(b.Addr()) || b.Contains(a.Addr()) {
				return true
			}
		}
	}
	return false
}

type portInterval struct {
	first uint16
	last  uint16
}

func diagnosticPortConstrained(set PortSet) bool {
	return len(set.Values) > 0 || len(set.Ranges) > 0
}

func normalizedPortIntervals(set PortSet) []portInterval {
	if !diagnosticPortConstrained(set) {
		return []portInterval{{first: 0, last: 65535}}
	}
	intervals := make([]portInterval, 0, len(set.Values)+len(set.Ranges))
	for _, value := range set.Values {
		intervals = append(intervals, portInterval{first: value, last: value})
	}
	for _, value := range set.Ranges {
		intervals = append(intervals, portInterval{first: value.First, last: value.Last})
	}
	sort.Slice(intervals, func(i, j int) bool {
		if intervals[i].first == intervals[j].first {
			return intervals[i].last < intervals[j].last
		}
		return intervals[i].first < intervals[j].first
	})
	merged := intervals[:0]
	for _, current := range intervals {
		if len(merged) == 0 || uint32(current.first) > uint32(merged[len(merged)-1].last)+1 {
			merged = append(merged, current)
			continue
		}
		if current.last > merged[len(merged)-1].last {
			merged[len(merged)-1].last = current.last
		}
	}
	if !set.Negate {
		return merged
	}
	complement := make([]portInterval, 0, len(merged)+1)
	next := uint32(0)
	for _, excluded := range merged {
		if next < uint32(excluded.first) {
			complement = append(complement, portInterval{first: uint16(next), last: excluded.first - 1})
		}
		next = uint32(excluded.last) + 1
	}
	if next <= 65535 {
		complement = append(complement, portInterval{first: uint16(next), last: 65535})
	}
	return complement
}

func portSetContains(outer, inner PortSet) bool {
	a, b := normalizedPortIntervals(outer), normalizedPortIntervals(inner)
	for _, candidate := range b {
		covered := false
		for _, allowed := range a {
			if allowed.first <= candidate.first && allowed.last >= candidate.last {
				covered = true
				break
			}
		}
		if !covered {
			return false
		}
	}
	return true
}

func portSetsOverlap(left, right PortSet) bool {
	for _, a := range normalizedPortIntervals(left) {
		for _, b := range normalizedPortIntervals(right) {
			if a.first <= b.last && b.first <= a.last {
				return true
			}
		}
	}
	return false
}

func tcpFlagsContain(outerMask, outerValue, innerMask, innerValue traffic.TCPFlags) bool {
	return outerMask&innerMask == outerMask && outerValue&outerMask == innerValue&outerMask
}

func tcpFlagsOverlap(leftMask, leftValue, rightMask, rightValue traffic.TCPFlags) bool {
	shared := leftMask & rightMask
	return leftValue&shared == rightValue&shared
}

func patternORContains(outer, inner []compiledPattern) bool {
	if len(outer) == 0 {
		return true
	}
	if len(inner) == 0 {
		return false
	}
	for _, candidate := range inner {
		implied := false
		for _, required := range outer {
			if patternContains(required, candidate) {
				implied = true
				break
			}
		}
		if !implied {
			return false
		}
	}
	return true
}

func patternANDContains(outer, inner []compiledPattern) bool {
	if len(outer) == 0 {
		return true
	}
	if len(inner) == 0 {
		return false
	}
	for _, required := range outer {
		implied := false
		for _, candidate := range inner {
			if patternContains(required, candidate) {
				implied = true
				break
			}
		}
		if !implied {
			return false
		}
	}
	return true
}

func patternContains(outer, inner compiledPattern) bool {
	if outer.kind == PatternLiteral && inner.kind == PatternLiteral {
		return bytes.Contains(inner.literal, outer.literal)
	}
	if outer.kind != inner.kind {
		return false
	}
	switch outer.kind {
	case PatternRE2:
		return outer.re2.String() == inner.re2.String()
	case PatternMasked:
		return bytes.Equal(outer.value, inner.value) && bytes.Equal(outer.mask, inner.mask)
	default:
		return false
	}
}

func headerSetContains(outer, inner []compiledHeader) bool {
	if len(outer) == 0 {
		return true
	}
	if len(inner) == 0 {
		return false
	}
	for _, required := range outer {
		implied := false
		for _, candidate := range inner {
			if strings.EqualFold(required.name, candidate.name) && patternContains(required.pattern, candidate.pattern) {
				implied = true
				break
			}
		}
		if !implied {
			return false
		}
	}
	return true
}

func uint8SetContains(values []uint8, candidate uint8) bool {
	for _, value := range values {
		if value == candidate {
			return true
		}
	}
	return false
}

func uint16SetContains(values []uint16, candidate uint16) bool {
	for _, value := range values {
		if value == candidate {
			return true
		}
	}
	return false
}

func stringSliceContainsEmpty(values []string) bool {
	for _, value := range values {
		if strings.TrimSpace(value) == "" {
			return true
		}
	}
	return false
}
