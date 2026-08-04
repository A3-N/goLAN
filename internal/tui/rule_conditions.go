package tui

import (
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"

	"golan/internal/dataplane"
	"golan/internal/policy"
	"golan/internal/traffic"
)

type guidedConditionKind string

const (
	conditionDirection  guidedConditionKind = "direction"
	conditionProtocol   guidedConditionKind = "protocol"
	conditionDstPort    guidedConditionKind = "destination-port"
	conditionSrcPort    guidedConditionKind = "source-port"
	conditionSrcCIDR    guidedConditionKind = "source-cidr"
	conditionDstCIDR    guidedConditionKind = "destination-cidr"
	conditionSrcMAC     guidedConditionKind = "source-mac"
	conditionDstMAC     guidedConditionKind = "destination-mac"
	conditionVLAN       guidedConditionKind = "vlan"
	conditionEtherType  guidedConditionKind = "ether-type"
	conditionIPVersion  guidedConditionKind = "ip-version"
	conditionDSCP       guidedConditionKind = "dscp"
	conditionTTL        guidedConditionKind = "ttl"
	conditionTCPFlags   guidedConditionKind = "tcp-flags"
	conditionICMPType   guidedConditionKind = "icmp-type"
	conditionICMPCode   guidedConditionKind = "icmp-code"
	conditionEAPOLType  guidedConditionKind = "eapol-type"
	conditionDNSName    guidedConditionKind = "dns-name"
	conditionDNSType    guidedConditionKind = "dns-type"
	conditionHTTPMethod guidedConditionKind = "http-method"
	conditionHTTPStatus guidedConditionKind = "http-status"
	conditionHTTPHost   guidedConditionKind = "http-host"
	conditionHTTPPath   guidedConditionKind = "http-path"
	conditionHTTPHeader guidedConditionKind = "http-header"
	conditionPayload    guidedConditionKind = "payload"
	conditionMode       guidedConditionKind = "mode"
	conditionTopology   guidedConditionKind = "topology"
	conditionIngress    guidedConditionKind = "ingress"
	conditionEgress     guidedConditionKind = "egress"
)

type guidedCondition struct {
	Kind   guidedConditionKind
	Value  string
	Negate bool
}

type guidedConditionSpec struct {
	Kind      guidedConditionKind
	Label     string
	Default   string
	Options   []string
	Negatable bool
}

var guidedConditionSpecs = []guidedConditionSpec{
	{Kind: conditionDirection, Label: "Direction", Default: "outbound", Options: []string{"outbound", "inbound", "host-to-switch", "switch-to-host"}},
	{Kind: conditionProtocol, Label: "Protocol", Default: "tcp", Options: []string{"tcp", "udp", "icmp", "icmpv6"}},
	{Kind: conditionDstPort, Label: "Destination port", Default: "80,443", Negatable: true},
	{Kind: conditionSrcPort, Label: "Source port", Default: "1024-65535", Negatable: true},
	{Kind: conditionSrcCIDR, Label: "Source CIDR", Default: "10.0.0.0/8"},
	{Kind: conditionDstCIDR, Label: "Destination CIDR", Default: "0.0.0.0/0"},
	{Kind: conditionSrcMAC, Label: "Source MAC", Default: "02:00:00:00:00:01"},
	{Kind: conditionDstMAC, Label: "Destination MAC", Default: "ff:ff:ff:ff:ff:ff"},
	{Kind: conditionVLAN, Label: "VLAN ID", Default: "1"},
	{Kind: conditionEtherType, Label: "EtherType", Default: "0x0800"},
	{Kind: conditionIPVersion, Label: "IP version", Default: "4", Options: []string{"4", "6"}},
	{Kind: conditionDSCP, Label: "DSCP", Default: "0"},
	{Kind: conditionTTL, Label: "TTL/hop limit", Default: "64"},
	{Kind: conditionTCPFlags, Label: "TCP flags set", Default: "syn"},
	{Kind: conditionICMPType, Label: "ICMP type", Default: "8"},
	{Kind: conditionICMPCode, Label: "ICMP code", Default: "0"},
	{Kind: conditionEAPOLType, Label: "EAPOL type", Default: "1"},
	{Kind: conditionDNSName, Label: "DNS name literal", Default: "example.test"},
	{Kind: conditionDNSType, Label: "DNS type", Default: "1"},
	{Kind: conditionHTTPMethod, Label: "HTTP method", Default: "GET"},
	{Kind: conditionHTTPStatus, Label: "HTTP response status", Default: "200"},
	{Kind: conditionHTTPHost, Label: "HTTP host literal", Default: "example.test"},
	{Kind: conditionHTTPPath, Label: "HTTP path literal", Default: "/"},
	{Kind: conditionHTTPHeader, Label: "HTTP header", Default: "content-type=text/plain"},
	{Kind: conditionPayload, Label: "Payload literal", Default: "text"},
	{Kind: conditionMode, Label: "Mode", Default: string(dataplane.ModeControlledBridge), Options: guidedModeOptions()},
	{Kind: conditionTopology, Label: "Topology side", Default: string(traffic.SideHost), Options: topologyOptions()},
	{Kind: conditionIngress, Label: "Ingress adapter", Default: "en0"},
	{Kind: conditionEgress, Label: "Egress side", Default: string(traffic.SideSwitch), Options: topologyOptions()},
}

type conditionCursor struct {
	Index int
}

type conditionField uint8

const (
	conditionKindField conditionField = iota
	conditionValueField
)

func defaultGuidedConditions() []guidedCondition {
	return []guidedCondition{
		newGuidedCondition(conditionDirection),
		newGuidedCondition(conditionProtocol),
		newGuidedCondition(conditionDstPort),
	}
}

func newGuidedCondition(kind guidedConditionKind) guidedCondition {
	spec := guidedConditionSpecFor(kind)
	return guidedCondition{Kind: spec.Kind, Value: spec.Default}
}

func guidedConditionSpecFor(kind guidedConditionKind) guidedConditionSpec {
	for _, spec := range guidedConditionSpecs {
		if spec.Kind == kind {
			return spec
		}
	}
	return guidedConditionSpecs[0]
}

func guidedModeOptions() []string {
	return []string{
		string(dataplane.ModeListen), string(dataplane.ModeFastBridge), string(dataplane.ModeControlledBridge),
		string(dataplane.ModeNAT), string(dataplane.ModeEdgeObserve), string(dataplane.ModeEdgeRoute),
	}
}

func topologyOptions() []string {
	return []string{
		string(traffic.SideUnknown), string(traffic.SideHost), string(traffic.SideSwitch), string(traffic.SideLocal),
		string(traffic.SideUpstream), string(traffic.SideDownstream),
	}
}

func (e ruleEditorState) conditionAtCursor(cursor int) (conditionCursor, conditionField, bool) {
	if e.replace || cursor < 2 || cursor >= e.fieldCount()-1 {
		return conditionCursor{}, 0, false
	}
	relative := cursor - 2
	index := relative / 2
	if index < 0 || index >= len(e.draft.conditions) {
		return conditionCursor{}, 0, false
	}
	return conditionCursor{Index: index}, conditionField(relative % 2), true
}

func (e *ruleEditorState) addCondition() bool {
	used := make(map[guidedConditionKind]bool, len(e.draft.conditions))
	for _, condition := range e.draft.conditions {
		used[condition.Kind] = true
	}
	var kind guidedConditionKind
	for _, spec := range guidedConditionSpecs {
		if !used[spec.Kind] {
			kind = spec.Kind
			break
		}
	}
	if kind == "" {
		return false
	}
	insert := len(e.draft.conditions)
	if condition, _, ok := e.conditionAtCursor(e.cursor); ok {
		insert = condition.Index + 1
	}
	e.draft.conditions = append(e.draft.conditions, guidedCondition{})
	copy(e.draft.conditions[insert+1:], e.draft.conditions[insert:])
	e.draft.conditions[insert] = newGuidedCondition(kind)
	e.cursor = 2 + insert*2
	return true
}

func (e *ruleEditorState) removeCondition() bool {
	condition, _, ok := e.conditionAtCursor(e.cursor)
	if !ok {
		return false
	}
	e.draft.conditions = append(e.draft.conditions[:condition.Index], e.draft.conditions[condition.Index+1:]...)
	if len(e.draft.conditions) == 0 {
		e.cursor = min(e.cursor, e.fieldCount()-1)
		return true
	}
	index := min(condition.Index, len(e.draft.conditions)-1)
	e.cursor = 2 + index*2
	return true
}

func (e *ruleEditorState) reorderCondition(delta int) bool {
	condition, part, ok := e.conditionAtCursor(e.cursor)
	if !ok {
		return false
	}
	next := condition.Index + delta
	if next < 0 || next >= len(e.draft.conditions) {
		return false
	}
	e.draft.conditions[condition.Index], e.draft.conditions[next] = e.draft.conditions[next], e.draft.conditions[condition.Index]
	e.cursor = 2 + next*2 + int(part)
	return true
}

func (e *ruleEditorState) toggleConditionNegation() bool {
	condition, _, ok := e.conditionAtCursor(e.cursor)
	if !ok || !guidedConditionSpecFor(e.draft.conditions[condition.Index].Kind).Negatable {
		return false
	}
	e.draft.conditions[condition.Index].Negate = !e.draft.conditions[condition.Index].Negate
	return true
}

func (e *ruleEditorState) cycleConditionKind(index, delta int) {
	if index < 0 || index >= len(e.draft.conditions) {
		return
	}
	used := make(map[guidedConditionKind]bool, len(e.draft.conditions)-1)
	for other, condition := range e.draft.conditions {
		if other != index {
			used[condition.Kind] = true
		}
	}
	current := 0
	for i, spec := range guidedConditionSpecs {
		if spec.Kind == e.draft.conditions[index].Kind {
			current = i
			break
		}
	}
	for offset := 1; offset <= len(guidedConditionSpecs); offset++ {
		next := (current + delta*offset + len(guidedConditionSpecs)*offset) % len(guidedConditionSpecs)
		kind := guidedConditionSpecs[next].Kind
		if !used[kind] {
			e.draft.conditions[index] = newGuidedCondition(kind)
			return
		}
	}
}

func (d guidedRuleDraft) policyMatch(replace bool) (policy.Match, error) {
	if replace {
		return d.legacyReplacementMatch()
	}
	var match policy.Match
	seen := make(map[guidedConditionKind]bool, len(d.conditions))
	for index, condition := range d.conditions {
		if seen[condition.Kind] {
			return policy.Match{}, fmt.Errorf("condition %d duplicates %s", index+1, guidedConditionSpecFor(condition.Kind).Label)
		}
		seen[condition.Kind] = true
		if err := applyGuidedCondition(&match, condition); err != nil {
			return policy.Match{}, fmt.Errorf("condition %d (%s): %w", index+1, guidedConditionSpecFor(condition.Kind).Label, err)
		}
	}
	return match, nil
}

func (d guidedRuleDraft) legacyReplacementMatch() (policy.Match, error) {
	var match policy.Match
	switch d.direction {
	case "outbound":
		match.Directions = []traffic.Direction{traffic.DirectionOutbound}
	case "inbound":
		match.Directions = []traffic.Direction{traffic.DirectionInbound}
	case "host-to-switch":
		match.Directions = []traffic.Direction{traffic.DirectionHostToSwitch}
	case "switch-to-host":
		match.Directions = []traffic.Direction{traffic.DirectionSwitchToHost}
	case "any":
	default:
		return policy.Match{}, fmt.Errorf("direction is invalid")
	}
	switch d.protocol {
	case "tcp":
		match.Protocols = []uint8{6}
	case "udp":
		match.Protocols = []uint8{17}
	case "icmp":
		match.Protocols = []uint8{1}
	case "icmpv6":
		match.Protocols = []uint8{58}
	case "any":
	default:
		return policy.Match{}, fmt.Errorf("protocol is invalid")
	}
	if portsValue := strings.TrimSpace(d.ports); portsValue != "" && !strings.EqualFold(portsValue, "any") {
		ports, err := parseGuidedPorts(portsValue)
		if err != nil {
			return policy.Match{}, fmt.Errorf("destination port: %w", err)
		}
		ports.Negate = d.negate
		match.DstPorts = ports
	}
	return match, nil
}

func applyGuidedCondition(match *policy.Match, condition guidedCondition) error {
	value := strings.TrimSpace(condition.Value)
	if value == "" {
		return fmt.Errorf("value is required")
	}
	if condition.Negate && !guidedConditionSpecFor(condition.Kind).Negatable {
		return fmt.Errorf("negation is not supported")
	}
	switch condition.Kind {
	case conditionDirection:
		values, err := parseDirections(value)
		match.Directions = values
		return err
	case conditionProtocol:
		values, err := parseProtocols(value)
		match.Protocols = values
		return err
	case conditionDstPort, conditionSrcPort:
		ports, err := parseGuidedPorts(value)
		if err != nil {
			return err
		}
		ports.Negate = condition.Negate
		if condition.Kind == conditionDstPort {
			match.DstPorts = ports
		} else {
			match.SrcPorts = ports
		}
		return nil
	case conditionSrcCIDR, conditionDstCIDR:
		values, err := parseCIDRs(value)
		if condition.Kind == conditionSrcCIDR {
			match.SrcCIDRs = values
		} else {
			match.DstCIDRs = values
		}
		return err
	case conditionSrcMAC, conditionDstMAC:
		values, err := parseMACs(value)
		if condition.Kind == conditionSrcMAC {
			match.SrcMAC = values
		} else {
			match.DstMAC = values
		}
		return err
	case conditionVLAN:
		values, err := parseUint16List(value, 0, 4094, "VLAN ID")
		match.VLANs = values
		return err
	case conditionEtherType:
		values, err := parseUint16List(value, 1, 65535, "EtherType")
		match.EtherTypes = values
		return err
	case conditionIPVersion:
		values, err := parseUint8List(value, 4, 6, "IP version")
		if err == nil {
			for _, version := range values {
				if version != 4 && version != 6 {
					return fmt.Errorf("IP version %d is not 4 or 6", version)
				}
			}
		}
		match.IPVersions = values
		return err
	case conditionDSCP:
		values, err := parseUint8List(value, 0, 63, "DSCP")
		match.DSCP = values
		return err
	case conditionTTL:
		values, err := parseUint8List(value, 1, 255, "TTL")
		match.TTL = values
		return err
	case conditionTCPFlags:
		flags, err := parseTCPFlags(value)
		match.TCPFlagMask = flags
		match.TCPFlags = flags
		return err
	case conditionICMPType, conditionICMPCode, conditionEAPOLType:
		values, err := parseUint8List(value, 0, 255, guidedConditionSpecFor(condition.Kind).Label)
		switch condition.Kind {
		case conditionICMPType:
			match.ICMPTypes = values
		case conditionICMPCode:
			match.ICMPCodes = values
		case conditionEAPOLType:
			match.EAPOLTypes = values
		}
		return err
	case conditionDNSName:
		match.DNSNames = literalPatterns(splitList(value))
	case conditionDNSType:
		values, err := parseUint16List(value, 1, 65535, "DNS type")
		match.DNSTypes = values
		return err
	case conditionHTTPMethod:
		match.HTTPMethods = uppercaseList(splitList(value))
	case conditionHTTPStatus:
		values, err := parseUint16List(value, 100, 599, "HTTP response status")
		match.HTTPStatuses = values
		return err
	case conditionHTTPHost:
		match.HTTPHosts = literalPatterns(splitList(value))
	case conditionHTTPPath:
		match.HTTPPaths = literalPatterns(splitList(value))
	case conditionHTTPHeader:
		headers, err := parseHTTPHeaders(value)
		match.HTTPHeaders = headers
		return err
	case conditionPayload:
		match.Payload = []policy.BytePattern{{Kind: policy.PatternLiteral, Value: condition.Value}}
	case conditionMode:
		values, err := parseModes(value)
		match.Modes = values
		return err
	case conditionTopology, conditionEgress:
		values, err := parseTopologySides(value)
		if condition.Kind == conditionTopology {
			match.Topologies = values
		} else {
			match.Egress = values
		}
		return err
	case conditionIngress:
		match.Ingress = splitList(value)
	default:
		return fmt.Errorf("unknown condition type %q", condition.Kind)
	}
	return nil
}

func parseGuidedPorts(value string) (policy.PortSet, error) {
	var result policy.PortSet
	for _, item := range splitList(value) {
		parts := strings.Split(item, "-")
		if len(parts) > 2 {
			return policy.PortSet{}, fmt.Errorf("port %q is invalid", item)
		}
		first, err := strconv.ParseUint(strings.TrimSpace(parts[0]), 10, 16)
		if err != nil || first == 0 {
			return policy.PortSet{}, fmt.Errorf("port %q is invalid", item)
		}
		if len(parts) == 1 {
			result.Values = append(result.Values, uint16(first))
			continue
		}
		last, err := strconv.ParseUint(strings.TrimSpace(parts[1]), 10, 16)
		if err != nil || last < first || last > 65535 {
			return policy.PortSet{}, fmt.Errorf("port range %q is invalid", item)
		}
		result.Ranges = append(result.Ranges, policy.PortRange{First: uint16(first), Last: uint16(last)})
	}
	return result, nil
}

func splitList(value string) []string {
	items := strings.Split(value, ",")
	result := make([]string, 0, len(items))
	for _, item := range items {
		if item = strings.TrimSpace(item); item != "" {
			result = append(result, item)
		}
	}
	return result
}

func parseUint8List(value string, minimum, maximum uint64, label string) ([]uint8, error) {
	return parseUnsignedList[uint8](value, minimum, maximum, 8, label)
}

func parseUint16List(value string, minimum, maximum uint64, label string) ([]uint16, error) {
	return parseUnsignedList[uint16](value, minimum, maximum, 16, label)
}

func parseUnsignedList[T uint8 | uint16](value string, minimum, maximum uint64, bitSize int, label string) ([]T, error) {
	items := splitList(value)
	result := make([]T, 0, len(items))
	for _, item := range items {
		parsed, err := strconv.ParseUint(item, 0, bitSize)
		if err != nil || parsed < minimum || parsed > maximum {
			return nil, fmt.Errorf("%s %q is outside %d-%d", label, item, minimum, maximum)
		}
		result = append(result, T(parsed))
	}
	return result, nil
}

func parseDirections(value string) ([]traffic.Direction, error) {
	valid := map[string]traffic.Direction{
		"outbound": traffic.DirectionOutbound, "inbound": traffic.DirectionInbound,
		"host-to-switch": traffic.DirectionHostToSwitch, "switch-to-host": traffic.DirectionSwitchToHost,
	}
	result := make([]traffic.Direction, 0, 1)
	for _, item := range splitList(strings.ToLower(value)) {
		direction, ok := valid[item]
		if !ok {
			return nil, fmt.Errorf("direction %q is invalid", item)
		}
		result = append(result, direction)
	}
	return result, nil
}

func parseProtocols(value string) ([]uint8, error) {
	known := map[string]uint8{"icmp": 1, "tcp": 6, "udp": 17, "icmpv6": 58}
	result := make([]uint8, 0, 1)
	for _, item := range splitList(strings.ToLower(value)) {
		if protocol, ok := known[item]; ok {
			result = append(result, protocol)
			continue
		}
		parsed, err := strconv.ParseUint(item, 0, 8)
		if err != nil {
			return nil, fmt.Errorf("protocol %q is invalid", item)
		}
		result = append(result, uint8(parsed))
	}
	return result, nil
}

func parseCIDRs(value string) ([]string, error) {
	items := splitList(value)
	for index, item := range items {
		prefix, err := netip.ParsePrefix(item)
		if err != nil {
			return nil, fmt.Errorf("CIDR %q is invalid", item)
		}
		items[index] = prefix.Masked().String()
	}
	return items, nil
}

func parseMACs(value string) ([]string, error) {
	items := splitList(value)
	for index, item := range items {
		mac, err := net.ParseMAC(item)
		if err != nil || len(mac) != 6 {
			return nil, fmt.Errorf("MAC %q is invalid", item)
		}
		items[index] = mac.String()
	}
	return items, nil
}

func parseTCPFlags(value string) (traffic.TCPFlags, error) {
	known := map[string]traffic.TCPFlags{
		"fin": 0x001, "syn": 0x002, "rst": 0x004, "psh": 0x008, "ack": 0x010,
		"urg": 0x020, "ece": 0x040, "cwr": 0x080, "ns": 0x100,
	}
	var flags traffic.TCPFlags
	for _, item := range splitList(strings.ToLower(value)) {
		flag, ok := known[item]
		if !ok {
			return 0, fmt.Errorf("TCP flag %q is invalid", item)
		}
		flags |= flag
	}
	return flags, nil
}

func literalPatterns(values []string) []policy.BytePattern {
	result := make([]policy.BytePattern, 0, len(values))
	for _, value := range values {
		result = append(result, policy.BytePattern{Kind: policy.PatternLiteral, Value: value})
	}
	return result
}

func uppercaseList(values []string) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		result = append(result, strings.ToUpper(value))
	}
	return result
}

func parseHTTPHeaders(value string) ([]policy.HeaderMatch, error) {
	items := strings.Split(value, ";")
	result := make([]policy.HeaderMatch, 0, len(items))
	for _, item := range items {
		name, pattern, ok := strings.Cut(item, "=")
		name = strings.TrimSpace(name)
		pattern = strings.TrimSpace(pattern)
		if !ok || name == "" || pattern == "" {
			return nil, fmt.Errorf("HTTP header %q must be name=value", strings.TrimSpace(item))
		}
		result = append(result, policy.HeaderMatch{Name: name, Value: policy.BytePattern{Kind: policy.PatternLiteral, Value: pattern}})
	}
	return result, nil
}

func parseModes(value string) ([]dataplane.Mode, error) {
	return parseNamedList[dataplane.Mode](value, guidedModeOptions(), "mode")
}

func parseTopologySides(value string) ([]traffic.TopologySide, error) {
	return parseNamedList[traffic.TopologySide](value, topologyOptions(), "topology side")
}

func parseNamedList[T ~string](value string, options []string, label string) ([]T, error) {
	valid := make(map[string]T, len(options))
	for _, item := range options {
		valid[item] = T(item)
	}
	result := make([]T, 0, 1)
	for _, item := range splitList(strings.ToLower(value)) {
		parsed, ok := valid[item]
		if !ok {
			return nil, fmt.Errorf("%s %q is invalid", label, item)
		}
		result = append(result, parsed)
	}
	return result, nil
}
