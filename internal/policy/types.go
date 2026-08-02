package policy

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"time"

	"golan/internal/dataplane"
	"golan/internal/traffic"
)

// Verdict is a terminal rule outcome.
type Verdict string

// Terminal verdicts use first-match semantics.
const (
	VerdictAllow Verdict = "allow"
	VerdictBlock Verdict = "block"
	// VerdictRedirect is retained for backward-compatible journal decoding.
	// Current policy revisions express NAT and inbound port forwarding as
	// validated data-plane session settings, not packet verdicts.
	VerdictRedirect Verdict = "redirect"
)

// ActionKind identifies terminal and non-terminal rule actions.
type ActionKind string

// Action kinds supported by the shared rule AST.
const (
	ActionAllow ActionKind = "allow"
	ActionBlock ActionKind = "block"
	// ActionRedirect, ActionNAT, and ActionPortForward are retained so an old
	// JSON policy receives a precise migration error. Translation ownership,
	// listeners, and targets are typed transactional session settings; they are
	// not valid actions in a current policy revision.
	ActionRedirect    ActionKind = "redirect"
	ActionTag         ActionKind = "tag"
	ActionNAT         ActionKind = "nat"
	ActionPortForward ActionKind = "port-forward"
	ActionDelay       ActionKind = "delay"
	ActionJitter      ActionKind = "jitter"
	ActionBandwidth   ActionKind = "bandwidth"
	ActionLoss        ActionKind = "loss"
	ActionDuplicate   ActionKind = "duplicate"
)

// Action is one typed rule action. Duration and Rate are interpreted only by
// traffic-shaping actions; Value contains a tag label. Network
// translation is configured through the owning data plane, not Value.
type Action struct {
	Kind     ActionKind    `json:"kind"`
	Value    string        `json:"value,omitempty"`
	Duration time.Duration `json:"duration,omitempty"`
	Rate     uint64        `json:"rate,omitempty"`
	Percent  float64       `json:"percent,omitempty"`
}

// PatternKind selects literal, RE2, or masked-byte matching.
type PatternKind string

// Pattern kinds use Go's bounded RE2 implementation for regular expressions.
const (
	PatternLiteral PatternKind = "literal"
	PatternRE2     PatternKind = "re2"
	PatternMasked  PatternKind = "masked"
)

// Occurrence controls whether the first or every match is transformed.
type Occurrence string

// Occurrence defaults to First when omitted.
const (
	OccurrenceFirst Occurrence = "first"
	OccurrenceAll   Occurrence = "all"
)

// BytePattern is a bounded payload matcher. Masked values use hexadecimal
// bytes with ?? wildcards, for example "de ad ?? ef".
type BytePattern struct {
	Kind  PatternKind `json:"kind"`
	Value string      `json:"value"`
}

// HeaderMatch matches one plaintext HTTP header value.
type HeaderMatch struct {
	Name  string      `json:"name"`
	Value BytePattern `json:"value"`
}

// PortRange is an inclusive transport port range.
type PortRange struct {
	First uint16 `json:"first"`
	Last  uint16 `json:"last"`
}

// PortSet matches explicit ports and inclusive ranges, optionally negated.
type PortSet struct {
	Values []uint16    `json:"values,omitempty"`
	Ranges []PortRange `json:"ranges,omitempty"`
	Negate bool        `json:"negate,omitempty"`
}

// Match is the guided and advanced editor's shared typed AST.
type Match struct {
	Modes        []dataplane.Mode       `json:"modes,omitempty"`
	Topologies   []traffic.TopologySide `json:"topologies,omitempty"`
	Ingress      []string               `json:"ingress,omitempty"`
	Egress       []traffic.TopologySide `json:"egress,omitempty"`
	Directions   []traffic.Direction    `json:"directions,omitempty"`
	SrcMAC       []string               `json:"src_mac,omitempty"`
	DstMAC       []string               `json:"dst_mac,omitempty"`
	EtherTypes   []uint16               `json:"ether_types,omitempty"`
	VLANs        []uint16               `json:"vlans,omitempty"`
	IPVersions   []uint8                `json:"ip_versions,omitempty"`
	SrcCIDRs     []string               `json:"src_cidrs,omitempty"`
	DstCIDRs     []string               `json:"dst_cidrs,omitempty"`
	Protocols    []uint8                `json:"protocols,omitempty"`
	DSCP         []uint8                `json:"dscp,omitempty"`
	TTL          []uint8                `json:"ttl,omitempty"`
	SrcPorts     PortSet                `json:"src_ports,omitempty"`
	DstPorts     PortSet                `json:"dst_ports,omitempty"`
	TCPFlagMask  traffic.TCPFlags       `json:"tcp_flag_mask,omitempty"`
	TCPFlags     traffic.TCPFlags       `json:"tcp_flags,omitempty"`
	ICMPTypes    []uint8                `json:"icmp_types,omitempty"`
	ICMPCodes    []uint8                `json:"icmp_codes,omitempty"`
	EAPOLTypes   []uint8                `json:"eapol_types,omitempty"`
	DNSNames     []BytePattern          `json:"dns_names,omitempty"`
	DNSTypes     []uint16               `json:"dns_types,omitempty"`
	HTTPMethods  []string               `json:"http_methods,omitempty"`
	HTTPStatuses []uint16               `json:"http_statuses,omitempty"`
	HTTPHosts    []BytePattern          `json:"http_hosts,omitempty"`
	HTTPPaths    []BytePattern          `json:"http_paths,omitempty"`
	HTTPHeaders  []HeaderMatch          `json:"http_headers,omitempty"`
	Payload      []BytePattern          `json:"payload,omitempty"`
}

// matchJSON keeps byte-valued protocol fields as human-readable JSON number
// arrays. encoding/json otherwise treats []uint8 as base64-encoded bytes.
// Decoding retains support for policy revisions written by older goLAN builds.
type matchJSON struct {
	Modes        []dataplane.Mode       `json:"modes,omitempty"`
	Topologies   []traffic.TopologySide `json:"topologies,omitempty"`
	Ingress      []string               `json:"ingress,omitempty"`
	Egress       []traffic.TopologySide `json:"egress,omitempty"`
	Directions   []traffic.Direction    `json:"directions,omitempty"`
	SrcMAC       []string               `json:"src_mac,omitempty"`
	DstMAC       []string               `json:"dst_mac,omitempty"`
	EtherTypes   []uint16               `json:"ether_types,omitempty"`
	VLANs        []uint16               `json:"vlans,omitempty"`
	IPVersions   numericBytes           `json:"ip_versions,omitempty"`
	SrcCIDRs     []string               `json:"src_cidrs,omitempty"`
	DstCIDRs     []string               `json:"dst_cidrs,omitempty"`
	Protocols    numericBytes           `json:"protocols,omitempty"`
	DSCP         numericBytes           `json:"dscp,omitempty"`
	TTL          numericBytes           `json:"ttl,omitempty"`
	SrcPorts     PortSet                `json:"src_ports,omitempty"`
	DstPorts     PortSet                `json:"dst_ports,omitempty"`
	TCPFlagMask  traffic.TCPFlags       `json:"tcp_flag_mask,omitempty"`
	TCPFlags     traffic.TCPFlags       `json:"tcp_flags,omitempty"`
	ICMPTypes    numericBytes           `json:"icmp_types,omitempty"`
	ICMPCodes    numericBytes           `json:"icmp_codes,omitempty"`
	EAPOLTypes   numericBytes           `json:"eapol_types,omitempty"`
	DNSNames     []BytePattern          `json:"dns_names,omitempty"`
	DNSTypes     []uint16               `json:"dns_types,omitempty"`
	HTTPMethods  []string               `json:"http_methods,omitempty"`
	HTTPStatuses []uint16               `json:"http_statuses,omitempty"`
	HTTPHosts    []BytePattern          `json:"http_hosts,omitempty"`
	HTTPPaths    []BytePattern          `json:"http_paths,omitempty"`
	HTTPHeaders  []HeaderMatch          `json:"http_headers,omitempty"`
	Payload      []BytePattern          `json:"payload,omitempty"`
}

type numericBytes []uint8

func (values numericBytes) MarshalJSON() ([]byte, error) {
	numbers := make([]uint16, len(values))
	for index, value := range values {
		numbers[index] = uint16(value)
	}
	return json.Marshal(numbers)
}

func (values *numericBytes) UnmarshalJSON(data []byte) error {
	if len(data) > 0 && data[0] == '"' {
		var encoded string
		if err := json.Unmarshal(data, &encoded); err != nil {
			return err
		}
		decoded, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			return fmt.Errorf("decode legacy byte list: %w", err)
		}
		*values = append((*values)[:0], decoded...)
		return nil
	}
	var numbers []uint16
	if err := json.Unmarshal(data, &numbers); err != nil {
		return err
	}
	decoded := make(numericBytes, len(numbers))
	for index, number := range numbers {
		if number > 255 {
			return fmt.Errorf("byte value %d is outside 0-255", number)
		}
		decoded[index] = uint8(number)
	}
	*values = decoded
	return nil
}

// MarshalJSON preserves the documented numeric-array representation for the
// byte-valued match fields used in Advanced and persisted policy JSON.
func (match Match) MarshalJSON() ([]byte, error) {
	return json.Marshal(matchJSON{
		Modes: match.Modes, Topologies: match.Topologies, Ingress: match.Ingress,
		Egress: match.Egress, Directions: match.Directions, SrcMAC: match.SrcMAC,
		DstMAC: match.DstMAC, EtherTypes: match.EtherTypes, VLANs: match.VLANs,
		IPVersions: numericBytes(match.IPVersions), SrcCIDRs: match.SrcCIDRs,
		DstCIDRs: match.DstCIDRs, Protocols: numericBytes(match.Protocols),
		DSCP: numericBytes(match.DSCP), TTL: numericBytes(match.TTL),
		SrcPorts: match.SrcPorts, DstPorts: match.DstPorts,
		TCPFlagMask: match.TCPFlagMask, TCPFlags: match.TCPFlags,
		ICMPTypes: numericBytes(match.ICMPTypes), ICMPCodes: numericBytes(match.ICMPCodes),
		EAPOLTypes: numericBytes(match.EAPOLTypes), DNSNames: match.DNSNames,
		DNSTypes: match.DNSTypes, HTTPMethods: match.HTTPMethods,
		HTTPStatuses: match.HTTPStatuses, HTTPHosts: match.HTTPHosts,
		HTTPPaths: match.HTTPPaths, HTTPHeaders: match.HTTPHeaders, Payload: match.Payload,
	})
}

// UnmarshalJSON accepts numeric arrays and the legacy base64 form while
// retaining strict nested-field validation for the Advanced editor.
func (match *Match) UnmarshalJSON(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var wire matchJSON
	if err := decoder.Decode(&wire); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return fmt.Errorf("match contains more than one JSON value")
		}
		return err
	}
	*match = Match{
		Modes: wire.Modes, Topologies: wire.Topologies, Ingress: wire.Ingress,
		Egress: wire.Egress, Directions: wire.Directions, SrcMAC: wire.SrcMAC,
		DstMAC: wire.DstMAC, EtherTypes: wire.EtherTypes, VLANs: wire.VLANs,
		IPVersions: []uint8(wire.IPVersions), SrcCIDRs: wire.SrcCIDRs,
		DstCIDRs: wire.DstCIDRs, Protocols: []uint8(wire.Protocols),
		DSCP: []uint8(wire.DSCP), TTL: []uint8(wire.TTL),
		SrcPorts: wire.SrcPorts, DstPorts: wire.DstPorts,
		TCPFlagMask: wire.TCPFlagMask, TCPFlags: wire.TCPFlags,
		ICMPTypes: []uint8(wire.ICMPTypes), ICMPCodes: []uint8(wire.ICMPCodes),
		EAPOLTypes: []uint8(wire.EAPOLTypes), DNSNames: wire.DNSNames,
		DNSTypes: wire.DNSTypes, HTTPMethods: wire.HTTPMethods,
		HTTPStatuses: wire.HTTPStatuses, HTTPHosts: wire.HTTPHosts,
		HTTPPaths: wire.HTTPPaths, HTTPHeaders: wire.HTTPHeaders, Payload: wire.Payload,
	}
	return nil
}

// TransformKind identifies safe structured and payload transformations.
type TransformKind string

// Transform kinds map directly to a required data-plane capability.
const (
	TransformField   TransformKind = "field"
	TransformLiteral TransformKind = "literal"
	TransformRE2     TransformKind = "re2"
	TransformMasked  TransformKind = "masked"
)

// Transformation describes one match-and-replace operation.
type Transformation struct {
	Kind       TransformKind `json:"kind"`
	Field      traffic.Field `json:"field,omitempty"`
	Search     string        `json:"search,omitempty"`
	Replace    string        `json:"replace"`
	Occurrence Occurrence    `json:"occurrence,omitempty"`
}

// Rule is a persisted typed policy rule.
type Rule struct {
	ID              string            `json:"id"`
	Name            string            `json:"name"`
	Priority        int               `json:"priority"`
	Enabled         bool              `json:"enabled"`
	Revision        uint64            `json:"revision"`
	Match           Match             `json:"match"`
	Actions         []Action          `json:"actions,omitempty"`
	Transformations []Transformation  `json:"transformations,omitempty"`
	HitCount        uint64            `json:"hit_count,omitempty"`
	LastMatch       *time.Time        `json:"last_match,omitempty"`
	Metadata        map[string]string `json:"metadata,omitempty"`
}

// Decision is the complete explainable result for one packet.
type Decision struct {
	PacketID                 traffic.PacketID     `json:"packet_id"`
	ForwardedPacketID        traffic.PacketID     `json:"forwarded_packet_id,omitempty"`
	DataPlane                dataplane.Mode       `json:"data_plane,omitempty"`
	EvidenceKind             traffic.EvidenceKind `json:"evidence_kind,omitempty"`
	OriginalCaptureOrdinal   uint64               `json:"original_capture_ordinal,omitempty"`
	ForwardedCaptureOrdinals []uint64             `json:"forwarded_capture_ordinals,omitempty"`
	RuleRevision             string               `json:"rule_revision"`
	Verdict                  Verdict              `json:"verdict"`
	EffectiveVerdict         Verdict              `json:"effective_verdict"`
	Status                   dataplane.Status     `json:"status"`
	MatchingRuleIDs          []string             `json:"matching_rule_ids,omitempty"`
	WinningRuleID            string               `json:"winning_rule_id,omitempty"`
	Edited                   bool                 `json:"edited,omitempty"`
	Explanation              string               `json:"explanation"`
	RequiredCapability       dataplane.Capability `json:"required_capability,omitempty"`
	Transformations          []Transformation     `json:"transformations,omitempty"`
	Actions                  []Action             `json:"actions,omitempty"`
	Tags                     []string             `json:"tags,omitempty"`
	EvaluatedAt              time.Time            `json:"evaluated_at"`
}

// DecisionSummary is bounded payload-free runtime telemetry for one decision.
// It deliberately excludes explanations, action values, transformation
// operands, logs, tags, and captured bytes.
type DecisionSummary struct {
	PacketID          traffic.PacketID     `json:"packet_id"`
	ForwardedPacketID traffic.PacketID     `json:"forwarded_packet_id,omitempty"`
	DataPlane         dataplane.Mode       `json:"data_plane,omitempty"`
	EvidenceKind      traffic.EvidenceKind `json:"evidence_kind,omitempty"`
	Verdict           Verdict              `json:"verdict"`
	EffectiveVerdict  Verdict              `json:"effective_verdict"`
	Status            dataplane.Status     `json:"status"`
	WinningRuleID     string               `json:"winning_rule_id,omitempty"`
	Edited            bool                 `json:"edited,omitempty"`
}

// Summary returns the payload-free fields needed by bounded runtime views.
func (d Decision) Summary() DecisionSummary {
	return DecisionSummary{
		PacketID:          d.PacketID,
		ForwardedPacketID: d.ForwardedPacketID,
		DataPlane:         d.DataPlane,
		EvidenceKind:      d.EvidenceKind,
		Verdict:           d.Verdict,
		EffectiveVerdict:  d.EffectiveVerdict,
		Status:            d.Status,
		WinningRuleID:     d.WinningRuleID,
		Edited:            d.Edited,
	}
}
