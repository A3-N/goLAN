package policy

import (
	"fmt"

	"golan/internal/dataplane"
)

// CompatibilityEntry describes one rule's static support in one documented
// data plane.
type CompatibilityEntry struct {
	Mode       dataplane.Mode
	Status     dataplane.Status
	Capability dataplane.Capability
	Reason     string
}

// CompatibilityMatrix returns static support for every documented data plane
// in stable Workbench order.
func CompatibilityMatrix(rule Rule) []CompatibilityEntry {
	modes := dataplane.Modes()
	result := make([]CompatibilityEntry, 0, len(modes))
	for _, mode := range modes {
		status, capability, reason := Compatibility(rule, dataplane.ForMode(mode))
		result = append(result, CompatibilityEntry{
			Mode: mode, Status: status, Capability: capability, Reason: reason,
		})
	}
	return result
}

// TransformationBoundary identifies where a transformation can safely run.
type TransformationBoundary string

// Transformations run only at the controlled-frame boundary.
const TransformationBoundaryFrame TransformationBoundary = "controlled-frame"

// LengthEffect describes whether a transformation preserves or changes the
// enclosing frame or message length.
type LengthEffect string

// Length effects distinguish guaranteed preservation from a data-dependent
// regular-expression result that is validated against the captured frame.
const (
	LengthEffectPreserved LengthEffect = "preserved"
	LengthEffectDynamic   LengthEffect = "dynamic"
)

// TransformationImpact is one static, payload-free deployment preview. Delta
// is bytes per message for Exact and bytes per match for PerMatch.
type TransformationImpact struct {
	Index        int
	Kind         TransformKind
	Boundary     TransformationBoundary
	LengthEffect LengthEffect
	Delta        int
	Capability   dataplane.Capability
	Repairs      []string
}

// TransformationImpacts validates a rule and returns ordered static impacts.
// Packet-specific values and total all-occurrence deltas require PCAP or live
// evidence and are deliberately not inferred here.
func TransformationImpacts(rule Rule) ([]TransformationImpact, error) {
	compiled, err := Compile("transformation-preview", []Rule{rule})
	if err != nil {
		return nil, err
	}
	rule = compiled.Rules()[0]
	result := make([]TransformationImpact, 0, len(rule.Transformations))
	for index, transformation := range rule.Transformations {
		impact, err := transformationImpact(index, transformation)
		if err != nil {
			return nil, fmt.Errorf("transformation %d: %w", index+1, err)
		}
		result = append(result, impact)
	}
	return result, nil
}

func transformationImpact(index int, transformation Transformation) (TransformationImpact, error) {
	impact := TransformationImpact{
		Index: index, Kind: transformation.Kind,
		Boundary:     TransformationBoundaryFrame,
		LengthEffect: LengthEffectPreserved,
		Capability:   transformationCapability(transformation),
		Repairs:      frameRepairPreview(),
	}
	switch transformation.Kind {
	case TransformField:
	case TransformLiteral:
		impact.Delta = len([]byte(transformation.Replace)) - len([]byte(transformation.Search))
	case TransformMasked:
		search, _, err := parseMasked(transformation.Search)
		if err != nil {
			return TransformationImpact{}, err
		}
		replacement, err := decodeHexBytes(transformation.Replace)
		if err != nil {
			return TransformationImpact{}, err
		}
		impact.Delta = len(replacement) - len(search)
	case TransformRE2:
		impact.LengthEffect = LengthEffectDynamic
	default:
		return TransformationImpact{}, fmt.Errorf("unknown transformation %q", transformation.Kind)
	}
	return impact, nil
}

func frameRepairPreview() []string {
	return []string{"IPv4 checksum when present", "TCP/UDP checksum when present"}
}
