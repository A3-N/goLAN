package tui

import (
	"fmt"
	"strings"

	"golan/internal/dataplane"
	"golan/internal/policy"
	"golan/internal/traffic"
)

const maxVisibleTransformationImpacts = 4

const (
	ruleEvidenceSourceLive = "Buffered live"
)

type rulePreviewAccumulator struct {
	rules           policy.RuleSet
	rule            policy.Rule
	matches         uint64
	sampleAttempted bool
	sample          *policy.TransformationEvidencePreview
	samplePacketID  string
	sampleErr       error
}

func newRulePreviewAccumulator(rule policy.Rule) (*rulePreviewAccumulator, error) {
	rules, err := policy.Compile("draft-preview", []policy.Rule{rule})
	if err != nil {
		return nil, err
	}
	compiledRule := rules.Rules()[0]
	return &rulePreviewAccumulator{
		rules: rules, rule: compiledRule,
	}, nil
}

func (a *rulePreviewAccumulator) observe(frame traffic.Frame, flow traffic.Flow, capabilities dataplane.Capabilities) {
	if a == nil {
		return
	}
	decision := a.rules.Evaluate(frame, flow, capabilities)
	if len(decision.MatchingRuleIDs) == 0 {
		return
	}
	a.matches++
	if a.sampleAttempted {
		return
	}
	a.sampleAttempted = true
	a.samplePacketID = string(frame.ID)
	result, err := policy.PreviewFrameTransformations(frame, a.rule.Transformations)
	if err == nil {
		a.sample = &result
	} else {
		a.sampleErr = err
	}
}

func (a *rulePreviewAccumulator) message(epoch uint64, source string, packets uint64, err error) rulePreviewMsg {
	if a == nil {
		return rulePreviewMsg{epoch: epoch, source: source, packets: packets, err: err}
	}
	return rulePreviewMsg{
		epoch: epoch, source: source, packets: packets, matches: a.matches,
		sample: a.sample, samplePacketID: a.samplePacketID,
		sampleErr: a.sampleErr, err: err,
	}
}

func formatRuleCompatibility(matrix []policy.CompatibilityEntry) []string {
	const entriesPerLine = 4
	lines := make([]string, 0, (len(matrix)+entriesPerLine-1)/entriesPerLine)
	for index := 0; index < len(matrix); index += entriesPerLine {
		end := min(index+entriesPerLine, len(matrix))
		entries := make([]string, 0, end-index)
		for _, entry := range matrix[index:end] {
			label := previewModeLabel(entry.Mode)
			entries = append(entries, fmt.Sprintf("%s=%s", label, entry.Status))
		}
		lines = append(lines, strings.Join(entries, " · "))
	}
	return lines
}

func previewModeLabel(mode dataplane.Mode) string {
	switch mode {
	case dataplane.ModeFastBridge:
		return "fast"
	case dataplane.ModeControlledBridge:
		return "controlled"
	default:
		return string(mode)
	}
}

func formatTransformationImpacts(impacts []policy.TransformationImpact) []string {
	if len(impacts) == 0 {
		return []string{"no transformations · packet bytes unchanged"}
	}
	visible := min(len(impacts), maxVisibleTransformationImpacts)
	lines := make([]string, 0, visible*2+1)
	for _, impact := range impacts[:visible] {
		lines = append(lines, fmt.Sprintf(
			"%d %s · boundary=%s · length=%s",
			impact.Index+1,
			impact.Kind,
			impact.Boundary,
			formatLengthEffect(impact),
		))
		lines = append(lines, fmt.Sprintf(
			"  requires=%s · repair=%s",
			impact.Capability,
			strings.Join(impact.Repairs, "; "),
		))
	}
	if hidden := len(impacts) - visible; hidden > 0 {
		lines = append(lines, fmt.Sprintf("+%d more transformation(s)", hidden))
	}
	return lines
}

func formatLengthEffect(impact policy.TransformationImpact) string {
	return string(impact.LengthEffect)
}

func (e ruleEditorState) previewLines() []string {
	source := e.previewSource
	if source == "" {
		source = ruleEvidenceSourceLive
	}
	lines := []string{source + " evidence: " + e.preview}
	for _, evidence := range e.evidence {
		lines = append(lines, "  "+evidence)
	}
	if len(e.compatibility) == 0 {
		lines = append(lines, "Static deployment: unavailable until the draft is valid")
	} else {
		lines = append(lines, "Static deployment:")
		for _, impact := range e.impacts {
			lines = append(lines, "  "+impact)
		}
		lines = append(lines, "Compatibility:")
		for _, entry := range e.compatibility {
			lines = append(lines, "  "+entry)
		}
	}
	lines = append(lines, "Active mode: "+e.diagnostic)
	return lines
}

func formatFrameTransformationPreview(preview policy.TransformationEvidencePreview) []string {
	header := fmt.Sprintf(
		"sample packet=%s · boundary=%s · %d B → %d B",
		preview.PacketID,
		preview.Boundary,
		preview.BeforeLength,
		preview.AfterLength,
	)
	if len(preview.SemanticChanges) == 0 && len(preview.HexChanges) == 0 {
		return []string{header + " · no byte changes"}
	}
	lines := []string{header}
	if len(preview.SemanticChanges) > 0 {
		lines = append(lines, "semantic:")
		for _, change := range preview.SemanticChanges {
			lines = append(lines, fmt.Sprintf("  %s: %s → %s", change.Label, change.Before, change.After))
		}
		if preview.OmittedSemantics > 0 {
			lines = append(lines, fmt.Sprintf("  +%d more semantic change(s)", preview.OmittedSemantics))
		}
	}
	if len(preview.HexChanges) > 0 {
		lines = append(lines, "hex ranges:")
		for _, change := range preview.HexChanges {
			suffix := ""
			if change.Truncated {
				suffix = " …"
			}
			lines = append(lines, fmt.Sprintf(
				"  [%d:%d] → [%d:%d] %s → %s%s",
				change.BeforeRange.Start,
				change.BeforeRange.End,
				change.AfterRange.Start,
				change.AfterRange.End,
				change.BeforeHex,
				change.AfterHex,
				suffix,
			))
		}
		if preview.OmittedHexRanges > 0 {
			lines = append(lines, fmt.Sprintf("  +%d more changed range(s)", preview.OmittedHexRanges))
		}
	}
	return lines
}
