package policy

import (
	"fmt"
	"strconv"
	"strings"

	"golan/internal/dataplane"
	"golan/internal/traffic"
)

const (
	maxFramePreviewChanges   = 4
	maxFramePreviewSemantics = 4
	maxFramePreviewBytes     = 32
	maxSemanticPreviewBytes  = 48
)

// SemanticChange is one bounded before/after value proven by a matching frame.
type SemanticChange struct {
	Label  string
	Before string
	After  string
}

// HexChange is one changed half-open frame range. Hex excerpts are capped and
// Truncated reports when additional bytes in the range are omitted.
type HexChange struct {
	BeforeRange traffic.ByteRange
	AfterRange  traffic.ByteRange
	BeforeHex   string
	AfterHex    string
	Truncated   bool
}

// TransformationEvidencePreview is a payload-bounded transformation result
// proven by one matching captured frame. Omitted counts preserve exact output
// bounds.
type TransformationEvidencePreview struct {
	PacketID         traffic.PacketID
	Boundary         TransformationBoundary
	BeforeLength     int
	AfterLength      int
	SemanticChanges  []SemanticChange
	HexChanges       []HexChange
	OmittedSemantics int
	OmittedHexRanges int
}

// PreviewFrameTransformations applies only transformations that are provably
// safe at a controlled-frame boundary and reports bounded before/after
// evidence using the same length-preserving boundary as live enforcement.
func PreviewFrameTransformations(frame traffic.Frame, transformations []Transformation) (TransformationEvidencePreview, error) {
	preview := TransformationEvidencePreview{
		PacketID:     frame.ID,
		Boundary:     TransformationBoundaryFrame,
		BeforeLength: len(frame.RawBytes()),
	}
	for index, transformation := range transformations {
		if err := validateTransformation(transformation); err != nil {
			return TransformationEvidencePreview{}, fmt.Errorf("transformation %d: %w", index+1, err)
		}
	}

	after := frame
	if len(transformations) > 0 {
		var err error
		after, err = ApplyTransformations(frame, Decision{
			Status:          dataplane.StatusLive,
			Transformations: cloneTransformations(transformations),
		})
		if err != nil {
			return TransformationEvidencePreview{}, fmt.Errorf("preview matching frame: %w", err)
		}
	}
	beforeRaw := frame.RawBytes()
	afterRaw := after.RawBytes()
	if len(afterRaw) != len(beforeRaw) {
		return TransformationEvidencePreview{}, fmt.Errorf("controlled-frame preview changed frame length")
	}
	preview.AfterLength = len(afterRaw)
	preview.SemanticChanges, preview.OmittedSemantics = frameSemanticChanges(frame, after, transformations)
	preview.HexChanges, preview.OmittedHexRanges = frameHexChanges(beforeRaw, afterRaw)
	return preview, nil
}

func frameSemanticChanges(before, after traffic.Frame, transformations []Transformation) ([]SemanticChange, int) {
	changes := make([]SemanticChange, 0, min(len(transformations), maxFramePreviewSemantics))
	omitted := 0
	seen := make(map[string]struct{}, len(transformations))
	add := func(change SemanticChange) {
		if change.Before == change.After {
			return
		}
		key := change.Label + "\x00" + change.Before + "\x00" + change.After
		if _, ok := seen[key]; ok {
			return
		}
		seen[key] = struct{}{}
		if len(changes) == maxFramePreviewSemantics {
			omitted++
			return
		}
		changes = append(changes, change)
	}
	for _, transformation := range transformations {
		switch transformation.Kind {
		case TransformField:
			add(SemanticChange{
				Label:  string(transformation.Field),
				Before: frameFieldValue(before, transformation.Field),
				After:  frameFieldValue(after, transformation.Field),
			})
		case TransformLiteral:
			add(SemanticChange{
				Label:  "payload literal",
				Before: boundedQuoted(transformation.Search),
				After:  boundedQuoted(transformation.Replace),
			})
		}
	}
	return changes, omitted
}

func frameFieldValue(frame traffic.Frame, field traffic.Field) string {
	decoded := frame.Decoded()
	switch field {
	case traffic.FieldSrcMAC:
		return decoded.SrcMAC
	case traffic.FieldDstMAC:
		return decoded.DstMAC
	case traffic.FieldEtherType:
		return fmt.Sprintf("0x%04x", decoded.EtherType)
	case traffic.FieldVLAN:
		if len(decoded.VLANs) == 0 {
			return "absent"
		}
		return strconv.FormatUint(uint64(decoded.VLANs[0].ID), 10)
	case traffic.FieldSrcIP:
		return decoded.SrcIP
	case traffic.FieldDstIP:
		return decoded.DstIP
	case traffic.FieldSrcPort:
		return strconv.FormatUint(uint64(decoded.SrcPort), 10)
	case traffic.FieldDstPort:
		return strconv.FormatUint(uint64(decoded.DstPort), 10)
	case traffic.FieldTTL:
		return strconv.FormatUint(uint64(decoded.TTL), 10)
	case traffic.FieldDSCP:
		return strconv.FormatUint(uint64(decoded.DSCP), 10)
	default:
		return ""
	}
}

func boundedQuoted(value string) string {
	raw := []byte(value)
	truncated := len(raw) > maxSemanticPreviewBytes
	if truncated {
		raw = raw[:maxSemanticPreviewBytes]
	}
	result := strconv.QuoteToASCII(string(raw))
	if truncated {
		result += "…"
	}
	return result
}

func frameHexChanges(before, after []byte) ([]HexChange, int) {
	if len(before) != len(after) {
		return nil, 0
	}
	changes := make([]HexChange, 0, maxFramePreviewChanges)
	omitted := 0
	for index := 0; index < len(before); {
		if before[index] == after[index] {
			index++
			continue
		}
		start := index
		for index < len(before) && before[index] != after[index] {
			index++
		}
		if len(changes) == maxFramePreviewChanges {
			omitted++
			continue
		}
		end := index
		excerptEnd := min(end, start+maxFramePreviewBytes)
		changes = append(changes, HexChange{
			BeforeRange: traffic.ByteRange{Start: start, End: end},
			AfterRange:  traffic.ByteRange{Start: start, End: end},
			BeforeHex:   spacedHex(before[start:excerptEnd]),
			AfterHex:    spacedHex(after[start:excerptEnd]),
			Truncated:   excerptEnd < end,
		})
	}
	return changes, omitted
}

func spacedHex(value []byte) string {
	if len(value) == 0 {
		return ""
	}
	var result strings.Builder
	result.Grow(len(value)*3 - 1)
	for index, octet := range value {
		if index > 0 {
			result.WriteByte(' ')
		}
		_, _ = fmt.Fprintf(&result, "%02x", octet)
	}
	return result.String()
}
