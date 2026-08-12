package policy

import (
	"bytes"
	"strings"
	"testing"

	"golan/internal/traffic"
)

func TestPreviewFrameTransformationsReportsSemanticAndHexEvidence(t *testing.T) {
	t.Parallel()
	frame := testTCPFrame(t, 80, []byte("old-old"))
	transformations := []Transformation{
		{Kind: TransformField, Field: traffic.FieldDstPort, Replace: "8080"},
		{Kind: TransformLiteral, Search: "old", Replace: "new", Occurrence: OccurrenceAll},
	}

	preview, err := PreviewFrameTransformations(frame, transformations)
	if err != nil {
		t.Fatalf("PreviewFrameTransformations: %v", err)
	}
	if preview.PacketID != frame.ID || preview.BeforeLength != len(frame.RawBytes()) ||
		preview.AfterLength != preview.BeforeLength {
		t.Fatalf("preview identity/length=%#v", preview)
	}
	if len(preview.SemanticChanges) != 2 || preview.OmittedSemantics != 0 {
		t.Fatalf("semantic changes=%#v omitted=%d", preview.SemanticChanges, preview.OmittedSemantics)
	}
	assertSemanticChange(t, preview.SemanticChanges, string(traffic.FieldDstPort), "80", "8080")
	assertSemanticChange(t, preview.SemanticChanges, "payload literal", `"old"`, `"new"`)
	if len(preview.HexChanges) == 0 || len(preview.HexChanges) > maxFramePreviewChanges {
		t.Fatalf("hex changes=%#v", preview.HexChanges)
	}
	assertChangedRangeOverlaps(t, preview.HexChanges, frame.Ranges(traffic.FieldDstPort)[0])
	assertChangedRangeOverlaps(t, preview.HexChanges, frame.Ranges(traffic.FieldPayload)[0])

	raw := frame.RawBytes()
	payload := frame.Ranges(traffic.FieldPayload)[0]
	if frame.Decoded().DstPort != 80 || string(raw[payload.Start:payload.End]) != "old-old" {
		t.Fatal("frame preview mutated its input")
	}

	preview.SemanticChanges[0].Before = "caller mutation"
	preview.HexChanges[0].BeforeHex = "caller mutation"
	next, err := PreviewFrameTransformations(frame, transformations)
	if err != nil || next.SemanticChanges[0].Before == "caller mutation" ||
		next.HexChanges[0].BeforeHex == "caller mutation" {
		t.Fatalf("preview returned shared mutable evidence: next=%#v err=%v", next, err)
	}
}

func TestPreviewFrameTransformationsReportsNoOpFrame(t *testing.T) {
	t.Parallel()
	frame := testTCPFrame(t, 80, nil)
	preview, err := PreviewFrameTransformations(frame, nil)
	if err != nil {
		t.Fatal(err)
	}
	if preview.BeforeLength != len(frame.RawBytes()) || preview.AfterLength != preview.BeforeLength ||
		len(preview.SemanticChanges) != 0 || len(preview.HexChanges) != 0 {
		t.Fatalf("no-op preview=%#v", preview)
	}
}

func TestPreviewFrameTransformationsBoundsEvidence(t *testing.T) {
	t.Parallel()
	longBefore := strings.Repeat("a", 64)
	longAfter := strings.Repeat("b", 64)
	frame := testTCPFrame(t, 80, []byte(longBefore))
	preview, err := PreviewFrameTransformations(frame, []Transformation{{
		Kind: TransformLiteral, Search: longBefore, Replace: longAfter,
	}})
	if err != nil {
		t.Fatal(err)
	}
	if len(preview.SemanticChanges) != 1 ||
		!strings.HasSuffix(preview.SemanticChanges[0].Before, "…") ||
		!strings.HasSuffix(preview.SemanticChanges[0].After, "…") {
		t.Fatalf("semantic excerpts are not bounded: %#v", preview.SemanticChanges)
	}
	payload := frame.Ranges(traffic.FieldPayload)[0]
	foundTruncatedPayload := false
	for _, change := range preview.HexChanges {
		if rangesOverlap(change.BeforeRange, payload) {
			foundTruncatedPayload = change.Truncated &&
				len(strings.Fields(change.BeforeHex)) == maxFramePreviewBytes &&
				len(strings.Fields(change.AfterHex)) == maxFramePreviewBytes
		}
	}
	if !foundTruncatedPayload {
		t.Fatalf("bounded payload hex change missing: %#v", preview.HexChanges)
	}

	separated := testTCPFrame(t, 80, []byte(strings.Repeat("a0", 12)))
	preview, err = PreviewFrameTransformations(separated, []Transformation{{
		Kind: TransformLiteral, Search: "a", Replace: "b", Occurrence: OccurrenceAll,
	}})
	if err != nil {
		t.Fatal(err)
	}
	if len(preview.HexChanges) != maxFramePreviewChanges || preview.OmittedHexRanges == 0 {
		t.Fatalf("hex range bound=%#v omitted=%d", preview.HexChanges, preview.OmittedHexRanges)
	}
}

func TestPreviewFrameTransformationErrorDoesNotEchoSearchBytes(t *testing.T) {
	t.Parallel()
	frame := testTCPFrame(t, 80, []byte("safe"))
	_, err := PreviewFrameTransformations(frame, []Transformation{{
		Kind: TransformLiteral, Search: "secret-needle", Replace: "same-length-x",
	}})
	if err == nil {
		t.Fatal("missing replacement match was accepted")
	}
	if strings.Contains(err.Error(), "secret-needle") {
		t.Fatalf("error exposed search bytes: %v", err)
	}
}

func assertSemanticChange(t *testing.T, changes []SemanticChange, label, before, after string) {
	t.Helper()
	for _, change := range changes {
		if change.Label == label {
			if change.Before != before || change.After != after {
				t.Fatalf("%s change=%#v", label, change)
			}
			return
		}
	}
	t.Fatalf("semantic change %q missing: %#v", label, changes)
}

func assertChangedRangeOverlaps(t *testing.T, changes []HexChange, want traffic.ByteRange) {
	t.Helper()
	for _, change := range changes {
		if rangesOverlap(change.BeforeRange, want) {
			return
		}
	}
	t.Fatalf("no hex change overlaps %#v: %#v", want, changes)
}

func rangesOverlap(left, right traffic.ByteRange) bool {
	return left.Start < right.End && right.Start < left.End
}

func FuzzFrameTransformationPreview(f *testing.F) {
	f.Add([]byte("token=old"), []byte("old"), []byte("new"), false)
	f.Add([]byte("aaaa"), []byte("a"), []byte("b"), true)
	f.Fuzz(func(t *testing.T, payload, search, replacement []byte, replaceAll bool) {
		const maxFuzzPreviewBytes = 512
		if len(payload) > maxFuzzPreviewBytes || len(search) > maxFuzzPreviewBytes ||
			len(replacement) > maxFuzzPreviewBytes {
			t.Skip()
		}
		frame := testTCPFrame(t, 80, payload)
		before := frame.RawBytes()
		occurrence := OccurrenceFirst
		if replaceAll {
			occurrence = OccurrenceAll
		}
		_, _ = PreviewFrameTransformations(frame, []Transformation{{
			Kind: TransformLiteral, Search: string(search), Replace: string(replacement),
			Occurrence: occurrence,
		}})
		if !bytes.Equal(before, frame.RawBytes()) {
			t.Fatal("frame preview mutated fuzz input")
		}
	})
}
