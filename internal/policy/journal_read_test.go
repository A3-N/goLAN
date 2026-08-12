package policy

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	"golan/internal/dataplane"
	"golan/internal/traffic"
)

func TestDecodeJournalStrictlyStreamsOrdinalLinks(t *testing.T) {
	first := Decision{
		PacketID:                 "packet-1",
		OriginalCaptureOrdinal:   1,
		ForwardedCaptureOrdinals: []uint64{1, 2},
		Verdict:                  VerdictAllow,
		EffectiveVerdict:         VerdictAllow,
	}
	second := Decision{
		PacketID:               "packet-2",
		OriginalCaptureOrdinal: 2,
		Verdict:                VerdictBlock,
		EffectiveVerdict:       VerdictBlock,
	}
	content := append(journalTestLine(t, first), journalTestLine(t, second)...)
	var visited []Decision
	summary, err := DecodeJournal(
		context.Background(),
		bytes.NewReader(content),
		JournalReadOptions{MaxRecords: 2},
		func(decision Decision) error {
			visited = append(visited, decision)
			return nil
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if summary.Records != 2 || !summary.Complete ||
		len(visited) != 2 ||
		visited[0].ForwardedCaptureOrdinals[1] != 2 {
		t.Fatalf("summary=%#v decisions=%#v", summary, visited)
	}
}

func TestDecodeJournalMarksOnlyAllowedTailIncomplete(t *testing.T) {
	complete := journalTestLine(t, Decision{
		OriginalCaptureOrdinal: 1,
		Verdict:                VerdictBlock,
		EffectiveVerdict:       VerdictBlock,
	})
	content := append(complete, []byte(`{"original_capture_ordinal":2`)...)
	visited := 0
	summary, err := DecodeJournal(
		context.Background(),
		bytes.NewReader(content),
		JournalReadOptions{AllowTruncatedTail: true},
		func(Decision) error {
			visited++
			return nil
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if summary.Records != 1 || summary.Complete || visited != 1 {
		t.Fatalf("summary=%#v visited=%d", summary, visited)
	}
	if _, err := DecodeJournal(
		context.Background(),
		bytes.NewReader(content),
		JournalReadOptions{},
		nil,
	); err == nil || !strings.Contains(err.Error(), "truncated") {
		t.Fatalf("strict truncated-tail error=%v", err)
	}
}

func TestDecodeJournalRejectsMalformedAndUnboundedEvidence(t *testing.T) {
	tests := []struct {
		name    string
		content []byte
		options JournalReadOptions
	}{
		{
			name: "unknown field",
			content: []byte(
				"{\"packet_id\":\"p\",\"unknown\":true}\n",
			),
		},
		{
			name: "forward without original",
			content: journalTestLine(t, Decision{
				ForwardedCaptureOrdinals: []uint64{1},
			}),
		},
		{
			name: "duplicate forward",
			content: journalTestLine(t, Decision{
				OriginalCaptureOrdinal:   1,
				ForwardedCaptureOrdinals: []uint64{1, 1},
			}),
		},
		{
			name: "invalid evidence kind",
			content: journalTestLine(t, Decision{
				EvidenceKind: traffic.EvidenceKind("message"),
			}),
		},
		{
			name:    "invalid data plane",
			content: journalTestLine(t, Decision{DataPlane: dataplane.Mode("invented")}),
		},
		{
			name:    "empty record",
			content: []byte("\n"),
		},
		{
			name: "record count",
			content: append(
				journalTestLine(t, Decision{}),
				journalTestLine(t, Decision{})...,
			),
			options: JournalReadOptions{MaxRecords: 1},
		},
		{
			name:    "record bytes",
			content: journalTestLine(t, Decision{Explanation: "oversize"}),
			options: JournalReadOptions{MaxRecordBytes: 4},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := DecodeJournal(
				context.Background(),
				bytes.NewReader(test.content),
				test.options,
				nil,
			); err == nil {
				t.Fatal("invalid journal was accepted")
			}
		})
	}
	privateField := []byte(
		"{\"packet_id\":\"p\",\"private-journal-field\":true}\n",
	)
	if _, err := DecodeJournal(
		context.Background(),
		bytes.NewReader(privateField),
		JournalReadOptions{},
		nil,
	); err == nil ||
		strings.Contains(err.Error(), "private-journal-field") {
		t.Fatalf("journal decoder leaked an unknown field in error=%v", err)
	}
}

func TestJournalAppendRejectsInvalidEvidenceLink(t *testing.T) {
	journal, err := OpenJournal(t.TempDir() + "/decisions.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	if err := journal.Append(Decision{
		ForwardedCaptureOrdinals: []uint64{1},
	}); err == nil {
		t.Fatal("invalid evidence link was appended")
	}
	if err := journal.Close(); err != nil {
		t.Fatal(err)
	}
}

func FuzzDecisionJournalDecode(f *testing.F) {
	f.Add([]byte("{}\n"), false)
	f.Add([]byte(
		"{\"original_capture_ordinal\":1,"+
			"\"forwarded_capture_ordinals\":[1]}\n",
	), false)
	f.Add([]byte("{\"original_capture_ordinal\":"), true)
	f.Fuzz(func(t *testing.T, content []byte, allowTruncated bool) {
		_, _ = DecodeJournal(
			context.Background(),
			bytes.NewReader(content),
			JournalReadOptions{
				MaxRecords:         128,
				MaxRecordBytes:     64 << 10,
				AllowTruncatedTail: allowTruncated,
			},
			func(Decision) error { return nil },
		)
	})
}

func journalTestLine(t *testing.T, decision Decision) []byte {
	t.Helper()
	data, err := json.Marshal(decision)
	if err != nil {
		t.Fatal(err)
	}
	return append(data, '\n')
}
