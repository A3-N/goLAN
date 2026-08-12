package policy

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golan/internal/dataplane"
	"golan/internal/traffic"
)

func TestJournalRedactsPolicyOperandsWithoutMutatingDecision(t *testing.T) {
	path := filepath.Join(t.TempDir(), "decisions.jsonl")
	journal, err := OpenJournal(path)
	if err != nil {
		t.Fatal(err)
	}
	decision := Decision{
		PacketID:         "packet",
		Verdict:          VerdictAllow,
		EffectiveVerdict: VerdictAllow,
		Status:           dataplane.StatusLive,
		Transformations: []Transformation{{
			Kind: TransformLiteral, Field: traffic.FieldPayload,
			Search: "private-search", Replace: "private-replacement",
			Occurrence: OccurrenceAll,
		}},
		Actions: []Action{
			{Kind: ActionTag, Value: "private-action"},
			{Kind: ActionDelay, Duration: 10},
		},
		Tags: []string{"private-tag"},
	}
	if err := journal.Append(decision); err != nil {
		t.Fatal(err)
	}
	if err := journal.Close(); err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, private := range []string{
		"private-search", "private-replacement",
		"private-action", "private-tag",
	} {
		if strings.Contains(string(content), private) {
			t.Fatalf("journal exposed %q: %s", private, content)
		}
	}
	var recorded Decision
	summary, err := DecodeJournal(
		context.Background(),
		strings.NewReader(string(content)),
		JournalReadOptions{},
		func(candidate Decision) error {
			recorded = candidate
			return nil
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if summary.Records != 1 || len(recorded.Transformations) != 1 ||
		recorded.Transformations[0].Kind != TransformLiteral ||
		recorded.Transformations[0].Occurrence != OccurrenceAll ||
		len(recorded.Actions) != 2 || recorded.Actions[0].Kind != ActionTag ||
		recorded.Actions[1].Kind != ActionDelay || recorded.Actions[1].Duration != 10 ||
		len(recorded.Tags) != 0 {
		t.Fatalf("redacted decision lost structural metadata: %#v", recorded)
	}
	if decision.Transformations[0].Search != "private-search" ||
		decision.Actions[0].Value != "private-action" ||
		len(decision.Tags) != 1 {
		t.Fatalf("journal mutated caller decision: %#v", decision)
	}
}
