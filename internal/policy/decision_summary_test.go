package policy

import (
	"encoding/json"
	"strings"
	"testing"

	"golan/internal/dataplane"
	"golan/internal/traffic"
)

func TestDecisionSummaryIsPayloadFreeAndReportsOutcome(t *testing.T) {
	decision := Decision{
		PacketID:          "original",
		ForwardedPacketID: "edited",
		DataPlane:         dataplane.ModeNAT,
		EvidenceKind:      traffic.EvidencePacket,
		Verdict:           VerdictBlock,
		EffectiveVerdict:  VerdictAllow,
		Status:            dataplane.StatusLive,
		WinningRuleID:     "rewrite-http",
		Edited:            true,
		Explanation:       "contains-private-explanation",
		Transformations: []Transformation{{
			Kind: TransformLiteral, Search: "private-search", Replace: "private-replacement",
		}},
		Actions: []Action{{Kind: ActionTag, Value: "private-action"}},
		Tags:    []string{"private-tag"},
	}
	summary := decision.Summary()
	if summary.PacketID != traffic.PacketID("original") ||
		summary.ForwardedPacketID != traffic.PacketID("edited") ||
		summary.DataPlane != dataplane.ModeNAT ||
		summary.EvidenceKind != traffic.EvidencePacket ||
		!summary.Edited ||
		summary.Status != dataplane.StatusLive ||
		summary.WinningRuleID != "rewrite-http" {
		t.Fatalf("summary = %#v", summary)
	}
	encoded, err := json.Marshal(summary)
	if err != nil {
		t.Fatal(err)
	}
	for _, private := range []string{
		"private-explanation",
		"private-search",
		"private-replacement",
		"private-action",
		"private-log",
		"private-tag",
	} {
		if strings.Contains(string(encoded), private) {
			t.Fatalf("summary exposed %q: %s", private, encoded)
		}
	}
}
