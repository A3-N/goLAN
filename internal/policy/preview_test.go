package policy

import (
	"reflect"
	"strings"
	"testing"

	"golan/internal/dataplane"
	"golan/internal/traffic"
)

func TestCompatibilityMatrixUsesStableDocumentedModeOrder(t *testing.T) {
	t.Parallel()
	rule := Rule{ID: "block", Enabled: true, Actions: []Action{{Kind: ActionBlock}}}
	matrix := CompatibilityMatrix(rule)
	if len(matrix) != len(dataplane.Modes()) {
		t.Fatalf("matrix entries=%d want=%d", len(matrix), len(dataplane.Modes()))
	}
	wantStatus := map[dataplane.Mode]dataplane.Status{
		dataplane.ModeListen:           dataplane.StatusShadow,
		dataplane.ModeFastBridge:       dataplane.StatusLive,
		dataplane.ModeControlledBridge: dataplane.StatusLive,
		dataplane.ModeNAT:              dataplane.StatusShadow,
		dataplane.ModeEdgeObserve:      dataplane.StatusShadow,
		dataplane.ModeEdgeRoute:        dataplane.StatusLive,
	}
	for index, mode := range dataplane.Modes() {
		entry := matrix[index]
		if entry.Mode != mode || entry.Status != wantStatus[mode] || entry.Capability == "" {
			t.Fatalf("matrix[%d]=%#v want mode=%s status=%s", index, entry, mode, wantStatus[mode])
		}
	}
	matrix[0].Reason = "caller mutation"
	if next := CompatibilityMatrix(rule); next[0].Reason == "caller mutation" {
		t.Fatal("compatibility matrix returned shared mutable state")
	}
}

func TestCompatibilityMatrixExplainsModeScope(t *testing.T) {
	t.Parallel()
	rule := Rule{
		ID: "controlled-only", Enabled: true,
		Match:   Match{Modes: []dataplane.Mode{dataplane.ModeControlledBridge}},
		Actions: []Action{{Kind: ActionBlock}},
	}
	for _, entry := range CompatibilityMatrix(rule) {
		if entry.Mode == dataplane.ModeControlledBridge {
			if entry.Status != dataplane.StatusLive {
				t.Fatalf("controlled entry=%#v", entry)
			}
			continue
		}
		if entry.Status != dataplane.StatusUnsupported || !strings.Contains(entry.Reason, "does not apply") {
			t.Fatalf("scoped entry=%#v", entry)
		}
	}
}

func TestTransformationImpactsDescribeFrameBoundaryAndRepairs(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name           string
		transformation Transformation
		wantEffect     LengthEffect
		wantCapability dataplane.Capability
	}{
		{
			name: "field",
			transformation: Transformation{
				Kind: TransformField, Field: traffic.FieldDstIP, Replace: "192.0.2.5",
			},
			wantEffect: LengthEffectPreserved, wantCapability: dataplane.CapabilityRewriteIP,
		},
		{
			name: "literal",
			transformation: Transformation{
				Kind: TransformLiteral, Search: "old", Replace: "new", Occurrence: OccurrenceFirst,
			},
			wantEffect: LengthEffectPreserved, wantCapability: dataplane.CapabilityRewritePayload,
		},
		{
			name: "re2",
			transformation: Transformation{
				Kind: TransformRE2, Search: "o(ld)", Replace: "n$1", Occurrence: OccurrenceFirst,
			},
			wantEffect: LengthEffectDynamic, wantCapability: dataplane.CapabilityRewritePayload,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			rule := Rule{
				ID: test.name, Enabled: true, Actions: []Action{{Kind: ActionAllow}},
				Transformations: []Transformation{test.transformation},
			}
			impacts, err := TransformationImpacts(rule)
			if err != nil || len(impacts) != 1 {
				t.Fatalf("impacts=%#v err=%v", impacts, err)
			}
			impact := impacts[0]
			if impact.Boundary != TransformationBoundaryFrame ||
				impact.LengthEffect != test.wantEffect ||
				impact.Capability != test.wantCapability ||
				!strings.Contains(strings.Join(impact.Repairs, ","), "checksum") {
				t.Fatalf("impact=%#v", impact)
			}
			impact.Repairs[0] = "caller mutation"
			next, err := TransformationImpacts(rule)
			if err != nil || reflect.DeepEqual(next[0].Repairs, impact.Repairs) {
				t.Fatalf("impacts returned shared state: next=%#v err=%v", next, err)
			}
		})
	}
}

func TestTransformationValidationRejectsInvalidStaticReplacements(t *testing.T) {
	t.Parallel()
	for name, transformation := range map[string]Transformation{
		"empty field":          {Kind: TransformField, Field: traffic.FieldDstIP},
		"unknown field":        {Kind: TransformField, Field: traffic.Field("unsafe"), Replace: "value"},
		"bad IP":               {Kind: TransformField, Field: traffic.FieldDstIP, Replace: "not-an-ip"},
		"bad MAC":              {Kind: TransformField, Field: traffic.FieldDstMAC, Replace: "00:11"},
		"port overflow":        {Kind: TransformField, Field: traffic.FieldDstPort, Replace: "65536"},
		"DSCP overflow":        {Kind: TransformField, Field: traffic.FieldDSCP, Replace: "64"},
		"VLAN overflow":        {Kind: TransformField, Field: traffic.FieldVLAN, Replace: "4096"},
		"bad masked output":    {Kind: TransformMasked, Search: "de ad", Replace: "not-hex"},
		"empty masked output":  {Kind: TransformMasked, Search: "de ad"},
		"longer masked output": {Kind: TransformMasked, Search: "de ad", Replace: "be ef 01"},
		"longer literal":       {Kind: TransformLiteral, Search: "old", Replace: "longer"},
		"unknown semantic":     {Kind: TransformKind("http"), Search: "old", Replace: "new"},
	} {
		_, err := Compile("invalid", []Rule{{ID: name, Enabled: true, Transformations: []Transformation{transformation}}})
		if err == nil {
			t.Fatalf("%s compiled", name)
		}
	}
}
