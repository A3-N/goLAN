package policy

import (
	"encoding/json"
	"reflect"
	"testing"

	"golan/internal/dataplane"
)

func FuzzPolicyCompile(f *testing.F) {
	f.Add([]byte(`[{"id":"allow","enabled":true,"actions":[{"kind":"allow"}]}]`))
	f.Add([]byte(`[{"id":"regex","enabled":true,"match":{"payload":[{"kind":"re2","value":"(a+)+"}]}}]`))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 1<<20 {
			t.Skip()
		}
		var rules []Rule
		if json.Unmarshal(data, &rules) != nil {
			return
		}
		revision, err := Compile("fuzz", rules)
		if err != nil {
			return
		}
		canonical := revision.Rules()
		encoded, err := json.Marshal(canonical)
		if err != nil {
			t.Fatalf("marshal compiled policy: %v", err)
		}
		var roundTrip []Rule
		if err := json.Unmarshal(encoded, &roundTrip); err != nil {
			t.Fatalf("unmarshal compiled policy: %v", err)
		}
		roundTripRevision, err := Compile("fuzz-round-trip", roundTrip)
		if err != nil {
			t.Fatalf("recompile JSON round trip: %v", err)
		}
		if got := roundTripRevision.Rules(); !reflect.DeepEqual(got, canonical) {
			t.Fatalf("compiled policy changed across JSON round trip:\n got=%#v\nwant=%#v", got, canonical)
		}
		if len(rules) <= 128 && !diagnosticCandidateIndexComplete(revision) {
			t.Fatal("diagnostic candidate index dropped a relevant rule pair")
		}
		modes := dataplane.Modes()
		for index, rule := range revision.Rules() {
			if index == 16 {
				break
			}
			if matrix := CompatibilityMatrix(rule); len(matrix) != len(modes) {
				t.Fatalf("compatibility matrix entries=%d want=%d", len(matrix), len(modes))
			}
			if _, err := TransformationImpacts(rule); err != nil {
				t.Fatalf("compiled rule transformation preview: %v", err)
			}
		}
		modeIndex := 0
		if len(data) > 0 {
			modeIndex = int(data[0]) % len(modes)
		}
		_ = revision.Diagnostics(dataplane.ForMode(modes[modeIndex]))
	})
}
