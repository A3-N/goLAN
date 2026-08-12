package policy

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"golan/internal/dataplane"
)

func TestMatchJSONUsesNumericByteArraysAndReadsLegacyBase64(t *testing.T) {
	want := Match{
		IPVersions: []uint8{4, 6}, Protocols: []uint8{6, 17},
		DSCP: []uint8{10}, TTL: []uint8{64}, ICMPTypes: []uint8{8},
		ICMPCodes: []uint8{0}, EAPOLTypes: []uint8{2},
	}
	encoded, err := json.Marshal(want)
	if err != nil {
		t.Fatal(err)
	}
	wantJSON := `{"ip_versions":[4,6],"protocols":[6,17],"dscp":[10],"ttl":[64],"src_ports":{},"dst_ports":{},"icmp_types":[8],"icmp_codes":[0],"eapol_types":[2]}`
	if string(encoded) != wantJSON {
		t.Fatalf("match JSON=%s want=%s", encoded, wantJSON)
	}
	var roundTrip Match
	if err := json.Unmarshal(encoded, &roundTrip); err != nil || !reflect.DeepEqual(roundTrip, want) {
		t.Fatalf("numeric round trip=%#v err=%v", roundTrip, err)
	}
	var legacy Match
	if err := json.Unmarshal([]byte(`{"ip_versions":"BAY=","protocols":"BhE="}`), &legacy); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(legacy.IPVersions, []uint8{4, 6}) || !reflect.DeepEqual(legacy.Protocols, []uint8{6, 17}) {
		t.Fatalf("legacy match=%#v", legacy)
	}
	for _, raw := range []string{`{"protocols":[256]}`, `{"unknown":true}`} {
		if err := json.Unmarshal([]byte(raw), &legacy); err == nil {
			t.Fatalf("invalid match accepted: %s", raw)
		}
	}
}

type policyGoldenCompatibility struct {
	RuleID  string   `json:"rule_id"`
	Results []string `json:"results"`
}

type policyGoldenArtifact struct {
	Revision      string                      `json:"revision"`
	Order         []string                    `json:"order"`
	Compatibility []policyGoldenCompatibility `json:"compatibility"`
}

func TestPolicyOrderingAndCompatibilityGolden(t *testing.T) {
	rules, err := Preset("web-only")
	if err != nil {
		t.Fatal(err)
	}
	compiled, err := Compile("policy-v1", rules)
	if err != nil {
		t.Fatal(err)
	}
	ordered := compiled.Rules()
	artifact := policyGoldenArtifact{Revision: compiled.Revision()}
	for _, rule := range ordered {
		artifact.Order = append(artifact.Order, rule.ID)
		row := policyGoldenCompatibility{RuleID: rule.ID}
		for _, mode := range dataplane.Modes() {
			status, capability, reason := Compatibility(rule, dataplane.ForMode(mode))
			result := fmt.Sprintf("%s=%s/%s", mode, status, capability)
			if reason != "" {
				result += ": " + reason
			}
			row.Results = append(row.Results, result)
		}
		artifact.Compatibility = append(artifact.Compatibility, row)
	}
	actual, err := json.MarshalIndent(artifact, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	actual = append(actual, '\n')
	goldenPath := filepath.Join("testdata", "policy-v1.golden.json")
	expected, err := os.ReadFile(goldenPath)
	if err != nil {
		t.Fatalf("read policy golden %s: %v\nreview and add this expected content:\n%s", goldenPath, err, actual)
	}
	if string(actual) != string(expected) {
		t.Fatalf("policy ordering or compatibility changed; review the semantic diff\nactual:\n%s", actual)
	}
}
