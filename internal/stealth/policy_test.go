package stealth

import (
	"reflect"
	"testing"

	"golan/internal/policy"
	"golan/internal/traffic"
)

func TestCompilePolicyRulesCompilesOnlyFastCompatibleRules(t *testing.T) {
	rules := []policy.Rule{
		{
			ID: "block-eapol-out", Enabled: true, Priority: 10,
			Match:   policy.Match{Directions: []traffic.Direction{traffic.DirectionHostToSwitch}, EtherTypes: []uint16{0x888e}},
			Actions: []policy.Action{{Kind: policy.ActionBlock}},
		},
		{
			ID: "userspace-http", Enabled: true, Priority: 20,
			Match:   policy.Match{HTTPMethods: []string{"POST"}},
			Actions: []policy.Action{{Kind: policy.ActionBlock}},
		},
	}
	got, err := compilePolicyRules("bridge7", "en7", "en8", rules)
	if err != nil {
		t.Fatal(err)
	}
	want := [][]string{{"bridge7", "rule", "block", "out", "on", "en8", "mac-type", "0x888e"}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("compiled rules = %#v, want %#v", got, want)
	}
}

func TestCompilePolicyRulesExpandsDirectionsDeterministically(t *testing.T) {
	rules := []policy.Rule{{
		ID: "allow-two-way", Enabled: true,
		Match:   policy.Match{SrcMAC: []string{"02:00:00:00:00:02"}},
		Actions: []policy.Action{{Kind: policy.ActionAllow}},
	}}
	got, err := compilePolicyRules("bridge0", "en8", "en7", rules)
	if err != nil {
		t.Fatal(err)
	}
	want := [][]string{
		{"bridge0", "rule", "pass", "out", "on", "en7", "src", "02:00:00:00:00:02"},
		{"bridge0", "rule", "pass", "out", "on", "en8", "src", "02:00:00:00:00:02"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("compiled rules = %#v, want %#v", got, want)
	}
}
