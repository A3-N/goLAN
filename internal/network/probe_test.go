package network

import (
	"context"
	"strings"
	"testing"
)

func TestProbePlanningIsExplicitAndBounded(t *testing.T) {
	tests := []struct {
		kind string
		args []string
	}{
		{kind: "gateway", args: []string{"192.0.2.1"}},
		{kind: "dns", args: []string{"example.test"}},
		{kind: "route", args: []string{"2001:db8::1"}},
		{kind: "device", args: []string{"192.0.2.10", "443"}},
		{kind: "dhcp", args: []string{"en7"}},
	}
	for _, test := range tests {
		plan, err := NewProbePlan(test.kind, test.args...)
		if err != nil || plan.Description == "" {
			t.Errorf("%s plan=%#v err=%v", test.kind, plan, err)
		}
	}
	for _, invalid := range [][]string{
		{"gateway", "example.test"},
		{"dns", "bad name"},
		{"device", "192.0.2.1", "0"},
		{"dhcp", "en0;touch"},
	} {
		if _, err := NewProbePlan(invalid[0], invalid[1:]...); err == nil {
			t.Errorf("invalid plan accepted: %v", invalid)
		}
	}
	lease := `op = BOOTREPLY
yiaddr = 192.0.2.10
server_identifier = 192.0.2.1
host_name = private-client
router = {192.0.2.1}
domain_name_server = {192.0.2.53}
`
	details := filteredDHCPLease(lease)
	joined := strings.Join(details, "\n")
	if !strings.Contains(joined, "router") || strings.Contains(joined, "host_name") || len(details) > 8 {
		t.Fatalf("filtered lease=%q", joined)
	}

	plan, err := NewProbePlan("device", "192.0.2.10", "443")
	if err != nil {
		t.Fatal(err)
	}
	plan.Description = "modified after review"
	result := RunProbe(context.Background(), plan)
	if result.Status != StageFail || result.Summary != "probe plan is invalid" {
		t.Fatalf("modified plan result=%#v", result)
	}
}
