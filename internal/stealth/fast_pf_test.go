package stealth

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"golan/internal/dataplane"
	"golan/internal/policy"
	"golan/internal/traffic"
)

func TestCompileFastBridgePFOrdersFamiliesDirectionsAndExactMatches(t *testing.T) {
	rules := []policy.Rule{
		{
			ID: "allow-v6-dns", Priority: 20, Enabled: true,
			Match: policy.Match{
				Directions: []traffic.Direction{traffic.DirectionSwitchToHost},
				IPVersions: []uint8{6}, DstCIDRs: []string{"2001:db8::1/32"},
				Protocols: []uint8{17}, SrcPorts: policy.PortSet{Values: []uint16{53}},
			},
			Actions: []policy.Action{{Kind: policy.ActionAllow}},
		},
		{
			ID: "shadow-http", Priority: 40, Enabled: true,
			Match:   policy.Match{HTTPMethods: []string{"POST"}},
			Actions: []policy.Action{{Kind: policy.ActionBlock}},
		},
		{
			ID: "block-v4-web", Priority: 30, Enabled: true,
			Match: policy.Match{
				Modes:      []dataplane.Mode{dataplane.ModeFastBridge},
				Directions: []traffic.Direction{traffic.DirectionHostToSwitch},
				IPVersions: []uint8{4}, SrcCIDRs: []string{"10.0.0.99/24"},
				Protocols: []uint8{6}, DstPorts: policy.PortSet{Values: []uint16{80, 443}},
			},
			Actions: []policy.Action{{Kind: policy.ActionBlock}},
		},
	}

	got, err := CompileFastBridgePF("en11", "en12", "fast-1", rules)
	if err != nil {
		t.Fatal(err)
	}
	want := strings.Join([]string{
		"block drop in quick on en11 inet proto tcp from 10.0.0.0/24 to any port { 80, 443 }",
		"pass in quick on en12 inet6 proto udp from any port 53 to 2001:db8::/32 keep state",
		"",
	}, "\n")
	if got != want {
		t.Fatalf("compiled PF rules:\n%s\nwant:\n%s", got, want)
	}
}

func TestCompileFastBridgePFSplitsUnspecifiedFamiliesAndIntersectsTopology(t *testing.T) {
	rule := policy.Rule{
		ID: "block-service", Enabled: true,
		Match: policy.Match{
			Directions: []traffic.Direction{traffic.DirectionOutbound},
			Topologies: []traffic.TopologySide{traffic.SideHost},
			Egress:     []traffic.TopologySide{traffic.SideSwitch},
			Protocols:  []uint8{17, 6},
			DstPorts:   policy.PortSet{Ranges: []policy.PortRange{{First: 8000, Last: 8010}}, Negate: true},
		},
		Actions: []policy.Action{{Kind: policy.ActionBlock}},
	}
	got, err := CompileFastBridgePF("en11", "en12", "families", []policy.Rule{rule})
	if err != nil {
		t.Fatal(err)
	}
	want := "block drop in quick on en11 inet proto { tcp, udp } from any to any port != 8000:8010\n" +
		"block drop in quick on en11 inet6 proto { tcp, udp } from any to any port != 8000:8010\n"
	if got != want {
		t.Fatalf("compiled PF rules:\n%s\nwant:\n%s", got, want)
	}

	rule.Match.Topologies = []traffic.TopologySide{traffic.SideSwitch}
	got, err = CompileFastBridgePF("en11", "en12", "contradictory", []policy.Rule{rule})
	if err != nil || got != "" {
		t.Fatalf("contradictory constraints rules=%q err=%v", got, err)
	}
}

func TestCompileFastBridgePFRejectsOverlappingL2BoundaryBeforeMutation(t *testing.T) {
	rules := []policy.Rule{
		{ID: "allow-all", Priority: 20, Enabled: true, Actions: []policy.Action{{Kind: policy.ActionAllow}}},
		{ID: "block-v4", Priority: 10, Enabled: true, Match: policy.Match{IPVersions: []uint8{4}}, Actions: []policy.Action{{Kind: policy.ActionBlock}}},
	}
	if _, err := CompileFastBridgePF("en11", "en12", "mixed", rules); err == nil || !strings.Contains(err.Error(), "overlapping Layer 2 rule allow-all") {
		t.Fatalf("mixed policy error=%v", err)
	}
	rules[0].Match.EtherTypes = []uint16{0x888e}
	if _, err := CompileFastBridgePF("en11", "en12", "disjoint", rules); err != nil {
		t.Fatalf("disjoint L2/PF policy: %v", err)
	}
	if _, err := CompileFastBridgePF("-a", "en12", "invalid-interface", rules); err == nil {
		t.Fatal("unsafe interface accepted")
	}
}

func TestCompileNATPFOrdersEndpointPolicyBeforeSafeDefaults(t *testing.T) {
	rules := []policy.Rule{
		{
			ID: "block-admin", Priority: 200, Enabled: true,
			Match: policy.Match{
				Modes: []dataplane.Mode{dataplane.ModeNAT}, Directions: []traffic.Direction{traffic.DirectionOutbound},
				IPVersions: []uint8{4}, Protocols: []uint8{6}, DstPorts: policy.PortSet{Values: []uint16{22}},
			},
			Actions: []policy.Action{{Kind: policy.ActionBlock}},
		},
		{
			ID: "shadow-http", Priority: 100, Enabled: true,
			Match:   policy.Match{HTTPMethods: []string{"POST"}},
			Actions: []policy.Action{{Kind: policy.ActionBlock}},
		},
	}
	got, err := CompileNATPF("bridge7", "nat-1", rules)
	if err != nil {
		t.Fatal(err)
	}
	want := strings.Join([]string{
		"pass out quick on bridge7 inet proto udp from any port 68 to any port 67 keep state",
		"pass in quick on bridge7 inet proto udp from any port 67 to any port 68 keep state",
		"block drop quick on bridge7 inet6 all",
		"block drop out quick on bridge7 inet proto tcp from any to any port 22",
		"pass out quick on bridge7 inet from any to any keep state",
		"block drop in quick on bridge7 inet all",
		"",
	}, "\n")
	if got != want {
		t.Fatalf("compiled nat PF rules:\n%s\nwant:\n%s", got, want)
	}
	if _, err := CompileNATPF("-a", "invalid", rules); err == nil {
		t.Fatal("unsafe nat interface accepted")
	}
}

type fastPFCall struct {
	args  []string
	input string
}

type fastPFResponse struct {
	output string
	err    error
}

type fakeFastPFRunner struct {
	calls     []fastPFCall
	responses []fastPFResponse
}

func (f *fakeFastPFRunner) Run(_ context.Context, _ string, args []string, input string) (string, error) {
	f.calls = append(f.calls, fastPFCall{args: append([]string(nil), args...), input: input})
	if len(f.responses) == 0 {
		return "", nil
	}
	response := f.responses[0]
	f.responses = f.responses[1:]
	return response.output, response.err
}

func TestFastBridgePFBackendValidatesOwnsAndRestoresOnlyChildAnchor(t *testing.T) {
	runner := &fakeFastPFRunner{responses: []fastPFResponse{
		{},
		{output: "Status: Disabled\n"},
		{output: "pf enabled\nToken : fast-token\n"},
		{},
	}}
	backend := newFastBridgePFBackend(runner)
	rules := "block drop in quick on en11 inet all\n"
	if err := backend.Apply(context.Background(), rules); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	wantApply := [][]string{
		{"-vnf", "-"},
		{"-s", "info"},
		{"-E"},
		{"-a", FastBridgePFAnchor, "-f", "-"},
	}
	for index, want := range wantApply {
		if !reflect.DeepEqual(runner.calls[index].args, want) {
			t.Fatalf("apply call %d=%v want=%v", index, runner.calls[index].args, want)
		}
	}
	if runner.calls[0].input != rules || runner.calls[3].input != rules {
		t.Fatal("validated and loaded rules differ")
	}

	if err := backend.Restore(context.Background()); err != nil {
		t.Fatalf("Restore: %v", err)
	}
	wantRestore := [][]string{
		{"-a", FastBridgePFAnchor, "-F", "rules"},
		{"-X", "fast-token"},
	}
	for index, want := range wantRestore {
		got := runner.calls[len(wantApply)+index].args
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("restore call %d=%v want=%v", index, got, want)
		}
	}
	for _, call := range runner.calls {
		if reflect.DeepEqual(call.args, []string{"-F", "all"}) {
			t.Fatal("global PF flush attempted")
		}
	}
}

func TestFastBridgePFBackendRetainsFailedCleanupAndPartialLoad(t *testing.T) {
	loadErr := errors.New("load failed")
	runner := &fakeFastPFRunner{responses: []fastPFResponse{
		{}, {output: "Status: Disabled"}, {output: "Token: retry-token"}, {output: "syntax race", err: loadErr},
	}}
	backend := newFastBridgePFBackend(runner)
	if err := backend.Apply(context.Background(), "block drop inet all\n"); !errors.Is(err, loadErr) {
		t.Fatalf("Apply error=%v", err)
	}
	flushErr := errors.New("flush failed")
	runner.responses = []fastPFResponse{{output: "busy", err: flushErr}}
	if err := backend.Restore(context.Background()); !errors.Is(err, flushErr) {
		t.Fatalf("first Restore error=%v", err)
	}
	if state := backend.backend.State(); !state.Loaded || !state.EnableTokenOwned {
		t.Fatalf("cleanup state discarded: %+v", state)
	}
	if got := runner.calls[len(runner.calls)-1].args; !reflect.DeepEqual(got, []string{"-a", FastBridgePFAnchor, "-F", "rules"}) {
		t.Fatalf("failed cleanup call=%v", got)
	}

	runner.responses = []fastPFResponse{{}, {}}
	if err := backend.Restore(context.Background()); err != nil {
		t.Fatalf("retry Restore: %v", err)
	}
	if state := backend.backend.State(); state.Loaded || state.EnableTokenOwned {
		t.Fatalf("cleanup state remains: %+v", state)
	}
}

func TestFastBridgePFBackendValidationFailureHasNoMutation(t *testing.T) {
	want := errors.New("invalid syntax")
	runner := &fakeFastPFRunner{responses: []fastPFResponse{{output: "bad rule", err: want}}}
	backend := newFastBridgePFBackend(runner)
	if err := backend.Apply(context.Background(), "bad\n"); !errors.Is(err, want) {
		t.Fatalf("Apply error=%v", err)
	}
	if len(runner.calls) != 1 || !reflect.DeepEqual(runner.calls[0].args, []string{"-vnf", "-"}) {
		t.Fatalf("calls after validation failure=%#v", runner.calls)
	}
}
