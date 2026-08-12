package policy

import (
	"strconv"
	"strings"
	"sync"
	"testing"

	"golan/internal/dataplane"
	"golan/internal/traffic"
)

func TestDiagnosticsProveCoveredAndImpossibleRulesUnreachable(t *testing.T) {
	t.Parallel()
	rules := []Rule{
		{
			ID: "broad-block", Priority: 300, Enabled: true,
			Match: Match{
				Directions: []traffic.Direction{traffic.DirectionOutbound},
				SrcCIDRs:   []string{"10.0.0.0/8"},
				Protocols:  []uint8{6},
				SrcPorts:   PortSet{Values: []uint16{22}, Negate: true},
				Payload:    []BytePattern{{Kind: PatternLiteral, Value: "auth"}},
			},
			Actions: []Action{{Kind: ActionBlock}},
		},
		{
			ID: "covered-allow", Priority: 200, Enabled: true,
			Match: Match{
				Directions: []traffic.Direction{traffic.DirectionOutbound},
				SrcCIDRs:   []string{"10.1.2.0/24"},
				Protocols:  []uint8{6},
				SrcPorts:   PortSet{Values: []uint16{443}},
				Payload:    []BytePattern{{Kind: PatternLiteral, Value: "authorization"}},
			},
			Actions: []Action{{Kind: ActionAllow}},
		},
		{
			ID: "impossible-family", Priority: 100, Enabled: true,
			Match:   Match{IPVersions: []uint8{4}, SrcCIDRs: []string{"2001:db8::/32"}},
			Actions: []Action{{Kind: ActionBlock}},
		},
	}
	revision, err := Compile("diagnostics", rules)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	diagnostics := revision.Diagnostics(dataplane.ForMode(dataplane.ModeControlledBridge))
	covered := findDiagnostic(diagnostics, DiagnosticUnreachable, "covered-allow")
	if covered == nil || covered.RelatedRuleID != "broad-block" || !strings.Contains(covered.Message, "covers every") {
		t.Fatalf("covered diagnostic = %#v; all=%#v", covered, diagnostics)
	}
	impossible := findDiagnostic(diagnostics, DiagnosticUnreachable, "impossible-family")
	if impossible == nil || impossible.RelatedRuleID != "" || !strings.Contains(impossible.Message, "families do not intersect") {
		t.Fatalf("impossible diagnostic = %#v; all=%#v", impossible, diagnostics)
	}
}

func TestDiagnosticsDistinguishPartialConflictFromSpecificFallback(t *testing.T) {
	t.Parallel()
	conflicting := []Rule{
		{
			ID: "block-web", Priority: 200, Enabled: true,
			Match:   Match{Directions: []traffic.Direction{traffic.DirectionOutbound}, Protocols: []uint8{6}, DstPorts: PortSet{Values: []uint16{80}}},
			Actions: []Action{{Kind: ActionBlock}},
		},
		{
			ID: "allow-client-ports", Priority: 100, Enabled: true,
			Match:   Match{Directions: []traffic.Direction{traffic.DirectionOutbound}, Protocols: []uint8{6}, SrcPorts: PortSet{Ranges: []PortRange{{First: 1000, Last: 2000}}}},
			Actions: []Action{{Kind: ActionAllow}},
		},
	}
	revision, err := Compile("conflict", conflicting)
	if err != nil {
		t.Fatalf("Compile conflict: %v", err)
	}
	diagnostics := revision.Diagnostics(dataplane.ForMode(dataplane.ModeControlledBridge))
	conflict := findDiagnostic(diagnostics, DiagnosticConflict, "allow-client-ports")
	if conflict == nil || conflict.RelatedRuleID != "block-web" || !strings.Contains(conflict.Message, "may overlap") {
		t.Fatalf("conflict diagnostic = %#v; all=%#v", conflict, diagnostics)
	}

	webOnly, err := Preset("web-only")
	if err != nil {
		t.Fatalf("Preset: %v", err)
	}
	revision, err = Compile("fallback", webOnly)
	if err != nil {
		t.Fatalf("Compile fallback: %v", err)
	}
	for _, diagnostic := range revision.Diagnostics(dataplane.ForMode(dataplane.ModeControlledBridge)) {
		if diagnostic.Kind == DiagnosticConflict {
			t.Fatalf("specific allow/default-block fallback reported as conflict: %#v", diagnostic)
		}
	}
}

func TestDiagnosticsReportExposureAndLiveCapabilityAlternative(t *testing.T) {
	t.Parallel()
	rules := []Rule{
		{
			ID: "open-inbound-web", Priority: 200, Enabled: true,
			Match:   Match{Directions: []traffic.Direction{traffic.DirectionInbound}, Protocols: []uint8{6}, DstPorts: PortSet{Values: []uint16{443}}},
			Actions: []Action{{Kind: ActionAllow}},
		},
		{
			ID: "rewrite-ip", Priority: 100, Enabled: true,
			Match:           Match{Directions: []traffic.Direction{traffic.DirectionOutbound}, IPVersions: []uint8{4}},
			Actions:         []Action{{Kind: ActionAllow}},
			Transformations: []Transformation{{Kind: TransformField, Field: traffic.FieldDstIP, Replace: "192.0.2.5"}},
		},
		{
			ID: "disabled-open", Enabled: false,
			Actions: []Action{{Kind: ActionAllow}},
		},
	}
	revision, err := Compile("warnings", rules)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	diagnostics := revision.Diagnostics(dataplane.ForMode(dataplane.ModeFastBridge))
	exposure := findDiagnostic(diagnostics, DiagnosticExposure, "open-inbound-web")
	if exposure == nil || !strings.Contains(exposure.Message, "any source") {
		t.Fatalf("exposure diagnostic = %#v; all=%#v", exposure, diagnostics)
	}
	capability := findDiagnostic(diagnostics, DiagnosticCapability, "rewrite-ip")
	if capability == nil || capability.Status != dataplane.StatusShadow ||
		!strings.Contains(capability.Message, "requires rewrite-ip") ||
		!strings.Contains(capability.Message, "LIVE in controlled-bridge") {
		t.Fatalf("capability diagnostic = %#v; all=%#v", capability, diagnostics)
	}
	for _, diagnostic := range diagnostics {
		if diagnostic.RuleID == "disabled-open" {
			t.Fatalf("disabled rule produced diagnostic: %#v", diagnostic)
		}
		if strings.ContainsAny(diagnostic.String(), "\r\n") {
			t.Fatalf("diagnostic is not one line: %q", diagnostic.String())
		}
	}
}

func TestDiagnosticsDetectDirectionEgressContradiction(t *testing.T) {
	t.Parallel()
	revision, err := Compile("direction", []Rule{{
		ID: "impossible-direction", Enabled: true,
		Match: Match{
			Directions: []traffic.Direction{traffic.DirectionOutbound},
			Egress:     []traffic.TopologySide{traffic.SideHost},
		},
		Actions: []Action{{Kind: ActionBlock}},
	}})
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	diagnostic := findDiagnostic(revision.Diagnostics(dataplane.ForMode(dataplane.ModeControlledBridge)), DiagnosticUnreachable, "impossible-direction")
	if diagnostic == nil || !strings.Contains(diagnostic.Message, "direction and egress") {
		t.Fatalf("direction diagnostic = %#v", diagnostic)
	}
}

func TestDiagnosticsDetectProtocolContradictions(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		match Match
		want  string
	}{
		{name: "http-over-udp", match: Match{Protocols: []uint8{17}, HTTPStatuses: []uint16{200}}, want: "HTTP conditions require TCP"},
		{name: "dns-over-icmp", match: Match{Protocols: []uint8{1}, DNSTypes: []uint16{1}}, want: "DNS conditions require TCP or UDP"},
		{name: "eapol-over-tcp", match: Match{Protocols: []uint8{6}, EAPOLTypes: []uint8{2}}, want: "EAPOL and IP constraints"},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			revision, err := Compile("protocol", []Rule{{
				ID: test.name, Enabled: true, Match: test.match,
				Actions: []Action{{Kind: ActionBlock}},
			}})
			if err != nil {
				t.Fatalf("Compile: %v", err)
			}
			diagnostic := findDiagnostic(revision.Diagnostics(dataplane.ForMode(dataplane.ModeControlledBridge)), DiagnosticUnreachable, test.name)
			if diagnostic == nil || !strings.Contains(diagnostic.Message, test.want) {
				t.Fatalf("diagnostic = %#v", diagnostic)
			}
		})
	}
}

func TestDiagnosticsFollowZeroValuedDecodedFieldSemantics(t *testing.T) {
	t.Parallel()
	revision, err := Compile("zero-fields", []Rule{
		{
			ID: "possible-non-ip", Priority: 100, Enabled: true,
			Match: Match{
				EtherTypes: []uint16{0x0806},
				Protocols:  []uint8{0},
				SrcPorts:   PortSet{Values: []uint16{80}, Negate: true},
				EAPOLTypes: []uint8{0},
			},
			Actions: []Action{{Kind: ActionBlock}},
		},
		{
			ID: "no-ports", Enabled: true,
			Match: Match{DstPorts: PortSet{
				Ranges: []PortRange{{First: 0, Last: 65535}}, Negate: true,
			}},
			Actions: []Action{{Kind: ActionBlock}},
		},
	})
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	diagnostics := revision.Diagnostics(dataplane.ForMode(dataplane.ModeControlledBridge))
	if diagnostic := findDiagnostic(diagnostics, DiagnosticUnreachable, "possible-non-ip"); diagnostic != nil {
		t.Fatalf("zero-valued non-IP match was incorrectly rejected: %#v", diagnostic)
	}
	diagnostic := findDiagnostic(diagnostics, DiagnosticUnreachable, "no-ports")
	if diagnostic == nil || !strings.Contains(diagnostic.Message, "excludes every port") {
		t.Fatalf("empty port domain diagnostic = %#v; all=%#v", diagnostic, diagnostics)
	}
}

func TestDiagnosticsCacheAndRuleLocalPreviewAreIndependentAndBounded(t *testing.T) {
	t.Parallel()
	revision, err := Compile("cache", []Rule{
		{ID: "draft", Priority: 100, Enabled: true, Actions: []Action{{Kind: ActionBlock}}},
		{
			ID: "later", Enabled: true,
			Match:   Match{Protocols: []uint8{6}, DstPorts: PortSet{Values: []uint16{443}}},
			Actions: []Action{{Kind: ActionAllow}},
		},
	})
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	capabilities := dataplane.ForMode(dataplane.ModeControlledBridge)
	first := revision.Diagnostics(capabilities)
	if len(first) == 0 {
		t.Fatal("expected diagnostics")
	}
	originalMessage := first[0].Message
	first[0].Message = "caller mutation"
	if second := revision.Diagnostics(capabilities); second[0].Message != originalMessage {
		t.Fatalf("cached diagnostics were mutable: %#v", second)
	}

	local := revision.DiagnosticsForRule(capabilities, "draft")
	impact := findDiagnostic(local, DiagnosticUnreachable, "later")
	if impact == nil || impact.RelatedRuleID != "draft" || !strings.Contains(impact.Message, "draft decisive") {
		t.Fatalf("rule-local impact = %#v; all=%#v", impact, local)
	}

	var wait sync.WaitGroup
	for range 16 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			for range 50 {
				_ = revision.Diagnostics(capabilities)
			}
		}()
	}
	wait.Wait()

	for index := 0; index < maxDiagnosticCacheEntries+8; index++ {
		custom, newErr := dataplane.New(dataplane.Mode("custom-"+strconv.Itoa(index)), map[dataplane.Capability]dataplane.Status{
			dataplane.CapabilityFrameFilter: dataplane.StatusLive,
		})
		if newErr != nil {
			t.Fatalf("New capabilities: %v", newErr)
		}
		_ = revision.Diagnostics(custom)
	}
	if got := len(revision.warningCache.byMode); got != maxDiagnosticCacheEntries {
		t.Fatalf("diagnostic cache entries=%d want=%d", got, maxDiagnosticCacheEntries)
	}
}

func TestDiagnosticCandidateIndexNeverDropsRelevantPairs(t *testing.T) {
	t.Parallel()
	rules := []Rule{
		{ID: "wildcard", Priority: 2000, Enabled: true, Actions: []Action{{Kind: ActionBlock}}},
		{ID: "ingress-a", Priority: 1900, Enabled: true, Match: Match{Ingress: []string{"en0"}}, Actions: []Action{{Kind: ActionBlock}}},
		{ID: "ingress-b", Priority: 1800, Enabled: true, Match: Match{Ingress: []string{"en1"}}, Actions: []Action{{Kind: ActionBlock}}},
		{ID: "ingress-set", Priority: 1700, Enabled: true, Match: Match{Ingress: []string{"EN0", "en1"}}, Actions: []Action{{Kind: ActionBlock}}},
		{ID: "outbound", Priority: 1600, Enabled: true, Match: Match{Directions: []traffic.Direction{traffic.DirectionOutbound}}, Actions: []Action{{Kind: ActionBlock}}},
		{ID: "inbound", Priority: 1500, Enabled: true, Match: Match{Directions: []traffic.Direction{traffic.DirectionInbound}}, Actions: []Action{{Kind: ActionBlock}}},
		{ID: "tcp", Priority: 1400, Enabled: true, Match: Match{Protocols: []uint8{6}}, Actions: []Action{{Kind: ActionBlock}}},
		{ID: "udp", Priority: 1300, Enabled: true, Match: Match{Protocols: []uint8{17}}, Actions: []Action{{Kind: ActionBlock}}},
		{ID: "tcp-udp", Priority: 1200, Enabled: true, Match: Match{Protocols: []uint8{6, 17}}, Actions: []Action{{Kind: ActionBlock}}},
		{ID: "exact-port", Priority: 1100, Enabled: true, Match: Match{DstPorts: PortSet{Values: []uint16{80}}}, Actions: []Action{{Kind: ActionBlock}}},
		{ID: "port-set", Priority: 1000, Enabled: true, Match: Match{DstPorts: PortSet{Values: []uint16{80, 443}}}, Actions: []Action{{Kind: ActionBlock}}},
		{ID: "port-range", Priority: 900, Enabled: true, Match: Match{DstPorts: PortSet{Ranges: []PortRange{{First: 1, Last: 1024}}}}, Actions: []Action{{Kind: ActionBlock}}},
		{ID: "negated-port", Priority: 800, Enabled: true, Match: Match{DstPorts: PortSet{Values: []uint16{22}, Negate: true}}, Actions: []Action{{Kind: ActionBlock}}},
		{ID: "mac-colon", Priority: 700, Enabled: true, Match: Match{SrcMAC: []string{"00:00:5e:00:53:01"}}, Actions: []Action{{Kind: ActionBlock}}},
		{ID: "mac-hyphen", Priority: 600, Enabled: true, Match: Match{SrcMAC: []string{"00-00-5e-00-53-01"}}, Actions: []Action{{Kind: ActionBlock}}},
		{ID: "ipv4", Priority: 500, Enabled: true, Match: Match{EtherTypes: []uint16{0x0800}, IPVersions: []uint8{4}}, Actions: []Action{{Kind: ActionBlock}}},
		{ID: "ipv6", Priority: 400, Enabled: true, Match: Match{EtherTypes: []uint16{0x86dd}, IPVersions: []uint8{6}}, Actions: []Action{{Kind: ActionBlock}}},
		{ID: "host", Priority: 300, Enabled: true, Match: Match{Topologies: []traffic.TopologySide{traffic.SideHost}}, Actions: []Action{{Kind: ActionBlock}}},
		{ID: "upstream-egress", Priority: 200, Enabled: true, Match: Match{Egress: []traffic.TopologySide{traffic.SideUpstream}}, Actions: []Action{{Kind: ActionBlock}}},
		{ID: "combined", Priority: 100, Enabled: true, Match: Match{Ingress: []string{"en0"}, Directions: []traffic.Direction{traffic.DirectionOutbound}, Protocols: []uint8{6}, DstPorts: PortSet{Values: []uint16{443}}}, Actions: []Action{{Kind: ActionAllow}}},
	}
	revision, err := Compile("candidate-index", rules)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	if !diagnosticCandidateIndexComplete(revision) {
		t.Fatal("candidate index dropped a containment or overlap pair")
	}
}

func findDiagnostic(values []Diagnostic, kind DiagnosticKind, ruleID string) *Diagnostic {
	for index := range values {
		if values[index].Kind == kind && values[index].RuleID == ruleID {
			return &values[index]
		}
	}
	return nil
}

func diagnosticCandidateIndexComplete(revision RuleSet) bool {
	index := newDiagnosticCandidateIndex()
	prior := make([]compiledRule, 0, len(revision.rules))
	for _, current := range revision.rules {
		candidates, filtered := index.candidates(current.source.Match)
		candidateSet := make(map[int]bool, len(candidates))
		for _, candidate := range candidates {
			candidateSet[candidate] = true
		}
		if filtered {
			for earlierIndex, earlier := range prior {
				relevant := diagnosticMatchContains(earlier, current) || diagnosticMatchesOverlap(earlier, current)
				if relevant && !candidateSet[earlierIndex] {
					return false
				}
			}
		}
		index.add(len(prior), current.source.Match)
		prior = append(prior, current)
	}
	return true
}

func BenchmarkDiagnosticsDistinctRulesCold(b *testing.B) {
	rules := make([]Rule, 256)
	for index := range rules {
		rules[index] = Rule{
			ID: "rule-" + strconv.Itoa(index), Priority: 256 - index, Enabled: true,
			Match:   Match{Ingress: []string{"interface-" + strconv.Itoa(index)}},
			Actions: []Action{{Kind: ActionBlock}},
		}
	}
	revision, err := Compile("benchmark", rules)
	if err != nil {
		b.Fatalf("Compile: %v", err)
	}
	capabilities := dataplane.ForMode(dataplane.ModeControlledBridge)
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		_ = revision.computeDiagnostics(capabilities)
	}
}

func BenchmarkDiagnosticsForRule(b *testing.B) {
	rules := make([]Rule, 4096)
	for index := range rules {
		rules[index] = Rule{
			ID: "rule-" + strconv.Itoa(index), Priority: 4096 - index, Enabled: true,
			Match:   Match{Ingress: []string{"interface-" + strconv.Itoa(index)}},
			Actions: []Action{{Kind: ActionBlock}},
		}
	}
	revision, err := Compile("benchmark-draft", rules)
	if err != nil {
		b.Fatalf("Compile: %v", err)
	}
	capabilities := dataplane.ForMode(dataplane.ModeControlledBridge)
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		_ = revision.DiagnosticsForRule(capabilities, "rule-2048")
	}
}
