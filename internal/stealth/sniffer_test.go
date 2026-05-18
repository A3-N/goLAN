package stealth

import (
	"net"
	"testing"
)

func TestCandidateReadyStrongSignals(t *testing.T) {
	mac, _ := net.ParseMAC("00:11:22:33:44:55")
	candidates := make(map[string]*targetCandidate)

	candidate, ready := recordCandidate(candidates, mac, []string{"ARP"}, 2)
	if !ready {
		t.Fatalf("expected ARP candidate ready")
	}
	if candidate.Count != 1 {
		t.Fatalf("candidate count = %d", candidate.Count)
	}
}

func TestCandidateRequiresRepeatedWeakSignals(t *testing.T) {
	mac, _ := net.ParseMAC("00:11:22:33:44:55")
	candidates := make(map[string]*targetCandidate)

	if _, ready := recordCandidate(candidates, mac, []string{"IPv6"}, 2); ready {
		t.Fatalf("single weak signal should not lock")
	}
	if _, ready := recordCandidate(candidates, mac, []string{"IPv6"}, 2); !ready {
		t.Fatalf("repeated weak signal should lock")
	}
}

func TestParseIgnoreMACsNormalizes(t *testing.T) {
	ignored := parseIgnoreMACs([]string{
		"AA:BB:CC:DD:EE:FF",
		"invalid",
	})

	if _, ok := ignored["aa:bb:cc:dd:ee:ff"]; !ok {
		t.Fatalf("expected normalized MAC in ignore set")
	}
	if len(ignored) != 1 {
		t.Fatalf("ignored length = %d", len(ignored))
	}
}
