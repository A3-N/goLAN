package eapol

import "testing"

func TestEAPTypeToMethodMapsMSCHAPv2Type26(t *testing.T) {
	if got := eapTypeToMethod(26); got != MethodMSCHAPv2 {
		t.Fatalf("eapTypeToMethod(26) = %q, want %q", got, MethodMSCHAPv2)
	}
	if got := eapTypeToMethod(29); got != MethodUnknown {
		t.Fatalf("eapTypeToMethod(29) = %q, want %q", got, MethodUnknown)
	}
}
