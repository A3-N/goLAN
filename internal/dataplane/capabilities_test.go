package dataplane

import (
	"reflect"
	"testing"
)

func TestCapabilityMatrixNeverSilentlyOmitsEnforcement(t *testing.T) {
	capabilities := []Capability{
		CapabilityFrameFilter, CapabilityStatefulFilter,
		CapabilityRewriteEthernet, CapabilityRewriteIP,
		CapabilityRewriteTransport, CapabilityRewritePayload,
		CapabilityNAT, CapabilityRedirect,
		CapabilityPortForward, CapabilityTrafficShape,
	}
	for _, mode := range []Mode{ModeListen, ModeFastBridge, ModeControlledBridge, ModeNAT, ModeEdgeObserve, ModeEdgeRoute} {
		matrix := ForMode(mode)
		for _, capability := range capabilities {
			switch got := matrix.Support(capability); got {
			case StatusLive, StatusShadow, StatusUnsupported:
			default:
				t.Fatalf("%s/%s status = %q", mode, capability, got)
			}
		}
	}
}

func TestModesReturnsStableIndependentInventory(t *testing.T) {
	want := []Mode{
		ModeListen, ModeFastBridge, ModeControlledBridge, ModeNAT,
		ModeEdgeObserve, ModeEdgeRoute,
	}
	first := Modes()
	if !reflect.DeepEqual(first, want) {
		t.Fatalf("Modes = %v, want %v", first, want)
	}
	first[0] = "changed"
	if second := Modes(); !reflect.DeepEqual(second, want) {
		t.Fatalf("Modes returned mutable inventory: %v", second)
	}
}
