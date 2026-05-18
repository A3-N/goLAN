package stats

import "testing"

func TestCounterDelta(t *testing.T) {
	if got := counterDelta(120, 100); got != 20 {
		t.Fatalf("counterDelta increase = %d", got)
	}
	if got := counterDelta(50, 100); got != 0 {
		t.Fatalf("counterDelta reset = %d", got)
	}
}
