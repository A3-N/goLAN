package policy

import (
	"testing"
	"time"

	"golan/internal/dataplane"
	"golan/internal/traffic"
)

func TestPlanTrafficShapingIsDeterministic(t *testing.T) {
	decision := Decision{Status: dataplane.StatusLive, Actions: []Action{
		{Kind: ActionDelay, Duration: 10 * time.Millisecond},
		{Kind: ActionJitter, Duration: 5 * time.Millisecond},
		{Kind: ActionBandwidth, Rate: 1000},
		{Kind: ActionLoss, Percent: 100},
		{Kind: ActionDuplicate, Percent: 100},
	}}
	first := PlanTrafficShaping(decision, traffic.PacketID("packet"), 1000)
	second := PlanTrafficShaping(decision, traffic.PacketID("packet"), 1000)
	if first != second {
		t.Fatalf("plans differ: %#v %#v", first, second)
	}
	if !first.Drop || first.Copies != 2 || first.Delay < time.Second+10*time.Millisecond || first.Delay > time.Second+15*time.Millisecond {
		t.Fatalf("plan = %#v", first)
	}
}

func TestShadowShapingDoesNotAlterForwarding(t *testing.T) {
	plan := PlanTrafficShaping(Decision{Status: dataplane.StatusShadow, Actions: []Action{{Kind: ActionLoss, Percent: 100}, {Kind: ActionDuplicate, Percent: 100}}}, "packet", 100)
	if plan.Drop || plan.Copies != 1 || plan.Delay != 0 {
		t.Fatalf("shadow plan = %#v", plan)
	}
}
