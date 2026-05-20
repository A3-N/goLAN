package bridge

import (
	"net"
	"testing"

	"github.com/mcrn/goLAN/internal/stealth"
)

func TestChooseNATAnchorUsesObservedSubnet(t *testing.T) {
	id := &stealth.TargetIdentity{
		IP:              net.ParseIP("10.77.0.42"),
		Netmask:         net.IPMask(net.ParseIP("255.255.255.0").To4()),
		NetmaskObserved: true,
		Gateway:         net.ParseIP("10.77.0.1"),
	}

	choice, err := chooseNATAnchor(id)
	if err != nil {
		t.Fatalf("chooseNATAnchor returned error: %v", err)
	}
	if !choice.SameSubnet {
		t.Fatalf("expected same-subnet anchor, got %+v", choice)
	}
	if choice.IP == "10.77.0.42" || choice.IP == "10.77.0.1" {
		t.Fatalf("anchor collided with known address: %s", choice.IP)
	}
	if got, want := choice.Netmask, "255.255.255.0"; got != want {
		t.Fatalf("netmask = %s, want %s", got, want)
	}
	if ip := net.ParseIP(choice.IP); ip == nil || !(&net.IPNet{IP: net.ParseIP("10.77.0.0"), Mask: id.Netmask}).Contains(ip) {
		t.Fatalf("anchor %s is not inside learned subnet", choice.IP)
	}
}

func TestChooseNATAnchorFallsBackWithoutObservedMask(t *testing.T) {
	id := &stealth.TargetIdentity{
		IP:      net.ParseIP("10.77.0.42"),
		Netmask: net.IPMask(net.ParseIP("255.255.255.0").To4()),
	}

	choice, err := chooseNATAnchor(id)
	if err != nil {
		t.Fatalf("chooseNATAnchor returned error: %v", err)
	}
	if choice.SameSubnet {
		t.Fatalf("expected orthogonal fallback without observed netmask, got %+v", choice)
	}
	if got, want := choice.IP, "172.16.254.10"; got != want {
		t.Fatalf("fallback IP = %s, want %s", got, want)
	}
}
