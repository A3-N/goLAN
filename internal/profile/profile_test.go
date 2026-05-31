package profile

import (
	"testing"

	"golan/internal/adapters"
)

func TestProfileAddMaxAdapters(t *testing.T) {
	var p Profile
	for _, name := range []string{"en0", "en1"} {
		if _, err := p.Add(adapters.Adapter{Name: name}); err != nil {
			t.Fatalf("Add(%s): %v", name, err)
		}
	}
	if _, err := p.Add(adapters.Adapter{Name: "en2"}); err == nil {
		t.Fatal("expected max adapter error")
	}
}

func TestAdapterConfigSetValidatesValues(t *testing.T) {
	cfg := FromAdapter(AdapterRoleHost, adapters.Adapter{Name: "en0"})
	if cfg.AdapterRole != AdapterRoleHost {
		t.Fatalf("AdapterRole = %q", cfg.AdapterRole)
	}
	if cfg.IP != "auto" || cfg.MAC != "auto" || cfg.State != "auto" {
		t.Fatalf("defaults = %+v", cfg)
	}
	if _, err := cfg.Set("mtu", "1500"); err != nil {
		t.Fatalf("Set mtu: %v", err)
	}
	if cfg.MTU != "1500" {
		t.Fatalf("MTU = %q", cfg.MTU)
	}
	if _, err := cfg.Set("mac", "not-a-mac"); err == nil {
		t.Fatal("expected mac validation error")
	}
	if _, err := cfg.Set("mac", "auto"); err != nil {
		t.Fatalf("Set mac auto: %v", err)
	}
	if cfg.MAC != "auto" {
		t.Fatalf("MAC = %q", cfg.MAC)
	}
	if _, err := cfg.Set("state", "down"); err != nil {
		t.Fatalf("Set state: %v", err)
	}
	if cfg.State != "down" {
		t.Fatalf("State = %q", cfg.State)
	}
}

func TestExplicitRolesArePreserved(t *testing.T) {
	var p Profile
	if _, err := p.SetAdapterRole(adapters.Adapter{Name: "en0"}, AdapterRoleHost); err != nil {
		t.Fatalf("SetAdapterRole en0: %v", err)
	}
	if _, err := p.SetAdapterRole(adapters.Adapter{Name: "en1"}, AdapterRoleSwitch); err != nil {
		t.Fatalf("SetAdapterRole en1: %v", err)
	}

	if _, ok := p.RemoveRole(AdapterRoleHost); !ok {
		t.Fatal("expected role removal")
	}
	if len(p.Adapters) != 1 || p.Adapters[0].AdapterRole != AdapterRoleSwitch || p.Adapters[0].Name != "en1" {
		t.Fatalf("unexpected adapters after removal: %+v", p.Adapters)
	}
	if _, err := p.Add(adapters.Adapter{Name: "en2"}); err != nil {
		t.Fatalf("Add en2: %v", err)
	}
	if p.Adapters[0].AdapterRole != AdapterRoleHost || p.Adapters[0].Name != "en2" {
		t.Fatalf("expected first free role to be filled: %+v", p.Adapters)
	}
}

func TestCanonicalAdapterRole(t *testing.T) {
	if got := CanonicalAdapterRole("1"); got != AdapterRoleHost {
		t.Fatalf("CanonicalAdapterRole(1) = %q", got)
	}
	if got := CanonicalAdapterRole("2"); got != AdapterRoleSwitch {
		t.Fatalf("CanonicalAdapterRole(2) = %q", got)
	}
}

func TestAddDiscoveryAppliesOnlyAutoValues(t *testing.T) {
	cfg := FromAdapter(AdapterRoleHost, adapters.Adapter{Name: "en0"})
	added, applied := cfg.AddDiscovery("mac", "02:00:00:00:00:11", "source mac", "IPv4")
	if !added || !applied {
		t.Fatalf("first auto discovery added=%v applied=%v", added, applied)
	}
	if cfg.MAC != "02:00:00:00:00:11" {
		t.Fatalf("MAC = %q", cfg.MAC)
	}

	added, applied = cfg.AddDiscovery("mac", "02:00:00:00:00:22", "source mac", "ARP")
	if !added || applied {
		t.Fatalf("explicit discovery added=%v applied=%v", added, applied)
	}
	if cfg.MAC != "02:00:00:00:00:11" {
		t.Fatalf("MAC changed unexpectedly to %q", cfg.MAC)
	}
	if got := cfg.Values("mac"); len(got) != 2 {
		t.Fatalf("mac candidates = %v", got)
	}
	if _, err := cfg.Set("mac", "auto"); err != nil {
		t.Fatalf("Set mac auto: %v", err)
	}
	if value, ok := cfg.ApplyFirstDiscovery("mac"); !ok || value != "02:00:00:00:00:11" {
		t.Fatalf("ApplyFirstDiscovery = %q ok=%v", value, ok)
	}
	if cfg.MAC != "02:00:00:00:00:11" {
		t.Fatalf("MAC after saved discovery = %q", cfg.MAC)
	}
}

func TestAddBridgeObservationDedupesCounts(t *testing.T) {
	var p Profile
	if !p.AddBridgeObservation("en11", AdapterRoleHost, "arp_who_has", "192.0.2.1", "who-has target ip", "ARP") {
		t.Fatal("expected new bridge observation")
	}
	if p.AddBridgeObservation("en11", AdapterRoleHost, "arp_who_has", "192.0.2.1", "who-has target ip", "ARP") {
		t.Fatal("expected duplicate bridge observation")
	}
	if len(p.Bridge.Observations) != 1 || p.Bridge.Observations[0].Count != 2 {
		t.Fatalf("bridge = %+v", p.Bridge.Observations)
	}
}
