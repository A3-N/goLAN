package profile

import (
	"encoding/json"
	"strings"
	"testing"

	"golan/internal/adapters"
)

func TestAdapterConfigDoesNotPersistLiveNetworkService(t *testing.T) {
	config := FromAdapter(AdapterRoleHost, adapters.Adapter{
		Name: "en7", HardwarePort: "USB Ethernet", NetworkService: "Renamed Lab Service",
	})
	encoded, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "Renamed Lab Service") || strings.Contains(string(encoded), "network_service") {
		t.Fatalf("live network service leaked into persisted config: %s", encoded)
	}
}

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
	if _, err := cfg.Set("mac", "01:00:5e:00:00:01"); err == nil {
		t.Fatal("expected multicast mac validation error")
	}
	if _, err := cfg.Set("cidr", "64"); err == nil {
		t.Fatal("expected IPv4 cidr validation error")
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

func TestRehydrateUsesCurrentAdapterMetadata(t *testing.T) {
	saved := Profile{Adapters: []AdapterConfig{{
		AdapterRole:  AdapterRoleHost,
		Name:         "en11",
		HardwarePort: "tampered service",
		CurrentMAC:   "02:00:00:00:00:99",
		IP:           "192.0.2.10",
		MAC:          "auto",
	}}}
	inventory := []adapters.Adapter{{
		Name:           "en11",
		HardwarePort:   "USB LAN",
		NetworkService: "Renamed Lab Service",
		MAC:            "02:00:00:00:00:11",
		MTU:            1500,
	}}

	got, err := Rehydrate(saved, inventory)
	if err != nil {
		t.Fatalf("Rehydrate: %v", err)
	}
	if len(got.Adapters) != 1 {
		t.Fatalf("Adapters = %+v", got.Adapters)
	}
	cfg := got.Adapters[0]
	if cfg.HardwarePort != "USB LAN" || cfg.NetworkService != "Renamed Lab Service" || cfg.CurrentMAC != "02:00:00:00:00:11" || cfg.CurrentMTU != 1500 {
		t.Fatalf("live metadata was not restored: %+v", cfg)
	}
	if cfg.IP != "192.0.2.10" {
		t.Fatalf("editable IP = %q", cfg.IP)
	}
}

func TestRehydrateRejectsMissingAndDuplicateAdapters(t *testing.T) {
	inventory := []adapters.Adapter{{Name: "en11"}}
	tests := []Profile{
		{Adapters: []AdapterConfig{{AdapterRole: AdapterRoleHost, Name: "missing"}}},
		{Adapters: []AdapterConfig{
			{AdapterRole: AdapterRoleHost, Name: "en11"},
			{AdapterRole: AdapterRoleSwitch, Name: "en11"},
		}},
	}
	for _, saved := range tests {
		if _, err := Rehydrate(saved, inventory); err == nil {
			t.Errorf("Rehydrate(%+v) succeeded", saved)
		}
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

func TestSetAdapterRolePreservesSettingsAndEvidence(t *testing.T) {
	var p Profile
	if _, err := p.SetAdapterRole(adapters.Adapter{Name: "en0", MAC: "02:00:00:00:00:10"}, AdapterRoleHost); err != nil {
		t.Fatalf("SetAdapterRole host: %v", err)
	}
	cfg, _ := p.ByName("en0")
	if _, err := cfg.Set("ip", "192.0.2.10"); err != nil {
		t.Fatalf("Set ip: %v", err)
	}
	cfg.AddDiscovery("gateway", "192.0.2.1", "ARP reply", "ARP")

	got, err := p.SetAdapterRole(adapters.Adapter{Name: "en0", MAC: "02:00:00:00:00:11"}, AdapterRoleSwitch)
	if err != nil {
		t.Fatalf("SetAdapterRole switch: %v", err)
	}
	if got.AdapterRole != AdapterRoleSwitch || got.IP != "192.0.2.10" || got.CurrentMAC != "02:00:00:00:00:11" || len(got.Discovered) != 1 {
		t.Fatalf("updated config = %+v", got)
	}
}

func TestCanonicalAdapterRole(t *testing.T) {
	if got := CanonicalAdapterRole(" HOST "); got != AdapterRoleHost {
		t.Fatalf("CanonicalAdapterRole(HOST) = %q", got)
	}
	if ValidAdapterRole("1") || ValidAdapterRole("2") {
		t.Fatal("numeric role aliases were accepted")
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
