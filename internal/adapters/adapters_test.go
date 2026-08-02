package adapters

import "testing"

func TestParseHardwarePorts(t *testing.T) {
	input := `Hardware Port: Wi-Fi
Device: en0
Ethernet Address: aa:bb:cc:dd:ee:ff

Hardware Port: USB 10/100/1000 LAN
Device: en7
Ethernet Address: 11:22:33:44:55:66
`

	got := ParseHardwarePorts(input)
	if got["en0"].Name != "Wi-Fi" {
		t.Fatalf("en0 hardware port = %q", got["en0"].Name)
	}
	if got["en7"].MAC != "11:22:33:44:55:66" {
		t.Fatalf("en7 mac = %q", got["en7"].MAC)
	}
}

func TestParseNetworkServiceOrderSeparatesRenamedAndDisabledServices(t *testing.T) {
	input := `An asterisk (*) denotes that a network service is disabled.
(1) Office Wi-Fi
(Hardware Port: Wi-Fi, Device: en0)

(*) Isolated Lab Target
(Hardware Port: USB 10/100/1000 LAN, Device: en7)

(3) Service Name With (Parentheses)
(Hardware Port: Thunderbolt Ethernet Slot 1, Device: en8)
`

	got := ParseNetworkServiceOrder(input)
	want := map[string]string{
		"en0": "Office Wi-Fi",
		"en7": "Isolated Lab Target",
		"en8": "Service Name With (Parentheses)",
	}
	if len(got) != len(want) {
		t.Fatalf("services=%#v", got)
	}
	for device, service := range want {
		if got[device] != service {
			t.Fatalf("service for %s=%q want %q", device, got[device], service)
		}
	}
}

func TestClassifyKind(t *testing.T) {
	cases := map[string]string{
		classifyKind("Wi-Fi", "en0"):                    "wifi",
		classifyKind("USB 10/100/1000 LAN", "en7"):      "usb-ethernet",
		classifyKind("Thunderbolt Ethernet", "en8"):     "thunderbolt",
		classifyKind("Unmapped Physical Ethernet", "x"): "ethernet",
	}

	for got, want := range cases {
		if got != want {
			t.Fatalf("classifyKind() = %q, want %q", got, want)
		}
	}
}
