package bridge

import "testing"

func TestParseNetworkServiceOrder(t *testing.T) {
	input := `(1) USB 10/100/1000 LAN
(Hardware Port: USB 10/100/1000 LAN, Device: en7)

(2) Wi-Fi
(Hardware Port: Wi-Fi, Device: en0)
`
	got := parseNetworkServiceOrder(input)

	if got["en7"] != "USB 10/100/1000 LAN" {
		t.Fatalf("en7 service = %q", got["en7"])
	}
	if got["en0"] != "Wi-Fi" {
		t.Fatalf("en0 service = %q", got["en0"])
	}
}

func TestParseNetworkServiceEnabled(t *testing.T) {
	input := `An asterisk (*) denotes that a network service is disabled.
USB 10/100/1000 LAN
*Wi-Fi
`
	got := parseNetworkServiceEnabled(input)

	if !got["USB 10/100/1000 LAN"] {
		t.Fatalf("expected USB service enabled")
	}
	if got["Wi-Fi"] {
		t.Fatalf("expected Wi-Fi disabled")
	}
}
