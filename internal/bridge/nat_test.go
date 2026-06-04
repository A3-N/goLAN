package bridge

import "testing"

func TestParseInterfaceIPv4(t *testing.T) {
	output := `bridge1: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500
	ether a0:ad:9f:1c:3c:a5
	inet6 fe80::abcd%bridge1 prefixlen 64 secured scopeid 0x16
	inet 192.0.2.145 netmask 0xffffff00 broadcast 192.0.2.255
	status: active`

	if got := parseInterfaceIPv4(output); got != "192.0.2.145" {
		t.Fatalf("ipv4 = %q", got)
	}
}

func TestParseInterfaceIPv4IgnoresIPv6Only(t *testing.T) {
	output := `bridge1: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500
	inet6 fe80::abcd%bridge1 prefixlen 64 secured scopeid 0x16`

	if got := parseInterfaceIPv4(output); got != "" {
		t.Fatalf("ipv4 = %q", got)
	}
}

func TestMissingAddressErrorsAreBenignForNATClear(t *testing.T) {
	output := "ifconfig: ioctl (SIOCAIFADDR): Invalid argument"
	if !isMissingAddressError(output) {
		t.Fatalf("expected missing address error for %q", output)
	}
}

func TestMissingRouteErrorsAreBenignForNATClear(t *testing.T) {
	output := "route: writing to routing socket: not in table"
	if !isMissingRouteError(output) {
		t.Fatalf("expected missing route error for %q", output)
	}
}
