package bridge

import (
	"net"
	"strings"
	"testing"
)

func TestParseInterfaceIPv4(t *testing.T) {
	output := `bridge1: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500
	ether 00:00:5e:00:53:01
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

func TestStartTakeoverRejectsAddressingBeforeAnyMutation(t *testing.T) {
	runner := &fakeCommandRunner{}
	backend := &fakeFastPolicyBackend{}
	session := &Session{
		bridgeName: "bridge7", targetMAC: net.HardwareAddr{2, 0, 0, 0, 0, 1},
		runner: runner, fastPF: backend, fastPFRules: "fast-rules\n",
	}
	err := session.StartTakeover(TakeoverConfig{
		IP: "192.0.2.10", CIDR: "24", Gateway: "not-an-ip", DHCP: "off",
	})
	if err == nil || !strings.Contains(err.Error(), "gateway") {
		t.Fatalf("StartTakeover error=%v", err)
	}
	if len(runner.calls) != 0 || backend.applyCalls != 0 || session.nat != nil {
		t.Fatalf("mutation before preflight: commands=%#v PF=%d state=%+v", runner.calls, backend.applyCalls, session.nat)
	}
}

func TestStartTakeoverRequiresAuthenticatedIdentityAndFastMode(t *testing.T) {
	tests := []struct {
		name    string
		session *Session
		config  TakeoverConfig
		want    string
	}{
		{
			name:    "identity mismatch",
			session: &Session{bridgeName: "bridge7", targetMAC: net.HardwareAddr{2, 0, 0, 0, 0, 1}, runner: &fakeCommandRunner{}},
			config:  TakeoverConfig{MAC: "02:00:00:00:00:02", IP: "192.0.2.10", CIDR: "24", DHCP: "off"},
			want:    "differs from authenticated identity",
		},
		{
			name:    "controlled bridge",
			session: &Session{Mode: ModeControlled, bridgeName: "bridge7", targetMAC: net.HardwareAddr{2, 0, 0, 0, 0, 1}, runner: &fakeCommandRunner{}},
			config:  TakeoverConfig{IP: "192.0.2.10", CIDR: "24", DHCP: "off"},
			want:    "requires a fast bridge",
		},
		{
			name:    "cleanup pending",
			session: &Session{Mode: ModeFast, bridgeName: "bridge7", nat: &NATState{}, runner: &fakeCommandRunner{}},
			config:  TakeoverConfig{IP: "192.0.2.10", CIDR: "24", DHCP: "off"},
			want:    "cleanup is pending",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := test.session.StartTakeover(test.config)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("StartTakeover error=%v", err)
			}
			runner := test.session.runner.(*fakeCommandRunner)
			if len(runner.calls) != 0 {
				t.Fatalf("commands before rejection=%#v", runner.calls)
			}
		})
	}
}
