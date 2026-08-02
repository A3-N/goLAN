package bridge

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"
)

type commandCall struct {
	name string
	args []string
}

type fakeCommandRunner struct {
	responses []fakeCommandResponse
	calls     []commandCall
}

type fakeCommandResponse struct {
	output string
	err    error
}

func (f *fakeCommandRunner) Run(_ context.Context, _ time.Duration, name string, args ...string) (string, error) {
	f.calls = append(f.calls, commandCall{name: name, args: append([]string(nil), args...)})
	if len(f.responses) == 0 {
		return "", nil
	}
	response := f.responses[0]
	f.responses = f.responses[1:]
	return response.output, response.err
}

func TestLockdownInterfaceSnapshotsBeforeMutation(t *testing.T) {
	runner := &fakeCommandRunner{responses: []fakeCommandResponse{
		{output: "Enabled\n"},
		{output: "en11: flags=8863<UP,BROADCAST,RUNNING> mtu 1500\n"},
		{},
		{},
	}}

	state, err := lockdownInterface(context.Background(), runner, "en11", "USB LAN")
	if err != nil {
		t.Fatalf("lockdownInterface: %v", err)
	}
	if !state.ServiceStateKnown || !state.ServiceEnabled || !state.InterfaceStateKnown || !state.InterfaceUp {
		t.Fatalf("state = %+v", state)
	}
	want := []commandCall{
		{name: "networksetup", args: []string{"-getnetworkserviceenabled", "USB LAN"}},
		{name: "ifconfig", args: []string{"en11"}},
		{name: "networksetup", args: []string{"-setnetworkserviceenabled", "USB LAN", "off"}},
		{name: "ifconfig", args: []string{"en11", "down"}},
	}
	if !reflect.DeepEqual(runner.calls, want) {
		t.Fatalf("calls = %#v, want %#v", runner.calls, want)
	}
}

func TestLockdownInterfaceRollsBackServiceOnDownFailure(t *testing.T) {
	runner := &fakeCommandRunner{responses: []fakeCommandResponse{
		{output: "Enabled\n"},
		{output: "en11: flags=8863<UP,BROADCAST> mtu 1500\n"},
		{},
		{output: "permission denied", err: errors.New("exit status 1")},
		{},
	}}

	_, err := lockdownInterface(context.Background(), runner, "en11", "USB LAN")
	if err == nil || !strings.Contains(err.Error(), "bring adapter down") {
		t.Fatalf("error = %v", err)
	}
	last := runner.calls[len(runner.calls)-1]
	if last.name != "networksetup" || !reflect.DeepEqual(last.args, []string{"-setnetworkserviceenabled", "USB LAN", "on"}) {
		t.Fatalf("rollback call = %#v", last)
	}
}

func TestLockdownInterfaceDoesNotMutateWithoutSnapshot(t *testing.T) {
	runner := &fakeCommandRunner{responses: []fakeCommandResponse{{err: errors.New("unavailable")}}}

	if _, err := lockdownInterface(context.Background(), runner, "en11", "USB LAN"); err == nil {
		t.Fatal("expected snapshot error")
	}
	if len(runner.calls) != 1 {
		t.Fatalf("calls = %#v", runner.calls)
	}
}

func TestRestoreInterfaceStateRestoresServiceThenAdminState(t *testing.T) {
	runner := &fakeCommandRunner{}
	state := InterfaceRestoreState{
		IfName:              "en11",
		NetworkService:      "USB LAN",
		ServiceStateKnown:   true,
		ServiceEnabled:      true,
		InterfaceStateKnown: true,
		InterfaceUp:         false,
	}

	if err := restoreInterfaceState(context.Background(), runner, state); err != nil {
		t.Fatalf("restoreInterfaceState: %v", err)
	}
	want := []commandCall{
		{name: "networksetup", args: []string{"-setnetworkserviceenabled", "USB LAN", "on"}},
		{name: "ifconfig", args: []string{"en11", "down"}},
	}
	if !reflect.DeepEqual(runner.calls, want) {
		t.Fatalf("calls = %#v, want %#v", runner.calls, want)
	}
}

func TestInterfaceAdminUpParsesFlagsOnly(t *testing.T) {
	if !interfaceAdminUp("en11: flags=8863<UP,BROADCAST,RUNNING> mtu 1500\nstatus: inactive") {
		t.Fatal("expected administrative UP flag")
	}
	if interfaceAdminUp("en11: flags=8822<BROADCAST,SMART> mtu 1500\nstatus: active") {
		t.Fatal("status must not override missing UP flag")
	}
}

func TestSetInterfaceStateValidatesBeforeCommand(t *testing.T) {
	runner := &fakeCommandRunner{}
	for _, test := range []struct {
		name  string
		state string
	}{{"", "up"}, {"-a", "up"}, {"en 11", "down"}, {"en11", "auto"}} {
		if err := setInterfaceState(context.Background(), runner, test.name, test.state); err == nil {
			t.Errorf("setInterfaceState(%q, %q) succeeded", test.name, test.state)
		}
	}
	if len(runner.calls) != 0 {
		t.Fatalf("invalid state ran commands: %#v", runner.calls)
	}
	if err := setInterfaceState(context.Background(), runner, " en11 ", " UP "); err != nil {
		t.Fatalf("setInterfaceState: %v", err)
	}
	want := commandCall{name: "ifconfig", args: []string{"en11", "up"}}
	if len(runner.calls) != 1 || !reflect.DeepEqual(runner.calls[0], want) {
		t.Fatalf("calls = %#v, want %#v", runner.calls, want)
	}
}

func TestRestoreInterfaceStateDoesNotGuessUnknownAdminState(t *testing.T) {
	runner := &fakeCommandRunner{}
	state := InterfaceRestoreState{IfName: "en11"}
	if err := restoreInterfaceState(context.Background(), runner, state); err != nil {
		t.Fatalf("restoreInterfaceState: %v", err)
	}
	if len(runner.calls) != 0 {
		t.Fatalf("unknown state ran commands: %#v", runner.calls)
	}
}
