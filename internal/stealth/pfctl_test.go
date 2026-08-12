package stealth

import (
	"errors"
	"net"
	"reflect"
	"strings"
	"testing"
	"time"
)

type commandCall struct {
	name string
	args []string
}

type commandResponse struct {
	output string
	err    error
}

type fakeCommandRunner struct {
	calls     []commandCall
	responses []commandResponse
}

func (f *fakeCommandRunner) Run(_ time.Duration, name string, args ...string) (string, error) {
	f.calls = append(f.calls, commandCall{name: name, args: append([]string(nil), args...)})
	if len(f.responses) == 0 {
		return "", nil
	}
	response := f.responses[0]
	f.responses = f.responses[1:]
	return response.output, response.err
}

func TestL2SafetyRulesDeduplicateUsableMACs(t *testing.T) {
	mac := net.HardwareAddr{0x02, 0, 0, 0, 0, 0x11}
	rules := l2SafetyRules("bridge7", []net.HardwareAddr{mac, append(net.HardwareAddr(nil), mac...), {1, 2}})
	want := [][]string{{"bridge7", "rule", "block", "out", "src", "02:00:00:00:00:11"}}
	if !reflect.DeepEqual(rules, want) {
		t.Fatalf("rules = %#v", rules)
	}
}

func TestApplyBridgeRulesAggregatesAndVerifies(t *testing.T) {
	installErr := errors.New("install failed")
	verifyErr := errors.New("verify failed")
	runner := &fakeCommandRunner{responses: []commandResponse{
		{output: "denied", err: installErr},
		{},
		{output: "unavailable", err: verifyErr},
	}}
	rules := [][]string{
		{"bridge7", "rule", "block", "out", "dst", "01:80:c2:00:00:00"},
		{"bridge7", "rule", "block", "out", "dst", "01:80:c2:00:00:0e"},
	}

	err := applyBridgeRules(runner, "bridge7", rules)
	if !errors.Is(err, installErr) || !errors.Is(err, verifyErr) {
		t.Fatalf("error = %v", err)
	}
	if !strings.Contains(err.Error(), "denied") || !strings.Contains(err.Error(), "unavailable") {
		t.Fatalf("command output missing: %v", err)
	}
	if len(runner.calls) != 3 || !reflect.DeepEqual(runner.calls[2].args, []string{"bridge7", "rule", "show"}) {
		t.Fatalf("calls = %#v", runner.calls)
	}
}

func TestBridgeRuleOperationsValidateBeforeCommands(t *testing.T) {
	runner := &fakeCommandRunner{}
	if err := applyBridgeRules(runner, "", nil); err == nil {
		t.Fatal("expected empty bridge rejection")
	}
	if err := resetBridgeRules(runner, " "); err == nil {
		t.Fatal("expected empty bridge rejection")
	}
	if err := applyBridgeRules(runner, "-a", nil); err == nil {
		t.Fatal("expected option-like bridge rejection")
	}
	if len(runner.calls) != 0 {
		t.Fatalf("commands = %#v", runner.calls)
	}
}

func TestResetBridgeRulesReportsCommandFailure(t *testing.T) {
	want := errors.New("flush failed")
	runner := &fakeCommandRunner{responses: []commandResponse{{output: "busy", err: want}}}
	err := resetBridgeRules(runner, "bridge7")
	if !errors.Is(err, want) || !strings.Contains(err.Error(), "busy") {
		t.Fatalf("error = %v", err)
	}
}

func TestSuppressNativeEAPOLRejectsUnsafeInterfaces(t *testing.T) {
	for _, interfaces := range [][2]string{{"-a", "en12"}, {"en11", "en 12"}, {"en11", "en11"}} {
		if err := SuppressNativeEAPOL("bridge7", interfaces[0], interfaces[1]); err == nil {
			t.Fatalf("SuppressNativeEAPOL(%q, %q) succeeded", interfaces[0], interfaces[1])
		}
	}
}
