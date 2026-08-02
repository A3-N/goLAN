package stealth

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os/exec"
	"strings"
	"time"
)

// SuppressL2Leaks installs bridge-local rules for discovery protocols that
// pfctl cannot intercept. It deliberately avoids changing global launchd
// services because their prior state cannot be restored reliably.
func SuppressL2Leaks(bridgeName string) error {
	// macOS bridge(4) supports Layer 2 packet filter rules via "ifconfig bridge rule".
	// Block outbound frames to well-known L2 multicast addresses that leak identity:
	//
	//   01:80:c2:00:00:00 — STP BPDUs (Spanning Tree Protocol)
	//   01:80:c2:00:00:0e — LLDP (Link Layer Discovery Protocol)
	//   01:00:0c:cc:cc:cc — CDP (Cisco Discovery Protocol)
	//
	// These rules operate at the bridge level before frames hit the wire.
	return applyBridgeRules(systemCommandRunner{}, bridgeName, [][]string{
		{bridgeName, "rule", "block", "out", "dst", "01:80:c2:00:00:00"},
		{bridgeName, "rule", "block", "out", "dst", "01:80:c2:00:00:0e"},
		{bridgeName, "rule", "block", "out", "dst", "01:00:0c:cc:cc:cc"},
	})
}

// InstallL2SafetyRules blocks frames sourced from local adapter identities.
// Forwarded target traffic is not sourced from these MACs, so these rules are
// intended to catch host-originated leaks before they leave the bridge.
func InstallL2SafetyRules(bridgeName string, sourceMACs []net.HardwareAddr) error {
	if err := validateBridgeName(bridgeName); err != nil {
		return err
	}
	rules := l2SafetyRules(bridgeName, sourceMACs)
	if len(rules) == 0 {
		return nil
	}
	return applyBridgeRules(systemCommandRunner{}, bridgeName, rules)
}

func l2SafetyRules(bridgeName string, sourceMACs []net.HardwareAddr) [][]string {
	var rules [][]string
	seen := make(map[string]bool)
	for _, mac := range sourceMACs {
		if len(mac) != 6 {
			continue
		}
		macStr := strings.ToLower(mac.String())
		if seen[macStr] {
			continue
		}
		seen[macStr] = true
		rules = append(rules, []string{bridgeName, "rule", "block", "out", "src", macStr})
	}
	return rules
}

// SuppressNativeEAPOL blocks the kernel bridge from forwarding EAPOL natively
// while the userspace relay is active. Without this, the relay can inspect and
// reinject a second copy of frames the bridge has already passed.
func SuppressNativeEAPOL(bridgeName, ifaceA, ifaceB string) error {
	if err := validateInterfaceName(ifaceA); err != nil {
		return fmt.Errorf("first EAPOL relay interface: %w", err)
	}
	if err := validateInterfaceName(ifaceB); err != nil {
		return fmt.Errorf("second EAPOL relay interface: %w", err)
	}
	ifaceA = strings.TrimSpace(ifaceA)
	ifaceB = strings.TrimSpace(ifaceB)
	if strings.EqualFold(ifaceA, ifaceB) {
		return fmt.Errorf("EAPOL relay interfaces must differ")
	}
	rules := [][]string{
		{bridgeName, "rule", "block", "out", "on", ifaceA, "mac-type", "0x888e"},
		{bridgeName, "rule", "block", "out", "on", ifaceB, "mac-type", "0x888e"},
	}
	return applyBridgeRules(systemCommandRunner{}, bridgeName, rules)
}

type commandRunner interface {
	Run(timeout time.Duration, name string, args ...string) (string, error)
}

type systemCommandRunner struct{}

func (systemCommandRunner) Run(timeout time.Duration, name string, args ...string) (string, error) {
	return runSystemCommand(timeout, name, args...)
}

func applyBridgeRules(runner commandRunner, bridgeName string, rules [][]string) error {
	if runner == nil {
		return fmt.Errorf("bridge rule command runner is required")
	}
	if err := validateBridgeName(bridgeName); err != nil {
		return err
	}
	bridgeName = strings.TrimSpace(bridgeName)
	var errs []error
	for _, args := range rules {
		if out, err := runner.Run(5*time.Second, "ifconfig", args...); err != nil {
			errs = append(errs, systemCommandError("install bridge rule "+strings.Join(args, " "), out, err))
		}
	}
	if out, err := runner.Run(5*time.Second, "ifconfig", bridgeName, "rule", "show"); err != nil {
		errs = append(errs, systemCommandError("verify bridge rules "+bridgeName, out, err))
	}
	return errors.Join(errs...)
}

// ResetBridgeRules flushes macOS bridge packet-filter rules. Callers should
// immediately reinstall the standard leak-suppression rules afterwards.
func ResetBridgeRules(bridgeName string) error {
	return resetBridgeRules(systemCommandRunner{}, bridgeName)
}

func resetBridgeRules(runner commandRunner, bridgeName string) error {
	if runner == nil {
		return fmt.Errorf("bridge rule command runner is required")
	}
	if err := validateBridgeName(bridgeName); err != nil {
		return err
	}
	bridgeName = strings.TrimSpace(bridgeName)
	out, err := runner.Run(5*time.Second, "ifconfig", bridgeName, "rule", "flush")
	if err != nil {
		return systemCommandError("flush bridge rules "+bridgeName, out, err)
	}
	return nil
}

func systemCommandError(operation, output string, err error) error {
	output = strings.TrimSpace(output)
	if output == "" {
		return fmt.Errorf("%s: %w", operation, err)
	}
	return fmt.Errorf("%s: %w (%s)", operation, err, output)
}

func validateBridgeName(bridgeName string) error {
	bridgeName = strings.TrimSpace(bridgeName)
	if len(bridgeName) > 15 || !strings.HasPrefix(bridgeName, "bridge") || len(bridgeName) == len("bridge") {
		return fmt.Errorf("bridge name %q is invalid", bridgeName)
	}
	for _, char := range strings.TrimPrefix(bridgeName, "bridge") {
		if char < '0' || char > '9' {
			return fmt.Errorf("bridge name %q is invalid", bridgeName)
		}
	}
	return nil
}

func validateInterfaceName(name string) error {
	name = strings.TrimSpace(name)
	if name == "" || len(name) > 15 {
		return fmt.Errorf("interface name %q is invalid", name)
	}
	for i, char := range name {
		if (char >= 'a' && char <= 'z') ||
			(char >= 'A' && char <= 'Z') ||
			(char >= '0' && char <= '9') {
			continue
		}
		if i > 0 && (char == '-' || char == '_' || char == '.' || char == ':') {
			continue
		}
		return fmt.Errorf("interface name %q is invalid", name)
	}
	return nil
}

func runSystemCommand(timeout time.Duration, name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	out, err := cmd.CombinedOutput()
	if ctx.Err() == context.DeadlineExceeded {
		return string(out), fmt.Errorf("%s %s timed out after %s", name, strings.Join(args, " "), timeout)
	}
	return string(out), err
}
