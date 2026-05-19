package stealth

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"time"
)

// PFRule defines a NAT masquerade rule.
type PFRule struct {
	Interface string
	HiddenIP  string
	TargetIP  string
}

// EnableNAT writes the rule to a temporary file and loads it into pf.
func EnableNAT(rule PFRule) error {
	// e.g. nat on bridge0 from 192.168.254.1 to any -> 10.0.0.50
	r := fmt.Sprintf("nat on %s from %s to any -> %s\n", rule.Interface, rule.HiddenIP, rule.TargetIP)
	// Block aggressive macOS identifying broadcasts (mDNS/Bonjour, LLMNR) that leak the Hostname
	// The firewall operates at Layer 3, so Layer 2 True Device passthrough is unharmed.
	r += fmt.Sprintf("block drop out quick on %s proto udp to 224.0.0.251 port 5353\n", rule.Interface)
	r += fmt.Sprintf("block drop out quick on %s proto udp to 224.0.0.252 port 5355\n", rule.Interface)
	r += fmt.Sprintf("block drop out quick on %s to 255.255.255.255\n", rule.Interface)

	// Block the macOS kernel from natively answering local network probes (which leaks the 'mac-os' hostname)
	// Because of NAT kernel absorption, the Mac natively fields reverse-DNS and Bonjour inquiries meant for the True Device.
	r += fmt.Sprintf("block drop in quick on %s proto udp to any port { 5353, 5355, 137, 138, 139 }\n", rule.Interface)
	r += fmt.Sprintf("block drop in quick on %s proto tcp to any port { 139, 445 }\n", rule.Interface)

	// Block IP-based multicast leaks (L3 only — L2 leaks like LLDP/CDP are handled by SuppressL2Leaks).
	r += fmt.Sprintf("block drop out quick on %s to 224.0.0.0/4\n", rule.Interface)

	f, err := os.Create("/tmp/golan_pf.conf")
	if err != nil {
		return err
	}
	if _, err := f.WriteString(r); err != nil {
		f.Close()
		return fmt.Errorf("writing pfctl rules: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("closing pfctl rules file: %w", err)
	}

	// pfctl -E enables pf — must succeed before loading rules.
	if out, err := runSystemCommand(5*time.Second, "pfctl", "-E"); err != nil {
		return fmt.Errorf("pfctl -E (enable pf) failed: %s", out)
	}

	// Load the dynamic rule
	out, err := runSystemCommand(5*time.Second, "pfctl", "-a", "com.apple/golan", "-f", "/tmp/golan_pf.conf")
	if err != nil {
		return fmt.Errorf("pfctl failed: %s", out)
	}
	return nil
}

// SuppressL2Leaks blocks Layer 2 discovery protocols that pfctl cannot intercept.
// LLDP (EtherType 0x88cc, dst 01:80:c2:00:00:0e) and CDP (dst 01:00:0c:cc:cc:cc) are
// raw Ethernet frames with no IP header, so pfctl (which operates at L3+) is blind to them.
//
// This function:
//  1. Disables the macOS LLDP daemon so the OS stops originating LLDP frames entirely.
//  2. Uses macOS bridge packet filter rules to block outbound STP/LLDP/CDP at Layer 2.
func SuppressL2Leaks(bridgeName string) error {
	// Kill the macOS LLDP daemon. This prevents the OS from generating LLDP frames
	// that advertise the hostname, OS version, and interface capabilities.
	_, _ = runSystemCommand(3*time.Second, "launchctl", "unload", "-w",
		"/System/Library/LaunchDaemons/com.apple.lldpd.plist")

	// macOS bridge(4) supports Layer 2 packet filter rules via "ifconfig bridge rule".
	// Block outbound frames to well-known L2 multicast addresses that leak identity:
	//
	//   01:80:c2:00:00:00 — STP BPDUs (Spanning Tree Protocol)
	//   01:80:c2:00:00:0e — LLDP (Link Layer Discovery Protocol)
	//   01:00:0c:cc:cc:cc — CDP (Cisco Discovery Protocol)
	//
	// These rules operate at the bridge level before frames hit the wire.
	return applyBridgeRules(bridgeName, [][]string{
		{bridgeName, "rule", "block", "out", "dst", "01:80:c2:00:00:00"},
		{bridgeName, "rule", "block", "out", "dst", "01:80:c2:00:00:0e"},
		{bridgeName, "rule", "block", "out", "dst", "01:00:0c:cc:cc:cc"},
	})
}

// InstallL2SafetyRules blocks frames sourced from local adapter identities.
// Forwarded target traffic is not sourced from these MACs, so these rules are
// intended to catch host-originated leaks before they leave the bridge.
func InstallL2SafetyRules(bridgeName string, sourceMACs []net.HardwareAddr) error {
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
	if len(rules) == 0 {
		return nil
	}
	return applyBridgeRules(bridgeName, rules)
}

// SuppressNativeEAPOL best-effort blocks the kernel bridge from forwarding
// EAPOL natively while the userspace relay is active. Without this, the relay
// can inspect/reinject a second copy of frames the bridge has already passed.
func SuppressNativeEAPOL(bridgeName, ifaceA, ifaceB string) error {
	rules := [][]string{
		{bridgeName, "rule", "block", "out", "on", ifaceA, "mac-type", "0x888e"},
		{bridgeName, "rule", "block", "out", "on", ifaceB, "mac-type", "0x888e"},
	}
	return applyBridgeRules(bridgeName, rules)
}

func applyBridgeRules(bridgeName string, rules [][]string) error {
	var errs []string
	for _, args := range rules {
		if out, err := runSystemCommand(5*time.Second, "ifconfig", args...); err != nil {
			errs = append(errs, fmt.Sprintf("ifconfig %s: %v (%s)", strings.Join(args, " "), err, strings.TrimSpace(string(out))))
		}
	}
	if out, err := runSystemCommand(5*time.Second, "ifconfig", bridgeName, "rule", "show"); err != nil {
		errs = append(errs, fmt.Sprintf("ifconfig %s rule show: %v (%s)", bridgeName, err, strings.TrimSpace(string(out))))
	}
	if len(errs) > 0 {
		return errors.New(strings.Join(errs, " | "))
	}
	return nil
}

// ResetBridgeRules flushes macOS bridge packet-filter rules. Callers should
// immediately reinstall the standard leak-suppression rules afterwards.
func ResetBridgeRules(bridgeName string) error {
	out, err := runSystemCommand(5*time.Second, "ifconfig", bridgeName, "rule", "flush")
	if err != nil {
		return fmt.Errorf("ifconfig %s rule flush: %v (%s)", bridgeName, err, strings.TrimSpace(string(out)))
	}
	return nil
}

// RestoreL2Services re-enables host L2 services that goLAN disabled globally.
func RestoreL2Services() {
	_, _ = runSystemCommand(3*time.Second, "launchctl", "load", "-w",
		"/System/Library/LaunchDaemons/com.apple.lldpd.plist")
}

// DisableNAT flushes the rules.
func DisableNAT() error {
	out, err := runSystemCommand(5*time.Second, "pfctl", "-a", "com.apple/golan", "-F", "all")
	if err != nil {
		return fmt.Errorf("pfctl flush failed: %s", out)
	}
	os.Remove("/tmp/golan_pf.conf")
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
