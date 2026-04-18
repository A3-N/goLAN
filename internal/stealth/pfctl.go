package stealth

import (
	"fmt"
	"os"
	"os/exec"
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

	// pfctl -E enables pf
	exec.Command("pfctl", "-E").Run()

	// Load the dynamic rule
	cmd := exec.Command("pfctl", "-a", "com.apple/golan", "-f", "/tmp/golan_pf.conf")
	out, err := cmd.CombinedOutput()
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
func SuppressL2Leaks(bridgeName string) {
	// Kill the macOS LLDP daemon. This prevents the OS from generating LLDP frames
	// that advertise the hostname, OS version, and interface capabilities.
	_ = exec.Command("launchctl", "unload", "-w",
		"/System/Library/LaunchDaemons/com.apple.lldpd.plist").Run()

	// macOS bridge(4) supports Layer 2 packet filter rules via "ifconfig bridge rule".
	// Block outbound frames to well-known L2 multicast addresses that leak identity:
	//
	//   01:80:c2:00:00:00 — STP BPDUs (Spanning Tree Protocol)
	//   01:80:c2:00:00:0e — LLDP (Link Layer Discovery Protocol)
	//   01:00:0c:cc:cc:cc — CDP (Cisco Discovery Protocol)
	//
	// These rules operate at the bridge level before frames hit the wire.
	_ = exec.Command("ifconfig", bridgeName, "rule", "block", "out",
		"dst", "01:80:c2:00:00:00").Run()
	_ = exec.Command("ifconfig", bridgeName, "rule", "block", "out",
		"dst", "01:80:c2:00:00:0e").Run()
	_ = exec.Command("ifconfig", bridgeName, "rule", "block", "out",
		"dst", "01:00:0c:cc:cc:cc").Run()
}

// DisableNAT flushes the rules.
func DisableNAT() error {
	cmd := exec.Command("pfctl", "-a", "com.apple/golan", "-F", "all")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("pfctl flush failed: %s", out)
	}
	os.Remove("/tmp/golan_pf.conf")
	return nil
}
