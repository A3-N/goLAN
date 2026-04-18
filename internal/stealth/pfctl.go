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
	
	f, err := os.Create("/tmp/golan_pf.conf")
	if err != nil {
		return err
	}
	f.WriteString(r)
	f.Close()

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
