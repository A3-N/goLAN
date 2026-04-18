package bridge

import (
	"fmt"
	"os/exec"
	"strings"
	"sync"
)

// BridgeState represents the current state of the bridge.
type BridgeState int

const (
	BridgeStateDown    BridgeState = iota
	BridgeStateCreated             // bridge created but not fully up
	BridgeStateUp                  // bridge active and forwarding
)

func (s BridgeState) String() string {
	switch s {
	case BridgeStateDown:
		return "Down"
	case BridgeStateCreated:
		return "Created"
	case BridgeStateUp:
		return "Active"
	default:
		return "Unknown"
	}
}

// Bridge represents a macOS kernel bridge between two network interfaces.
type Bridge struct {
	mu            sync.Mutex
	name          string // e.g. "bridge0"
	ifaceA        string // first member interface
	ifaceB        string // second member interface
	state         BridgeState
	origForwarding string // original ip.forwarding value before we changed it
}

// BridgeStatus is a snapshot of the bridge state for the TUI.
type BridgeStatus struct {
	Name    string
	IfaceA  string
	IfaceB  string
	State   BridgeState
	RawInfo string // raw output from ifconfig
}

// NewBridge creates a macOS kernel bridge between two interfaces.
// This requires root privileges.
func NewBridge(ifaceA, ifaceB string) (*Bridge, error) {
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

	// Step 2: Add both interfaces as members.
	if _, err := runCmd("ifconfig", b.name, "addm", ifaceA, "addm", ifaceB); err != nil {
		// Cleanup on failure.
		_ = b.destroy()
		return nil, fmt.Errorf("adding members %s and %s to %s: %w", ifaceA, ifaceB, b.name, err)
	}

	// Step 3: Bring the bridge up.
	if _, err := runCmd("ifconfig", b.name, "up"); err != nil {
		_ = b.destroy()
		return nil, fmt.Errorf("bringing up %s: %w", b.name, err)
	}

	// Step 4: Bring member interfaces up (they may be down).
	_, _ = runCmd("ifconfig", ifaceA, "up")
	_, _ = runCmd("ifconfig", ifaceB, "up")

	// Step 5: Enable IP forwarding.
	if _, err := runCmd("sysctl", "-w", "net.inet.ip.forwarding=1"); err != nil {
		// Non-fatal: bridge will still forward L2 traffic.
		fmt.Printf("warning: could not enable IP forwarding: %v\n", err)
	}

	b.state = BridgeStateUp
	return b, nil
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
		Name:   b.name,
		IfaceA: b.ifaceA,
		IfaceB: b.ifaceB,
		State:  b.state,
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
