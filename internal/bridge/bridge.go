package bridge

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os/exec"
	"strings"
	"sync"

	"github.com/mcrn/goLAN/internal/stealth"
)

// BridgeState represents the current state of the bridge.
type BridgeState int

const (
	BridgeStateDown        BridgeState = iota
	BridgeStateCreated                 // bridge created but not fully up
	BridgeStateSniffing                // device port up, waiting for target MAC
	BridgeStateConfiguring             // target MAC found, bridge members being attached
	BridgeStateL2Active                // bridge active and forwarding L2 frames
	BridgeStateL2Degraded              // bridge active with warnings such as failed MAC clone
	BridgeStateError                   // setup failed after bridge creation
)

func (s BridgeState) String() string {
	switch s {
	case BridgeStateDown:
		return "Down"
	case BridgeStateCreated:
		return "Created"
	case BridgeStateSniffing:
		return "Sniffing..."
	case BridgeStateConfiguring:
		return "Configuring"
	case BridgeStateL2Active:
		return "L2 Active"
	case BridgeStateL2Degraded:
		return "L2 Degraded"
	case BridgeStateError:
		return "Error"
	default:
		return "Unknown"
	}
}

// CommandResult records an external setup command and its outcome.
type CommandResult struct {
	Step    string
	Command []string
	Output  string
	Err     string
	OK      bool
}

// SetupError preserves setup diagnostics when NewBridge fails before returning a Bridge.
type SetupError struct {
	Err         error
	ReconLogs   []string
	CommandLogs []CommandResult
}

func (e *SetupError) Error() string {
	if e == nil || e.Err == nil {
		return ""
	}
	return e.Err.Error()
}

func (e *SetupError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}

// Summary returns a compact, UI-safe representation of the command result.
func (r CommandResult) Summary() string {
	status := "ok"
	if !r.OK {
		status = "fail"
	}
	cmd := commandString(r.Command)
	out := strings.TrimSpace(strings.ReplaceAll(r.Output, "\n", " | "))
	if len(out) > 160 {
		out = out[:157] + "..."
	}
	if r.Err != "" && out != "" {
		return fmt.Sprintf("[$] %s %s: %s (%s) -> %s", status, r.Step, cmd, r.Err, out)
	}
	if r.Err != "" {
		return fmt.Sprintf("[$] %s %s: %s (%s)", status, r.Step, cmd, r.Err)
	}
	if out != "" {
		return fmt.Sprintf("[$] %s %s: %s -> %s", status, r.Step, cmd, out)
	}
	return fmt.Sprintf("[$] %s %s: %s", status, r.Step, cmd)
}

func commandString(parts []string) string {
	quoted := make([]string, 0, len(parts))
	for _, part := range parts {
		if part == "" || strings.ContainsAny(part, " \t\"'") {
			part = `"` + strings.ReplaceAll(part, `"`, `\"`) + `"`
		}
		quoted = append(quoted, part)
	}
	return strings.Join(quoted, " ")
}

type restoreAction struct {
	iface          NetInterface
	serviceTouched bool
	manualAddrs    []string
}

// Bridge represents a macOS kernel bridge between two network interfaces.
type Bridge struct {
	mu             sync.Mutex
	name           string // e.g. "bridge0"
	ifaceA         string // first member interface (Device)
	ifaceB         string // second member interface (Switch)
	state          BridgeState
	targetID       *stealth.TargetIdentity
	cancelSniffer  context.CancelFunc
	reconLogs      []string
	commandLogs    []CommandResult
	restoreActions []restoreAction
}

// BridgeStatus is a snapshot of the bridge state for the TUI.
type BridgeStatus struct {
	Name        string
	IfaceA      string
	IfaceB      string
	State       BridgeState
	RawInfo     string // raw output from ifconfig
	IfaceAInfo  string
	IfaceBInfo  string
	TargetID    *stealth.TargetIdentity
	ReconLogs   []string
	CommandLogs []CommandResult
}

// NewBridge creates a macOS kernel bridge between two interfaces.
// This requires root privileges.
func NewBridge(ifaceA, ifaceB NetInterface) (*Bridge, error) {
	b := &Bridge{
		ifaceA: ifaceA.Name,
		ifaceB: ifaceB.Name,
		state:  BridgeStateDown,
	}

	b.logRecon("[*] Starting pure Layer-2 mode. No DHCP request, bridge IP, PF NAT, or IP forwarding will be configured.")

	if ifaceA.Name == ifaceB.Name {
		return nil, b.setupError(fmt.Errorf("device and switch ports must be different interfaces"))
	}
	if isInterfaceUp(ifaceB.Name) {
		return nil, b.setupError(fmt.Errorf("switch-side interface %s already has physical carrier; unplug the switch-side cable before starting", ifaceB.Name))
	}
	if !isInterfaceUp(ifaceA.Name) {
		b.logRecon(fmt.Sprintf("[!] Device-side interface %s has no carrier yet; waiting for printer-originated frames after it links.", ifaceA.Name))
	}

	if err := b.lockdownInterface(ifaceA); err != nil {
		_ = b.destroy()
		return nil, b.setupError(err)
	}
	if err := b.lockdownInterface(ifaceB); err != nil {
		_ = b.destroy()
		return nil, b.setupError(err)
	}

	// Step 1: Create the bridge interface.
	out, err := b.runLogged("create bridge", "ifconfig", "bridge", "create")
	if err != nil {
		setupErr := fmt.Errorf("creating bridge: %w (output: %s)", err, out)
		_ = b.destroy()
		return nil, b.setupError(setupErr)
	}
	b.name = strings.TrimSpace(out)
	b.state = BridgeStateCreated
	if _, err := b.runLogged("tag bridge", "ifconfig", b.name, "description", "goLAN"); err != nil {
		b.logRecon(fmt.Sprintf("[!] Could not tag %s for conservative cleanup: %v", b.name, err))
	}

	// Step 2: Bring only the device-side port up. The switch-side port stays
	// down until a target MAC has been learned and the bridge is ready.
	if _, err := b.runLogged("device port up for passive sniffing", "ifconfig", ifaceA.Name, "up"); err != nil {
		setupErr := fmt.Errorf("bringing %s up for passive sniffing: %w", ifaceA.Name, err)
		_ = b.destroy()
		return nil, b.setupError(setupErr)
	}

	ignoreMACs := []string{
		ifaceA.CurrentMAC,
		ifaceA.PermanentMAC,
		ifaceB.CurrentMAC,
		ifaceB.PermanentMAC,
		getCurrentMAC(b.name),
	}

	ctx, cancel := context.WithCancel(context.Background())
	b.cancelSniffer = cancel
	b.state = BridgeStateSniffing
	go b.runLayer2(ctx, ignoreMACs)

	return b, nil
}

// runLayer2 asynchronously sniffs the device line and activates the transparent L2 bridge.
func (b *Bridge) runLayer2(ctx context.Context, ignoreMACs []string) {
	sniff := stealth.NewSniffer(b.ifaceA)
	var activateOnce sync.Once

	logFunc := func(msg string) {
		b.logRecon(msg)
	}

	onUpdate := func(id stealth.TargetIdentity) {
		idCopy := id
		b.mu.Lock()
		b.targetID = &idCopy
		b.mu.Unlock()

		if id.IsLayer2Ready() {
			activateOnce.Do(func() {
				b.activateLayer2(ctx, id.MAC)
			})
		}
	}

	err := sniff.Observe(ctx, stealth.ObserveOptions{
		IgnoreMACs:              ignoreMACs,
		RequiredMACObservations: 2,
	}, logFunc, onUpdate)
	if err != nil && !errors.Is(err, context.Canceled) {
		b.logRecon(fmt.Sprintf("[!] Passive L2 observation aborted: %v", err))
		b.setState(BridgeStateError)
	}
}

func (b *Bridge) activateLayer2(ctx context.Context, mac net.HardwareAddr) {
	b.setState(BridgeStateConfiguring)
	warnings := 0

	b.logRecon(fmt.Sprintf("[*] Activating unnumbered L2 bridge with Target MAC %s", mac.String()))

	if _, err := b.runLogged("clone bridge MAC", "ifconfig", b.name, "ether", mac.String()); err != nil {
		warnings++
		b.logRecon(fmt.Sprintf("[!] Bridge MAC clone failed: %v", err))
	}

	if _, err := b.runLogged("clone switch-port MAC while link is down", "ifconfig", b.ifaceB, "ether", mac.String()); err != nil {
		warnings++
		b.logRecon("[!] Switch adapter MAC clone failed while down. Continuing with transparent frame forwarding.")
		b.logRecon("[!] If this adapter emits host-originated control traffic, the factory MAC may be visible upstream.")
	}

	if _, err := b.runLogged("attach bridge members", "ifconfig", b.name, "addm", b.ifaceA, "addm", b.ifaceB); err != nil {
		b.logRecon(fmt.Sprintf("[!] Bridge member attach failed: %v", err))
		b.setState(BridgeStateError)
		return
	}

	if _, err := b.runLogged("switch port up", "ifconfig", b.ifaceB, "up"); err != nil {
		b.logRecon(fmt.Sprintf("[!] Switch port up failed: %v", err))
		b.setState(BridgeStateError)
		return
	}

	if _, err := b.runLogged("bridge up", "ifconfig", b.name, "up"); err != nil {
		b.logRecon(fmt.Sprintf("[!] Bridge up failed: %v", err))
		b.setState(BridgeStateError)
		return
	}

	go stealth.NewControlRelay(b.ifaceA, b.ifaceB).Run(ctx, b.logRecon)

	if warnings > 0 {
		b.setState(BridgeStateL2Degraded)
		b.logRecon("[!] L2 bridge is forwarding, but setup completed with warnings.")
	} else {
		b.setState(BridgeStateL2Active)
	}
	b.logRecon("[+] Pure L2 bridge active. No IP lease, bridge address, NAT, or routing state was requested.")
	b.logRecon("[+] Switch side can be connected now; target traffic should traverse as native Ethernet frames.")
}

func (b *Bridge) lockdownInterface(iface NetInterface) error {
	b.logRecon(fmt.Sprintf("[*] Neutralizing host stack on %s without requesting DHCP.", iface.Name))

	action := restoreAction{iface: iface, manualAddrs: interfaceAddrStrings(iface)}
	if iface.NetworkService != "" {
		action.serviceTouched = iface.ServiceEnabled
		if iface.ServiceEnabled {
			if _, err := b.runLogged("disable network service", "networksetup", "-setnetworkserviceenabled", iface.NetworkService, "off"); err != nil {
				return fmt.Errorf("disabling network service %q for %s: %w", iface.NetworkService, iface.Name, err)
			}
		} else {
			b.logRecon(fmt.Sprintf("[*] Network service %q already disabled for %s.", iface.NetworkService, iface.Name))
		}
	} else {
		b.logRecon(fmt.Sprintf("[!] No network service mapping found for %s; configd may still manage this interface.", iface.Name))
	}
	b.restoreActions = append(b.restoreActions, action)

	if _, err := b.runLogged("interface down", "ifconfig", iface.Name, "down"); err != nil {
		return fmt.Errorf("bringing %s down: %w", iface.Name, err)
	}

	for _, ip := range interfaceIPs(iface) {
		if ip.To4() != nil {
			if _, err := b.runLogged("remove IPv4 address", "ifconfig", iface.Name, "inet", ip.String(), "delete"); err != nil {
				b.logRecon(fmt.Sprintf("[!] Could not remove IPv4 %s from %s: %v", ip.String(), iface.Name, err))
			}
			continue
		}
		if ip.To16() != nil {
			if _, err := b.runLogged("remove IPv6 address", "ifconfig", iface.Name, "inet6", ip.String(), "-alias"); err != nil {
				b.logRecon(fmt.Sprintf("[!] Could not remove IPv6 %s from %s: %v", ip.String(), iface.Name, err))
			}
		}
	}

	return nil
}

func interfaceAddrStrings(iface NetInterface) []string {
	addrs := iface.Addrs
	if len(addrs) == 0 {
		if ni, err := net.InterfaceByName(iface.Name); err == nil {
			if live, err := ni.Addrs(); err == nil {
				for _, addr := range live {
					addrs = append(addrs, addr.String())
				}
			}
		}
	}
	return append([]string(nil), addrs...)
}

func interfaceIPs(iface NetInterface) []net.IP {
	addrs := interfaceAddrStrings(iface)

	var ips []net.IP
	for _, raw := range addrs {
		ipStr := raw
		if ip, _, err := net.ParseCIDR(raw); err == nil {
			ips = append(ips, normalizeScopedIP(ip, iface.Name))
			continue
		}
		if idx := strings.Index(ipStr, "/"); idx != -1 {
			ipStr = ipStr[:idx]
		}
		if ip := net.ParseIP(strings.TrimSpace(ipStr)); ip != nil {
			ips = append(ips, normalizeScopedIP(ip, iface.Name))
		}
	}
	return ips
}

func normalizeScopedIP(ip net.IP, _ string) net.IP {
	// net.ParseCIDR drops the textual IPv6 scope. Link-local IPv6 aliases on
	// macOS require the scope when deleting, so this helper intentionally leaves
	// parsed IPs unchanged and the delete path treats failures as diagnostic.
	return ip
}

func manualIPv4RestoreArgs(addrs []string) [][]string {
	var restored [][]string
	for _, raw := range addrs {
		ip, ipNet, err := net.ParseCIDR(raw)
		if err != nil || ip.To4() == nil || ipNet == nil {
			continue
		}
		mask := dottedIPv4Mask(ipNet.Mask)
		if mask == "" {
			continue
		}
		restored = append(restored, []string{ip.String(), "netmask", mask, "alias"})
	}
	return restored
}

func dottedIPv4Mask(mask net.IPMask) string {
	if len(mask) == net.IPv6len {
		mask = mask[12:]
	}
	if len(mask) != net.IPv4len {
		return ""
	}
	return net.IP(mask).String()
}

func (b *Bridge) logRecon(msg string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.reconLogs = append(b.reconLogs, msg)
}

func (b *Bridge) setState(state BridgeState) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.state = state
}

func (b *Bridge) runLogged(step, name string, args ...string) (string, error) {
	out, err := runCmd(name, args...)
	result := CommandResult{
		Step:    step,
		Command: append([]string{name}, args...),
		Output:  strings.TrimSpace(out),
		OK:      err == nil,
	}
	if err != nil {
		result.Err = err.Error()
	}
	b.mu.Lock()
	b.commandLogs = append(b.commandLogs, result)
	b.reconLogs = append(b.reconLogs, result.Summary())
	b.mu.Unlock()
	return out, err
}

func (b *Bridge) setupError(err error) error {
	if err == nil {
		return nil
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	return &SetupError{
		Err:         err,
		ReconLogs:   append([]string(nil), b.reconLogs...),
		CommandLogs: append([]CommandResult(nil), b.commandLogs...),
	}
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
	status := BridgeStatus{
		Name:        b.name,
		IfaceA:      b.ifaceA,
		IfaceB:      b.ifaceB,
		State:       b.state,
		TargetID:    b.targetID,
		ReconLogs:   append([]string(nil), b.reconLogs...), // copy so UI slice is safe
		CommandLogs: append([]CommandResult(nil), b.commandLogs...),
	}
	b.mu.Unlock()

	if b.name != "" {
		out, err := runCmd("ifconfig", b.name)
		if err == nil {
			status.RawInfo = out
		}
	}
	if b.ifaceA != "" {
		out, err := runCmd("ifconfig", b.ifaceA)
		if err == nil {
			status.IfaceAInfo = out
		}
	}
	if b.ifaceB != "" {
		out, err := runCmd("ifconfig", b.ifaceB)
		if err == nil {
			status.IfaceBInfo = out
		}
	}

	return status
}

// Destroy tears down the bridge, removes members, and restores touched host state.
func (b *Bridge) Destroy() error {
	return b.destroy()
}

// destroy is the internal teardown.
func (b *Bridge) destroy() error {
	if b.cancelSniffer != nil {
		b.cancelSniffer()
	}

	var errs []string

	if b.name != "" {
		// On macOS, destroying the bridge interface automatically unbinds all members.
		if _, err := b.runLogged("destroy bridge", "ifconfig", b.name, "destroy"); err != nil {
			errs = append(errs, fmt.Sprintf("destroying %s: %v", b.name, err))
		}
	}

	for _, action := range b.restoreActions {
		if action.iface.PermanentMAC != "" {
			if _, err := b.runLogged("restore adapter MAC", "ifconfig", action.iface.Name, "ether", action.iface.PermanentMAC); err != nil {
				errs = append(errs, fmt.Sprintf("restoring MAC on %s: %v", action.iface.Name, err))
			}
		}
		if action.serviceTouched && action.iface.NetworkService != "" {
			if _, err := b.runLogged("restore network service", "networksetup", "-setnetworkserviceenabled", action.iface.NetworkService, "on"); err != nil {
				errs = append(errs, fmt.Sprintf("restoring service %s: %v", action.iface.NetworkService, err))
			}
		}
		if action.iface.NetworkService == "" {
			for _, addr := range manualIPv4RestoreArgs(action.manualAddrs) {
				args := append([]string{action.iface.Name, "inet"}, addr...)
				if _, err := b.runLogged("restore manual IPv4 address", "ifconfig", args...); err != nil {
					errs = append(errs, fmt.Sprintf("restoring IPv4 on %s: %v", action.iface.Name, err))
				}
			}
		}
		if action.iface.IsUp {
			if _, err := b.runLogged("restore interface up", "ifconfig", action.iface.Name, "up"); err != nil {
				errs = append(errs, fmt.Sprintf("restoring %s up: %v", action.iface.Name, err))
			}
		}
	}

	b.setState(BridgeStateDown)

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
			info, err := runCmd("ifconfig", name)
			if err != nil {
				continue
			}
			if !strings.Contains(info, "description: goLAN") {
				continue
			}
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
