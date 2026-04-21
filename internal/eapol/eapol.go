// Package eapol provides 802.1X (EAP over LAN) protocol handling for goLAN.
//
// It implements EAPOL frame detection, transparent relay between a supplicant
// (real device) and an authenticator (switch), and MACsec downgrade logic.
package eapol

import (
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/google/gopacket/pcap"
)

// ─── EAPOL Protocol Constants ───────────────────────────────────────────────

// PAEGroupAddr is the IEEE 802.1X PAE (Port Access Entity) multicast address.
// All EAPOL frames are sent to this well-known destination.
var PAEGroupAddr = net.HardwareAddr{0x01, 0x80, 0xc2, 0x00, 0x00, 0x03}

// BPFFilter captures all EAPOL frames on a raw interface.
const BPFFilter = "ether proto 0x888e"

// ─── State Machine ─────────────────────────────────────────────────────────

// State represents the current 802.1X authentication state.
type State int

const (
	StateIdle            State = iota // No 802.1X activity detected
	StateDetecting                    // Listening for EAPOL frames
	StateRelaying                     // Actively relaying EAPOL between supplicant and authenticator
	StateAuthenticated                // EAP-Success received, port is open
	StateFailed                       // EAP-Failure received
	StateMACsecDetected               // MACsec negotiation detected
	StateDowngrading                  // Attempting MACsec downgrade
)

func (s State) String() string {
	switch s {
	case StateIdle:
		return "Idle"
	case StateDetecting:
		return "Detecting"
	case StateRelaying:
		return "Relaying"
	case StateAuthenticated:
		return "Authenticated"
	case StateFailed:
		return "Failed"
	case StateMACsecDetected:
		return "MACsec Detected"
	case StateDowngrading:
		return "Downgrading"
	default:
		return "Unknown"
	}
}

// ─── EAP Method Tracking ────────────────────────────────────────────────────

// EAPMethod represents the detected EAP authentication method.
type EAPMethod string

const (
	MethodUnknown EAPMethod = "Unknown"
	MethodIdentity EAPMethod = "Identity"
	MethodMD5     EAPMethod = "EAP-MD5"
	MethodTLS     EAPMethod = "EAP-TLS"
	MethodPEAP    EAPMethod = "PEAP"
	MethodTTLS    EAPMethod = "EAP-TTLS"
	MethodFAST    EAPMethod = "EAP-FAST"
	MethodLEAP    EAPMethod = "LEAP"
	MethodMSCHAPv2 EAPMethod = "MSCHAPv2"
)

// eapTypeToMethod maps the EAP Type field (from RFC) to our method names.
// gopacket's layers.EAPType only defines up to 5, so we handle extended types manually.
func eapTypeToMethod(eapType uint8) EAPMethod {
	switch eapType {
	case 1:
		return MethodIdentity
	case 4:
		return MethodMD5
	case 13:
		return MethodTLS
	case 21:
		return MethodTTLS
	case 25:
		return MethodPEAP
	case 43:
		return MethodFAST
	case 17:
		return MethodLEAP
	case 29:
		return MethodMSCHAPv2
	default:
		return MethodUnknown
	}
}

// ─── Auth Session ───────────────────────────────────────────────────────────

// AuthSession tracks the state of an ongoing 802.1X authentication exchange.
type AuthSession struct {
	mu sync.Mutex

	State            State
	SupplicantMAC    net.HardwareAddr // MAC of the real device (supplicant)
	AuthenticatorMAC net.HardwareAddr // MAC of the switch (authenticator)
	Method           EAPMethod        // Detected EAP method
	MACsecDetected   bool             // Whether MACsec key negotiation was seen

	// Counters
	FramesRelayed  int // Total EAPOL frames forwarded
	FramesDropped  int // Frames dropped (e.g. MACsec downgrade)
	ReauthCount    int // Number of re-authentications handled
	LastEAPID      uint8
	LastActivity   time.Time

	// Timing
	StartedAt      time.Time
	AuthenticatedAt time.Time
}

// NewAuthSession creates a fresh session for the given supplicant.
func NewAuthSession(supplicantMAC net.HardwareAddr) *AuthSession {
	return &AuthSession{
		State:         StateIdle,
		SupplicantMAC: supplicantMAC,
		Method:        MethodUnknown,
		StartedAt:     time.Now(),
		LastActivity:  time.Now(),
	}
}

// SetState updates the session state thread-safely.
func (s *AuthSession) SetState(state State) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.State = state
	s.LastActivity = time.Now()
}

// GetState returns the current state thread-safely.
func (s *AuthSession) GetState() State {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.State
}

// RecordRelay increments the relay counter.
func (s *AuthSession) RecordRelay() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.FramesRelayed++
	s.LastActivity = time.Now()
}

// RecordDrop increments the drop counter.
func (s *AuthSession) RecordDrop() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.FramesDropped++
	s.LastActivity = time.Now()
}

// MarkAuthenticated transitions to authenticated state.
func (s *AuthSession) MarkAuthenticated() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.State = StateAuthenticated
	s.AuthenticatedAt = time.Now()
	s.LastActivity = time.Now()
}

// MarkFailed transitions to failed state.
func (s *AuthSession) MarkFailed() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.State = StateFailed
	s.LastActivity = time.Now()
}

// Snapshot returns a thread-safe copy of the session status.
func (s *AuthSession) Snapshot() AuthSessionSnapshot {
	s.mu.Lock()
	defer s.mu.Unlock()
	return AuthSessionSnapshot{
		State:            s.State,
		SupplicantMAC:    s.SupplicantMAC,
		AuthenticatorMAC: s.AuthenticatorMAC,
		Method:           s.Method,
		MACsecDetected:   s.MACsecDetected,
		FramesRelayed:    s.FramesRelayed,
		FramesDropped:    s.FramesDropped,
		ReauthCount:      s.ReauthCount,
		StartedAt:        s.StartedAt,
		AuthenticatedAt:  s.AuthenticatedAt,
	}
}

// AuthSessionSnapshot is an immutable copy of AuthSession for safe TUI reads.
type AuthSessionSnapshot struct {
	State            State
	SupplicantMAC    net.HardwareAddr
	AuthenticatorMAC net.HardwareAddr
	Method           EAPMethod
	MACsecDetected   bool
	FramesRelayed    int
	FramesDropped    int
	ReauthCount      int
	StartedAt        time.Time
	AuthenticatedAt  time.Time
}

// ─── Auth Result ────────────────────────────────────────────────────────────

// AuthResult is the final outcome of an authentication attempt.
type AuthResult struct {
	Success        bool
	Method         EAPMethod
	MACsecDetected bool
	Error          error
}

func (r AuthResult) String() string {
	if r.Success {
		return fmt.Sprintf("Authenticated via %s", r.Method)
	}
	if r.Error != nil {
		return fmt.Sprintf("Failed: %v", r.Error)
	}
	return "Failed"
}

// ─── EAPOL-Start Injection ──────────────────────────────────────────────────

// InjectEAPOLStart crafts and injects a synthetic EAPOL-Start frame on the given
// interface using the provided supplicant MAC. This "pokes" the authenticator
// (switch) into sending an EAP-Request/Identity if it's waiting for an
// EAPOL-Start before initiating authentication.
//
// Frame format:
//
//	Dst: 01:80:c2:00:00:03 (PAE group address)
//	Src: supplicantMAC
//	EtherType: 0x888E (EAPOL)
//	EAPOL Version: 2
//	EAPOL Type: 1 (Start)
//	EAPOL Length: 0
func InjectEAPOLStart(iface string, supplicantMAC net.HardwareAddr, logFunc func(string)) error {
	if logFunc == nil {
		logFunc = func(string) {}
	}

	handle, err := pcap.OpenLive(iface, 65535, true, time.Second)
	if err != nil {
		return fmt.Errorf("opening %s for EAPOL-Start injection: %w", iface, err)
	}
	defer handle.Close()

	// Build the raw Ethernet + EAPOL-Start frame.
	// Ethernet header: 14 bytes (dst[6] + src[6] + type[2])
	// EAPOL header: 4 bytes (version[1] + type[1] + length[2])
	frame := make([]byte, 18)

	// Destination: PAE group multicast address
	copy(frame[0:6], PAEGroupAddr)
	// Source: supplicant MAC
	copy(frame[6:12], supplicantMAC)
	// EtherType: 0x888E (EAPOL)
	frame[12] = 0x88
	frame[13] = 0x8E
	// EAPOL Version: 2
	frame[14] = 0x02
	// EAPOL Type: 1 (Start)
	frame[15] = 0x01
	// EAPOL Length: 0 (no body)
	frame[16] = 0x00
	frame[17] = 0x00

	if err := handle.WritePacketData(frame); err != nil {
		return fmt.Errorf("injecting EAPOL-Start on %s: %w", iface, err)
	}

	logFunc(fmt.Sprintf("[*][802.1X] Injected EAPOL-Start on %s (src: %s)", iface, supplicantMAC))
	return nil
}
