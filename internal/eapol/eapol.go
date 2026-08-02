// Package eapol provides 802.1X (EAP over LAN) protocol handling for golan.
//
// It implements EAPOL frame detection, transparent relay between a supplicant
// (real device) and an authenticator (switch), and MACsec downgrade logic.
package eapol

import (
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/google/gopacket/pcap"
)

// ─── EAPOL Protocol Constants ───────────────────────────────────────────────

// All EAPOL frames use the IEEE 802.1X PAE multicast destination.
var paeGroupAddress = [6]byte{0x01, 0x80, 0xc2, 0x00, 0x00, 0x03}

// BPFFilter captures all EAPOL frames on a raw interface.
const BPFFilter = "(ether proto 0x888e) or (vlan and ether proto 0x888e)"

// ─── State Machine ─────────────────────────────────────────────────────────

// State represents the current 802.1X authentication state.
type State int

// EAPOL session states run from idle detection through optional downgrade.
const (
	StateIdle           State = iota // No 802.1X activity detected
	StateDetecting                   // Listening for EAPOL frames
	StateRelaying                    // Actively relaying EAPOL between supplicant and authenticator
	StateAuthenticated               // EAP-Success received, port is open
	StateFailed                      // EAP-Failure received
	StateMACsecDetected              // MACsec negotiation detected
	StateDowngrading                 // Attempting MACsec downgrade
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

// EAP method constants identify the authentication method observed on the wire.
const (
	MethodUnknown  EAPMethod = "Unknown"
	MethodIdentity EAPMethod = "Identity"
	MethodMD5      EAPMethod = "EAP-MD5"
	MethodTLS      EAPMethod = "EAP-TLS"
	MethodPEAP     EAPMethod = "PEAP"
	MethodTTLS     EAPMethod = "EAP-TTLS"
	MethodFAST     EAPMethod = "EAP-FAST"
	MethodLEAP     EAPMethod = "LEAP"
	MethodMSCHAPv2 EAPMethod = "EAP-MSCHAPv2"
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
	case 26:
		return MethodMSCHAPv2
	default:
		return MethodUnknown
	}
}

// ─── Auth Session ───────────────────────────────────────────────────────────

// AuthSession tracks the state of an ongoing 802.1X authentication exchange.
type AuthSession struct {
	mu sync.Mutex

	state            State
	supplicantMAC    net.HardwareAddr
	authenticatorMAC net.HardwareAddr
	vlanID           uint16
	method           EAPMethod
	macsecDetected   bool

	framesRelayed int
	framesDropped int
	reauthCount   int
	lastEAPID     uint8
	lastActivity  time.Time

	startedAt       time.Time
	authenticatedAt time.Time
}

// NewAuthSession creates a fresh session for the given supplicant.
func NewAuthSession(supplicantMAC net.HardwareAddr) *AuthSession {
	return &AuthSession{
		state:         StateIdle,
		supplicantMAC: copyMAC(supplicantMAC),
		method:        MethodUnknown,
		startedAt:     time.Now(),
		lastActivity:  time.Now(),
	}
}

// SetState updates the session state thread-safely.
func (s *AuthSession) SetState(state State) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.state = state
	s.lastActivity = time.Now()
}

// GetState returns the current state thread-safely.
func (s *AuthSession) GetState() State {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.state
}

// RecordRelay increments the relay counter.
func (s *AuthSession) RecordRelay() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.framesRelayed++
	s.lastActivity = time.Now()
}

// RecordDrop increments the drop counter.
func (s *AuthSession) RecordDrop() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.framesDropped++
	s.lastActivity = time.Now()
}

// MarkAuthenticated transitions to authenticated state.
func (s *AuthSession) MarkAuthenticated() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.state = StateAuthenticated
	s.authenticatedAt = time.Now()
	s.lastActivity = time.Now()
}

// MarkFailed transitions to failed state.
func (s *AuthSession) MarkFailed() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.state = StateFailed
	s.lastActivity = time.Now()
}

// Snapshot returns a thread-safe copy of the session status.
func (s *AuthSession) Snapshot() AuthSessionSnapshot {
	s.mu.Lock()
	defer s.mu.Unlock()
	return AuthSessionSnapshot{
		State:            s.state,
		SupplicantMAC:    copyMAC(s.supplicantMAC),
		AuthenticatorMAC: copyMAC(s.authenticatorMAC),
		VLANID:           s.vlanID,
		Method:           s.method,
		MACsecDetected:   s.macsecDetected,
		FramesRelayed:    s.framesRelayed,
		FramesDropped:    s.framesDropped,
		ReauthCount:      s.reauthCount,
		LastEAPID:        s.lastEAPID,
		LastActivity:     s.lastActivity,
		StartedAt:        s.startedAt,
		AuthenticatedAt:  s.authenticatedAt,
	}
}

// AuthSessionSnapshot is an immutable copy of AuthSession for safe TUI reads.
type AuthSessionSnapshot struct {
	State            State
	SupplicantMAC    net.HardwareAddr
	AuthenticatorMAC net.HardwareAddr
	VLANID           uint16
	Method           EAPMethod
	MACsecDetected   bool
	FramesRelayed    int
	FramesDropped    int
	ReauthCount      int
	LastEAPID        uint8
	LastActivity     time.Time
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

// InjectEAPOLStartWithVLAN crafts and injects an EAPOL-Start frame. If vlanID
// is non-zero, the Ethernet frame includes an 802.1Q tag.
func InjectEAPOLStartWithVLAN(iface string, supplicantMAC net.HardwareAddr, vlanID uint16, logFunc func(string)) error {
	iface = strings.TrimSpace(iface)
	if iface == "" {
		return fmt.Errorf("EAPOL-Start interface is required")
	}
	if !validUnicastMAC(supplicantMAC) {
		return fmt.Errorf("EAPOL-Start requires a 48-bit unicast supplicant MAC")
	}
	if vlanID > 4094 {
		return fmt.Errorf("EAPOL-Start VLAN %d is outside 1-4094", vlanID)
	}
	if logFunc == nil {
		logFunc = func(string) {}
	}

	handle, err := pcap.OpenLive(iface, 65535, true, time.Second)
	if err != nil {
		return fmt.Errorf("opening %s for EAPOL-Start injection: %w", iface, err)
	}
	defer handle.Close()

	frameLen := 18
	if vlanID != 0 {
		frameLen = 22
	}
	frame := make([]byte, frameLen)

	copy(frame[0:6], paeGroupAddress[:])
	copy(frame[6:12], supplicantMAC)

	offset := 12
	if vlanID != 0 {
		frame[12] = 0x81
		frame[13] = 0x00
		tci := vlanID & 0x0fff
		frame[14] = byte(tci >> 8)
		frame[15] = byte(tci)
		offset = 16
	}

	frame[offset] = 0x88
	frame[offset+1] = 0x8E
	frame[offset+2] = 0x02
	frame[offset+3] = 0x01
	frame[offset+4] = 0x00
	frame[offset+5] = 0x00

	if err := handle.WritePacketData(frame); err != nil {
		return fmt.Errorf("injecting EAPOL-Start on %s: %w", iface, err)
	}

	if vlanID != 0 {
		logFunc(fmt.Sprintf("[*][802.1X] Injected VLAN %d EAPOL-Start on %s (src: %s)", vlanID, iface, supplicantMAC))
	} else {
		logFunc(fmt.Sprintf("[*][802.1X] Injected EAPOL-Start on %s (src: %s)", iface, supplicantMAC))
	}
	return nil
}
