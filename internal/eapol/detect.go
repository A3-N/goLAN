package eapol

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// DetectResult holds the outcome of passive 802.1X detection on a wire.
type DetectResult struct {
	Detected         bool              // Whether any EAPOL frames were seen
	AuthenticatorMAC net.HardwareAddr  // MAC of the switch sending EAPOL
	EAPMethod        EAPMethod         // If determinable from initial exchange
	MACsecCapable    bool              // If EAPOL-Key MKA frames were detected
	FramesSeen       int               // Number of EAPOL frames observed
}

// Detector passively listens on an interface for 802.1X activity.
type Detector struct {
	iface string
}

// NewDetector creates a new 802.1X detector for the given interface.
func NewDetector(iface string) *Detector {
	return &Detector{iface: iface}
}

// Detect passively listens for EAPOL frames on the interface for up to `timeout`.
// It returns as soon as an EAPOL frame is seen, or after the timeout expires.
// The logFunc callback is used to stream events to the TUI.
func (d *Detector) Detect(ctx context.Context, timeout time.Duration, logFunc func(string)) (*DetectResult, error) {
	if logFunc == nil {
		logFunc = func(string) {}
	}

	result := &DetectResult{}

	logFunc(fmt.Sprintf("[802.1X] Passive EAPOL detection on %s (timeout: %s)", d.iface, timeout))

	handle, err := pcap.OpenLive(d.iface, 65535, true, pcap.BlockForever)
	if err != nil {
		return nil, fmt.Errorf("opening %s for EAPOL detection: %w", d.iface, err)
	}
	defer handle.Close()

	// Only capture EAPOL frames (EtherType 0x888E).
	if err := handle.SetBPFFilter(BPFFilter); err != nil {
		return nil, fmt.Errorf("setting BPF filter for EAPOL: %w", err)
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packets := packetSource.Packets()

	timer := time.NewTimer(timeout)
	defer timer.Stop()

	for {
		select {
		case <-ctx.Done():
			logFunc("[802.1X] Detection cancelled.")
			return result, ctx.Err()

		case <-timer.C:
			if result.FramesSeen == 0 {
				logFunc("[802.1X] No EAPOL frames detected. Network is not 802.1X protected.")
			}
			return result, nil

		case packet := <-packets:
			if packet == nil {
				continue
			}

			ethLayer := packet.Layer(layers.LayerTypeEthernet)
			if ethLayer == nil {
				continue
			}
			eth, _ := ethLayer.(*layers.Ethernet)

			// Any EAPOL frame means 802.1X is active.
			eapolLayer := packet.Layer(layers.LayerTypeEAPOL)
			if eapolLayer == nil {
				continue
			}

			eapol, _ := eapolLayer.(*layers.EAPOL)
			result.FramesSeen++
			result.Detected = true

			// Capture the authenticator MAC (the side sending EAPOL toward us).
			if len(result.AuthenticatorMAC) == 0 {
				result.AuthenticatorMAC = eth.SrcMAC
				logFunc(fmt.Sprintf("[802.1X] ● Authenticator detected: %s", eth.SrcMAC))
			}

			// Classify what kind of EAPOL it is.
			switch eapol.Type {
			case layers.EAPOLTypeEAP:
				// Dig into the EAP layer for method detection.
				eapLayer := packet.Layer(layers.LayerTypeEAP)
				if eapLayer != nil {
					eap, _ := eapLayer.(*layers.EAP)
					if eap.Code == layers.EAPCodeRequest && result.EAPMethod == MethodUnknown {
						method := eapTypeToMethod(uint8(eap.Type))
						if method != MethodUnknown && method != MethodIdentity {
							result.EAPMethod = method
							logFunc(fmt.Sprintf("[802.1X] EAP method detected: %s", method))
						}
					}
				}
				logFunc(fmt.Sprintf("[802.1X] EAPOL-EAP frame from %s (ver:%d, len:%d)", eth.SrcMAC, eapol.Version, eapol.Length))

			case layers.EAPOLTypeStart:
				logFunc(fmt.Sprintf("[802.1X] EAPOL-Start from %s", eth.SrcMAC))

			case layers.EAPOLTypeLogOff:
				logFunc(fmt.Sprintf("[802.1X] EAPOL-Logoff from %s", eth.SrcMAC))

			case layers.EAPOLTypeKey:
				// EAPOL-Key frames may indicate MACsec (MKA) negotiation.
				result.MACsecCapable = true
				logFunc(fmt.Sprintf("[MACSEC] EAPOL-Key/MKA frame detected from %s", eth.SrcMAC))

			default:
				logFunc(fmt.Sprintf("[802.1X] Unknown EAPOL type %d from %s", eapol.Type, eth.SrcMAC))
			}

			// Once we've confirmed detection, return immediately so the caller
			// can transition to relay mode without waiting for the full timeout.
			if result.FramesSeen >= 1 {
				logFunc("[802.1X] ✓ 802.1X is active on this port. Transitioning to relay mode.")
				return result, nil
			}
		}
	}
}
