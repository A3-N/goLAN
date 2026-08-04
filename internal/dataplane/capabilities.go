package dataplane

import (
	"fmt"
	"sort"
	"strings"
)

// Mode identifies one live data-plane path.
type Mode string

// Modes are stable values used by policies, manifests, and the Workbench.
const (
	ModeListen           Mode = "listen"
	ModeFastBridge       Mode = "fast-bridge"
	ModeControlledBridge Mode = "controlled-bridge"
	ModeNAT              Mode = "nat"
	ModeEdgeObserve      Mode = "edge-observe"
	ModeEdgeRoute        Mode = "edge-route"
)

// Modes returns every documented data plane in stable Workbench order.
func Modes() []Mode {
	return []Mode{
		ModeListen,
		ModeFastBridge,
		ModeControlledBridge,
		ModeNAT,
		ModeEdgeObserve,
		ModeEdgeRoute,
	}
}

// Capability names a policy operation or an owned session-level network
// function that a data plane may enforce.
type Capability string

// Capabilities separate evaluability from enforcement support.
const (
	CapabilityObserve          Capability = "observe"
	CapabilityFrameFilter      Capability = "frame-filter"
	CapabilityStatefulFilter   Capability = "stateful-filter"
	CapabilityRewriteEthernet  Capability = "rewrite-ethernet"
	CapabilityRewriteIP        Capability = "rewrite-ip"
	CapabilityRewriteTransport Capability = "rewrite-transport"
	CapabilityRewritePayload   Capability = "rewrite-payload-same-length"
	CapabilityNAT              Capability = "nat"
	CapabilityRedirect         Capability = "redirect"
	CapabilityPortForward      Capability = "port-forward"
	CapabilityTrafficShape     Capability = "traffic-shape"
)

// Status reports whether a matching rule is enforced, evaluated only, or not
// meaningful on the active data plane.
type Status string

// Rule status values are intentionally uppercase for unambiguous UI display.
const (
	StatusLive        Status = "LIVE"
	StatusShadow      Status = "SHADOW"
	StatusUnsupported Status = "UNSUPPORTED"
)

// Capabilities is an immutable mode capability matrix.
type Capabilities struct {
	mode    Mode
	support map[Capability]Status
}

// ForMode returns the documented capabilities for mode.
func ForMode(mode Mode) Capabilities {
	c := Capabilities{mode: mode, support: make(map[Capability]Status)}
	c.support[CapabilityObserve] = StatusLive
	shadow := func(values ...Capability) {
		for _, value := range values {
			c.support[value] = StatusShadow
		}
	}
	live := func(values ...Capability) {
		for _, value := range values {
			c.support[value] = StatusLive
		}
	}
	unsupported := func(values ...Capability) {
		for _, value := range values {
			c.support[value] = StatusUnsupported
		}
	}

	allEnforcement := []Capability{
		CapabilityFrameFilter, CapabilityStatefulFilter,
		CapabilityRewriteEthernet, CapabilityRewriteIP,
		CapabilityRewriteTransport, CapabilityRewritePayload,
		CapabilityNAT, CapabilityRedirect,
		CapabilityPortForward, CapabilityTrafficShape,
	}
	switch mode {
	case ModeListen, ModeEdgeObserve:
		shadow(allEnforcement...)
	case ModeFastBridge:
		live(CapabilityFrameFilter, CapabilityStatefulFilter)
		shadow(CapabilityRewriteEthernet, CapabilityRewriteIP,
			CapabilityRewriteTransport, CapabilityRewritePayload,
			CapabilityTrafficShape, CapabilityRedirect)
		unsupported(CapabilityNAT, CapabilityPortForward)
	case ModeControlledBridge:
		live(CapabilityFrameFilter, CapabilityRewriteEthernet,
			CapabilityRewriteIP, CapabilityRewriteTransport, CapabilityRewritePayload,
			CapabilityTrafficShape)
		shadow(CapabilityStatefulFilter, CapabilityRedirect)
		unsupported(CapabilityNAT, CapabilityPortForward)
	case ModeNAT:
		live(CapabilityStatefulFilter)
		shadow(CapabilityFrameFilter, CapabilityRewritePayload,
			CapabilityTrafficShape)
		unsupported(CapabilityRedirect)
		unsupported(CapabilityRewriteEthernet, CapabilityRewriteIP,
			CapabilityRewriteTransport, CapabilityNAT, CapabilityPortForward)
	case ModeEdgeRoute:
		live(CapabilityStatefulFilter, CapabilityNAT, CapabilityPortForward)
		shadow(CapabilityFrameFilter,
			CapabilityRedirect, CapabilityTrafficShape)
		unsupported(CapabilityRewriteEthernet, CapabilityRewriteIP,
			CapabilityRewriteTransport, CapabilityRewritePayload)
	default:
		c.mode = ""
		unsupported(allEnforcement...)
	}
	return c
}

// New creates a custom immutable capability matrix for tests or a future data
// plane. Missing capabilities are UNSUPPORTED.
func New(mode Mode, support map[Capability]Status) (Capabilities, error) {
	if strings.TrimSpace(string(mode)) == "" {
		return Capabilities{}, fmt.Errorf("data plane mode is required")
	}
	copySupport := make(map[Capability]Status, len(support))
	for capability, status := range support {
		if strings.TrimSpace(string(capability)) == "" {
			return Capabilities{}, fmt.Errorf("capability name is required")
		}
		switch status {
		case StatusLive, StatusShadow, StatusUnsupported:
		default:
			return Capabilities{}, fmt.Errorf("capability %s has invalid status %q", capability, status)
		}
		copySupport[capability] = status
	}
	return Capabilities{mode: mode, support: copySupport}, nil
}

// Mode returns the data plane mode.
func (c Capabilities) Mode() Mode {
	return c.mode
}

// Support returns the explicit status for capability.
func (c Capabilities) Support(capability Capability) Status {
	if status, ok := c.support[capability]; ok {
		return status
	}
	return StatusUnsupported
}

// Snapshot returns a copy of the matrix.
func (c Capabilities) Snapshot() map[Capability]Status {
	out := make(map[Capability]Status, len(c.support))
	for capability, status := range c.support {
		out[capability] = status
	}
	return out
}

// Summary returns stable capability=status strings for diagnostics.
func (c Capabilities) Summary() []string {
	keys := make([]string, 0, len(c.support))
	for capability := range c.support {
		keys = append(keys, string(capability))
	}
	sort.Strings(keys)
	out := make([]string, 0, len(keys))
	for _, key := range keys {
		out = append(out, key+"="+string(c.support[Capability(key)]))
	}
	return out
}
