package traffic

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
)

// FlowID is stable for both directions of one endpoint pair.
type FlowID string

// FlowState is the observed transport lifecycle.
type FlowState string

// Flow state values are conservative; packet loss may leave a flow in a less
// advanced state but never causes an impossible transition.
const (
	FlowStateUnknown     FlowState = "unknown"
	FlowStateNew         FlowState = "new"
	FlowStateEstablished FlowState = "established"
	FlowStateClosing     FlowState = "closing"
	FlowStateClosed      FlowState = "closed"
)

// Endpoint is a normalized network endpoint.
type Endpoint struct {
	IP   string `json:"ip,omitempty"`
	Port uint16 `json:"port,omitempty"`
	MAC  string `json:"mac,omitempty"`
}

// Flow is an immutable tracker snapshot.
type Flow struct {
	ID             FlowID            `json:"id"`
	EndpointA      Endpoint          `json:"endpoint_a"`
	EndpointB      Endpoint          `json:"endpoint_b"`
	Protocol       uint8             `json:"protocol"`
	State          FlowState         `json:"state"`
	Packets        uint64            `json:"packets"`
	Bytes          uint64            `json:"bytes"`
	FirstSeen      time.Time         `json:"first_seen"`
	LastSeen       time.Time         `json:"last_seen"`
	DirectionCount map[Direction]int `json:"direction_count,omitempty"`
}

// Tracker owns bounded mutable flow state and returns immutable snapshots.
type Tracker struct {
	mu       sync.Mutex
	maxFlows int
	flows    map[FlowID]*trackedFlow
}

type trackedFlow struct {
	flow Flow
}

// NewTracker creates a tracker capped at maxFlows. When full, the least
// recently seen flow is evicted before a new flow is admitted.
func NewTracker(maxFlows int) *Tracker {
	if maxFlows <= 0 {
		maxFlows = 4096
	}
	return &Tracker{maxFlows: maxFlows, flows: make(map[FlowID]*trackedFlow)}
}

// Observe merges frame counters and transport state, then returns a snapshot.
func (t *Tracker) Observe(frame Frame) Flow {
	if t == nil {
		return Flow{}
	}
	decoded := frame.Decoded()
	a := Endpoint{IP: decoded.SrcIP, Port: decoded.SrcPort, MAC: decoded.SrcMAC}
	b := Endpoint{IP: decoded.DstIP, Port: decoded.DstPort, MAC: decoded.DstMAC}
	canonicalA, canonicalB := canonicalEndpoints(a, b)
	id := flowID(decoded.IPProtocol, canonicalA, canonicalB)

	t.mu.Lock()
	defer t.mu.Unlock()
	tracked := t.flows[id]
	if tracked == nil {
		if len(t.flows) >= t.maxFlows {
			t.evictOldest()
		}
		state := FlowStateNew
		if decoded.IPProtocol == 0 {
			state = FlowStateUnknown
		}
		tracked = &trackedFlow{flow: Flow{
			ID:             id,
			EndpointA:      canonicalA,
			EndpointB:      canonicalB,
			Protocol:       decoded.IPProtocol,
			State:          state,
			FirstSeen:      frame.Timestamp,
			DirectionCount: make(map[Direction]int),
		}}
		t.flows[id] = tracked
	}
	tracked.flow.Packets++
	tracked.flow.Bytes += uint64(len(frame.raw))
	tracked.flow.LastSeen = frame.Timestamp
	if tracked.flow.FirstSeen.IsZero() || (!frame.Timestamp.IsZero() && frame.Timestamp.Before(tracked.flow.FirstSeen)) {
		tracked.flow.FirstSeen = frame.Timestamp
	}
	tracked.flow.DirectionCount[frame.Direction]++
	tracked.flow.State = nextFlowState(tracked.flow.State, decoded)
	return cloneFlow(tracked.flow)
}

// Snapshot returns all flows sorted by ID.
func (t *Tracker) Snapshot() []Flow {
	if t == nil {
		return nil
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	ids := make([]string, 0, len(t.flows))
	for id := range t.flows {
		ids = append(ids, string(id))
	}
	sort.Strings(ids)
	out := make([]Flow, 0, len(ids))
	for _, value := range ids {
		tracked := t.flows[FlowID(value)]
		out = append(out, cloneFlow(tracked.flow))
	}
	return out
}

func (t *Tracker) evictOldest() {
	var oldest FlowID
	var timestamp time.Time
	for id, tracked := range t.flows {
		if oldest == "" || tracked.flow.LastSeen.Before(timestamp) || (tracked.flow.LastSeen.Equal(timestamp) && id < oldest) {
			oldest = id
			timestamp = tracked.flow.LastSeen
		}
	}
	delete(t.flows, oldest)
}

func canonicalEndpoints(a, b Endpoint) (Endpoint, Endpoint) {
	if endpointKey(a) <= endpointKey(b) {
		return a, b
	}
	return b, a
}

func endpointKey(endpoint Endpoint) string {
	return strings.ToLower(fmt.Sprintf("%s\x00%05d\x00%s", endpoint.IP, endpoint.Port, endpoint.MAC))
}

func flowID(protocol uint8, a, b Endpoint) FlowID {
	sum := sha256.Sum256([]byte(fmt.Sprintf("%d\x00%s\x00%s", protocol, endpointKey(a), endpointKey(b))))
	return FlowID(hex.EncodeToString(sum[:12]))
}

func nextFlowState(current FlowState, decoded DecodedFields) FlowState {
	if decoded.IPProtocol != 6 {
		if current == FlowStateUnknown {
			return FlowStateNew
		}
		return current
	}
	flags := uint16(decoded.TCPFlags)
	const (
		flagFIN = 0x01
		flagSYN = 0x02
		flagRST = 0x04
		flagACK = 0x10
	)
	switch {
	case flags&flagRST != 0:
		return FlowStateClosed
	case current == FlowStateClosed:
		return current
	case flags&flagFIN != 0:
		return FlowStateClosing
	case flags&flagSYN != 0 && flags&flagACK != 0:
		return FlowStateEstablished
	case current == FlowStateNew && flags&flagACK != 0:
		return FlowStateEstablished
	default:
		return current
	}
}

func cloneFlow(flow Flow) Flow {
	if flow.DirectionCount != nil {
		counts := make(map[Direction]int, len(flow.DirectionCount))
		for direction, count := range flow.DirectionCount {
			counts[direction] = count
		}
		flow.DirectionCount = counts
	}
	return flow
}
