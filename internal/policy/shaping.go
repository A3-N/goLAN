package policy

import (
	"crypto/sha256"
	"encoding/binary"
	"time"

	"golan/internal/dataplane"
	"golan/internal/traffic"
)

// ShapePlan is a deterministic controlled-path action plan.
type ShapePlan struct {
	Delay  time.Duration `json:"delay,omitempty"`
	Drop   bool          `json:"drop,omitempty"`
	Copies int           `json:"copies"`
}

// PlanTrafficShaping interprets live shaping actions without global randomness,
// making repeated evaluation reproducible for the same packet ID.
func PlanTrafficShaping(decision Decision, packetID traffic.PacketID, length int) ShapePlan {
	plan := ShapePlan{Copies: 1}
	if decision.Status != dataplane.StatusLive {
		return plan
	}
	for index, action := range decision.Actions {
		switch action.Kind {
		case ActionDelay:
			plan.Delay += action.Duration
		case ActionJitter:
			if action.Duration > 0 {
				plan.Delay += time.Duration(deterministicValue(packetID, action.Kind, index) % uint64(action.Duration+1))
			}
		case ActionBandwidth:
			if action.Rate > 0 && length > 0 {
				plan.Delay += time.Duration((uint64(length)*uint64(time.Second) + action.Rate - 1) / action.Rate)
			}
		case ActionLoss:
			if deterministicPercent(packetID, action.Kind, index) < action.Percent {
				plan.Drop = true
			}
		case ActionDuplicate:
			if deterministicPercent(packetID, action.Kind, index) < action.Percent {
				plan.Copies++
			}
		}
	}
	return plan
}

func deterministicPercent(packetID traffic.PacketID, kind ActionKind, index int) float64 {
	return float64(deterministicValue(packetID, kind, index)%1_000_000) / 10_000
}

func deterministicValue(packetID traffic.PacketID, kind ActionKind, index int) uint64 {
	digest := sha256.Sum256([]byte(string(packetID) + "\x00" + string(kind) + "\x00" + string(rune(index))))
	return binary.BigEndian.Uint64(digest[:8])
}
