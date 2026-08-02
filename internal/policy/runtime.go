package policy

import (
	"sync"
	"time"

	"golan/internal/dataplane"
	"golan/internal/traffic"
)

// Result is one normalized flow and policy pipeline result.
type Result struct {
	Original  traffic.Frame `json:"-"`
	Forwarded traffic.Frame `json:"-"`
	Flow      traffic.Flow  `json:"flow"`
	Decision  Decision      `json:"decision"`
}

// RuleStats is runtime metadata kept outside immutable rule revisions.
type RuleStats struct {
	Hits      uint64    `json:"hits"`
	LastMatch time.Time `json:"last_match"`
}

// Engine combines flow tracking, the atomically active revision, optional
// rewriting, and bounded runtime statistics.
type Engine struct {
	Policies *Store
	Flows    *traffic.Tracker

	statsMu sync.Mutex
	stats   map[string]RuleStats
}

// NewEngine creates a shared policy runtime with bounded flow tracking.
func NewEngine(maxFlows int) *Engine {
	return &Engine{Policies: &Store{}, Flows: traffic.NewTracker(maxFlows), stats: make(map[string]RuleStats)}
}

// Process evaluates a normalized frame and applies live safe transformations.
// A transform failure is returned and leaves Forwarded equal to Original.
func (e *Engine) Process(frame traffic.Frame, capabilities dataplane.Capabilities) (Result, error) {
	result := e.Evaluate(frame, capabilities)
	decision := result.Decision
	if decision.EffectiveVerdict != VerdictAllow || len(decision.Transformations) == 0 {
		return result, nil
	}
	forwarded, err := ApplyTransformations(frame, decision)
	if err != nil {
		return result, err
	}
	result.Forwarded = forwarded
	result.Decision.ForwardedPacketID = forwarded.ID
	result.Decision.Edited = forwarded.ID != frame.ID
	return result, nil
}

// Evaluate runs internal request correlation and policy decisions without
// applying frame transformations.
func (e *Engine) Evaluate(frame traffic.Frame, capabilities dataplane.Capabilities) Result {
	flow := e.Flows.Observe(frame)
	revision, ok := e.Policies.Active()
	evaluatedAt := frame.Timestamp
	if evaluatedAt.IsZero() {
		evaluatedAt = time.Now().UTC()
	}
	decision := Decision{
		PacketID: frame.ID, DataPlane: capabilities.Mode(), EvidenceKind: frame.Kind,
		Verdict: VerdictAllow, EffectiveVerdict: VerdictAllow, Status: dataplane.StatusLive,
		Explanation: "no active policy revision", EvaluatedAt: evaluatedAt,
	}
	if ok {
		decision = revision.Evaluate(frame, flow, capabilities)
	}
	result := Result{Original: frame, Forwarded: frame, Flow: flow, Decision: decision}
	if decision.WinningRuleID != "" {
		e.recordHit(decision.WinningRuleID, decision.EvaluatedAt)
	}
	return result
}

// Stats returns a copy of runtime rule hit counters.
func (e *Engine) Stats() map[string]RuleStats {
	if e == nil {
		return nil
	}
	e.statsMu.Lock()
	defer e.statsMu.Unlock()
	out := make(map[string]RuleStats, len(e.stats))
	for id, stats := range e.stats {
		out[id] = stats
	}
	return out
}

func (e *Engine) recordHit(id string, now time.Time) {
	e.statsMu.Lock()
	stats := e.stats[id]
	stats.Hits++
	stats.LastMatch = now
	e.stats[id] = stats
	e.statsMu.Unlock()
}
