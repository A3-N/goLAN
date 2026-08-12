package tui

import (
	"golan/internal/dataplane"
	networkobs "golan/internal/network"
	"golan/internal/policy"
	"golan/internal/traffic"
)

const (
	maxLiveEvidenceFrames = 64
	maxLiveEvidenceBytes  = 2 << 20
)

// liveEvidenceRecord is private, bounded packet evidence used only by the
// Rules preview. Frame bytes never enter output, observations, or project data.
type liveEvidenceRecord struct {
	Frame    traffic.Frame
	Flow     traffic.Flow
	Mode     dataplane.Mode
	Decision policy.DecisionSummary
}

func (m *Model) addLiveEvidenceDecision(
	frame traffic.Frame,
	flow traffic.Flow,
	mode dataplane.Mode,
	decision policy.DecisionSummary,
) {
	if mode == "" {
		return
	}
	if m.networkTracker == nil {
		m.networkTracker = networkobs.NewTracker("current", string(mode), frame.Timestamp)
	}
	m.networkTracker.ObserveFrame(frame, string(frame.Side), decision)
	m.ensureNetworkSelection()

	size := frame.RawLength()
	if size == 0 || size > maxLiveEvidenceBytes {
		return
	}
	for index := range m.liveEvidence {
		if m.liveEvidence[index].Frame.ID == frame.ID {
			m.liveEvidence[index].Flow = cloneEvidenceFlow(flow)
			m.liveEvidence[index].Mode = mode
			m.liveEvidence[index].Decision = decision
			return
		}
	}
	for len(m.liveEvidence) >= maxLiveEvidenceFrames ||
		m.liveEvidenceBytes+size > maxLiveEvidenceBytes {
		m.evictOldestLiveEvidence()
	}
	m.liveEvidence = append(m.liveEvidence, liveEvidenceRecord{
		Frame: frame, Flow: cloneEvidenceFlow(flow), Mode: mode, Decision: decision,
	})
	m.liveEvidenceBytes += size
}

func (m *Model) evictOldestLiveEvidence() {
	if len(m.liveEvidence) == 0 {
		m.liveEvidenceBytes = 0
		return
	}
	m.liveEvidenceBytes -= m.liveEvidence[0].Frame.RawLength()
	if m.liveEvidenceBytes < 0 {
		m.liveEvidenceBytes = 0
	}
	copy(m.liveEvidence, m.liveEvidence[1:])
	m.liveEvidence[len(m.liveEvidence)-1] = liveEvidenceRecord{}
	m.liveEvidence = m.liveEvidence[:len(m.liveEvidence)-1]
}

func (m *Model) clearLiveEvidence() {
	for index := range m.liveEvidence {
		m.liveEvidence[index] = liveEvidenceRecord{}
	}
	m.liveEvidence = nil
	m.liveEvidenceBytes = 0
}

func (m Model) liveEvidenceSnapshot() []liveEvidenceRecord {
	records := make([]liveEvidenceRecord, len(m.liveEvidence))
	for index, record := range m.liveEvidence {
		records[index] = liveEvidenceRecord{
			Frame: record.Frame, Flow: cloneEvidenceFlow(record.Flow),
			Mode: record.Mode, Decision: record.Decision,
		}
	}
	return records
}

func cloneEvidenceFlow(flow traffic.Flow) traffic.Flow {
	if flow.DirectionCount != nil {
		counts := make(map[traffic.Direction]int, len(flow.DirectionCount))
		for direction, count := range flow.DirectionCount {
			counts[direction] = count
		}
		flow.DirectionCount = counts
	}
	return flow
}
