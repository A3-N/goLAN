package tui

import (
	"sort"
	"sync"

	tea "github.com/charmbracelet/bubbletea"
)

// effectResultMsg keeps a privileged command result available until Update has
// incorporated it. Bubble Tea does not wait for running commands when its event
// loop exits, so Shutdown replays any result that could not reach the model.
type effectResultMsg struct {
	id  uint64
	msg tea.Msg
}

type effectTracker struct {
	mu      sync.Mutex
	nextID  uint64
	pending map[uint64]*trackedEffect
}

type trackedEffect struct {
	mu       sync.Mutex
	cmd      tea.Cmd
	done     chan struct{}
	started  bool
	canceled bool
	msg      tea.Msg
}

func newEffectTracker() *effectTracker {
	return &effectTracker{pending: make(map[uint64]*trackedEffect)}
}

func (tracker *effectTracker) track(cmd tea.Cmd) tea.Cmd {
	if tracker == nil || cmd == nil {
		return cmd
	}

	tracker.mu.Lock()
	tracker.nextID++
	id := tracker.nextID
	effect := &trackedEffect{cmd: cmd, done: make(chan struct{})}
	tracker.pending[id] = effect
	tracker.mu.Unlock()

	return func() tea.Msg {
		return effectResultMsg{id: id, msg: effect.execute()}
	}
}

func (effect *trackedEffect) execute() tea.Msg {
	effect.mu.Lock()
	if effect.canceled {
		effect.mu.Unlock()
		return nil
	}
	if effect.started {
		done := effect.done
		effect.mu.Unlock()
		<-done
		effect.mu.Lock()
		msg := effect.msg
		effect.mu.Unlock()
		return msg
	}
	effect.started = true
	effect.mu.Unlock()

	var msg tea.Msg
	defer func() {
		effect.mu.Lock()
		effect.msg = msg
		close(effect.done)
		effect.mu.Unlock()
	}()
	msg = effect.cmd()
	return msg
}

func (effect *trackedEffect) finish() (tea.Msg, bool) {
	effect.mu.Lock()
	if !effect.started {
		effect.canceled = true
		effect.mu.Unlock()
		return nil, false
	}
	done := effect.done
	effect.mu.Unlock()
	<-done

	effect.mu.Lock()
	msg := effect.msg
	effect.mu.Unlock()
	return msg, true
}

func (tracker *effectTracker) acknowledge(id uint64) {
	if tracker == nil {
		return
	}
	tracker.mu.Lock()
	delete(tracker.pending, id)
	tracker.mu.Unlock()
}

func (tracker *effectTracker) waitPending() []effectResultMsg {
	if tracker == nil {
		return nil
	}

	tracker.mu.Lock()
	ids := make([]uint64, 0, len(tracker.pending))
	for id := range tracker.pending {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	effects := make([]*trackedEffect, 0, len(ids))
	for _, id := range ids {
		effects = append(effects, tracker.pending[id])
	}
	tracker.mu.Unlock()

	results := make([]effectResultMsg, 0, len(ids))
	for i, id := range ids {
		msg, started := effects[i].finish()
		if !started {
			tracker.acknowledge(id)
			continue
		}
		results = append(results, effectResultMsg{id: id, msg: msg})
	}
	return results
}

func (m *Model) trackEffect(cmd tea.Cmd) tea.Cmd {
	if cmd == nil {
		return nil
	}
	if m.effects == nil {
		m.effects = newEffectTracker()
	}
	return m.effects.track(cmd)
}

func (m *Model) finishPendingEffects() {
	if m.effects == nil {
		return
	}
	for _, result := range m.effects.waitPending() {
		next, _ := m.Update(result)
		switch next := next.(type) {
		case Model:
			*m = next
		case *Model:
			*m = *next
		}
	}
}
