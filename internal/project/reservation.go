package project

import (
	"context"
	"fmt"
)

// reserveProjectArtifact serializes publication of one bounded, content-
// addressed inventory record without holding the project lock while waiting.
func reserveProjectArtifact[T any](
	ctx context.Context,
	project *Project,
	id string,
	pending *map[string]chan struct{},
	records func() []T,
	matchingID func(T) bool,
	sameRecord func(T) bool,
	limit int,
	kind string,
) (T, bool, chan struct{}, error) {
	var zero T
	for {
		project.mu.Lock()
		for _, existing := range records() {
			if !matchingID(existing) {
				continue
			}
			project.mu.Unlock()
			if sameRecord(existing) {
				return existing, true, nil, nil
			}
			return zero, false, nil, fmt.Errorf("%s id %s conflicts with project inventory", kind, id)
		}
		if wait := (*pending)[id]; wait != nil {
			project.mu.Unlock()
			select {
			case <-ctx.Done():
				return zero, false, nil, ctx.Err()
			case <-wait:
				continue
			}
		}
		if len(records())+len(*pending) >= limit {
			project.mu.Unlock()
			return zero, false, nil, fmt.Errorf("project %s limit is %d", kind, limit)
		}
		if *pending == nil {
			*pending = make(map[string]chan struct{})
		}
		reservation := make(chan struct{})
		(*pending)[id] = reservation
		project.mu.Unlock()
		return zero, false, reservation, nil
	}
}

// clearProjectReservation removes and closes a reservation exactly once. The
// caller must hold the project lock.
func clearProjectReservation(pending map[string]chan struct{}, id string, reservation chan struct{}) {
	if pending[id] != reservation {
		return
	}
	delete(pending, id)
	close(reservation)
}
