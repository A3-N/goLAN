// Package syncgate provides a zero-value-ready gate for serializing blocking
// effects without holding a caller's state mutex.
package syncgate

import "sync"

// Gate serializes callers in arrival order.
type Gate struct {
	once  sync.Once
	token chan struct{}
}

// Enter waits for the gate and returns the release function. Callers should
// defer the returned function immediately.
func (gate *Gate) Enter() func() {
	gate.once.Do(func() {
		gate.token = make(chan struct{}, 1)
	})
	gate.token <- struct{}{}
	return func() { <-gate.token }
}
