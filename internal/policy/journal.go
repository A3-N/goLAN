package policy

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sync"
)

// Journal writes payload-free decisions as JSON Lines independently of TUI
// retention. It is safe for concurrent packet workers.
type Journal struct {
	gate   chan struct{}
	once   sync.Once
	file   *os.File
	writer *bufio.Writer
	closed bool
}

func (j *Journal) enter() func() {
	j.once.Do(func() {
		j.gate = make(chan struct{}, 1)
	})
	j.gate <- struct{}{}
	return func() { <-j.gate }
}

// OpenJournal creates an owner-only decision journal at path.
func OpenJournal(path string) (*Journal, error) {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, fmt.Errorf("create decision journal: %w", err)
	}
	return &Journal{file: file, writer: bufio.NewWriterSize(file, 64<<10)}, nil
}

// Append writes one complete decision record without packet payload bytes.
func (j *Journal) Append(decision Decision) error {
	if j == nil {
		return fmt.Errorf("decision journal is nil")
	}
	release := j.enter()
	defer release()
	if j.closed {
		return fmt.Errorf("decision journal is closed")
	}
	if err := validateDecisionEvidenceLink(decision); err != nil {
		return err
	}
	decision = redactDecisionForJournal(decision)
	data, err := json.Marshal(decision)
	if err != nil {
		return fmt.Errorf("encode decision: %w", err)
	}
	if _, err := j.writer.Write(append(data, '\n')); err != nil {
		return fmt.Errorf("write decision: %w", err)
	}
	return nil
}

// redactDecisionForJournal retains structural policy and evidence metadata but
// removes operands that may originate in captured content or operator secrets.
// The in-memory decision remains unchanged for enforcement and explicit
// editors.
func redactDecisionForJournal(decision Decision) Decision {
	if len(decision.Transformations) > 0 {
		decision.Transformations = append([]Transformation(nil), decision.Transformations...)
		for index := range decision.Transformations {
			decision.Transformations[index].Search = ""
			decision.Transformations[index].Replace = ""
		}
	}
	if len(decision.Actions) > 0 {
		decision.Actions = append([]Action(nil), decision.Actions...)
		for index := range decision.Actions {
			decision.Actions[index].Value = ""
		}
	}
	decision.Tags = nil
	return decision
}

// Close flushes, syncs, and closes the journal. Repeated calls are harmless.
func (j *Journal) Close() error {
	if j == nil {
		return nil
	}
	release := j.enter()
	defer release()
	if j.closed {
		return nil
	}
	j.closed = true
	flushErr := j.writer.Flush()
	syncErr := j.file.Sync()
	closeErr := j.file.Close()
	return errors.Join(wrapJournalError("flush", flushErr), wrapJournalError("sync", syncErr), wrapJournalError("close", closeErr))
}

func wrapJournalError(operation string, err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%s decision journal: %w", operation, err)
}
