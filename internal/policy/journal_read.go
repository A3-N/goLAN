package policy

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"golan/internal/dataplane"
	"golan/internal/traffic"
)

const (
	defaultJournalMaxRecords    = 1 << 20
	defaultJournalMaxRecordSize = 1 << 20
	maxJournalMaxRecords        = 4 << 20
	maxJournalMaxRecordSize     = 1 << 20
	maxDecisionForwardOrdinals  = 4096
)

// JournalReadOptions bounds strict decision-journal decoding. A truncated
// non-newline-terminated tail can be ignored explicitly so evidence written
// before a hard interruption remains usable while completeness stays false.
type JournalReadOptions struct {
	MaxRecords         uint64
	MaxRecordBytes     int
	AllowTruncatedTail bool
}

// JournalReadSummary reports how much complete JSON Lines evidence was
// decoded. Complete is false only when an explicitly allowed trailing fragment
// was ignored.
type JournalReadSummary struct {
	Records  uint64
	Complete bool
}

// DecodeJournal strictly streams bounded decision JSON Lines. It never returns
// a partial record to visit and never includes journal content in errors.
func DecodeJournal(
	ctx context.Context,
	reader io.Reader,
	options JournalReadOptions,
	visit func(Decision) error,
) (JournalReadSummary, error) {
	if reader == nil {
		return JournalReadSummary{}, fmt.Errorf("decision journal reader is nil")
	}
	if options.MaxRecords == 0 {
		options.MaxRecords = defaultJournalMaxRecords
	}
	if options.MaxRecords > maxJournalMaxRecords {
		return JournalReadSummary{}, fmt.Errorf(
			"decision journal record bound exceeds %d",
			maxJournalMaxRecords,
		)
	}
	if options.MaxRecordBytes <= 0 {
		options.MaxRecordBytes = defaultJournalMaxRecordSize
	}
	if options.MaxRecordBytes > maxJournalMaxRecordSize {
		return JournalReadSummary{}, fmt.Errorf(
			"decision journal record-size bound exceeds %d bytes",
			maxJournalMaxRecordSize,
		)
	}
	summary := JournalReadSummary{Complete: true}
	buffered := bufio.NewReaderSize(reader, 64<<10)
	record := make([]byte, 0, min(options.MaxRecordBytes, 64<<10))
	for {
		if err := ctx.Err(); err != nil {
			return summary, err
		}
		fragment, readErr := buffered.ReadSlice('\n')
		if len(record)+len(fragment) > options.MaxRecordBytes {
			return summary, fmt.Errorf(
				"decision journal record exceeds %d bytes",
				options.MaxRecordBytes,
			)
		}
		record = append(record, fragment...)
		if errors.Is(readErr, bufio.ErrBufferFull) {
			continue
		}
		if errors.Is(readErr, io.EOF) {
			if len(record) == 0 {
				return summary, nil
			}
			if options.AllowTruncatedTail {
				summary.Complete = false
				return summary, nil
			}
			return summary, fmt.Errorf(
				"decision journal has a truncated trailing record",
			)
		}
		if readErr != nil {
			return summary, fmt.Errorf("read decision journal: %w", readErr)
		}
		if len(record) == 0 || record[len(record)-1] != '\n' {
			return summary, fmt.Errorf("decision journal record is incomplete")
		}
		line := bytes.TrimSuffix(record, []byte{'\n'})
		line = bytes.TrimSuffix(line, []byte{'\r'})
		if len(bytes.TrimSpace(line)) == 0 {
			return summary, fmt.Errorf("decision journal contains an empty record")
		}
		if summary.Records >= options.MaxRecords {
			return summary, fmt.Errorf(
				"decision journal exceeds %d records",
				options.MaxRecords,
			)
		}
		var decision Decision
		decoder := json.NewDecoder(bytes.NewReader(line))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&decision); err != nil {
			return summary, fmt.Errorf(
				"decision journal record %d is invalid JSON",
				summary.Records+1,
			)
		}
		var extra json.RawMessage
		if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
			return summary, fmt.Errorf(
				"decision journal record %d has trailing data",
				summary.Records+1,
			)
		}
		if err := validateDecisionEvidenceLink(decision); err != nil {
			return summary, fmt.Errorf(
				"decision journal record %d: %w",
				summary.Records+1,
				err,
			)
		}
		summary.Records++
		if visit != nil {
			if err := visit(decision); err != nil {
				return summary, fmt.Errorf(
					"visit decision journal record %d: %w",
					summary.Records,
					err,
				)
			}
		}
		record = record[:0]
	}
}

func validateDecisionEvidenceLink(decision Decision) error {
	if decision.DataPlane != "" {
		valid := false
		for _, mode := range dataplane.Modes() {
			if decision.DataPlane == mode {
				valid = true
				break
			}
		}
		if !valid {
			return fmt.Errorf("decision data plane is invalid")
		}
	}
	switch decision.EvidenceKind {
	case "", traffic.EvidencePacket:
	default:
		return fmt.Errorf("decision evidence kind is invalid")
	}
	if len(decision.ForwardedCaptureOrdinals) >
		maxDecisionForwardOrdinals {
		return fmt.Errorf(
			"decision has more than %d forwarded capture ordinals",
			maxDecisionForwardOrdinals,
		)
	}
	if decision.OriginalCaptureOrdinal == 0 &&
		len(decision.ForwardedCaptureOrdinals) > 0 {
		return fmt.Errorf(
			"forwarded capture ordinals require an original capture ordinal",
		)
	}
	seen := make(map[uint64]bool, len(decision.ForwardedCaptureOrdinals))
	for _, ordinal := range decision.ForwardedCaptureOrdinals {
		if ordinal == 0 || seen[ordinal] {
			return fmt.Errorf("forwarded capture ordinals are invalid")
		}
		seen[ordinal] = true
	}
	return nil
}
