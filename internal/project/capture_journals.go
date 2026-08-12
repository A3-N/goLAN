package project

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golan/internal/dataplane"
	"golan/internal/policy"
	"golan/internal/traffic"
)

const maxCaptureJournals = 2048

// VerifyCaptureJournal rehashes and strictly decodes one managed passive
// decision stream before evidence reuse.
func (p *Project) VerifyCaptureJournal(ctx context.Context, journal CaptureJournal) (resultErr error) {
	if p == nil {
		return fmt.Errorf("project is nil")
	}
	manifest := p.Manifest()
	captures := make(map[string]bool, len(manifest.Captures))
	for _, capture := range manifest.Captures {
		captures[capture.ID] = true
	}
	if err := validateCaptureJournal(journal, captures); err != nil {
		return err
	}
	path := filepath.Join(p.Path(), filepath.FromSlash(journal.Path))
	before, digest, err := inspectStableFile(ctx, path, maxPairJournalBytes)
	if err != nil {
		return fmt.Errorf("inspect capture journal %s: %w", journal.ID, err)
	}
	if before.Size() != journal.Size || digest != journal.SHA256 {
		return fmt.Errorf("capture journal %s fingerprint differs from inventory", journal.ID)
	}
	input, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open capture journal %s: %w", journal.ID, err)
	}
	defer func() { resultErr = errors.Join(resultErr, input.Close()) }()
	opened, err := input.Stat()
	if err != nil || !os.SameFile(before, opened) {
		return fmt.Errorf("capture journal %s changed before verification", journal.ID)
	}
	summary, err := decodeCaptureJournal(ctx, input, dataplane.Mode(journal.Mode))
	if err != nil {
		return fmt.Errorf("decode capture journal %s: %w", journal.ID, err)
	}
	if summary.Records != journal.Records || summary.Complete != journal.Complete {
		return fmt.Errorf("capture journal %s summary differs from inventory", journal.ID)
	}
	after, afterDigest, err := inspectStableFile(ctx, path, maxPairJournalBytes)
	if err != nil || !os.SameFile(before, after) || before.Size() != after.Size() ||
		!before.ModTime().Equal(after.ModTime()) || afterDigest != digest {
		return fmt.Errorf("capture journal %s changed during verification", journal.ID)
	}
	return nil
}

func (p *Project) importCaptureJournal(ctx context.Context, source string, capture Capture, mode dataplane.Mode) (record CaptureJournal, duplicate bool, resultErr error) {
	if !captureJournalMode(mode) {
		return CaptureJournal{}, false, fmt.Errorf("capture decision journal mode is unsupported")
	}
	staging, digest, size, stagedSummary, err := p.stageCapturePairJournal(ctx, source)
	if err != nil {
		return CaptureJournal{}, false, err
	}
	defer func() { resultErr = errors.Join(resultErr, ignoreNotExist(os.Remove(staging))) }()
	validate, err := os.Open(staging)
	if err != nil {
		return CaptureJournal{}, false, err
	}
	summary, decodeErr := decodeCaptureJournal(ctx, validate, mode)
	closeErr := validate.Close()
	if err := errors.Join(decodeErr, closeErr); err != nil {
		return CaptureJournal{}, false, err
	}
	if summary != stagedSummary {
		return CaptureJournal{}, false, fmt.Errorf("capture journal summary changed during validation")
	}
	id := captureJournalID(capture.ID, string(mode), digest)
	record = CaptureJournal{
		ID: id, CaptureID: capture.ID,
		Path: filepath.ToSlash(filepath.Join("journals", id+"-capture-decisions.jsonl")),
		Mode: string(mode), SHA256: digest, Size: size,
		Records: summary.Records, Complete: summary.Complete, ImportedAt: time.Now().UTC(),
	}

	existing, duplicate, reservation, err := reserveProjectArtifact(
		ctx, p, id, &p.pendingCaptureJournals,
		func() []CaptureJournal { return p.manifest.CaptureJournals },
		func(existing CaptureJournal) bool { return existing.ID == id },
		func(existing CaptureJournal) bool { return sameCaptureJournal(existing, record) },
		maxCaptureJournals, "capture journal",
	)
	if err != nil {
		return CaptureJournal{}, false, err
	}
	if duplicate {
		return existing, true, nil
	}
	reserved := true
	defer func() {
		if !reserved {
			return
		}
		p.mu.Lock()
		clearProjectReservation(p.pendingCaptureJournals, id, reservation)
		p.mu.Unlock()
	}()

	destination := filepath.Join(p.Path(), filepath.FromSlash(record.Path))
	if err := os.MkdirAll(filepath.Dir(destination), 0o700); err != nil {
		return CaptureJournal{}, false, fmt.Errorf("create project journal directory: %w", err)
	}
	if info, statErr := os.Lstat(destination); statErr == nil {
		if info.Mode()&fs.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return CaptureJournal{}, false, fmt.Errorf("capture journal destination is unsafe")
		}
		stable, existingDigest, inspectErr := inspectStableFile(ctx, destination, maxPairJournalBytes)
		if inspectErr != nil || stable.Size() != record.Size || existingDigest != record.SHA256 {
			return CaptureJournal{}, false, fmt.Errorf("capture journal destination conflicts with staged evidence")
		}
	} else if !errors.Is(statErr, os.ErrNotExist) {
		return CaptureJournal{}, false, fmt.Errorf("inspect capture journal destination: %w", statErr)
	} else if err := os.Link(staging, destination); err != nil {
		return CaptureJournal{}, false, fmt.Errorf("publish capture journal: %w", err)
	} else if err := syncDirectory(filepath.Dir(destination)); err != nil {
		return CaptureJournal{}, false, fmt.Errorf("sync capture journal directory: %w", err)
	}

	p.mu.Lock()
	for _, existing := range p.manifest.CaptureJournals {
		if existing.ID == id {
			clearProjectReservation(p.pendingCaptureJournals, id, reservation)
			reserved = false
			p.mu.Unlock()
			if sameCaptureJournal(existing, record) {
				return existing, true, nil
			}
			return CaptureJournal{}, false, fmt.Errorf("capture journal id %s conflicts with project inventory", id)
		}
	}
	if len(p.manifest.CaptureJournals) >= maxCaptureJournals {
		clearProjectReservation(p.pendingCaptureJournals, id, reservation)
		reserved = false
		p.mu.Unlock()
		return CaptureJournal{}, false, fmt.Errorf("project capture journal limit changed during import")
	}
	p.manifest.CaptureJournals = append(p.manifest.CaptureJournals, record)
	p.dirty = true
	clearProjectReservation(p.pendingCaptureJournals, id, reservation)
	reserved = false
	p.mu.Unlock()
	return record, false, nil
}

func decodeCaptureJournal(ctx context.Context, input *os.File, mode dataplane.Mode) (policy.JournalReadSummary, error) {
	var expected uint64
	return policy.DecodeJournal(ctx, input, policy.JournalReadOptions{
		MaxRecords: maxPairJournalRecords, AllowTruncatedTail: true,
	}, func(decision policy.Decision) error {
		expected++
		if decision.EvidenceKind != traffic.EvidencePacket {
			return fmt.Errorf("capture journal contains non-packet evidence")
		}
		if decision.DataPlane != mode {
			return fmt.Errorf("capture journal data plane differs from sidecar mode")
		}
		if decision.PacketID == "" || decision.OriginalCaptureOrdinal != expected {
			return fmt.Errorf("capture journal ordinal sequence is invalid")
		}
		if decision.ForwardedPacketID != "" || len(decision.ForwardedCaptureOrdinals) != 0 {
			return fmt.Errorf("capture journal claims unrelated forwarding evidence")
		}
		return nil
	})
}

func captureJournalID(captureID, mode, digest string) string {
	hash := sha256.Sum256([]byte(captureID + "\x00" + mode + "\x00" + digest))
	return hex.EncodeToString(hash[:16])
}

func captureJournalMode(mode dataplane.Mode) bool {
	return mode == dataplane.ModeListen || mode == dataplane.ModeEdgeObserve
}

func sameCaptureJournal(left, right CaptureJournal) bool {
	return left.ID == right.ID && left.CaptureID == right.CaptureID && left.Path == right.Path &&
		left.Mode == right.Mode && left.SHA256 == right.SHA256 && left.Size == right.Size &&
		left.Records == right.Records && left.Complete == right.Complete
}

func validateCaptureJournals(journals []CaptureJournal, captures map[string]bool) error {
	if len(journals) > maxCaptureJournals {
		return fmt.Errorf("project has more than %d capture journals", maxCaptureJournals)
	}
	ids := make(map[string]bool, len(journals))
	paths := make(map[string]bool, len(journals))
	for _, journal := range journals {
		if err := validateCaptureJournal(journal, captures); err != nil || ids[journal.ID] ||
			paths[journal.Path] {
			return fmt.Errorf("project capture journal %q is invalid", journal.ID)
		}
		ids[journal.ID] = true
		paths[journal.Path] = true
	}
	return nil
}

func validateCaptureJournal(journal CaptureJournal, captures map[string]bool) error {
	decodedID, idErr := hex.DecodeString(journal.ID)
	expectedPath := filepath.ToSlash(filepath.Join("journals", journal.ID+"-capture-decisions.jsonl"))
	if idErr != nil || len(decodedID) != 16 || !captures[journal.CaptureID] ||
		journal.ID != captureJournalID(journal.CaptureID, journal.Mode, journal.SHA256) ||
		!captureJournalMode(dataplane.Mode(journal.Mode)) || journal.Path != expectedPath ||
		!validProjectArtifact(journal.Path, "journals") || !validDigest(journal.SHA256) ||
		journal.Size < 0 || journal.Size > maxPairJournalBytes ||
		journal.Records > maxPairJournalRecords || journal.ImportedAt.IsZero() {
		return fmt.Errorf("capture journal inventory is invalid")
	}
	return nil
}

func captureJournalSourceName(capturePath string, mode dataplane.Mode) string {
	base := strings.TrimSuffix(capturePath, filepath.Ext(capturePath))
	return base + "." + string(mode) + ".decisions.jsonl"
}
