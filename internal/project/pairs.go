package project

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golan/internal/policy"
)

const (
	maxCapturePairs       = 2048
	maxPairJournalBytes   = int64(512 << 20)
	maxPairJournalRecords = uint64(4 << 20)
)

// CapturePair returns one immutable pair record without exposing project
// slices.
func (p *Project) CapturePair(id string) (CapturePair, bool) {
	if p == nil {
		return CapturePair{}, false
	}
	id = strings.TrimSpace(id)
	p.mu.RLock()
	defer p.mu.RUnlock()
	for _, pair := range p.manifest.CapturePairs {
		if pair.ID == id {
			return pair, true
		}
	}
	return CapturePair{}, false
}

// VerifyCapturePairJournal rehashes and strictly decodes one managed decision
// journal before evidence reuse.
func (p *Project) VerifyCapturePairJournal(
	ctx context.Context,
	pair CapturePair,
) (resultErr error) {
	if p == nil {
		return fmt.Errorf("project is nil")
	}
	if !validProjectArtifact(pair.JournalPath, "journals") ||
		!validDigest(pair.JournalSHA256) ||
		pair.JournalSize < 0 ||
		pair.JournalSize > maxPairJournalBytes ||
		pair.JournalRecords > maxPairJournalRecords {
		return fmt.Errorf("capture pair %q journal inventory is invalid", pair.ID)
	}
	path := filepath.Join(
		p.Path(),
		filepath.FromSlash(pair.JournalPath),
	)
	before, digest, err := inspectStableFile(
		ctx,
		path,
		maxPairJournalBytes,
	)
	if err != nil {
		return fmt.Errorf("inspect capture pair %s journal: %w", pair.ID, err)
	}
	if before.Size() != pair.JournalSize ||
		digest != pair.JournalSHA256 {
		return fmt.Errorf(
			"capture pair %s journal fingerprint differs from inventory",
			pair.ID,
		)
	}
	input, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open capture pair %s journal: %w", pair.ID, err)
	}
	defer func() {
		resultErr = errors.Join(resultErr, input.Close())
	}()
	opened, err := input.Stat()
	if err != nil || !os.SameFile(before, opened) {
		return fmt.Errorf(
			"capture pair %s journal changed before verification",
			pair.ID,
		)
	}
	summary, err := policy.DecodeJournal(
		ctx,
		input,
		policy.JournalReadOptions{
			MaxRecords:         maxPairJournalRecords,
			AllowTruncatedTail: true,
		},
		nil,
	)
	if err != nil {
		return fmt.Errorf("decode capture pair %s journal: %w", pair.ID, err)
	}
	if summary.Records != pair.JournalRecords ||
		summary.Complete != pair.JournalComplete {
		return fmt.Errorf(
			"capture pair %s journal summary differs from inventory",
			pair.ID,
		)
	}
	after, afterDigest, err := inspectStableFile(
		ctx,
		path,
		maxPairJournalBytes,
	)
	if err != nil ||
		!os.SameFile(before, after) ||
		before.Size() != after.Size() ||
		!before.ModTime().Equal(after.ModTime()) ||
		afterDigest != digest {
		return fmt.Errorf(
			"capture pair %s journal changed during verification",
			pair.ID,
		)
	}
	return nil
}

func (p *Project) importCapturePairJournal(
	ctx context.Context,
	journalPath string,
	original,
	forwarded Capture,
) (
	pair CapturePair,
	duplicate bool,
	resultErr error,
) {
	staging, digest, size, summary, err := p.stageCapturePairJournal(
		ctx,
		journalPath,
	)
	if err != nil {
		return CapturePair{}, false, err
	}
	defer func() {
		resultErr = errors.Join(
			resultErr,
			ignoreNotExist(os.Remove(staging)),
		)
	}()
	id := capturePairID(original.ID, forwarded.ID, digest)
	record := CapturePair{
		ID: id, OriginalCaptureID: original.ID,
		ForwardedCaptureID: forwarded.ID,
		JournalPath: filepath.ToSlash(filepath.Join(
			"journals",
			id+"-decisions.jsonl",
		)),
		JournalSHA256: digest, JournalSize: size,
		JournalRecords:  summary.Records,
		JournalComplete: summary.Complete,
		ImportedAt:      time.Now().UTC(),
	}

	root := p.Path()
	destination := filepath.Join(
		root,
		filepath.FromSlash(record.JournalPath),
	)

	// Reserve bounded inventory before filesystem work without holding the
	// project mutex across that work.
	existing, duplicate, reservation, err := reserveProjectArtifact(
		ctx, p, id, &p.pendingCapturePairs,
		func() []CapturePair { return p.manifest.CapturePairs },
		func(existing CapturePair) bool { return existing.ID == id },
		func(existing CapturePair) bool { return sameCapturePair(existing, record) },
		maxCapturePairs, "capture pair",
	)
	if err != nil {
		return CapturePair{}, false, err
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
		clearProjectReservation(p.pendingCapturePairs, id, reservation)
		p.mu.Unlock()
	}()

	if err := os.MkdirAll(filepath.Dir(destination), 0o700); err != nil {
		return CapturePair{}, false, fmt.Errorf(
			"create project journal directory: %w",
			err,
		)
	}
	if info, err := os.Lstat(destination); err == nil {
		if info.Mode()&fs.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return CapturePair{}, false, fmt.Errorf(
				"capture pair journal destination is unsafe",
			)
		}
		stableInfo, existingDigest, inspectErr := inspectStableFile(
			ctx,
			destination,
			maxPairJournalBytes,
		)
		if inspectErr != nil ||
			stableInfo.Size() != record.JournalSize ||
			existingDigest != record.JournalSHA256 {
			return CapturePair{}, false, fmt.Errorf(
				"capture pair journal destination conflicts with staged evidence",
			)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return CapturePair{}, false, fmt.Errorf(
			"inspect capture pair journal destination: %w",
			err,
		)
	} else {
		if err := os.Link(staging, destination); err != nil {
			if errors.Is(err, fs.ErrExist) {
				return CapturePair{}, false, fmt.Errorf(
					"capture pair journal destination appeared during import",
				)
			}
			return CapturePair{}, false, fmt.Errorf(
				"publish capture pair journal: %w",
				err,
			)
		}
		if err := syncDirectory(filepath.Dir(destination)); err != nil {
			return CapturePair{}, false, fmt.Errorf(
				"sync capture pair journal directory: %w",
				err,
			)
		}
	}

	p.mu.Lock()
	for _, existing := range p.manifest.CapturePairs {
		if existing.ID == id {
			clearProjectReservation(p.pendingCapturePairs, id, reservation)
			reserved = false
			p.mu.Unlock()
			if sameCapturePair(existing, record) {
				return existing, true, nil
			}
			return CapturePair{}, false, fmt.Errorf(
				"capture pair id %s changed during import",
				id,
			)
		}
	}
	if len(p.manifest.CapturePairs) >= maxCapturePairs {
		clearProjectReservation(p.pendingCapturePairs, id, reservation)
		reserved = false
		p.mu.Unlock()
		return CapturePair{}, false, fmt.Errorf(
			"project capture pair limit changed during import",
		)
	}
	p.manifest.CapturePairs = append(p.manifest.CapturePairs, record)
	p.dirty = true
	clearProjectReservation(p.pendingCapturePairs, id, reservation)
	reserved = false
	p.mu.Unlock()
	return record, false, nil
}

func (p *Project) stageCapturePairJournal(
	ctx context.Context,
	source string,
) (
	staging,
	digest string,
	size int64,
	summary policy.JournalReadSummary,
	resultErr error,
) {
	source, err := filepath.Abs(strings.TrimSpace(source))
	if err != nil {
		return "", "", 0, summary, fmt.Errorf(
			"resolve decision journal: %w",
			err,
		)
	}
	before, err := os.Lstat(source)
	if err != nil {
		return "", "", 0, summary, fmt.Errorf(
			"inspect decision journal: %w",
			err,
		)
	}
	if before.Mode()&fs.ModeSymlink != 0 || !before.Mode().IsRegular() {
		return "", "", 0, summary, fmt.Errorf(
			"decision journal must be a regular non-symlink file",
		)
	}
	if before.Size() > maxPairJournalBytes {
		return "", "", 0, summary, fmt.Errorf(
			"decision journal exceeds %d MiB",
			maxPairJournalBytes>>20,
		)
	}
	input, err := os.Open(source)
	if err != nil {
		return "", "", 0, summary, fmt.Errorf(
			"open decision journal: %w",
			err,
		)
	}
	defer func() {
		resultErr = errors.Join(resultErr, input.Close())
	}()
	opened, err := input.Stat()
	if err != nil || !os.SameFile(before, opened) {
		return "", "", 0, summary, fmt.Errorf(
			"decision journal changed before import",
		)
	}
	output, err := os.CreateTemp(
		filepath.Join(p.Path(), ".staging"),
		"journal-*.part",
	)
	if err != nil {
		return "", "", 0, summary, fmt.Errorf(
			"create decision journal staging file: %w",
			err,
		)
	}
	staging = output.Name()
	closed := false
	defer func() {
		if !closed {
			resultErr = errors.Join(resultErr, output.Close())
		}
		if resultErr != nil {
			resultErr = errors.Join(resultErr, ignoreNotExist(os.Remove(staging)))
			staging = ""
		}
	}()
	if err := output.Chmod(0o600); err != nil {
		return "", "", 0, summary, err
	}
	hash := sha256.New()
	written, err := copyWithContext(
		ctx,
		io.MultiWriter(output, hash),
		io.LimitReader(input, maxPairJournalBytes+1),
	)
	if err != nil {
		return "", "", 0, summary, fmt.Errorf(
			"copy decision journal: %w",
			err,
		)
	}
	if written != before.Size() || written > maxPairJournalBytes {
		return "", "", 0, summary, fmt.Errorf(
			"decision journal changed or exceeds size limit",
		)
	}
	afterOpen, err := input.Stat()
	if err != nil {
		return "", "", 0, summary, err
	}
	afterPath, err := os.Lstat(source)
	if err != nil ||
		afterPath.Mode()&fs.ModeSymlink != 0 ||
		!os.SameFile(before, afterOpen) ||
		!os.SameFile(before, afterPath) ||
		before.Size() != afterOpen.Size() ||
		before.Size() != afterPath.Size() ||
		!before.ModTime().Equal(afterOpen.ModTime()) ||
		!before.ModTime().Equal(afterPath.ModTime()) {
		return "", "", 0, summary, fmt.Errorf(
			"decision journal changed during import",
		)
	}
	if err := output.Sync(); err != nil {
		return "", "", 0, summary, fmt.Errorf(
			"sync decision journal staging file: %w",
			err,
		)
	}
	if err := output.Close(); err != nil {
		return "", "", 0, summary, fmt.Errorf(
			"close decision journal staging file: %w",
			err,
		)
	}
	closed = true
	validate, err := os.Open(staging)
	if err != nil {
		return "", "", 0, summary, err
	}
	summary, decodeErr := policy.DecodeJournal(
		ctx,
		validate,
		policy.JournalReadOptions{
			MaxRecords:         maxPairJournalRecords,
			AllowTruncatedTail: true,
		},
		nil,
	)
	closeErr := validate.Close()
	if decodeErr != nil || closeErr != nil {
		return "", "", 0, summary, errors.Join(decodeErr, closeErr)
	}
	return staging,
		hex.EncodeToString(hash.Sum(nil)),
		written,
		summary,
		nil
}

func inspectStableFile(
	ctx context.Context,
	path string,
	limit int64,
) (os.FileInfo, string, error) {
	before, err := os.Lstat(path)
	if err != nil {
		return nil, "", err
	}
	if before.Mode()&fs.ModeSymlink != 0 ||
		!before.Mode().IsRegular() ||
		before.Size() > limit {
		return nil, "", fmt.Errorf("project evidence file is unsafe")
	}
	digest, err := hashFile(ctx, path)
	if err != nil {
		return nil, "", err
	}
	after, err := os.Lstat(path)
	if err != nil ||
		after.Mode()&fs.ModeSymlink != 0 ||
		!os.SameFile(before, after) ||
		before.Size() != after.Size() ||
		!before.ModTime().Equal(after.ModTime()) {
		return nil, "", fmt.Errorf("project evidence changed while hashing")
	}
	return after, digest, nil
}

func capturePairID(originalID, forwardedID, journalDigest string) string {
	digest := sha256.Sum256([]byte(
		originalID + "\x00" + forwardedID + "\x00" + journalDigest,
	))
	return hex.EncodeToString(digest[:16])
}

func sameCapturePair(left, right CapturePair) bool {
	return left.ID == right.ID &&
		left.OriginalCaptureID == right.OriginalCaptureID &&
		left.ForwardedCaptureID == right.ForwardedCaptureID &&
		left.JournalPath == right.JournalPath &&
		left.JournalSHA256 == right.JournalSHA256 &&
		left.JournalSize == right.JournalSize &&
		left.JournalRecords == right.JournalRecords &&
		left.JournalComplete == right.JournalComplete
}

func validateCapturePairs(
	pairs []CapturePair,
	captures map[string]bool,
) error {
	if len(pairs) > maxCapturePairs {
		return fmt.Errorf(
			"project has more than %d capture pairs",
			maxCapturePairs,
		)
	}
	ids := make(map[string]bool, len(pairs))
	paths := make(map[string]bool, len(pairs))
	for _, pair := range pairs {
		decodedID, idErr := hex.DecodeString(pair.ID)
		expectedPath := filepath.ToSlash(filepath.Join(
			"journals",
			pair.ID+"-decisions.jsonl",
		))
		if idErr != nil ||
			len(decodedID) != 16 ||
			ids[pair.ID] ||
			paths[pair.JournalPath] ||
			pair.ID != capturePairID(
				pair.OriginalCaptureID,
				pair.ForwardedCaptureID,
				pair.JournalSHA256,
			) ||
			!captures[pair.OriginalCaptureID] ||
			!captures[pair.ForwardedCaptureID] ||
			!validProjectArtifact(pair.JournalPath, "journals") ||
			pair.JournalPath != expectedPath ||
			!validDigest(pair.JournalSHA256) ||
			pair.JournalSize < 0 ||
			pair.JournalSize > maxPairJournalBytes ||
			pair.JournalRecords > maxPairJournalRecords ||
			pair.ImportedAt.IsZero() {
			return fmt.Errorf("project capture pair %q is invalid", pair.ID)
		}
		ids[pair.ID] = true
		paths[pair.JournalPath] = true
	}
	return nil
}
