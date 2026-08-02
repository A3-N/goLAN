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
	"sort"
	"strings"
	"time"

	"golan/internal/dataplane"
)

const maxSessionCaptureEntries = 4096

// SessionCaptureImport reports the result of importing one finalized capture
// from a live-session artifact directory.
type SessionCaptureImport struct {
	Source           string
	Capture          Capture
	Duplicate        bool
	Pair             *CapturePair
	PairDuplicate    bool
	Journal          *CaptureJournal
	JournalDuplicate bool
	JournalErr       error
	Err              error
}

// ImportSessionCaptures scans one real directory for direct PCAP/PCAPNG files
// and imports each stable artifact as a managed project copy. When the
// canonical original.pcap, forwarded.pcap, and decisions.jsonl artifacts are
// all present, their verified ordinal linkage is indexed as one capture pair.
// A direct <capture-base>.decisions.jsonl sidecar is verified and indexed to
// that exact capture. Manifests, nested directories, and unrelated files are
// left untouched.
func (p *Project) ImportSessionCaptures(ctx context.Context, directory string) ([]SessionCaptureImport, error) {
	if p == nil {
		return nil, fmt.Errorf("project is nil")
	}
	directory, err := filepath.Abs(strings.TrimSpace(directory))
	if err != nil {
		return nil, fmt.Errorf("resolve session directory: %w", err)
	}
	info, err := os.Lstat(directory)
	if err != nil {
		return nil, fmt.Errorf("inspect session directory: %w", err)
	}
	if info.Mode()&fs.ModeSymlink != 0 || !info.IsDir() {
		return nil, fmt.Errorf("session artifacts must be in a real directory")
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		return nil, fmt.Errorf("scan session directory: %w", err)
	}
	if len(entries) > maxSessionCaptureEntries {
		return nil, fmt.Errorf("session directory contains more than %d entries", maxSessionCaptureEntries)
	}
	paths := make([]string, 0, len(entries))
	results := make([]SessionCaptureImport, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || !captureExtension(entry.Name()) {
			continue
		}
		path := filepath.Join(directory, entry.Name())
		if entry.Type()&fs.ModeSymlink != 0 {
			results = append(results, SessionCaptureImport{Source: path, Err: fmt.Errorf("capture source must be a regular non-symlink file")})
			continue
		}
		paths = append(paths, path)
	}
	sort.Strings(paths)
	for _, path := range paths {
		if err := ctx.Err(); err != nil {
			return results, err
		}
		capture, duplicate, err := p.importManagedCapture(ctx, path)
		results = append(results, SessionCaptureImport{Source: path, Capture: capture, Duplicate: duplicate, Err: err})
	}
	for index := range results {
		if results[index].Err != nil {
			continue
		}
		source := results[index].Source
		var sidecar string
		var journalMode dataplane.Mode
		for _, mode := range []dataplane.Mode{dataplane.ModeListen, dataplane.ModeEdgeObserve} {
			candidate := captureJournalSourceName(source, mode)
			info, err := os.Lstat(candidate)
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			if err != nil {
				results[index].JournalErr = fmt.Errorf("inspect capture decision journal: %w", err)
				break
			}
			if info.Mode()&fs.ModeSymlink != 0 || !info.Mode().IsRegular() {
				results[index].JournalErr = fmt.Errorf("capture decision journal must be a regular non-symlink file")
				break
			}
			if sidecar != "" {
				results[index].JournalErr = fmt.Errorf("capture has multiple recognized decision journals")
				break
			}
			sidecar = candidate
			journalMode = mode
		}
		if results[index].JournalErr != nil || sidecar == "" {
			continue
		}
		journal, duplicate, err := p.importCaptureJournal(ctx, sidecar, results[index].Capture, journalMode)
		if err != nil {
			results[index].JournalErr = err
			continue
		}
		results[index].Journal = &journal
		results[index].JournalDuplicate = duplicate
	}
	originalIndex := -1
	forwardedIndex := -1
	for index := range results {
		if results[index].Err != nil {
			continue
		}
		switch strings.ToLower(filepath.Base(results[index].Source)) {
		case "original.pcap":
			originalIndex = index
		case "forwarded.pcap":
			forwardedIndex = index
		}
	}
	if originalIndex < 0 || forwardedIndex < 0 {
		return results, nil
	}
	journalPath := filepath.Join(directory, "decisions.jsonl")
	if _, err := os.Lstat(journalPath); errors.Is(err, os.ErrNotExist) {
		return results, nil
	} else if err != nil {
		return results, fmt.Errorf("inspect session decision journal: %w", err)
	}
	pair, duplicate, err := p.importCapturePairJournal(
		ctx,
		journalPath,
		results[originalIndex].Capture,
		results[forwardedIndex].Capture,
	)
	if err != nil {
		return results, fmt.Errorf("index session decision journal: %w", err)
	}
	results[originalIndex].Pair = &pair
	results[originalIndex].PairDuplicate = duplicate
	return results, nil
}

// importManagedCapture indexes one finalized live-session capture as an
// immutable project-owned copy. It never alters the source file.
func (p *Project) importManagedCapture(ctx context.Context, source string) (Capture, bool, error) {
	if p == nil {
		return Capture{}, false, fmt.Errorf("project is nil")
	}
	source, err := filepath.Abs(strings.TrimSpace(source))
	if err != nil {
		return Capture{}, false, fmt.Errorf("resolve capture: %w", err)
	}
	info, err := os.Lstat(source)
	if err != nil {
		return Capture{}, false, fmt.Errorf("inspect capture: %w", err)
	}
	if info.Mode()&fs.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return Capture{}, false, fmt.Errorf("capture source must be a regular non-symlink file")
	}
	format, err := captureFormat(source)
	if err != nil {
		return Capture{}, false, err
	}

	digest, err := p.copyCapture(ctx, source, info)
	if err != nil {
		return Capture{}, false, err
	}
	if existing, ok := p.captureByHash(digest); ok {
		return existing, true, nil
	}
	path := filepath.ToSlash(filepath.Join("captures", digest[:16]+"-"+safeBase(filepath.Base(source))))
	record := Capture{
		ID: digest[:16], Name: filepath.Base(source), Path: path, Mode: ImportCopy,
		Format: format, SHA256: digest, Size: info.Size(), ModifiedAt: info.ModTime().UTC(),
		ImportedAt: time.Now().UTC(), Indexed: true,
	}
	p.mu.Lock()
	for _, existing := range p.manifest.Captures {
		if existing.SHA256 == digest {
			p.mu.Unlock()
			return existing, true, nil
		}
	}
	p.manifest.Captures = append(p.manifest.Captures, record)
	p.dirty = true
	p.mu.Unlock()
	return record, false, nil
}

// VerifyCapture validates one managed capture's size and fingerprint.
func (p *Project) VerifyCapture(ctx context.Context, capture Capture) error {
	if capture.Mode != ImportCopy {
		return fmt.Errorf("capture is not a managed live-session artifact")
	}
	path := filepath.Join(p.Path(), filepath.FromSlash(capture.Path))
	info, format, digest, err := inspectCaptureCandidate(ctx, path)
	if err != nil {
		return err
	}
	if info.Size() != capture.Size {
		return fmt.Errorf("capture size differs from inventory")
	}
	if format != capture.Format {
		return fmt.Errorf("capture format differs from inventory")
	}
	if digest != capture.SHA256 {
		return fmt.Errorf("capture fingerprint differs from inventory")
	}
	return nil
}

// AttachUnindexedCapture adds an already-finalized capture from this project's
// captures directory to the in-memory inventory. The packet evidence is not
// copied or modified; only project metadata becomes dirty.
func (p *Project) AttachUnindexedCapture(ctx context.Context, path string) (Capture, bool, error) {
	if p == nil {
		return Capture{}, false, fmt.Errorf("project is nil")
	}
	path, err := p.resolveUnindexedCapture(path)
	if err != nil {
		return Capture{}, false, err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return Capture{}, false, fmt.Errorf("inspect capture: %w", err)
	}
	if info.Mode()&fs.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return Capture{}, false, fmt.Errorf("capture must be a regular non-symlink file")
	}
	format, err := captureFormat(path)
	if err != nil {
		return Capture{}, false, err
	}
	digest, err := hashFile(ctx, path)
	if err != nil {
		return Capture{}, false, err
	}
	current, err := os.Stat(path)
	if err != nil || current.Size() != info.Size() || !current.ModTime().Equal(info.ModTime()) {
		return Capture{}, false, fmt.Errorf("capture changed while attaching")
	}
	if existing, ok := p.captureByHash(digest); ok {
		return existing, true, nil
	}
	record := Capture{
		ID: digest[:16], Name: filepath.Base(path),
		Path: filepath.ToSlash(filepath.Join("captures", filepath.Base(path))), Mode: ImportCopy,
		Format: format, SHA256: digest, Size: info.Size(), ModifiedAt: info.ModTime().UTC(),
		ImportedAt: time.Now().UTC(), Indexed: true,
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, existing := range p.manifest.Captures {
		if existing.SHA256 == digest {
			return existing, true, nil
		}
	}
	p.manifest.Captures = append(p.manifest.Captures, record)
	p.dirty = true
	return record, false, nil
}

// ArchiveUnindexedCapture moves an explicitly selected, unindexed capture to
// captures/archive. It remains recoverable evidence but is no longer offered
// for attachment when the project is reopened.
func (p *Project) ArchiveUnindexedCapture(path string) (string, error) {
	if p == nil {
		return "", fmt.Errorf("project is nil")
	}
	path, err := p.resolveUnindexedCapture(path)
	if err != nil {
		return "", err
	}
	unindexed, err := p.UnindexedCaptures()
	if err != nil {
		return "", err
	}
	found := false
	for _, candidate := range unindexed {
		if candidate == path {
			found = true
			break
		}
	}
	if !found {
		return "", fmt.Errorf("capture is already indexed or is not recoverable")
	}
	archive := filepath.Join(p.Path(), "captures", "archive")
	if err := os.Mkdir(archive, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
		return "", fmt.Errorf("create capture archive: %w", err)
	}
	destination := filepath.Join(archive, filepath.Base(path))
	if _, err := os.Lstat(destination); err == nil {
		return "", fmt.Errorf("archive already contains %s", filepath.Base(path))
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", fmt.Errorf("inspect capture archive: %w", err)
	}
	if err := os.Rename(path, destination); err != nil {
		return "", fmt.Errorf("archive capture: %w", err)
	}
	return destination, nil
}

func (p *Project) resolveUnindexedCapture(path string) (string, error) {
	path, err := filepath.Abs(strings.TrimSpace(path))
	if err != nil {
		return "", fmt.Errorf("resolve capture: %w", err)
	}
	captures := filepath.Clean(filepath.Join(p.Path(), "captures"))
	if filepath.Dir(path) != captures || !captureExtension(filepath.Base(path)) {
		return "", fmt.Errorf("capture must be a PCAP or PCAPNG file directly in %s", captures)
	}
	return path, nil
}

func inspectCaptureCandidate(ctx context.Context, path string) (os.FileInfo, string, string, error) {
	path, err := filepath.Abs(strings.TrimSpace(path))
	if err != nil {
		return nil, "", "", fmt.Errorf("resolve capture: %w", err)
	}
	before, err := os.Lstat(path)
	if err != nil {
		return nil, "", "", fmt.Errorf("inspect capture: %w", err)
	}
	if before.Mode()&fs.ModeSymlink != 0 || !before.Mode().IsRegular() {
		return nil, "", "", fmt.Errorf("capture source must be a regular non-symlink file")
	}
	if !captureExtension(path) {
		return nil, "", "", fmt.Errorf("capture filename must use .pcap or .pcapng")
	}
	format, err := captureFormat(path)
	if err != nil {
		return nil, "", "", err
	}
	digest, err := hashFile(ctx, path)
	if err != nil {
		return nil, "", "", err
	}
	after, err := os.Lstat(path)
	if err != nil || after.Mode()&fs.ModeSymlink != 0 || !os.SameFile(before, after) || before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) {
		return nil, "", "", fmt.Errorf("capture changed while hashing")
	}
	return after, format, digest, nil
}

func (p *Project) copyCapture(ctx context.Context, source string, sourceInfo os.FileInfo) (digest string, resultErr error) {
	stagingDir := filepath.Join(p.Path(), ".staging")
	file, err := os.CreateTemp(stagingDir, "capture-*.part")
	if err != nil {
		return "", fmt.Errorf("create capture staging file: %w", err)
	}
	stagingPath := file.Name()
	defer func() {
		if removeErr := os.Remove(stagingPath); removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
			resultErr = errors.Join(resultErr, fmt.Errorf("remove capture staging file: %w", removeErr))
		}
	}()
	if err := file.Chmod(0o600); err != nil {
		return "", errors.Join(err, file.Close())
	}
	in, err := os.Open(source)
	if err != nil {
		return "", errors.Join(err, file.Close())
	}
	hash := sha256.New()
	written, copyErr := copyWithContext(ctx, io.MultiWriter(file, hash), in)
	closeInErr := in.Close()
	if copyErr != nil || closeInErr != nil {
		return "", errors.Join(copyErr, closeInErr, file.Close())
	}
	if written != sourceInfo.Size() {
		return "", errors.Join(fmt.Errorf("capture changed while copying"), file.Close())
	}
	if err := file.Sync(); err != nil {
		return "", errors.Join(err, file.Close())
	}
	if err := file.Close(); err != nil {
		return "", err
	}
	currentInfo, err := os.Stat(source)
	if err != nil || currentInfo.Size() != sourceInfo.Size() || !currentInfo.ModTime().Equal(sourceInfo.ModTime()) {
		return "", fmt.Errorf("capture changed while copying")
	}
	digest = hex.EncodeToString(hash.Sum(nil))
	if _, exists := p.captureByHash(digest); exists {
		return digest, nil
	}
	destination := filepath.Join(p.Path(), "captures", digest[:16]+"-"+safeBase(filepath.Base(source)))
	if existingInfo, err := os.Stat(destination); err == nil {
		if existingInfo.Size() != written {
			return "", fmt.Errorf("managed capture destination collision")
		}
		return digest, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	if err := os.Rename(stagingPath, destination); err != nil {
		return "", fmt.Errorf("promote capture: %w", err)
	}
	return digest, nil
}

func (p *Project) captureByHash(digest string) (Capture, bool) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	for _, capture := range p.manifest.Captures {
		if capture.SHA256 == digest {
			return capture, true
		}
	}
	return Capture{}, false
}

func hashFile(ctx context.Context, path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("open capture for hashing: %w", err)
	}
	hash := sha256.New()
	_, copyErr := copyWithContext(ctx, hash, file)
	closeErr := file.Close()
	if copyErr != nil || closeErr != nil {
		return "", errors.Join(copyErr, closeErr)
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func copyWithContext(ctx context.Context, destination io.Writer, source io.Reader) (int64, error) {
	buffer := make([]byte, 256<<10)
	var total int64
	for {
		select {
		case <-ctx.Done():
			return total, ctx.Err()
		default:
		}
		read, readErr := source.Read(buffer)
		if read > 0 {
			written, writeErr := destination.Write(buffer[:read])
			total += int64(written)
			if writeErr != nil {
				return total, writeErr
			}
			if written != read {
				return total, io.ErrShortWrite
			}
		}
		if errors.Is(readErr, io.EOF) {
			return total, nil
		}
		if readErr != nil {
			return total, readErr
		}
	}
}

func captureFormat(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	var header [4]byte
	_, readErr := io.ReadFull(file, header[:])
	closeErr := file.Close()
	if readErr != nil || closeErr != nil {
		return "", errors.Join(readErr, closeErr)
	}
	if header == [4]byte{0x0a, 0x0d, 0x0d, 0x0a} {
		return "pcapng", nil
	}
	switch header {
	case [4]byte{0xd4, 0xc3, 0xb2, 0xa1}, [4]byte{0xa1, 0xb2, 0xc3, 0xd4}, [4]byte{0x4d, 0x3c, 0xb2, 0xa1}, [4]byte{0xa1, 0xb2, 0x3c, 0x4d}:
		return "pcap", nil
	default:
		return "", fmt.Errorf("capture format is not PCAP or PCAPNG")
	}
}

func captureExtension(name string) bool {
	extension := strings.ToLower(filepath.Ext(name))
	return extension == ".pcap" || extension == ".pcapng"
}
