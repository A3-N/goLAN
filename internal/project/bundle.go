package project

import (
	"archive/zip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const (
	bundleVersion        = 1
	bundleDescriptorFile = "bundle.json"
	maxBundleEntries     = 4096
	maxBundleFileSize    = 512 << 20
	maxBundleTotalSize   = 2 << 30
	maxChecksumFileSize  = 8 << 20
)

// BundleKind controls evidence inclusion.
type BundleKind string

// Bundle variants retain fingerprints even when evidence is omitted.
const (
	BundleFull      BundleKind = "full"
	BundleMetadata  BundleKind = "metadata"
	BundleSanitized BundleKind = "sanitized"
)

// BundleOptions controls which evidence is present in an exported bundle.
// A nil CaptureIDs slice selects every capture for a full bundle. A non-nil,
// empty slice explicitly selects none. CaptureIDs are not accepted for
// metadata or sanitized bundles because those variants never include capture
// bytes.
type BundleOptions struct {
	Kind       BundleKind
	CaptureIDs []string
}

// BundleReport is a deterministic inventory of an exported or imported
// bundle. Files and Bytes count project payload entries, excluding the bundle
// descriptor and checksum inventory.
type BundleReport struct {
	Kind             BundleKind `json:"kind"`
	Files            int        `json:"files"`
	Bytes            int64      `json:"bytes"`
	SourceCaptures   int        `json:"source_captures"`
	IncludedCaptures []string   `json:"included_captures,omitempty"`
	OmittedCaptures  []string   `json:"omitted_captures,omitempty"`
}

type bundleDescriptor struct {
	Version int          `json:"version"`
	Report  BundleReport `json:"report"`
}

type bundleChecksums struct {
	Version int               `json:"version"`
	Files   map[string]string `json:"files"`
}

type bundleEntry struct {
	name string
	data []byte
}

// ExportBundle writes a checksum-verified .golanproj bundle. Dirty metadata is
// intentionally not auto-saved; the last explicit project.json is exported.
func (p *Project) ExportBundle(ctx context.Context, destination string, kind BundleKind) error {
	_, err := p.ExportBundleWithOptions(ctx, destination, BundleOptions{Kind: kind})
	return err
}

// ExportBundleWithOptions writes a checksum-verified .golanproj bundle and
// returns the exact evidence inventory written to it.
func (p *Project) ExportBundleWithOptions(ctx context.Context, destination string, options BundleOptions) (report BundleReport, resultErr error) {
	if p == nil {
		return report, fmt.Errorf("project is nil")
	}
	switch options.Kind {
	case BundleFull, BundleMetadata, BundleSanitized:
	default:
		return report, fmt.Errorf("bundle kind must be full, metadata, or sanitized")
	}
	if options.Kind != BundleFull && options.CaptureIDs != nil {
		return report, fmt.Errorf("capture selection is only valid for full bundles")
	}
	if p.Dirty() {
		return report, fmt.Errorf("project has unsaved metadata; save before export")
	}
	destination, err := filepath.Abs(strings.TrimSpace(destination))
	if err != nil {
		return report, fmt.Errorf("resolve bundle destination: %w", err)
	}
	if !strings.EqualFold(filepath.Ext(destination), ".golanproj") {
		return report, fmt.Errorf("bundle destination must use .golanproj")
	}
	if _, err := os.Lstat(destination); err == nil {
		return report, fmt.Errorf("bundle destination already exists")
	} else if !errors.Is(err, os.ErrNotExist) {
		return report, err
	}
	entries, report, err := p.bundleEntries(ctx, options)
	if err != nil {
		return report, err
	}
	descriptorData, err := json.MarshalIndent(bundleDescriptor{Version: bundleVersion, Report: report}, "", "  ")
	if err != nil {
		return report, fmt.Errorf("encode bundle descriptor: %w", err)
	}
	entries = append(entries, bundleEntry{name: bundleDescriptorFile, data: append(descriptorData, '\n')})
	if len(descriptorData)+1 > maxChecksumFileSize {
		return report, fmt.Errorf("bundle descriptor exceeds size limit")
	}
	if len(entries)+1 > maxBundleEntries {
		return report, fmt.Errorf("bundle entry count exceeds %d", maxBundleEntries)
	}
	checksums := bundleChecksums{Version: bundleVersion, Files: make(map[string]string, len(entries))}
	for _, entry := range entries {
		digest := sha256.Sum256(entry.data)
		checksums.Files[entry.name] = hex.EncodeToString(digest[:])
	}
	checksumData, err := json.MarshalIndent(checksums, "", "  ")
	if err != nil {
		return report, fmt.Errorf("encode bundle checksums: %w", err)
	}
	if len(checksumData)+1 > maxChecksumFileSize {
		return report, fmt.Errorf("bundle checksum inventory exceeds size limit")
	}
	entries = append(entries, bundleEntry{name: "checksums.json", data: append(checksumData, '\n')})
	sort.Slice(entries, func(i, j int) bool { return entries[i].name < entries[j].name })

	temporary, err := os.CreateTemp(filepath.Dir(destination), ".golan-bundle-*.tmp")
	if err != nil {
		return report, fmt.Errorf("create bundle staging file: %w", err)
	}
	temporaryPath := temporary.Name()
	defer func() {
		if removeErr := os.Remove(temporaryPath); removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
			resultErr = errors.Join(resultErr, removeErr)
		}
	}()
	if err := temporary.Chmod(0o600); err != nil {
		return report, errors.Join(err, temporary.Close())
	}
	archive := zip.NewWriter(temporary)
	for _, entry := range entries {
		select {
		case <-ctx.Done():
			return report, errors.Join(ctx.Err(), archive.Close(), temporary.Close())
		default:
		}
		header := &zip.FileHeader{Name: entry.name, Method: zip.Deflate}
		header.SetMode(0o600)
		header.Modified = time.Unix(0, 0).UTC()
		writer, err := archive.CreateHeader(header)
		if err != nil {
			return report, errors.Join(fmt.Errorf("create bundle entry %s: %w", entry.name, err), archive.Close(), temporary.Close())
		}
		if _, err := writer.Write(entry.data); err != nil {
			return report, errors.Join(fmt.Errorf("write bundle entry %s: %w", entry.name, err), archive.Close(), temporary.Close())
		}
	}
	if err := archive.Close(); err != nil {
		return report, errors.Join(fmt.Errorf("finalize bundle: %w", err), temporary.Close())
	}
	if err := temporary.Sync(); err != nil {
		return report, errors.Join(fmt.Errorf("sync bundle: %w", err), temporary.Close())
	}
	if err := temporary.Close(); err != nil {
		return report, fmt.Errorf("close bundle: %w", err)
	}
	if err := os.Rename(temporaryPath, destination); err != nil {
		return report, fmt.Errorf("promote bundle: %w", err)
	}
	return report, nil
}

func (p *Project) bundleEntries(ctx context.Context, options BundleOptions) ([]bundleEntry, BundleReport, error) {
	manifest := p.Manifest()
	report := BundleReport{Kind: options.Kind, SourceCaptures: len(manifest.Captures)}
	selected, err := selectBundleCaptures(manifest.Captures, options)
	if err != nil {
		return nil, report, err
	}
	if options.Kind == BundleFull {
		captures := make([]Capture, 0, len(selected))
		for _, capture := range manifest.Captures {
			if selected[capture.ID] {
				captures = append(captures, capture)
				report.IncludedCaptures = append(report.IncludedCaptures, capture.ID)
			} else {
				report.OmittedCaptures = append(report.OmittedCaptures, capture.ID)
			}
		}
		manifest.Captures = captures
		pairs := manifest.CapturePairs[:0]
		for _, pair := range manifest.CapturePairs {
			if selected[pair.OriginalCaptureID] &&
				selected[pair.ForwardedCaptureID] {
				pairs = append(pairs, pair)
			}
		}
		manifest.CapturePairs = pairs
		captureJournals := manifest.CaptureJournals[:0]
		for _, journal := range manifest.CaptureJournals {
			if selected[journal.CaptureID] {
				captureJournals = append(captureJournals, journal)
			}
		}
		manifest.CaptureJournals = captureJournals
	} else {
		for _, capture := range manifest.Captures {
			report.OmittedCaptures = append(report.OmittedCaptures, capture.ID)
		}
		manifest.CapturePairs = nil
		manifest.CaptureJournals = nil
		manifest.NetworkSessions = nil
		manifest.Preferences.NetworkBaselineSessionID = ""
	}
	sort.Strings(report.IncludedCaptures)
	sort.Strings(report.OmittedCaptures)

	managedCaptures := make(map[string]Capture)
	selectedJournals := make(map[string]CapturePair)
	selectedCaptureJournals := make(map[string]CaptureJournal)
	if options.Kind == BundleFull {
		for _, pair := range manifest.CapturePairs {
			if err := p.VerifyCapturePairJournal(ctx, pair); err != nil {
				return nil, report, err
			}
			selectedJournals[pair.JournalPath] = pair
		}
		for _, journal := range manifest.CaptureJournals {
			if err := p.VerifyCaptureJournal(ctx, journal); err != nil {
				return nil, report, err
			}
			selectedCaptureJournals[journal.Path] = journal
		}
		for _, capture := range manifest.Captures {
			if err := p.VerifyCapture(ctx, capture); err != nil {
				return nil, report, fmt.Errorf("verify capture %s: %w", capture.ID, err)
			}
			managedCaptures[capture.Path] = capture
		}
	}
	manifestData, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return nil, report, fmt.Errorf("encode bundle project: %w", err)
	}
	entries := []bundleEntry{{name: manifestFile, data: append(manifestData, '\n')}}
	entryNames := make(map[string]bool, len(entries))
	for _, entry := range entries {
		entryNames[entry.name] = true
	}
	root := p.Path()
	err = filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		relative, err := filepath.Rel(root, path)
		if err != nil || relative == "." {
			return err
		}
		relative = filepath.ToSlash(relative)
		if entry.Type()&fs.ModeSymlink != 0 {
			return fmt.Errorf("bundle source %s is a symlink", relative)
		}
		if entry.IsDir() {
			if relative == ".staging" {
				return filepath.SkipDir
			}
			return nil
		}
		if relative == manifestFile || relative == bundleDescriptorFile || relative == "checksums.json" || !entry.Type().IsRegular() {
			return nil
		}
		if strings.HasPrefix(relative, "exports/") && strings.EqualFold(filepath.Ext(relative), ".golanproj") {
			return nil
		}
		if strings.HasPrefix(relative, "captures/") {
			if options.Kind != BundleFull {
				return nil
			}
			if _, ok := managedCaptures[relative]; !ok {
				return nil
			}
		}
		if strings.HasPrefix(relative, "observations/") && options.Kind != BundleFull {
			return nil
		}
		if strings.HasPrefix(relative, "journals/") {
			if options.Kind != BundleFull {
				return nil
			}
			if _, pairOK := selectedJournals[relative]; !pairOK {
				if _, captureOK := selectedCaptureJournals[relative]; !captureOK {
					return nil
				}
			}
		}
		if strings.HasPrefix(relative, "canvas/") || strings.HasPrefix(relative, "notes/") {
			return nil
		}
		if options.Kind == BundleSanitized && strings.HasSuffix(relative, "/observations.jsonl") {
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if info.Size() > maxBundleFileSize {
			return fmt.Errorf("bundle source %s exceeds size limit", relative)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if capture, ok := managedCaptures[relative]; ok {
			digest := sha256.Sum256(data)
			if int64(len(data)) != capture.Size || hex.EncodeToString(digest[:]) != capture.SHA256 {
				return fmt.Errorf("managed capture %s changed while bundling", capture.ID)
			}
		}
		if pair, ok := selectedJournals[relative]; ok {
			digest := sha256.Sum256(data)
			if int64(len(data)) != pair.JournalSize ||
				hex.EncodeToString(digest[:]) != pair.JournalSHA256 {
				return fmt.Errorf(
					"capture pair %s journal changed while bundling",
					pair.ID,
				)
			}
		}
		if journal, ok := selectedCaptureJournals[relative]; ok {
			digest := sha256.Sum256(data)
			if int64(len(data)) != journal.Size || hex.EncodeToString(digest[:]) != journal.SHA256 {
				return fmt.Errorf("capture journal %s changed while bundling", journal.ID)
			}
		}
		if !entryNames[relative] {
			entries = append(entries, bundleEntry{name: relative, data: data})
			entryNames[relative] = true
		}
		return nil
	})
	if err != nil {
		return nil, report, fmt.Errorf("collect bundle: %w", err)
	}
	for _, entry := range entries {
		report.Files++
		report.Bytes += int64(len(entry.data))
		if report.Bytes > maxBundleTotalSize {
			return nil, report, fmt.Errorf("bundle exceeds total size limit")
		}
	}
	return entries, report, nil
}

func selectBundleCaptures(captures []Capture, options BundleOptions) (map[string]bool, error) {
	selected := make(map[string]bool)
	if options.Kind != BundleFull {
		return selected, nil
	}
	known := make(map[string]bool, len(captures))
	for _, capture := range captures {
		known[capture.ID] = true
		if options.CaptureIDs == nil {
			selected[capture.ID] = true
		}
	}
	for _, rawID := range options.CaptureIDs {
		id := strings.TrimSpace(rawID)
		if id == "" {
			return nil, fmt.Errorf("capture selection contains an empty id")
		}
		if selected[id] {
			return nil, fmt.Errorf("capture %s is selected more than once", id)
		}
		if !known[id] {
			return nil, fmt.Errorf("capture %s is not indexed by the project", id)
		}
		selected[id] = true
	}
	return selected, nil
}

// ImportBundle validates checksums and archive safety before atomically
// promoting a new working project directory.
func ImportBundle(ctx context.Context, bundlePath, base, name string) (*Project, error) {
	project, _, err := ImportBundleWithReport(ctx, bundlePath, base, name)
	return project, err
}

// ImportBundleWithReport validates checksums and archive safety before
// atomically promoting a new working project directory. Its report is read
// from a checksummed descriptor when available and safely inferred for legacy
// bundles.
func ImportBundleWithReport(ctx context.Context, bundlePath, base, name string) (project *Project, report BundleReport, resultErr error) {
	bundlePath, err := filepath.Abs(strings.TrimSpace(bundlePath))
	if err != nil {
		return nil, report, fmt.Errorf("resolve bundle: %w", err)
	}
	info, err := os.Lstat(bundlePath)
	if err != nil {
		return nil, report, fmt.Errorf("inspect bundle: %w", err)
	}
	if info.Mode()&fs.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return nil, report, fmt.Errorf("bundle must be a regular non-symlink file")
	}
	archive, err := zip.OpenReader(bundlePath)
	if err != nil {
		return nil, report, fmt.Errorf("open bundle: %w", err)
	}
	defer func() { resultErr = errors.Join(resultErr, archive.Close()) }()
	if len(archive.File) == 0 || len(archive.File) > maxBundleEntries {
		return nil, report, fmt.Errorf("bundle entry count is outside 1-%d", maxBundleEntries)
	}
	files, err := validateBundleFiles(archive.File)
	if err != nil {
		return nil, report, err
	}
	checksumsFile := files["checksums.json"]
	if checksumsFile == nil {
		return nil, report, fmt.Errorf("bundle checksums.json is missing")
	}
	checksumsData, err := readZipFile(checksumsFile, maxChecksumFileSize)
	if err != nil {
		return nil, report, err
	}
	var checksums bundleChecksums
	decoder := json.NewDecoder(strings.NewReader(string(checksumsData)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&checksums); err != nil || checksums.Version != bundleVersion {
		return nil, report, fmt.Errorf("bundle checksums are invalid or unsupported")
	}
	var trailing json.RawMessage
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return nil, report, fmt.Errorf("bundle checksums contain trailing data")
	}
	if len(checksums.Files) != len(files)-1 {
		return nil, report, fmt.Errorf("bundle checksum inventory does not match entries")
	}
	directoryName, _, err := normalizeProjectName(name)
	if err != nil {
		return nil, report, err
	}
	base, err = filepath.Abs(strings.TrimSpace(base))
	if err != nil {
		return nil, report, fmt.Errorf("resolve project base: %w", err)
	}
	if err := os.MkdirAll(base, 0o700); err != nil {
		return nil, report, fmt.Errorf("create project base: %w", err)
	}
	destination := filepath.Join(base, directoryName)
	if _, err := os.Lstat(destination); err == nil {
		return nil, report, fmt.Errorf("project destination already exists")
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, report, err
	}
	staging, err := os.MkdirTemp(base, ".golan-import-*")
	if err != nil {
		return nil, report, fmt.Errorf("create bundle staging directory: %w", err)
	}
	defer func() {
		if removeErr := os.RemoveAll(staging); removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
			resultErr = errors.Join(resultErr, removeErr)
		}
	}()
	for name, file := range files {
		if name == "checksums.json" || name == bundleDescriptorFile {
			continue
		}
		select {
		case <-ctx.Done():
			return nil, report, ctx.Err()
		default:
		}
		expected, ok := checksums.Files[name]
		if !ok || len(expected) != 64 {
			return nil, report, fmt.Errorf("bundle checksum for %s is missing", name)
		}
		target := filepath.Join(staging, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
			return nil, report, err
		}
		if err := extractZipFile(file, target, expected); err != nil {
			return nil, report, err
		}
	}
	if _, ok := files[manifestFile]; !ok {
		return nil, report, fmt.Errorf("bundle project.json is missing")
	}
	if err := createProjectDirectories(staging); err != nil {
		return nil, report, err
	}
	manifestData, err := os.ReadFile(filepath.Join(staging, manifestFile))
	if err != nil {
		return nil, report, err
	}
	manifest, err := decodeManifest(manifestData)
	if err != nil {
		return nil, report, err
	}
	report, err = importBundleReport(files, checksums, manifest)
	if err != nil {
		return nil, report, err
	}
	if err := validateImportedBundleEvidence(ctx, staging, files, manifest, report, files[bundleDescriptorFile] != nil); err != nil {
		return nil, report, err
	}
	if err := os.Rename(staging, destination); err != nil {
		return nil, report, fmt.Errorf("promote imported project: %w", err)
	}
	project, err = Open(destination)
	return project, report, err
}

func importBundleReport(files map[string]*zip.File, checksums bundleChecksums, manifest Manifest) (BundleReport, error) {
	report := BundleReport{}
	if descriptorFile := files[bundleDescriptorFile]; descriptorFile != nil {
		expected, ok := checksums.Files[bundleDescriptorFile]
		if !ok || len(expected) != 64 {
			return report, fmt.Errorf("bundle descriptor checksum is missing")
		}
		data, err := readZipFile(descriptorFile, maxChecksumFileSize)
		if err != nil {
			return report, err
		}
		digest := sha256.Sum256(data)
		if hex.EncodeToString(digest[:]) != strings.ToLower(expected) {
			return report, fmt.Errorf("bundle checksum mismatch for %s", bundleDescriptorFile)
		}
		var descriptor bundleDescriptor
		decoder := json.NewDecoder(strings.NewReader(string(data)))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&descriptor); err != nil || descriptor.Version != bundleVersion {
			return report, fmt.Errorf("bundle descriptor is invalid or unsupported")
		}
		var trailing json.RawMessage
		if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
			return report, fmt.Errorf("bundle descriptor contains trailing data")
		}
		report = descriptor.Report
	}

	observedFiles := 0
	var observedBytes int64
	for name, file := range files {
		if name == "checksums.json" || name == bundleDescriptorFile {
			continue
		}
		observedFiles++
		observedBytes += int64(file.UncompressedSize64)
	}
	if report.Kind == "" {
		report = inferLegacyBundleReport(files, manifest)
	}
	if err := validateBundleReport(report, manifest, observedFiles, observedBytes); err != nil {
		return BundleReport{}, err
	}
	return report, nil
}

func inferLegacyBundleReport(files map[string]*zip.File, manifest Manifest) BundleReport {
	report := BundleReport{Kind: BundleMetadata, SourceCaptures: len(manifest.Captures)}
	for name, file := range files {
		if name == "checksums.json" || name == bundleDescriptorFile {
			continue
		}
		report.Files++
		report.Bytes += int64(file.UncompressedSize64)
	}
	full := len(manifest.Captures) > 0
	for _, capture := range manifest.Captures {
		if capture.Mode != ImportCopy || files[capture.Path] == nil {
			full = false
			report.OmittedCaptures = append(report.OmittedCaptures, capture.ID)
		} else {
			report.IncludedCaptures = append(report.IncludedCaptures, capture.ID)
		}
	}
	if full {
		report.Kind = BundleFull
	}
	sort.Strings(report.IncludedCaptures)
	sort.Strings(report.OmittedCaptures)
	return report
}

func validateBundleReport(report BundleReport, manifest Manifest, files int, bytes int64) error {
	switch report.Kind {
	case BundleFull, BundleMetadata, BundleSanitized:
	default:
		return fmt.Errorf("bundle descriptor kind is invalid")
	}
	if report.Files != files || report.Bytes != bytes || report.SourceCaptures < 0 {
		return fmt.Errorf("bundle descriptor inventory does not match entries")
	}
	seen := make(map[string]bool, report.SourceCaptures)
	included := make(map[string]bool, len(report.IncludedCaptures))
	for _, collection := range [][]string{report.IncludedCaptures, report.OmittedCaptures} {
		if !sort.StringsAreSorted(collection) {
			return fmt.Errorf("bundle descriptor capture inventory is not sorted")
		}
		for _, id := range collection {
			if id == "" || seen[id] {
				return fmt.Errorf("bundle descriptor capture inventory is invalid")
			}
			seen[id] = true
		}
	}
	for _, id := range report.IncludedCaptures {
		included[id] = true
	}
	if len(seen) != report.SourceCaptures {
		return fmt.Errorf("bundle descriptor capture counts do not match project metadata")
	}
	manifestIDs := make(map[string]bool, len(manifest.Captures))
	for _, capture := range manifest.Captures {
		manifestIDs[capture.ID] = true
	}
	if report.Kind == BundleFull {
		if len(manifestIDs) != len(included) {
			return fmt.Errorf("bundle descriptor included captures do not match project metadata")
		}
		for id := range manifestIDs {
			if !included[id] {
				return fmt.Errorf("bundle descriptor included captures do not match project metadata")
			}
		}
	} else {
		if len(included) != 0 || len(manifestIDs) != len(report.OmittedCaptures) {
			return fmt.Errorf("bundle descriptor omitted captures do not match project metadata")
		}
		for id := range manifestIDs {
			if !seen[id] {
				return fmt.Errorf("bundle descriptor omitted captures do not match project metadata")
			}
		}
	}
	return nil
}

func validateImportedBundleEvidence(ctx context.Context, staging string, files map[string]*zip.File, manifest Manifest, report BundleReport, described bool) error {
	if !described && len(manifest.CapturePairs) == 0 && len(manifest.CaptureJournals) == 0 && len(manifest.NetworkSessions) == 0 {
		return nil
	}
	if report.Kind != BundleFull {
		if len(manifest.CapturePairs) != 0 {
			return fmt.Errorf(
				"%s bundle unexpectedly indexes capture-pair evidence",
				report.Kind,
			)
		}
		if len(manifest.CaptureJournals) != 0 {
			return fmt.Errorf(
				"%s bundle unexpectedly indexes capture-journal evidence",
				report.Kind,
			)
		}
		if len(manifest.NetworkSessions) != 0 {
			return fmt.Errorf("%s bundle unexpectedly indexes network observations", report.Kind)
		}
		for name := range files {
			if strings.HasPrefix(name, "captures/") ||
				strings.HasPrefix(name, "journals/") ||
				strings.HasPrefix(name, "observations/") {
				return fmt.Errorf(
					"%s bundle unexpectedly contains capture evidence",
					report.Kind,
				)
			}
		}
		return nil
	}

	allowedCaptures := make(map[string]Capture, len(manifest.Captures))
	for _, capture := range manifest.Captures {
		if capture.Mode != ImportCopy || files[capture.Path] == nil {
			return fmt.Errorf("full bundle capture %s is not a managed payload", capture.ID)
		}
		allowedCaptures[capture.Path] = capture
	}
	allowedJournals := make(map[string]CapturePair, len(manifest.CapturePairs))
	for _, pair := range manifest.CapturePairs {
		if files[pair.JournalPath] == nil {
			return fmt.Errorf(
				"full bundle capture pair %s journal is missing",
				pair.ID,
			)
		}
		allowedJournals[pair.JournalPath] = pair
	}
	allowedCaptureJournals := make(map[string]CaptureJournal, len(manifest.CaptureJournals))
	for _, journal := range manifest.CaptureJournals {
		if files[journal.Path] == nil {
			return fmt.Errorf("full bundle capture journal %s is missing", journal.ID)
		}
		allowedCaptureJournals[journal.Path] = journal
	}
	allowedNetworkSessions := make(map[string]NetworkSessionReference, len(manifest.NetworkSessions))
	for _, session := range manifest.NetworkSessions {
		if files[session.Path] == nil {
			return fmt.Errorf("full bundle network session %s is missing", session.ID)
		}
		allowedNetworkSessions[session.Path] = session
	}
	for name := range files {
		if strings.HasPrefix(name, "captures/") {
			if _, ok := allowedCaptures[name]; !ok {
				return fmt.Errorf("full bundle contains unindexed capture payload %s", name)
			}
		}
		if strings.HasPrefix(name, "canvas/") || strings.HasPrefix(name, "notes/") {
			return fmt.Errorf("full bundle contains retired payload %s", name)
		}
		if strings.HasPrefix(name, "journals/") {
			if _, pairOK := allowedJournals[name]; !pairOK {
				if _, captureOK := allowedCaptureJournals[name]; !captureOK {
					return fmt.Errorf(
						"full bundle contains unindexed journal payload %s",
						name,
					)
				}
			}
		}
		if strings.HasPrefix(name, "observations/") {
			if _, ok := allowedNetworkSessions[name]; !ok {
				return fmt.Errorf("full bundle contains unindexed network observations %s", name)
			}
		}
	}
	project := &Project{path: staging, manifest: manifest}
	for _, capture := range manifest.Captures {
		if err := project.VerifyCapture(ctx, capture); err != nil {
			return fmt.Errorf("verify imported capture %s: %w", capture.ID, err)
		}
	}
	for _, pair := range manifest.CapturePairs {
		if err := project.VerifyCapturePairJournal(ctx, pair); err != nil {
			return fmt.Errorf(
				"verify imported capture pair %s: %w",
				pair.ID,
				err,
			)
		}
	}
	for _, journal := range manifest.CaptureJournals {
		if err := project.VerifyCaptureJournal(ctx, journal); err != nil {
			return fmt.Errorf("verify imported capture journal %s: %w", journal.ID, err)
		}
	}
	for _, session := range manifest.NetworkSessions {
		if _, _, err := project.ReadNetworkSession(session.ID); err != nil {
			return fmt.Errorf("verify imported network session %s: %w", session.ID, err)
		}
	}
	return nil
}

func validateBundleFiles(files []*zip.File) (map[string]*zip.File, error) {
	out := make(map[string]*zip.File, len(files))
	var total uint64
	for _, file := range files {
		name := file.Name
		if name == "" || strings.Contains(name, "\\") || !filepath.IsLocal(filepath.FromSlash(name)) || strings.HasSuffix(name, "/") {
			return nil, fmt.Errorf("bundle entry path %q is unsafe", name)
		}
		if _, exists := out[name]; exists {
			return nil, fmt.Errorf("bundle entry %q is duplicated", name)
		}
		if file.Mode()&fs.ModeSymlink != 0 || !file.Mode().IsRegular() {
			return nil, fmt.Errorf("bundle entry %q is not a regular file", name)
		}
		if file.UncompressedSize64 > maxBundleFileSize {
			return nil, fmt.Errorf("bundle entry %q exceeds size limit", name)
		}
		total += file.UncompressedSize64
		if total > maxBundleTotalSize {
			return nil, fmt.Errorf("bundle exceeds total size limit")
		}
		if file.CompressedSize64 > 0 && file.UncompressedSize64 > 1<<20 && file.UncompressedSize64/file.CompressedSize64 > 1000 {
			return nil, fmt.Errorf("bundle entry %q has an unsafe compression ratio", name)
		}
		out[name] = file
	}
	return out, nil
}

func readZipFile(file *zip.File, limit int64) ([]byte, error) {
	reader, err := file.Open()
	if err != nil {
		return nil, err
	}
	data, readErr := io.ReadAll(io.LimitReader(reader, limit+1))
	closeErr := reader.Close()
	if readErr != nil || closeErr != nil {
		return nil, errors.Join(readErr, closeErr)
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("bundle entry %s exceeds read limit", file.Name)
	}
	return data, nil
}

func extractZipFile(file *zip.File, target, expected string) error {
	reader, err := file.Open()
	if err != nil {
		return err
	}
	out, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		_ = reader.Close()
		return err
	}
	hash := sha256.New()
	written, copyErr := io.Copy(io.MultiWriter(out, hash), io.LimitReader(reader, maxBundleFileSize+1))
	closeReaderErr := reader.Close()
	syncErr := out.Sync()
	closeOutErr := out.Close()
	if copyErr != nil || closeReaderErr != nil || syncErr != nil || closeOutErr != nil {
		return errors.Join(copyErr, closeReaderErr, syncErr, closeOutErr)
	}
	if written > maxBundleFileSize {
		return fmt.Errorf("bundle entry %s exceeds extraction limit", file.Name)
	}
	if got := hex.EncodeToString(hash.Sum(nil)); got != strings.ToLower(expected) {
		return fmt.Errorf("bundle checksum mismatch for %s", file.Name)
	}
	return nil
}
