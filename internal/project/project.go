package project

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"sync"
	"time"

	"golan/internal/network"
	"golan/internal/paths"
	"golan/internal/syncgate"
)

const (
	// CurrentVersion is the supported project manifest schema.
	CurrentVersion   = 3
	manifestFile     = "project.json"
	maxManifestSize  = 8 << 20
	maxPolicySize    = 64 << 20
	projectExtension = ".golan"
)

var projectDirectories = []string{"configs", "policies", "captures", "journals", "observations", "exports", ".staging"}

// Manifest is the explicitly saved project metadata. Captures themselves are
// immutable evidence and may exist before this inventory is saved.
type Manifest struct {
	Version         int                       `json:"version"`
	ID              string                    `json:"id"`
	Name            string                    `json:"name"`
	CreatedAt       time.Time                 `json:"created_at"`
	UpdatedAt       time.Time                 `json:"updated_at"`
	Configs         []ConfigSource            `json:"configs,omitempty"`
	Policies        []PolicyRevision          `json:"policies,omitempty"`
	Captures        []Capture                 `json:"captures,omitempty"`
	CapturePairs    []CapturePair             `json:"capture_pairs,omitempty"`
	CaptureJournals []CaptureJournal          `json:"capture_journals,omitempty"`
	NetworkSessions []NetworkSessionReference `json:"network_sessions,omitempty"`
	Preferences     Preferences               `json:"preferences,omitempty"`
}

// NetworkSessionReference indexes one immutable sanitized observation session.
type NetworkSessionReference struct {
	ID           string    `json:"id"`
	Path         string    `json:"path"`
	SHA256       string    `json:"sha256"`
	Size         int64     `json:"size"`
	Mode         string    `json:"mode"`
	StartedAt    time.Time `json:"started_at"`
	EndedAt      time.Time `json:"ended_at,omitempty"`
	Devices      int       `json:"devices"`
	Observations int       `json:"observations"`
}

// ConfigSource records an immutable source snapshot and fingerprint.
type ConfigSource struct {
	ID         string    `json:"id"`
	Name       string    `json:"name"`
	Snapshot   string    `json:"snapshot"`
	SourcePath string    `json:"source_path,omitempty"`
	SHA256     string    `json:"sha256"`
	Size       int64     `json:"size"`
	ModifiedAt time.Time `json:"modified_at,omitempty"`
	ImportedAt time.Time `json:"imported_at"`
}

// PolicyRevision references one immutable policy JSON artifact.
type PolicyRevision struct {
	Revision  string    `json:"revision"`
	Name      string    `json:"name,omitempty"`
	Path      string    `json:"path"`
	SHA256    string    `json:"sha256"`
	CreatedAt time.Time `json:"created_at"`
}

// ImportMode controls capture ownership.
type ImportMode string

// Capture imports default to managed copies.
const (
	ImportCopy ImportMode = "copy"
)

// Capture records an immutable managed copy or fingerprinted reference.
type Capture struct {
	ID         string     `json:"id"`
	Name       string     `json:"name"`
	Path       string     `json:"path"`
	Mode       ImportMode `json:"mode"`
	Format     string     `json:"format"`
	SHA256     string     `json:"sha256"`
	Size       int64      `json:"size"`
	ModifiedAt time.Time  `json:"modified_at"`
	ImportedAt time.Time  `json:"imported_at"`
	Indexed    bool       `json:"indexed"`
}

// CapturePair links managed original/forwarded evidence to one immutable,
// payload-free decision journal.
type CapturePair struct {
	ID                 string    `json:"id"`
	OriginalCaptureID  string    `json:"original_capture_id"`
	ForwardedCaptureID string    `json:"forwarded_capture_id"`
	JournalPath        string    `json:"journal_path"`
	JournalSHA256      string    `json:"journal_sha256"`
	JournalSize        int64     `json:"journal_size"`
	JournalRecords     uint64    `json:"journal_records"`
	JournalComplete    bool      `json:"journal_complete"`
	ImportedAt         time.Time `json:"imported_at"`
}

// CaptureJournal links one immutable passive packet capture to its
// payload-free, ordinal-addressed shadow decision stream.
type CaptureJournal struct {
	ID         string    `json:"id"`
	CaptureID  string    `json:"capture_id"`
	Path       string    `json:"path"`
	Mode       string    `json:"mode"`
	SHA256     string    `json:"sha256"`
	Size       int64     `json:"size"`
	Records    uint64    `json:"records"`
	Complete   bool      `json:"complete"`
	ImportedAt time.Time `json:"imported_at"`
}

// Preferences stores the small amount of project-scoped Workbench state.
type Preferences struct {
	Workspace            string `json:"workspace,omitempty"`
	ActivePolicyRevision string `json:"active_policy_revision,omitempty"`
}

// Project owns one working directory and its explicit-save state.
type Project struct {
	mu                     sync.RWMutex
	path                   string
	manifest               Manifest
	saved                  Manifest
	dirty                  bool
	pendingCapturePairs    map[string]chan struct{}
	pendingCaptureJournals map[string]chan struct{}
	policySaveGate         syncgate.Gate
	saveGate               syncgate.Gate
}

// DefaultRoot returns ~/.config/goLAN/projects for the invoking user.
func DefaultRoot() (string, error) {
	root, err := paths.ConfigRoot()
	if err != nil {
		return "", err
	}
	return filepath.Join(root, "projects"), nil
}

// New creates a blank project directory but does not write project.json until
// Save is explicitly called.
func New(base, name string) (*Project, error) {
	directoryName, displayName, err := normalizeProjectName(name)
	if err != nil {
		return nil, err
	}
	base, err = filepath.Abs(strings.TrimSpace(base))
	if err != nil || base == "" {
		return nil, fmt.Errorf("resolve project base: %w", err)
	}
	if err := os.MkdirAll(base, 0o700); err != nil {
		return nil, fmt.Errorf("create project base: %w", err)
	}
	path := filepath.Join(base, directoryName)
	if err := os.Mkdir(path, 0o700); err != nil {
		return nil, fmt.Errorf("create project: %w", err)
	}
	if err := createProjectDirectories(path); err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	manifest := Manifest{Version: CurrentVersion, ID: newID(now, displayName), Name: displayName, CreatedAt: now, UpdatedAt: now}
	return &Project{path: path, manifest: manifest, saved: cloneManifest(manifest), dirty: true}, nil
}

// NewDefault creates a blank project under DefaultRoot.
func NewDefault(name string) (*Project, error) {
	root, err := DefaultRoot()
	if err != nil {
		return nil, err
	}
	return New(root, name)
}

// Open loads a saved project without starting or mutating networking.
func Open(path string) (*Project, error) {
	path, err := validateProjectPath(path)
	if err != nil {
		return nil, err
	}
	content, err := readProjectFile(path, manifestFile, maxManifestSize)
	if err != nil {
		return nil, err
	}
	manifest, err := decodeManifest(content)
	if err != nil {
		return nil, err
	}
	return &Project{path: path, manifest: manifest, saved: cloneManifest(manifest)}, nil
}

// Path returns the absolute working project directory.
func (p *Project) Path() string {
	if p == nil {
		return ""
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.path
}

// Manifest returns a deep copy of current in-memory metadata.
func (p *Project) Manifest() Manifest {
	if p == nil {
		return Manifest{}
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	return cloneManifest(p.manifest)
}

// Dirty reports whether metadata differs from the last explicit save.
func (p *Project) Dirty() bool {
	if p == nil {
		return false
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.dirty
}

// SetWorkspace marks Workbench preference metadata dirty.
func (p *Project) SetWorkspace(workspace string) {
	if p == nil {
		return
	}
	workspace = strings.TrimSpace(workspace)
	p.mu.Lock()
	if p.manifest.Preferences.Workspace != workspace {
		p.manifest.Preferences.Workspace = workspace
		p.dirty = true
	}
	p.mu.Unlock()
}

// SetActivePolicyRevision records which already-indexed immutable policy
// revision should be restored when the project is opened. An empty revision
// explicitly clears the selection.
func (p *Project) SetActivePolicyRevision(revision string) error {
	if p == nil {
		return fmt.Errorf("project is nil")
	}
	revision = strings.TrimSpace(revision)
	p.mu.Lock()
	defer p.mu.Unlock()
	if revision != "" {
		found := false
		for _, candidate := range p.manifest.Policies {
			if candidate.Revision == revision {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("policy revision %q is not indexed", revision)
		}
	}
	if p.manifest.Preferences.ActivePolicyRevision != revision {
		p.manifest.Preferences.ActivePolicyRevision = revision
		p.dirty = true
	}
	return nil
}

// Save atomically writes project.json and clears PROJECT* state.
func (p *Project) Save() error {
	if p == nil {
		return fmt.Errorf("project is nil")
	}
	release := p.saveGate.Enter()
	defer release()
	p.mu.RLock()
	path := p.path
	original := cloneManifest(p.manifest)
	p.mu.RUnlock()
	manifest := cloneManifest(original)
	manifest.Version = CurrentVersion
	manifest.UpdatedAt = time.Now().UTC()
	content, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return fmt.Errorf("encode project: %w", err)
	}
	if err := writeProjectFile(path, manifestFile, append(content, '\n')); err != nil {
		return err
	}
	p.finishSave(original, manifest)
	return nil
}

func (p *Project) finishSave(original, saved Manifest) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.saved = cloneManifest(saved)
	if reflect.DeepEqual(p.manifest, original) {
		p.manifest = cloneManifest(saved)
		p.dirty = false
		return
	}
	// The durable file is the saved baseline, while edits made during the
	// write remain staged for the next explicit save.
	p.dirty = true
}

// SaveAs copies immutable project artifacts to a new working directory and
// saves the current metadata there.
func (p *Project) SaveAs(base, name string) (*Project, error) {
	return p.SaveAsContext(context.Background(), base, name)
}

// SaveAsContext creates a complete sibling project in private staging and
// atomically promotes it only after every artifact and the current in-memory
// manifest have been durably written. Cancellation or failure leaves the
// source project unchanged and removes the incomplete staging directory.
func (p *Project) SaveAsContext(ctx context.Context, base, name string) (next *Project, resultErr error) {
	if p == nil {
		return nil, fmt.Errorf("project is nil")
	}
	if ctx == nil {
		return nil, fmt.Errorf("save-as context is nil")
	}
	directoryName, displayName, err := normalizeProjectName(name)
	if err != nil {
		return nil, err
	}
	p.mu.RLock()
	sourcePath := p.path
	manifest := cloneManifest(p.manifest)
	p.mu.RUnlock()
	sourcePath, err = validateProjectPath(sourcePath)
	if err != nil {
		return nil, err
	}
	base, err = filepath.Abs(strings.TrimSpace(base))
	if err != nil || base == "" {
		return nil, fmt.Errorf("resolve project base: %w", err)
	}
	destination := filepath.Join(base, directoryName)
	if pathWithin(sourcePath, destination) {
		return nil, fmt.Errorf("project destination must not be inside the source project")
	}
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}
	if err := os.MkdirAll(base, 0o700); err != nil {
		return nil, fmt.Errorf("create project base: %w", err)
	}
	base, err = filepath.EvalSymlinks(base)
	if err != nil {
		return nil, fmt.Errorf("resolve real project base: %w", err)
	}
	destination = filepath.Join(base, directoryName)
	if pathWithin(sourcePath, destination) {
		return nil, fmt.Errorf("project destination must not be inside the source project")
	}
	if _, err := os.Lstat(destination); err == nil {
		return nil, fmt.Errorf("project destination already exists")
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("inspect project destination: %w", err)
	}
	staging, err := os.MkdirTemp(base, ".golan-save-as-*")
	if err != nil {
		return nil, fmt.Errorf("create save-as staging directory: %w", err)
	}
	defer func() {
		if removeErr := os.RemoveAll(staging); removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
			resultErr = errors.Join(resultErr, fmt.Errorf("remove save-as staging directory: %w", removeErr))
		}
	}()
	if err := createProjectDirectories(staging); err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	manifest.ID = newID(now, destination)
	manifest.Name = displayName
	manifest.CreatedAt = now
	manifest.UpdatedAt = now
	manifest.Version = CurrentVersion
	if err := validateManifest(manifest); err != nil {
		return nil, fmt.Errorf("validate save-as project: %w", err)
	}
	if err := copyProjectArtifacts(ctx, sourcePath, staging, manifest); err != nil {
		return nil, err
	}
	staged := &Project{path: staging, manifest: manifest, saved: cloneManifest(manifest), dirty: true}
	if err := staged.Save(); err != nil {
		return nil, err
	}
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}
	if _, err := os.Lstat(destination); err == nil {
		return nil, fmt.Errorf("project destination appeared during save-as")
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("reinspect project destination: %w", err)
	}
	if err := syncProjectTreeDirectories(ctx, staging); err != nil {
		return nil, fmt.Errorf("sync save-as staging tree: %w", err)
	}
	if err := os.Rename(staging, destination); err != nil {
		return nil, fmt.Errorf("promote saved project: %w", err)
	}
	staged.mu.Lock()
	staged.path = destination
	staged.mu.Unlock()
	next = staged
	if err := syncDirectory(base); err != nil {
		return next, fmt.Errorf("saved project was promoted at %s but its parent directory could not be synced: %w", destination, err)
	}
	return staged, nil
}

// CloseChoice controls explicit dirty-metadata close behavior.
type CloseChoice string

// Close choices match the Workbench confirmation dialog.
const (
	CloseSave    CloseChoice = "save"
	CloseDiscard CloseChoice = "discard"
	CloseCancel  CloseChoice = "cancel"
)

// Close applies an explicit metadata choice. It does not remove finalized
// captures and performs no networking operation.
func (p *Project) Close(choice CloseChoice) (bool, error) {
	if p == nil {
		return true, nil
	}
	switch choice {
	case CloseSave:
		return true, p.Save()
	case CloseDiscard:
		p.mu.Lock()
		p.manifest = cloneManifest(p.saved)
		p.dirty = false
		p.mu.Unlock()
		return true, nil
	case CloseCancel:
		return false, nil
	default:
		return false, fmt.Errorf("unknown close choice %q", choice)
	}
}

// ImportConfig snapshots a source config without trusting it as current live
// adapter metadata.
func (p *Project) ImportConfig(source string) (ConfigSource, error) {
	if p == nil {
		return ConfigSource{}, fmt.Errorf("project is nil")
	}
	info, content, digest, err := readAndHash(source, maxManifestSize)
	if err != nil {
		return ConfigSource{}, fmt.Errorf("import config: %w", err)
	}
	name := filepath.Base(source)
	snapshot := filepath.Join("configs", digest[:16]+"-"+safeBase(name))
	if err := writeProjectFile(p.Path(), snapshot, content); err != nil {
		return ConfigSource{}, fmt.Errorf("snapshot config: %w", err)
	}
	record := ConfigSource{
		ID: digest[:16], Name: name, Snapshot: filepath.ToSlash(snapshot),
		SourcePath: absolutePath(source), SHA256: digest, Size: info.Size(),
		ModifiedAt: info.ModTime().UTC(), ImportedAt: time.Now().UTC(),
	}
	p.mu.Lock()
	for _, existing := range p.manifest.Configs {
		if existing.SHA256 == digest {
			p.mu.Unlock()
			return existing, nil
		}
	}
	p.manifest.Configs = append(p.manifest.Configs, record)
	p.dirty = true
	p.mu.Unlock()
	return record, nil
}

// ReadConfigSnapshot returns one indexed immutable source and checksum-verifies
// its project-owned snapshot before releasing a copy of the bytes.
func (p *Project) ReadConfigSnapshot(id string) (ConfigSource, []byte, error) {
	if p == nil {
		return ConfigSource{}, nil, fmt.Errorf("project is nil")
	}
	record, ok := p.configSource(id)
	if !ok {
		return ConfigSource{}, nil, fmt.Errorf("config source %q was not found", strings.TrimSpace(id))
	}
	content, err := readProjectFile(p.Path(), filepath.FromSlash(record.Snapshot), maxManifestSize)
	if err != nil {
		return ConfigSource{}, nil, fmt.Errorf("read config snapshot: %w", err)
	}
	digest := sha256.Sum256(content)
	if hex.EncodeToString(digest[:]) != record.SHA256 || int64(len(content)) != record.Size {
		return ConfigSource{}, nil, fmt.Errorf("config snapshot fingerprint differs from inventory")
	}
	return record, content, nil
}

// UpdateConfigSource snapshots the current bytes at an indexed source path
// only when they match the caller's already-validated SHA-256 fingerprint.
// Existing snapshot files are never overwritten. An unchanged source returns
// the previous record; content already indexed elsewhere is deduplicated.
func (p *Project) UpdateConfigSource(id, expectedSHA256 string) (previous, current ConfigSource, changed, duplicate bool, err error) {
	if p == nil {
		return ConfigSource{}, ConfigSource{}, false, false, fmt.Errorf("project is nil")
	}
	previous, ok := p.configSource(id)
	if !ok {
		return ConfigSource{}, ConfigSource{}, false, false, fmt.Errorf("config source %q was not found", strings.TrimSpace(id))
	}
	if strings.TrimSpace(previous.SourcePath) == "" {
		return ConfigSource{}, ConfigSource{}, false, false, fmt.Errorf("config source has no update path")
	}
	expectedSHA256 = strings.ToLower(strings.TrimSpace(expectedSHA256))
	decodedDigest, decodeErr := hex.DecodeString(expectedSHA256)
	if decodeErr != nil || len(decodedDigest) != sha256.Size {
		return ConfigSource{}, ConfigSource{}, false, false, fmt.Errorf("validated config fingerprint is invalid")
	}
	info, content, digest, err := readAndHash(previous.SourcePath, maxManifestSize)
	if err != nil {
		return ConfigSource{}, ConfigSource{}, false, false, fmt.Errorf("update config source: %w", err)
	}
	if digest != expectedSHA256 {
		return ConfigSource{}, ConfigSource{}, false, false, fmt.Errorf("config source changed after validation; retry the update")
	}
	if digest == previous.SHA256 {
		return previous, previous, false, false, nil
	}
	p.mu.RLock()
	for _, existing := range p.manifest.Configs {
		if existing.SHA256 == digest {
			p.mu.RUnlock()
			return previous, existing, true, true, nil
		}
	}
	p.mu.RUnlock()
	name := filepath.Base(previous.SourcePath)
	snapshot := filepath.Join("configs", digest[:16]+"-"+safeBase(name))
	if err := writeProjectFile(p.Path(), snapshot, content); err != nil {
		return ConfigSource{}, ConfigSource{}, false, false, fmt.Errorf("snapshot updated config: %w", err)
	}
	current = ConfigSource{
		ID: digest[:16], Name: name, Snapshot: filepath.ToSlash(snapshot),
		SourcePath: absolutePath(previous.SourcePath), SHA256: digest, Size: info.Size(),
		ModifiedAt: info.ModTime().UTC(), ImportedAt: time.Now().UTC(),
	}
	p.mu.Lock()
	for _, existing := range p.manifest.Configs {
		if existing.SHA256 == digest {
			p.mu.Unlock()
			return previous, existing, true, true, nil
		}
	}
	p.manifest.Configs = append(p.manifest.Configs, current)
	p.dirty = true
	p.mu.Unlock()
	return previous, current, true, false, nil
}

func (p *Project) configSource(id string) (ConfigSource, bool) {
	id = strings.TrimSpace(id)
	p.mu.RLock()
	defer p.mu.RUnlock()
	for _, source := range p.manifest.Configs {
		if source.ID == id {
			return source, true
		}
	}
	return ConfigSource{}, false
}

// SavePolicyRevision atomically stores one policy artifact and indexes it in
// project metadata.
func (p *Project) SavePolicyRevision(revision, name string, content []byte) (PolicyRevision, error) {
	if p == nil {
		return PolicyRevision{}, fmt.Errorf("project is nil")
	}
	if err := validatePolicyRevisionName(revision); err != nil {
		return PolicyRevision{}, err
	}
	revision = strings.TrimSpace(revision)
	if len(content) > maxPolicySize {
		return PolicyRevision{}, fmt.Errorf("policy revision exceeds %d bytes", maxPolicySize)
	}
	digest := sha256.Sum256(content)
	hexDigest := hex.EncodeToString(digest[:])
	revisionDigest := sha256.Sum256([]byte(revision))
	relative := filepath.Join("policies", hexDigest[:12]+"-"+hex.EncodeToString(revisionDigest[:6])+"-"+safeBase(revision)+".json")
	release := p.policySaveGate.Enter()
	defer release()

	p.mu.Lock()
	root := p.path
	for _, existing := range p.manifest.Policies {
		if existing.Revision != revision {
			continue
		}
		if existing.SHA256 != hexDigest {
			p.mu.Unlock()
			return PolicyRevision{}, fmt.Errorf("policy revision %q already exists with different content", revision)
		}
		p.mu.Unlock()
		if err := writeProjectFile(root, filepath.FromSlash(existing.Path), content); err != nil {
			return PolicyRevision{}, err
		}
		return existing, nil
	}
	p.mu.Unlock()
	if err := writeProjectFile(root, relative, content); err != nil {
		return PolicyRevision{}, err
	}
	record := PolicyRevision{Revision: revision, Name: strings.TrimSpace(name), Path: filepath.ToSlash(relative), SHA256: hexDigest, CreatedAt: time.Now().UTC()}
	p.mu.Lock()
	p.manifest.Policies = append(p.manifest.Policies, record)
	p.dirty = true
	p.mu.Unlock()
	return record, nil
}

func validatePolicyRevisionName(revision string) error {
	revision = strings.TrimSpace(revision)
	if revision == "" || filepath.Base(revision) != revision || strings.ContainsAny(revision, "/\\\x00\r\n") {
		return fmt.Errorf("policy revision name is invalid")
	}
	return nil
}

// ReadPolicyRevision reads one indexed policy artifact and verifies its digest
// before returning any bytes to the policy decoder.
func (p *Project) ReadPolicyRevision(revision string) ([]byte, PolicyRevision, error) {
	if p == nil {
		return nil, PolicyRevision{}, fmt.Errorf("project is nil")
	}
	revision = strings.TrimSpace(revision)
	p.mu.RLock()
	root := p.path
	var record PolicyRevision
	for _, candidate := range p.manifest.Policies {
		if candidate.Revision == revision {
			record = candidate
			break
		}
	}
	p.mu.RUnlock()
	if record.Revision == "" {
		return nil, PolicyRevision{}, fmt.Errorf("policy revision %q is not indexed", revision)
	}
	content, err := readProjectFile(root, record.Path, maxPolicySize)
	if err != nil {
		return nil, PolicyRevision{}, err
	}
	digest := sha256.Sum256(content)
	if hex.EncodeToString(digest[:]) != record.SHA256 {
		return nil, PolicyRevision{}, fmt.Errorf("policy revision %q checksum mismatch", revision)
	}
	return content, record, nil
}

// UnindexedCaptures returns finalized capture files not present in saved or
// in-memory inventory. Callers can offer Attach or Archive explicitly.
func (p *Project) UnindexedCaptures() ([]string, error) {
	if p == nil {
		return nil, fmt.Errorf("project is nil")
	}
	root := filepath.Join(p.Path(), "captures")
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil, fmt.Errorf("scan captures: %w", err)
	}
	p.mu.RLock()
	indexed := make(map[string]bool, len(p.manifest.Captures))
	for _, capture := range p.manifest.Captures {
		if capture.Mode == ImportCopy {
			indexed[filepath.Clean(filepath.Join(p.path, filepath.FromSlash(capture.Path)))] = true
		}
	}
	p.mu.RUnlock()
	var out []string
	for _, entry := range entries {
		if entry.IsDir() || entry.Type()&fs.ModeSymlink != 0 || !captureExtension(entry.Name()) {
			continue
		}
		path := filepath.Join(root, entry.Name())
		if !indexed[path] {
			out = append(out, path)
		}
	}
	sort.Strings(out)
	return out, nil
}

func normalizeProjectName(name string) (string, string, error) {
	name = strings.TrimSpace(name)
	if strings.EqualFold(filepath.Ext(name), projectExtension) {
		name = strings.TrimSuffix(name, filepath.Ext(name))
	}
	if name == "" || filepath.Base(name) != name || name == "." || name == ".." || strings.ContainsAny(name, "/\\\x00\r\n") {
		return "", "", fmt.Errorf("project name is invalid")
	}
	return name + projectExtension, name, nil
}

func validateProjectPath(path string) (string, error) {
	path, err := filepath.Abs(strings.TrimSpace(path))
	if err != nil {
		return "", fmt.Errorf("resolve project path: %w", err)
	}
	if !strings.EqualFold(filepath.Ext(path), projectExtension) {
		return "", fmt.Errorf("project directory must use %s", projectExtension)
	}
	info, err := os.Lstat(path)
	if err != nil {
		return "", fmt.Errorf("inspect project: %w", err)
	}
	if info.Mode()&fs.ModeSymlink != 0 || !info.IsDir() {
		return "", fmt.Errorf("project path must be a real directory")
	}
	return path, nil
}

func createProjectDirectories(root string) error {
	for _, directory := range projectDirectories {
		if err := os.Mkdir(filepath.Join(root, directory), 0o700); err != nil && !errors.Is(err, os.ErrExist) {
			return fmt.Errorf("create project directory %s: %w", directory, err)
		}
	}
	return nil
}

func decodeManifest(content []byte) (Manifest, error) {
	content = migrateManifest(content)
	var manifest Manifest
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&manifest); err != nil {
		return Manifest{}, fmt.Errorf("decode project: %w", err)
	}
	var extra json.RawMessage
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			err = fmt.Errorf("multiple JSON values")
		}
		return Manifest{}, fmt.Errorf("decode project: %w", err)
	}
	if manifest.Version != CurrentVersion {
		return Manifest{}, fmt.Errorf("unsupported project version %d", manifest.Version)
	}
	if strings.TrimSpace(manifest.ID) == "" || strings.TrimSpace(manifest.Name) == "" {
		return Manifest{}, fmt.Errorf("project identity is incomplete")
	}
	if err := validateManifest(manifest); err != nil {
		return Manifest{}, err
	}
	return manifest, nil
}

func migrateManifest(content []byte) []byte {
	var header struct {
		Version int `json:"version"`
	}
	if json.Unmarshal(content, &header) != nil || header.Version < 1 || header.Version >= CurrentVersion {
		return content
	}
	var raw map[string]json.RawMessage
	if json.Unmarshal(content, &raw) != nil {
		return content
	}
	for _, retired := range []string{"canvases", "bookmarks", "highlights", "notes", "filters", "live_views"} {
		delete(raw, retired)
	}
	keptCaptures := make(map[string]bool)
	if encoded, ok := raw["captures"]; ok {
		var captures []Capture
		if json.Unmarshal(encoded, &captures) == nil {
			managed := captures[:0]
			for _, capture := range captures {
				if capture.Mode == ImportMode("reference") {
					continue
				}
				managed = append(managed, capture)
				keptCaptures[capture.ID] = true
			}
			if migrated, err := json.Marshal(managed); err == nil {
				raw["captures"] = migrated
			}
		}
	}
	if encoded, ok := raw["capture_pairs"]; ok {
		var pairs []CapturePair
		if json.Unmarshal(encoded, &pairs) == nil {
			kept := pairs[:0]
			for _, pair := range pairs {
				if keptCaptures[pair.OriginalCaptureID] && keptCaptures[pair.ForwardedCaptureID] {
					kept = append(kept, pair)
				}
			}
			if migrated, err := json.Marshal(kept); err == nil {
				raw["capture_pairs"] = migrated
			}
		}
	}
	if encoded, ok := raw["capture_journals"]; ok {
		var journals []CaptureJournal
		if json.Unmarshal(encoded, &journals) == nil {
			kept := journals[:0]
			for _, journal := range journals {
				if keptCaptures[journal.CaptureID] {
					kept = append(kept, journal)
				}
			}
			if migrated, err := json.Marshal(kept); err == nil {
				raw["capture_journals"] = migrated
			}
		}
	}
	if encoded, ok := raw["preferences"]; ok {
		var preferences map[string]json.RawMessage
		if json.Unmarshal(encoded, &preferences) == nil {
			delete(preferences, "sidebar_visible")
			delete(preferences, "inspector_visible")
			delete(preferences, "canvas_visible")
			if migrated, err := json.Marshal(preferences); err == nil {
				raw["preferences"] = migrated
			}
		}
	}
	raw["version"] = json.RawMessage("3")
	migrated, err := json.Marshal(raw)
	if err != nil {
		return content
	}
	return migrated
}

func validateManifest(manifest Manifest) error {
	if len(manifest.ID) > 256 || len(manifest.Name) > 512 || strings.ContainsAny(manifest.ID+manifest.Name, "\x00\r\n") {
		return fmt.Errorf("project identity is invalid")
	}
	seenConfigs := make(map[string]bool)
	for _, config := range manifest.Configs {
		if config.ID == "" || seenConfigs[config.ID] || !validDigest(config.SHA256) || config.Size < 0 || !validProjectArtifact(config.Snapshot, "configs") {
			return fmt.Errorf("project config record %q is invalid", config.ID)
		}
		seenConfigs[config.ID] = true
	}
	seenPolicies := make(map[string]bool)
	for _, revision := range manifest.Policies {
		if revision.Revision == "" || seenPolicies[revision.Revision] || !validDigest(revision.SHA256) || !validProjectArtifact(revision.Path, "policies") {
			return fmt.Errorf("project policy record %q is invalid", revision.Revision)
		}
		seenPolicies[revision.Revision] = true
	}
	if active := manifest.Preferences.ActivePolicyRevision; active != "" && !seenPolicies[active] {
		return fmt.Errorf("active policy revision %q is not indexed", active)
	}
	seenCaptures := make(map[string]bool)
	for _, capture := range manifest.Captures {
		if capture.ID == "" || seenCaptures[capture.ID] || !validDigest(capture.SHA256) || capture.Size < 0 || !captureExtension(capture.Name) {
			return fmt.Errorf("project capture record %q is invalid", capture.ID)
		}
		switch capture.Mode {
		case ImportCopy:
			if !validProjectArtifact(capture.Path, "captures") {
				return fmt.Errorf("managed capture %q path is invalid", capture.ID)
			}
		default:
			return fmt.Errorf("capture %q import mode is invalid", capture.ID)
		}
		seenCaptures[capture.ID] = true
	}
	if err := validateCapturePairs(manifest.CapturePairs, seenCaptures); err != nil {
		return err
	}
	if err := validateCaptureJournals(manifest.CaptureJournals, seenCaptures); err != nil {
		return err
	}
	seenNetworkSessions := make(map[string]bool)
	for _, session := range manifest.NetworkSessions {
		if session.ID == "" || seenNetworkSessions[session.ID] || !validDigest(session.SHA256) ||
			session.Size <= 0 || session.Size > maxNetworkSessionSize ||
			session.Devices < 0 || session.Devices > network.MaxDevices ||
			session.Observations < 0 || session.Observations > network.MaxDevices*network.MaxObservationsPerDevice ||
			!validProjectArtifact(session.Path, "observations") {
			return fmt.Errorf("network session record %q is invalid", session.ID)
		}
		seenNetworkSessions[session.ID] = true
	}
	return nil
}

func validDigest(value string) bool {
	if len(value) != sha256.Size*2 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func validProjectArtifact(value, directory string) bool {
	if value == "" || strings.Contains(value, "\\") {
		return false
	}
	local := filepath.FromSlash(value)
	if !filepath.IsLocal(local) || local == "." {
		return false
	}
	clean := filepath.Clean(local)
	prefix := directory + string(filepath.Separator)
	return strings.HasPrefix(clean, prefix) && clean != directory
}

func cloneManifest(manifest Manifest) Manifest {
	content, err := json.Marshal(manifest)
	if err != nil {
		return manifest
	}
	var clone Manifest
	if err := json.Unmarshal(content, &clone); err != nil {
		return manifest
	}
	return clone
}

func newID(now time.Time, seed string) string {
	var entropy [16]byte
	if _, err := rand.Read(entropy[:]); err != nil {
		sum := sha256.Sum256([]byte(now.UTC().Format(time.RFC3339Nano) + "\x00" + seed))
		copy(entropy[:], sum[:])
	}
	return hex.EncodeToString(entropy[:])
}

func safeBase(value string) string {
	value = filepath.Base(strings.TrimSpace(value))
	var out strings.Builder
	for _, char := range value {
		switch {
		case char >= 'a' && char <= 'z', char >= 'A' && char <= 'Z', char >= '0' && char <= '9', char == '-', char == '_', char == '.':
			out.WriteRune(char)
		default:
			out.WriteByte('_')
		}
	}
	name := strings.Trim(out.String(), ".")
	if name == "" {
		return "artifact"
	}
	return name
}

func absolutePath(path string) string {
	value, err := filepath.Abs(path)
	if err != nil {
		return path
	}
	return value
}

func readAndHash(path string, limit int64) (os.FileInfo, []byte, string, error) {
	path, err := filepath.Abs(strings.TrimSpace(path))
	if err != nil {
		return nil, nil, "", err
	}
	before, err := os.Lstat(path)
	if err != nil {
		return nil, nil, "", err
	}
	if before.Mode()&fs.ModeSymlink != 0 {
		return nil, nil, "", fmt.Errorf("source must be a regular non-symlink file")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, nil, "", err
	}
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, nil, "", err
	}
	if !os.SameFile(before, info) || !info.Mode().IsRegular() || info.Size() > limit {
		_ = file.Close()
		return nil, nil, "", fmt.Errorf("source must be a regular file no larger than %d bytes", limit)
	}
	content, readErr := io.ReadAll(io.LimitReader(file, limit+1))
	closeErr := file.Close()
	if readErr != nil || closeErr != nil {
		return nil, nil, "", errors.Join(readErr, closeErr)
	}
	if int64(len(content)) > limit {
		return nil, nil, "", fmt.Errorf("source exceeds %d bytes", limit)
	}
	after, err := os.Lstat(path)
	if err != nil || after.Mode()&fs.ModeSymlink != 0 || !os.SameFile(before, after) || before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) {
		return nil, nil, "", fmt.Errorf("source changed while reading")
	}
	digest := sha256.Sum256(content)
	return info, content, hex.EncodeToString(digest[:]), nil
}

func readProjectFile(rootPath, relative string, limit int64) (content []byte, err error) {
	if !filepath.IsLocal(relative) || relative == "." {
		return nil, fmt.Errorf("project artifact path is invalid")
	}
	root, err := os.OpenRoot(rootPath)
	if err != nil {
		return nil, fmt.Errorf("open project: %w", err)
	}
	defer func() { err = errors.Join(err, root.Close()) }()
	file, err := root.Open(filepath.FromSlash(relative))
	if err != nil {
		return nil, fmt.Errorf("open project artifact: %w", err)
	}
	content, readErr := io.ReadAll(io.LimitReader(file, limit+1))
	closeErr := file.Close()
	if readErr != nil || closeErr != nil {
		return nil, errors.Join(readErr, closeErr)
	}
	if int64(len(content)) > limit {
		return nil, fmt.Errorf("project artifact exceeds %d bytes", limit)
	}
	return content, nil
}

func writeProjectFile(rootPath, relative string, content []byte) (err error) {
	if !filepath.IsLocal(relative) || relative == "." {
		return fmt.Errorf("project artifact path is invalid")
	}
	root, err := os.OpenRoot(rootPath)
	if err != nil {
		return fmt.Errorf("open project: %w", err)
	}
	defer func() { err = errors.Join(err, root.Close()) }()
	parent := filepath.Dir(relative)
	if err := root.MkdirAll(parent, 0o700); err != nil {
		return fmt.Errorf("create project artifact directory: %w", err)
	}
	temporary := filepath.Join(parent, "."+filepath.Base(relative)+".tmp-"+newID(time.Now(), relative)[:12])
	file, err := root.OpenFile(temporary, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("create project artifact: %w", err)
	}
	removeTemporary := true
	defer func() {
		if removeTemporary {
			err = errors.Join(err, ignoreNotExist(root.Remove(temporary)))
		}
	}()
	if _, err := file.Write(content); err != nil {
		return errors.Join(fmt.Errorf("write project artifact: %w", err), file.Close())
	}
	if err := file.Sync(); err != nil {
		return errors.Join(fmt.Errorf("sync project artifact: %w", err), file.Close())
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close project artifact: %w", err)
	}
	if err := root.Rename(temporary, relative); err != nil {
		return fmt.Errorf("replace project artifact: %w", err)
	}
	removeTemporary = false
	return nil
}

func ignoreNotExist(err error) error {
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

type projectArtifactFingerprint struct {
	sha256 string
	size   int64
}

func copyProjectArtifacts(ctx context.Context, source, destination string, manifest Manifest) (resultErr error) {
	expected, err := indexedArtifactFingerprints(manifest)
	if err != nil {
		return err
	}
	seen := make(map[string]bool, len(expected))
	sourceInfo, err := os.Lstat(source)
	if err != nil || sourceInfo.Mode()&fs.ModeSymlink != 0 || !sourceInfo.IsDir() {
		return fmt.Errorf("source project is not a real directory")
	}
	sourceRoot, err := os.OpenRoot(source)
	if err != nil {
		return fmt.Errorf("open source project: %w", err)
	}
	defer func() { resultErr = errors.Join(resultErr, sourceRoot.Close()) }()
	sourceDirectory, err := sourceRoot.Open(".")
	if err != nil {
		return fmt.Errorf("open source project directory: %w", err)
	}
	openedSourceInfo, statErr := sourceDirectory.Stat()
	closeSourceErr := sourceDirectory.Close()
	if statErr != nil || closeSourceErr != nil {
		return errors.Join(statErr, closeSourceErr)
	}
	if !os.SameFile(sourceInfo, openedSourceInfo) {
		return fmt.Errorf("source project changed before copy")
	}
	destinationRoot, err := os.OpenRoot(destination)
	if err != nil {
		return fmt.Errorf("open destination project: %w", err)
	}
	defer func() { resultErr = errors.Join(resultErr, destinationRoot.Close()) }()

	err = filepath.WalkDir(source, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		relative, err := filepath.Rel(source, path)
		if err != nil || relative == "." {
			return err
		}
		if entry.Type()&fs.ModeSymlink != 0 {
			return fmt.Errorf("project artifact %s is a symlink", relative)
		}
		if relative == manifestFile || relative == ".staging" || strings.HasPrefix(relative, ".staging"+string(filepath.Separator)) {
			if entry.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if entry.IsDir() {
			if err := destinationRoot.MkdirAll(relative, 0o700); err != nil {
				return fmt.Errorf("create project artifact directory %s: %w", relative, err)
			}
			return nil
		}
		if !entry.Type().IsRegular() {
			return fmt.Errorf("project artifact %s is not a regular file", relative)
		}
		before, err := sourceRoot.Lstat(relative)
		if err != nil {
			return fmt.Errorf("inspect project artifact %s: %w", relative, err)
		}
		if before.Mode()&fs.ModeSymlink != 0 || !before.Mode().IsRegular() {
			return fmt.Errorf("project artifact %s is not a regular non-symlink file", relative)
		}
		fingerprint, indexed := expected[filepath.ToSlash(relative)]
		if err := copyProjectFile(ctx, sourceRoot, destinationRoot, relative, before, fingerprint, indexed); err != nil {
			return fmt.Errorf("copy project artifact %s: %w", relative, err)
		}
		if indexed {
			seen[filepath.ToSlash(relative)] = true
		}
		return nil
	})
	if err != nil {
		return err
	}
	for path := range expected {
		if !seen[path] {
			return fmt.Errorf("indexed project artifact %s is missing", path)
		}
	}
	return nil
}

func copyProjectFile(ctx context.Context, sourceRoot, destinationRoot *os.Root, relative string, before fs.FileInfo, fingerprint projectArtifactFingerprint, indexed bool) (resultErr error) {
	in, err := sourceRoot.Open(relative)
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, in.Close()) }()
	opened, err := in.Stat()
	if err != nil {
		return err
	}
	if !os.SameFile(before, opened) || !opened.Mode().IsRegular() {
		return fmt.Errorf("source changed before copy")
	}
	out, err := destinationRoot.OpenFile(relative, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	closed := false
	defer func() {
		if !closed {
			resultErr = errors.Join(resultErr, out.Close())
		}
	}()
	hash := sha256.New()
	destination := io.Writer(out)
	if indexed {
		destination = io.MultiWriter(out, hash)
	}
	written, err := copyWithContext(ctx, destination, in)
	if err != nil {
		return err
	}
	afterOpen, err := in.Stat()
	if err != nil {
		return err
	}
	afterPath, err := sourceRoot.Lstat(relative)
	if err != nil {
		return fmt.Errorf("source changed during copy")
	}
	if indexed {
		if fingerprint.size >= 0 && written != fingerprint.size {
			return fmt.Errorf("size differs from project inventory")
		}
		if hex.EncodeToString(hash.Sum(nil)) != fingerprint.sha256 {
			return fmt.Errorf("fingerprint differs from project inventory")
		}
	}
	if !os.SameFile(before, afterOpen) || !os.SameFile(before, afterPath) ||
		written != before.Size() || before.Size() != afterOpen.Size() || before.Size() != afterPath.Size() ||
		!before.ModTime().Equal(afterOpen.ModTime()) || !before.ModTime().Equal(afterPath.ModTime()) {
		return fmt.Errorf("source changed during copy")
	}
	if err := out.Sync(); err != nil {
		return err
	}
	if err := out.Close(); err != nil {
		closed = true
		return err
	}
	closed = true
	return nil
}

func indexedArtifactFingerprints(manifest Manifest) (map[string]projectArtifactFingerprint, error) {
	out := make(
		map[string]projectArtifactFingerprint,
		len(manifest.Configs)+
			len(manifest.Policies)+
			len(manifest.Captures)+
			len(manifest.CapturePairs)+
			len(manifest.CaptureJournals)+
			len(manifest.NetworkSessions),
	)
	add := func(path, digest string, size int64) error {
		path = filepath.ToSlash(path)
		if existing, ok := out[path]; ok && (existing.sha256 != digest || existing.size != size && existing.size >= 0 && size >= 0) {
			return fmt.Errorf("project artifact %s has conflicting inventory", path)
		}
		if existing, ok := out[path]; ok && existing.size >= 0 {
			size = existing.size
		}
		out[path] = projectArtifactFingerprint{sha256: digest, size: size}
		return nil
	}
	for _, config := range manifest.Configs {
		if err := add(config.Snapshot, config.SHA256, config.Size); err != nil {
			return nil, err
		}
	}
	for _, revision := range manifest.Policies {
		if err := add(revision.Path, revision.SHA256, -1); err != nil {
			return nil, err
		}
	}
	for _, capture := range manifest.Captures {
		if capture.Mode == ImportCopy {
			if err := add(capture.Path, capture.SHA256, capture.Size); err != nil {
				return nil, err
			}
		}
	}
	for _, pair := range manifest.CapturePairs {
		if err := add(
			pair.JournalPath,
			pair.JournalSHA256,
			pair.JournalSize,
		); err != nil {
			return nil, err
		}
	}
	for _, journal := range manifest.CaptureJournals {
		if err := add(journal.Path, journal.SHA256, journal.Size); err != nil {
			return nil, err
		}
	}
	for _, session := range manifest.NetworkSessions {
		if err := add(session.Path, session.SHA256, session.Size); err != nil {
			return nil, err
		}
	}
	return out, nil
}

func pathWithin(root, candidate string) bool {
	relative, err := filepath.Rel(filepath.Clean(root), filepath.Clean(candidate))
	return err == nil && relative != "." && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))
}

func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	if err := directory.Sync(); err != nil {
		return errors.Join(err, directory.Close())
	}
	return directory.Close()
}

func syncProjectTreeDirectories(ctx context.Context, root string) error {
	var directories []string
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		if entry.Type()&fs.ModeSymlink != 0 {
			return fmt.Errorf("staged project artifact %s is a symlink", path)
		}
		if entry.IsDir() {
			directories = append(directories, path)
		}
		return nil
	})
	if err != nil {
		return err
	}
	for index := len(directories) - 1; index >= 0; index-- {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		if err := syncDirectory(directories[index]); err != nil {
			return err
		}
	}
	return nil
}
