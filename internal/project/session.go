package project

import (
	"bytes"
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

	"golan/internal/paths"
)

const (
	sessionAssociationFile = ".golan-project.json"
	sessionArchiveDir      = ".association-archive"
	maxSessionMarkerSize   = 8 << 10
)

// AssociatedSession describes one valid runtime recovery marker owned by a
// project. Recoverable is true when the directory contains at least one direct
// regular PCAP or PCAPNG candidate; capture validity is checked during indexing.
type AssociatedSession struct {
	Directory   string
	CreatedAt   time.Time
	Recoverable bool
}

type sessionAssociation struct {
	Version     int       `json:"version"`
	ProjectID   string    `json:"project_id"`
	ProjectName string    `json:"project_name"`
	ProjectPath string    `json:"project_path"`
	CreatedAt   time.Time `json:"created_at"`
}

// AssociateSession writes an owner-only recovery marker into a live-session
// directory. It does not change project metadata or session capture bytes.
func (p *Project) AssociateSession(directory string) error {
	if p == nil {
		return fmt.Errorf("project is nil")
	}
	directory, err := validateRuntimeSessionDirectory(directory)
	if err != nil {
		return err
	}
	p.mu.RLock()
	association := sessionAssociation{
		Version: 1, ProjectID: p.manifest.ID, ProjectName: p.manifest.Name,
		ProjectPath: p.path, CreatedAt: time.Now().UTC(),
	}
	p.mu.RUnlock()
	marker := filepath.Join(directory, sessionAssociationFile)
	if content, err := paths.ReadConfigArtifact(marker, maxSessionMarkerSize); err == nil {
		existing, decodeErr := decodeSessionAssociation(content)
		if decodeErr != nil {
			return fmt.Errorf("read existing session association: %w", decodeErr)
		}
		if existing.ProjectID != association.ProjectID {
			return fmt.Errorf("session is already associated with another project")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("read existing session association: %w", err)
	}
	content, err := json.MarshalIndent(association, "", "  ")
	if err != nil {
		return fmt.Errorf("encode session association: %w", err)
	}
	if err := paths.WriteConfigArtifact(marker, append(content, '\n')); err != nil {
		return fmt.Errorf("write session association: %w", err)
	}
	return nil
}

// RecoverableSessions returns finalized or interrupted runtime directories
// explicitly associated with this project and still awaiting capture indexing.
func (p *Project) RecoverableSessions() ([]string, error) {
	sessions, err := p.AssociatedSessions()
	if err != nil {
		return nil, err
	}
	result := make([]string, 0, len(sessions))
	for _, session := range sessions {
		if session.Recoverable {
			result = append(result, session.Directory)
		}
	}
	return result, nil
}

// AssociatedSessions returns a bounded inventory of valid runtime association
// markers owned by this project, including stale markers with no capture files.
// Invalid or foreign markers are ignored and can never be archived through the
// project API.
func (p *Project) AssociatedSessions() ([]AssociatedSession, error) {
	if p == nil {
		return nil, fmt.Errorf("project is nil")
	}
	root, err := paths.PcapRoot()
	if err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(root)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("scan runtime sessions: %w", err)
	}
	if len(entries) > maxSessionCaptureEntries {
		return nil, fmt.Errorf("runtime session root contains more than %d entries", maxSessionCaptureEntries)
	}
	p.mu.RLock()
	projectID := p.manifest.ID
	p.mu.RUnlock()
	var result []AssociatedSession
	for _, entry := range entries {
		if !entry.IsDir() || entry.Type()&fs.ModeSymlink != 0 {
			continue
		}
		directory := filepath.Join(root, entry.Name())
		marker := filepath.Join(directory, sessionAssociationFile)
		info, err := os.Lstat(marker)
		if err != nil || info.Mode()&fs.ModeSymlink != 0 || !info.Mode().IsRegular() {
			continue
		}
		content, err := paths.ReadConfigArtifact(marker, maxSessionMarkerSize)
		if err != nil {
			return nil, fmt.Errorf("read session association %s: %w", directory, err)
		}
		association, err := decodeSessionAssociation(content)
		if err != nil {
			continue
		}
		if association.ProjectID != projectID {
			continue
		}
		hasCaptures, err := runtimeSessionHasCaptures(directory)
		if err != nil {
			return nil, err
		}
		result = append(result, AssociatedSession{Directory: directory, CreatedAt: association.CreatedAt, Recoverable: hasCaptures})
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Directory < result[j].Directory })
	return result, nil
}

// ArchiveStaleSessionAssociation preserves and removes this project's marker
// from a runtime directory only when no direct regular PCAP/PCAPNG candidate
// remains. Other runtime artifacts and the directory itself are untouched.
func (p *Project) ArchiveStaleSessionAssociation(directory string) (string, error) {
	if p == nil {
		return "", fmt.Errorf("project is nil")
	}
	directory, err := validateRuntimeSessionDirectory(directory)
	if err != nil {
		return "", err
	}
	marker := filepath.Join(directory, sessionAssociationFile)
	info, err := os.Lstat(marker)
	if err != nil {
		return "", fmt.Errorf("inspect session association: %w", err)
	}
	if info.Mode()&fs.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return "", fmt.Errorf("session association must be a regular non-symlink file")
	}
	content, err := paths.ReadConfigArtifact(marker, maxSessionMarkerSize)
	if err != nil {
		return "", err
	}
	association, err := decodeSessionAssociation(content)
	if err != nil {
		return "", err
	}
	p.mu.RLock()
	projectID := p.manifest.ID
	p.mu.RUnlock()
	if association.ProjectID != projectID {
		return "", fmt.Errorf("session association belongs to another project")
	}
	hasCaptures, err := runtimeSessionHasCaptures(directory)
	if err != nil {
		return "", err
	}
	if hasCaptures {
		return "", fmt.Errorf("session still contains direct PCAP or PCAPNG captures; recover them before archiving the marker")
	}
	root, err := paths.PcapRoot()
	if err != nil {
		return "", err
	}
	name := time.Now().UTC().Format("20060102T150405.000000000Z") + "-" + paths.SafeFilenamePart(filepath.Base(directory)) + ".json"
	destination := filepath.Join(root, sessionArchiveDir, name)
	if err := paths.WriteConfigArtifact(destination, content); err != nil {
		return "", fmt.Errorf("archive session association: %w", err)
	}
	if err := os.Remove(marker); err != nil && !errors.Is(err, os.ErrNotExist) {
		return destination, fmt.Errorf("remove stale session association after archive (archived copy retained at %s): %w", destination, err)
	}
	return destination, nil
}

// CompleteSessionAssociation removes this project's recovery marker after all
// direct captures were imported. Missing markers are already complete.
func (p *Project) CompleteSessionAssociation(directory string) error {
	if p == nil {
		return fmt.Errorf("project is nil")
	}
	directory, err := filepath.Abs(strings.TrimSpace(directory))
	if err != nil {
		return fmt.Errorf("resolve runtime session: %w", err)
	}
	root, err := paths.PcapRoot()
	if err != nil {
		return err
	}
	if filepath.Dir(directory) != filepath.Clean(root) {
		return nil
	}
	directory, err = validateRuntimeSessionDirectory(directory)
	if err != nil {
		return err
	}
	marker := filepath.Join(directory, sessionAssociationFile)
	info, err := os.Lstat(marker)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect session association: %w", err)
	}
	if info.Mode()&fs.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return fmt.Errorf("session association must be a regular non-symlink file")
	}
	content, err := paths.ReadConfigArtifact(marker, maxSessionMarkerSize)
	if err != nil {
		return err
	}
	association, err := decodeSessionAssociation(content)
	if err != nil {
		return err
	}
	p.mu.RLock()
	projectID := p.manifest.ID
	p.mu.RUnlock()
	if association.ProjectID != projectID {
		return fmt.Errorf("session association belongs to another project")
	}
	if err := os.Remove(marker); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove session association: %w", err)
	}
	return nil
}

func validateRuntimeSessionDirectory(directory string) (string, error) {
	directory, err := filepath.Abs(strings.TrimSpace(directory))
	if err != nil {
		return "", fmt.Errorf("resolve runtime session: %w", err)
	}
	root, err := paths.PcapRoot()
	if err != nil {
		return "", err
	}
	if filepath.Dir(directory) != filepath.Clean(root) {
		return "", fmt.Errorf("runtime session must be directly in %s", root)
	}
	info, err := os.Lstat(directory)
	if err != nil {
		return "", fmt.Errorf("inspect runtime session: %w", err)
	}
	if info.Mode()&fs.ModeSymlink != 0 || !info.IsDir() {
		return "", fmt.Errorf("runtime session must be a real directory")
	}
	return directory, nil
}

func runtimeSessionHasCaptures(directory string) (bool, error) {
	entries, err := os.ReadDir(directory)
	if err != nil {
		return false, fmt.Errorf("scan runtime session %s: %w", directory, err)
	}
	if len(entries) > maxSessionCaptureEntries {
		return false, fmt.Errorf("runtime session %s contains more than %d entries", directory, maxSessionCaptureEntries)
	}
	for _, entry := range entries {
		if entry.IsDir() || entry.Type()&fs.ModeSymlink != 0 || !captureExtension(entry.Name()) {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			return false, fmt.Errorf("inspect runtime session capture: %w", err)
		}
		if info.Mode().IsRegular() {
			return true, nil
		}
	}
	return false, nil
}

func decodeSessionAssociation(content []byte) (sessionAssociation, error) {
	var association sessionAssociation
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&association); err != nil {
		return sessionAssociation{}, err
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			err = fmt.Errorf("multiple JSON values")
		}
		return sessionAssociation{}, err
	}
	if association.Version != 1 || strings.TrimSpace(association.ProjectID) == "" || strings.TrimSpace(association.ProjectPath) == "" || association.CreatedAt.IsZero() {
		return sessionAssociation{}, fmt.Errorf("session association is invalid")
	}
	return association, nil
}
