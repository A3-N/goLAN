package project

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// UnindexedPolicies returns policy JSON artifacts directly in the project's
// policies directory that are not present in the saved or in-memory manifest.
// Callers must validate policy semantics before attaching one.
func (p *Project) UnindexedPolicies() ([]string, error) {
	if p == nil {
		return nil, fmt.Errorf("project is nil")
	}
	root := filepath.Join(p.Path(), "policies")
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil, fmt.Errorf("scan policies: %w", err)
	}
	p.mu.RLock()
	indexed := make(map[string]bool, len(p.manifest.Policies))
	for _, revision := range p.manifest.Policies {
		indexed[filepath.Clean(filepath.Join(p.path, filepath.FromSlash(revision.Path)))] = true
	}
	p.mu.RUnlock()
	var out []string
	for _, entry := range entries {
		if entry.IsDir() || entry.Type()&fs.ModeSymlink != 0 || !strings.EqualFold(filepath.Ext(entry.Name()), ".json") {
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

// ReadUnindexedPolicy returns one bounded, stable policy artifact and its
// SHA-256 digest. This is the validation snapshot callers must use when
// attaching the artifact.
func (p *Project) ReadUnindexedPolicy(path string) ([]byte, string, error) {
	if p == nil {
		return nil, "", fmt.Errorf("project is nil")
	}
	path, err := p.resolveUnindexedPolicy(path)
	if err != nil {
		return nil, "", err
	}
	found, err := p.policyIsUnindexed(path)
	if err != nil {
		return nil, "", err
	}
	if !found {
		return nil, "", fmt.Errorf("policy is already indexed or is not recoverable")
	}
	before, err := os.Lstat(path)
	if err != nil {
		return nil, "", fmt.Errorf("inspect policy: %w", err)
	}
	if before.Mode()&fs.ModeSymlink != 0 || !before.Mode().IsRegular() {
		return nil, "", fmt.Errorf("policy must be a regular non-symlink file")
	}
	if before.Size() > maxPolicySize {
		return nil, "", fmt.Errorf("policy revision exceeds %d bytes", maxPolicySize)
	}
	relative := filepath.Join("policies", filepath.Base(path))
	content, err := readProjectFile(p.Path(), relative, maxPolicySize)
	if err != nil {
		return nil, "", err
	}
	after, err := os.Lstat(path)
	if err != nil || after.Mode() != before.Mode() || after.Size() != before.Size() || !after.ModTime().Equal(before.ModTime()) {
		return nil, "", fmt.Errorf("policy changed while reading")
	}
	digest := sha256.Sum256(content)
	return content, hex.EncodeToString(digest[:]), nil
}

// AttachUnindexedPolicy indexes a policy artifact only if it is unchanged
// from a caller-validated SHA-256 snapshot. It does not activate the revision.
func (p *Project) AttachUnindexedPolicy(path, revision, name, expectedSHA256 string) (PolicyRevision, error) {
	if p == nil {
		return PolicyRevision{}, fmt.Errorf("project is nil")
	}
	if err := validatePolicyRevisionName(revision); err != nil {
		return PolicyRevision{}, err
	}
	if !validDigest(expectedSHA256) {
		return PolicyRevision{}, fmt.Errorf("validated policy checksum is invalid")
	}
	path, err := p.resolveUnindexedPolicy(path)
	if err != nil {
		return PolicyRevision{}, err
	}
	_, digest, err := p.ReadUnindexedPolicy(path)
	if err != nil {
		return PolicyRevision{}, err
	}
	if digest != expectedSHA256 {
		return PolicyRevision{}, fmt.Errorf("policy changed after validation")
	}
	relative := filepath.ToSlash(filepath.Join("policies", filepath.Base(path)))
	record := PolicyRevision{
		Revision:  strings.TrimSpace(revision),
		Name:      strings.TrimSpace(name),
		Path:      relative,
		SHA256:    digest,
		CreatedAt: time.Now().UTC(),
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, existing := range p.manifest.Policies {
		if existing.Revision == record.Revision {
			return PolicyRevision{}, fmt.Errorf("policy revision %q is already indexed", record.Revision)
		}
		if existing.Path == relative {
			return PolicyRevision{}, fmt.Errorf("policy artifact is already indexed as %q", existing.Revision)
		}
	}
	p.manifest.Policies = append(p.manifest.Policies, record)
	p.dirty = true
	return record, nil
}

// ArchiveUnindexedPolicy moves an explicitly selected orphan into
// policies/archive. The bytes remain recoverable but are no longer offered for
// attachment when the project is reopened.
func (p *Project) ArchiveUnindexedPolicy(path string) (string, error) {
	if p == nil {
		return "", fmt.Errorf("project is nil")
	}
	path, err := p.resolveUnindexedPolicy(path)
	if err != nil {
		return "", err
	}
	found, err := p.policyIsUnindexed(path)
	if err != nil {
		return "", err
	}
	if !found {
		return "", fmt.Errorf("policy is already indexed or is not recoverable")
	}
	info, err := os.Lstat(path)
	if err != nil {
		return "", fmt.Errorf("inspect policy: %w", err)
	}
	if info.Mode()&fs.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return "", fmt.Errorf("policy must be a regular non-symlink file")
	}
	archive := filepath.Join(p.Path(), "policies", "archive")
	if err := os.Mkdir(archive, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
		return "", fmt.Errorf("create policy archive: %w", err)
	}
	destination := filepath.Join(archive, filepath.Base(path))
	if _, err := os.Lstat(destination); err == nil {
		return "", fmt.Errorf("archive already contains %s", filepath.Base(path))
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", fmt.Errorf("inspect policy archive: %w", err)
	}
	if err := os.Rename(path, destination); err != nil {
		return "", fmt.Errorf("archive policy: %w", err)
	}
	return destination, nil
}

func (p *Project) resolveUnindexedPolicy(path string) (string, error) {
	path, err := filepath.Abs(strings.TrimSpace(path))
	if err != nil {
		return "", fmt.Errorf("resolve policy: %w", err)
	}
	policies := filepath.Clean(filepath.Join(p.Path(), "policies"))
	if filepath.Dir(path) != policies || !strings.EqualFold(filepath.Ext(filepath.Base(path)), ".json") {
		return "", fmt.Errorf("policy must be a JSON file directly in %s", policies)
	}
	return path, nil
}

func (p *Project) policyIsUnindexed(path string) (bool, error) {
	unindexed, err := p.UnindexedPolicies()
	if err != nil {
		return false, err
	}
	for _, candidate := range unindexed {
		if candidate == path {
			return true, nil
		}
	}
	return false, nil
}
