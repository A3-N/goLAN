package project

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golan/internal/network"
)

const maxNetworkSessionSize = 8 << 20

// SaveNetworkSession atomically stores one immutable sanitized observation
// session and adds it to the project inventory.
func (p *Project) SaveNetworkSession(session network.Session) (NetworkSessionReference, error) {
	if p == nil {
		return NetworkSessionReference{}, fmt.Errorf("project is nil")
	}
	if err := network.ValidateSession(session); err != nil {
		return NetworkSessionReference{}, err
	}
	content, err := json.MarshalIndent(session, "", "  ")
	if err != nil {
		return NetworkSessionReference{}, fmt.Errorf("encode network session: %w", err)
	}
	content = append(content, '\n')
	if len(content) > maxNetworkSessionSize {
		return NetworkSessionReference{}, fmt.Errorf("network session exceeds %d bytes", maxNetworkSessionSize)
	}
	digest := sha256.Sum256(content)
	hexDigest := hex.EncodeToString(digest[:])
	relative := filepath.ToSlash(filepath.Join(
		"observations",
		hexDigest[:12]+"-"+safeBase(session.ID)+".json",
	))
	observations := 0
	for _, device := range session.Devices {
		observations += len(device.Observations)
	}
	record := NetworkSessionReference{
		ID: session.ID, Path: relative, SHA256: hexDigest, Size: int64(len(content)),
		Mode: session.Mode, StartedAt: session.StartedAt, EndedAt: session.EndedAt,
		Devices: len(session.Devices), Observations: observations,
	}

	p.mu.Lock()
	root := p.path
	for _, existing := range p.manifest.NetworkSessions {
		if existing.ID != session.ID {
			continue
		}
		p.mu.Unlock()
		if existing.SHA256 != hexDigest {
			return NetworkSessionReference{}, fmt.Errorf("network session %q already exists with different content", session.ID)
		}
		return existing, nil
	}
	p.mu.Unlock()

	if _, err := os.Lstat(filepath.Join(root, filepath.FromSlash(relative))); err == nil {
		return NetworkSessionReference{}, fmt.Errorf("network session destination already exists")
	} else if !os.IsNotExist(err) {
		return NetworkSessionReference{}, fmt.Errorf("inspect network session destination: %w", err)
	}
	if err := writeProjectFile(root, filepath.FromSlash(relative), content); err != nil {
		return NetworkSessionReference{}, err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, existing := range p.manifest.NetworkSessions {
		if existing.ID == session.ID {
			if existing.SHA256 == hexDigest {
				return existing, nil
			}
			return NetworkSessionReference{}, fmt.Errorf("network session %q already exists with different content", session.ID)
		}
	}
	p.manifest.NetworkSessions = append(p.manifest.NetworkSessions, record)
	p.dirty = true
	return record, nil
}

// ReadNetworkSession verifies and returns one indexed sanitized session.
func (p *Project) ReadNetworkSession(id string) (network.Session, NetworkSessionReference, error) {
	if p == nil {
		return network.Session{}, NetworkSessionReference{}, fmt.Errorf("project is nil")
	}
	id = strings.TrimSpace(id)
	p.mu.RLock()
	root := p.path
	var record NetworkSessionReference
	for _, candidate := range p.manifest.NetworkSessions {
		if candidate.ID == id {
			record = candidate
			break
		}
	}
	p.mu.RUnlock()
	if record.ID == "" {
		return network.Session{}, NetworkSessionReference{}, fmt.Errorf("network session %q is not indexed", id)
	}
	content, err := readProjectFile(root, record.Path, maxNetworkSessionSize)
	if err != nil {
		return network.Session{}, record, err
	}
	if int64(len(content)) != record.Size {
		return network.Session{}, record, fmt.Errorf("network session size differs from inventory")
	}
	digest := sha256.Sum256(content)
	if hex.EncodeToString(digest[:]) != record.SHA256 {
		return network.Session{}, record, fmt.Errorf("network session fingerprint differs from inventory")
	}
	session, err := network.DecodeSession(content)
	if err != nil {
		return network.Session{}, record, err
	}
	if session.ID != record.ID {
		return network.Session{}, record, fmt.Errorf("network session identity differs from inventory")
	}
	return session, record, nil
}
