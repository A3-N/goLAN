package configs

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"golan/internal/paths"
	"golan/internal/profile"
)

const envConfigDir = paths.EnvConfigDir

// Snapshot is the persisted setup state.
type Snapshot struct {
	Version       int             `json:"version"`
	SavedAt       time.Time       `json:"saved_at"`
	ActiveAdapter string          `json:"active_adapter"`
	Profile       profile.Profile `json:"profile"`
}

// ConfigDir returns the directory used for golan JSON configs.
func ConfigDir() (string, error) {
	return paths.ConfigDir()
}

// Save writes a setup snapshot as JSON and returns the full path.
func Save(name string, snapshot Snapshot) (string, error) {
	dir, err := ConfigDir()
	if err != nil {
		return "", err
	}
	fileName, err := normalizeName(name)
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("create config dir: %w", err)
	}

	snapshot.Version = 1
	snapshot.SavedAt = time.Now().UTC()

	content, err := json.MarshalIndent(snapshot, "", "  ")
	if err != nil {
		return "", fmt.Errorf("encode config: %w", err)
	}

	path := filepath.Join(dir, fileName)
	if err := os.WriteFile(path, append(content, '\n'), 0o600); err != nil {
		return "", fmt.Errorf("write config: %w", err)
	}
	if root, err := paths.ConfigRoot(); err == nil {
		if err := paths.FinalizeTree(root); err != nil {
			return "", fmt.Errorf("finalize config permissions: %w", err)
		}
	}
	return path, nil
}

// Load reads a JSON setup snapshot and returns it with the full path.
func Load(name string) (Snapshot, string, error) {
	dir, err := ConfigDir()
	if err != nil {
		return Snapshot{}, "", err
	}
	fileName, err := normalizeName(name)
	if err != nil {
		return Snapshot{}, "", err
	}
	path := filepath.Join(dir, fileName)
	content, err := os.ReadFile(path)
	if err != nil {
		return Snapshot{}, "", fmt.Errorf("read config: %w", err)
	}
	var snapshot Snapshot
	if err := json.Unmarshal(content, &snapshot); err != nil {
		return Snapshot{}, "", fmt.Errorf("decode config: %w", err)
	}
	return snapshot, path, nil
}

// List returns saved JSON config filenames.
func List() ([]string, error) {
	dir, err := ConfigDir()
	if err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(dir)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("list configs: %w", err)
	}

	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if strings.EqualFold(filepath.Ext(name), ".json") {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	return names, nil
}

func normalizeName(name string) (string, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return "", fmt.Errorf("filename is required")
	}
	if filepath.Base(name) != name {
		return "", fmt.Errorf("filename must not include a path")
	}
	if filepath.Ext(name) == "" {
		name += ".json"
	}
	if !strings.EqualFold(filepath.Ext(name), ".json") {
		return "", fmt.Errorf("filename must use .json")
	}
	return name, nil
}
