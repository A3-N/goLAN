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
	"golan/internal/syncgate"
)

const (
	recentVersion  = 1
	recentFile     = "recent.json"
	maxRecentItems = 12
	maxRecentSize  = 128 << 10
)

var recentGate syncgate.Gate

// RecentState is the bounded per-user startup history. Missing entries remain
// visible so the Workbench can offer an explicit locate or removal workflow.
type RecentState struct {
	Version  int             `json:"version"`
	Projects []RecentProject `json:"projects,omitempty"`
}

// recentStateDisk is the compatibility boundary for persisted startup history.
// Captures were part of version 1 before recent capture history was retired;
// accept the bounded legacy array only long enough to discard it. Saving still
// writes RecentState, so the retired field cannot be reintroduced.
type recentStateDisk struct {
	Version  int               `json:"version"`
	Projects []RecentProject   `json:"projects,omitempty"`
	Captures []json.RawMessage `json:"captures,omitempty"`
}

// RecentProject records one project directory last opened by the Workbench.
type RecentProject struct {
	Name      string    `json:"name"`
	Path      string    `json:"path"`
	OpenedAt  time.Time `json:"opened_at"`
	Available bool      `json:"-"`
}

// LoadRecents strictly loads bounded startup history. A missing file is an
// empty versioned history; malformed state is never silently overwritten.
func LoadRecents() (RecentState, error) {
	release := recentGate.Enter()
	defer release()
	return loadRecentsLocked()
}

// RememberRecentProject moves one real project directory to the front of the
// recent-project list and persists it atomically.
func RememberRecentProject(project *Project) error {
	if project == nil {
		return fmt.Errorf("project is nil")
	}
	manifest := project.Manifest()
	path := project.Path()
	if !availableRecentProject(path) {
		return fmt.Errorf("recent project must be a saved real %s directory", projectExtension)
	}
	entry := RecentProject{Name: manifest.Name, Path: path, OpenedAt: time.Now().UTC(), Available: true}
	release := recentGate.Enter()
	defer release()
	state, err := loadRecentsLocked()
	if err != nil {
		return err
	}
	projects := []RecentProject{entry}
	for _, existing := range state.Projects {
		if existing.Path != entry.Path {
			projects = append(projects, existing)
		}
	}
	state.Projects = projects[:min(len(projects), maxRecentItems)]
	return saveRecentsLocked(state)
}

func loadRecentsLocked() (RecentState, error) {
	path, err := recentPath()
	if err != nil {
		return RecentState{}, err
	}
	content, err := paths.ReadConfigArtifact(path, maxRecentSize)
	if errors.Is(err, os.ErrNotExist) {
		return RecentState{Version: recentVersion}, nil
	}
	if err != nil {
		return RecentState{}, fmt.Errorf("read recent items: %w", err)
	}
	var disk recentStateDisk
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&disk); err != nil {
		return RecentState{}, fmt.Errorf("decode recent items: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			err = fmt.Errorf("multiple JSON values")
		}
		return RecentState{}, fmt.Errorf("decode recent items: %w", err)
	}
	state := RecentState{Version: disk.Version, Projects: disk.Projects}
	if err := validateRecentState(state); err != nil {
		return RecentState{}, err
	}
	sort.SliceStable(state.Projects, func(i, j int) bool { return state.Projects[i].OpenedAt.After(state.Projects[j].OpenedAt) })
	for index := range state.Projects {
		state.Projects[index].Available = availableRecentProject(state.Projects[index].Path)
	}
	return state, nil
}

func saveRecentsLocked(state RecentState) error {
	state.Version = recentVersion
	if err := validateRecentState(state); err != nil {
		return err
	}
	content, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return fmt.Errorf("encode recent items: %w", err)
	}
	path, err := recentPath()
	if err != nil {
		return err
	}
	if err := paths.WriteConfigArtifact(path, append(content, '\n')); err != nil {
		return fmt.Errorf("write recent items: %w", err)
	}
	return nil
}

func validateRecentState(state RecentState) error {
	if state.Version != recentVersion {
		return fmt.Errorf("unsupported recent-item version %d", state.Version)
	}
	if len(state.Projects) > maxRecentItems {
		return fmt.Errorf("recent-item list exceeds %d entries", maxRecentItems)
	}
	projectPaths := make(map[string]bool, len(state.Projects))
	for _, entry := range state.Projects {
		if !validRecentEntry(entry.Name, entry.Path, entry.OpenedAt) || !strings.EqualFold(filepath.Ext(entry.Path), projectExtension) || projectPaths[entry.Path] {
			return fmt.Errorf("recent project entry is invalid")
		}
		projectPaths[entry.Path] = true
	}
	return nil
}

func validRecentEntry(name, path string, openedAt time.Time) bool {
	return strings.TrimSpace(name) != "" && len(name) <= 512 && !strings.ContainsAny(name, "\x00\r\n") &&
		filepath.IsAbs(path) && filepath.Clean(path) == path && len(path) <= 8192 && !strings.ContainsAny(path, "\x00\r\n") && !openedAt.IsZero()
}

func availableRecentProject(path string) bool {
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&fs.ModeSymlink != 0 || !info.IsDir() || !strings.EqualFold(filepath.Ext(path), projectExtension) {
		return false
	}
	manifest, err := os.Lstat(filepath.Join(path, manifestFile))
	return err == nil && manifest.Mode()&fs.ModeSymlink == 0 && manifest.Mode().IsRegular()
}

func recentPath() (string, error) {
	root, err := paths.ConfigRoot()
	if err != nil {
		return "", err
	}
	return filepath.Join(root, recentFile), nil
}
