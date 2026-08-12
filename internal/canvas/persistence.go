package canvas

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"

	"golan/internal/paths"
)

// ValidatePath requires a .canvas file beneath goLAN's canvas directory.
func ValidatePath(path string) error {
	path = strings.TrimSpace(path)
	if path == "" {
		return fmt.Errorf("canvas path is empty")
	}
	if !strings.EqualFold(filepath.Ext(path), ".canvas") {
		return fmt.Errorf("canvas path must use .canvas")
	}
	root, err := paths.ConfigRoot()
	if err != nil {
		return err
	}
	canvasRoot := filepath.Join(root, "canvases")
	absPath, err := filepath.Abs(path)
	if err != nil {
		return fmt.Errorf("resolve canvas path: %w", err)
	}
	relativePath, err := filepath.Rel(canvasRoot, absPath)
	if err != nil {
		return fmt.Errorf("resolve canvas path relative to canvas root: %w", err)
	}
	if relativePath == "." || !filepath.IsLocal(relativePath) {
		return fmt.Errorf("canvas path must be a file beneath the canvas directory")
	}
	return nil
}

// WriteFile atomically writes an owner-only Obsidian canvas beneath ConfigRoot.
func (m *Map) WriteFile(path string) error {
	if m == nil {
		return fmt.Errorf("canvas map is nil")
	}
	if err := ValidatePath(path); err != nil {
		return err
	}
	data, err := json.MarshalIndent(m.JSONCanvas(), "", "  ")
	if err != nil {
		return fmt.Errorf("encode canvas: %w", err)
	}
	if err := paths.WriteConfigArtifact(path, append(data, '\n')); err != nil {
		return fmt.Errorf("write canvas: %w", err)
	}
	return nil
}
