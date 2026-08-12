package bridge

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"golan/internal/dataplane"
)

func (s *Session) writeFastManifest(started, stopped time.Time, sessionErr error) error {
	manifest := struct {
		Version        int       `json:"version"`
		Mode           Mode      `json:"mode"`
		StartedAt      time.Time `json:"started_at"`
		StoppedAt      time.Time `json:"stopped_at"`
		Host           string    `json:"host_adapter"`
		Switch         string    `json:"switch_adapter"`
		Capabilities   []string  `json:"capabilities"`
		PairedEvidence bool      `json:"paired_evidence"`
		Error          string    `json:"error,omitempty"`
	}{
		Version: 1, Mode: ModeFast, StartedAt: started, StoppedAt: stopped,
		Host: s.Host.Name, Switch: s.Switch.Name,
		Capabilities: dataplane.ForMode(dataplane.ModeFastBridge).Summary(),
	}
	manifest.Error = sessionErrorMarker(sessionErr)
	return writeBridgeManifest(filepath.Join(s.Dir, "session.json"), manifest)
}

func sessionErrorMarker(err error) string {
	if err == nil {
		return ""
	}
	return "session ended with an error; details were reported at runtime"
}

func writeBridgeManifest(path string, manifest any) error {
	content, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return fmt.Errorf("encode session manifest: %w", err)
	}
	temporary := path + ".tmp"
	if err := os.WriteFile(temporary, append(content, '\n'), 0o600); err != nil {
		return fmt.Errorf("write session manifest: %w", err)
	}
	if err := os.Rename(temporary, path); err != nil {
		return fmt.Errorf("publish session manifest: %w", err)
	}
	return nil
}
