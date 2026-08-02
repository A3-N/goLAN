package workflow_test

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"golan/internal/canvas"
	networkobs "golan/internal/network"
	"golan/internal/paths"
	"golan/internal/project"
)

func TestNetworkSessionProjectCanvasWorkflow(t *testing.T) {
	now := time.Unix(1_800_000_000, 0).UTC()
	session := networkobs.Session{
		Version:   networkobs.CurrentVersion,
		ID:        "workflow-session",
		Mode:      "listen",
		StartedAt: now,
		EndedAt:   now.Add(time.Minute),
		Devices: []networkobs.Device{{
			Key: "mac:02:00:00:00:00:10", MAC: "02:00:00:00:00:10",
			Adapter: "en7", Role: "host", IPs: []string{"192.168.1.10"},
			FirstSeen: now, LastSeen: now.Add(time.Minute),
			Observations: []networkobs.Observation{{
				Category: networkobs.CategoryDNS, Kind: "query", Summary: "DNS query example.test A",
				Protocol: "DNS", Source: "192.168.1.10", Destination: "192.168.1.1",
				Severity: networkobs.SeverityInfo, FirstSeen: now, LastSeen: now, Count: 1,
			}},
		}},
	}
	if err := networkobs.ValidateSession(session); err != nil {
		t.Fatal(err)
	}

	work, err := project.New(t.TempDir(), "Workflow")
	if err != nil {
		t.Fatal(err)
	}
	reference, err := work.SaveNetworkSession(session)
	if err != nil {
		t.Fatal(err)
	}
	if err := work.Save(); err != nil {
		t.Fatal(err)
	}
	reopened, err := project.Open(work.Path())
	if err != nil {
		t.Fatal(err)
	}
	loaded, inventory, err := reopened.ReadNetworkSession(reference.ID)
	if err != nil {
		t.Fatal(err)
	}
	if inventory.SHA256 != reference.SHA256 || len(loaded.Devices) != 1 {
		t.Fatalf("inventory=%#v session=%#v", inventory, loaded)
	}

	generated := canvas.FromNetworkSession(loaded)
	if len(generated.Hosts) != 2 || len(generated.Conversations) != 1 {
		t.Fatalf("hosts=%d conversations=%d", len(generated.Hosts), len(generated.Conversations))
	}
	configRoot := t.TempDir()
	t.Setenv(paths.EnvConfigDir, configRoot)
	destination := filepath.Join(configRoot, "canvases", "workflow.canvas")
	if err := generated.WriteFile(destination); err != nil {
		t.Fatal(err)
	}
	if info, err := os.Stat(destination); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("canvas info=%#v err=%v", info, err)
	}
}
