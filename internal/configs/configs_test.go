package configs

import (
	"path/filepath"
	"testing"

	"golan/internal/profile"
)

func TestSaveListLoad(t *testing.T) {
	t.Setenv(envConfigDir, t.TempDir())

	path, err := Save("lab", Snapshot{
		ActiveAdapter: "en11",
		Profile: profile.Profile{
			Adapters: []profile.AdapterConfig{{AdapterRole: profile.AdapterRoleHost, Name: "en11", IP: "auto"}},
		},
	})
	if err != nil {
		t.Fatalf("Save: %v", err)
	}
	if filepath.Base(path) != "lab.json" {
		t.Fatalf("path = %q", path)
	}

	names, err := List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(names) != 1 || names[0] != "lab.json" {
		t.Fatalf("names = %v", names)
	}

	snapshot, _, err := Load("lab")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if snapshot.ActiveAdapter != "en11" {
		t.Fatalf("ActiveAdapter = %q", snapshot.ActiveAdapter)
	}
	if len(snapshot.Profile.Adapters) != 1 {
		t.Fatalf("Adapters = %+v", snapshot.Profile.Adapters)
	}
}

func TestNormalizeNameRejectsPath(t *testing.T) {
	if _, err := normalizeName("../bad.json"); err == nil {
		t.Fatal("expected path rejection")
	}
}
