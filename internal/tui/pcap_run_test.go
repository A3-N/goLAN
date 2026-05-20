package tui

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPcapRunCreatesTimestampedDirectory(t *testing.T) {
	root := t.TempDir()
	t.Setenv("GOLAN_CONFIG_DIR", root)

	run := NewPcapRun()
	if run.Timestamp == "" {
		t.Fatalf("expected timestamp")
	}
	if !strings.HasPrefix(run.PcapDir(), filepath.Join(root, "pcaps", run.Timestamp)) {
		t.Fatalf("pcap dir = %q, want under timestamped pcap root", run.PcapDir())
	}
	if _, err := os.Stat(run.PcapDir()); err != nil {
		t.Fatalf("pcap directory was not created: %v", err)
	}

	pcap := filepath.Join(run.PcapDir(), "test.pcap")
	if err := os.WriteFile(pcap, []byte("pcap"), 0o600); err != nil {
		t.Fatalf("write pcap fixture: %v", err)
	}
	files := run.Files()
	if len(files) != 1 || files[0] != pcap {
		t.Fatalf("files = %v, want [%s]", files, pcap)
	}
}

func TestPcapRunFinalizePermissionsMakesPcapsReadable(t *testing.T) {
	root := t.TempDir()
	t.Setenv("GOLAN_CONFIG_DIR", root)
	t.Setenv("SUDO_UID", "")
	t.Setenv("SUDO_GID", "")
	t.Setenv("SUDO_USER", "")

	run := NewPcapRun()
	pcap := filepath.Join(run.PcapDir(), "test.pcap")
	if err := os.WriteFile(pcap, []byte("pcap"), 0o600); err != nil {
		t.Fatalf("write pcap fixture: %v", err)
	}

	if err := run.FinalizePermissions(); err != nil {
		t.Fatalf("finalize pcap permissions: %v", err)
	}
	if info, err := os.Stat(run.PcapDir()); err != nil {
		t.Fatalf("stat pcap dir: %v", err)
	} else if got := info.Mode().Perm(); got != 0o755 {
		t.Fatalf("pcap dir mode = %#o, want 0755", got)
	}
	if info, err := os.Stat(pcap); err != nil {
		t.Fatalf("stat pcap: %v", err)
	} else if got := info.Mode().Perm(); got != 0o644 {
		t.Fatalf("pcap mode = %#o, want 0644", got)
	}
}

func TestNukePcapsRemovesOnlyPcapRoot(t *testing.T) {
	root := t.TempDir()
	t.Setenv("GOLAN_CONFIG_DIR", root)

	pcapRoot := filepath.Join(root, "pcaps")
	other := filepath.Join(root, "other")
	if err := os.MkdirAll(filepath.Join(pcapRoot, "run"), 0o700); err != nil {
		t.Fatalf("create pcap root: %v", err)
	}
	if err := os.MkdirAll(other, 0o700); err != nil {
		t.Fatalf("create other root: %v", err)
	}

	removed, err := NukePcaps()
	if err != nil {
		t.Fatalf("nuke pcaps: %v", err)
	}
	if removed != pcapRoot {
		t.Fatalf("removed root = %q, want %q", removed, pcapRoot)
	}
	if _, err := os.Stat(pcapRoot); !os.IsNotExist(err) {
		t.Fatalf("pcap root still exists or unexpected stat error: %v", err)
	}
	if _, err := os.Stat(other); err != nil {
		t.Fatalf("non-pcap config data should remain: %v", err)
	}
}
