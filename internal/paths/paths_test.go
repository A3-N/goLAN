package paths

import (
	"os"
	"path/filepath"
	"testing"
)

func TestConfigRootUsesOverride(t *testing.T) {
	root := t.TempDir()
	t.Setenv(EnvConfigDir, root)

	got, err := ConfigRoot()
	if err != nil {
		t.Fatalf("ConfigRoot: %v", err)
	}
	if got != root {
		t.Fatalf("ConfigRoot = %q, want %q", got, root)
	}
}

func TestPcapRunDirUsesConfigRoot(t *testing.T) {
	root := t.TempDir()
	t.Setenv(EnvConfigDir, root)

	got, err := PcapRunDir()
	if err != nil {
		t.Fatalf("PcapRunDir: %v", err)
	}
	if filepath.Dir(got) != filepath.Join(root, "pcaps") {
		t.Fatalf("PcapRunDir = %q", got)
	}
}

func TestFinalizeTreeMakesFilesReadable(t *testing.T) {
	root := t.TempDir()
	subdir := filepath.Join(root, "pcaps")
	if err := os.Mkdir(subdir, 0o700); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}
	pcap := filepath.Join(subdir, "host-en0.pcap")
	if err := os.WriteFile(pcap, []byte("pcap"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	if err := FinalizeTree(root); err != nil {
		t.Fatalf("FinalizeTree: %v", err)
	}

	if info, err := os.Stat(subdir); err != nil {
		t.Fatalf("Stat dir: %v", err)
	} else if got := info.Mode().Perm(); got != 0o755 {
		t.Fatalf("dir mode = %o", got)
	}
	if info, err := os.Stat(pcap); err != nil {
		t.Fatalf("Stat file: %v", err)
	} else if got := info.Mode().Perm(); got != 0o644 {
		t.Fatalf("file mode = %o", got)
	}
}
