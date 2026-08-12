package paths

import (
	"math"
	"os"
	"path/filepath"
	"strings"
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

func TestPcapRootUsesConfigRoot(t *testing.T) {
	root := t.TempDir()
	t.Setenv(EnvConfigDir, root)

	got, err := PcapRoot()
	if err != nil {
		t.Fatalf("PcapRoot: %v", err)
	}
	if got != filepath.Join(root, "pcaps") {
		t.Fatalf("PcapRoot = %q", got)
	}
}

func TestFinalizeTreeMakesArtifactsOwnerOnly(t *testing.T) {
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
	} else if got := info.Mode().Perm(); got != 0o700 {
		t.Fatalf("dir mode = %o", got)
	}
	if info, err := os.Stat(pcap); err != nil {
		t.Fatalf("Stat file: %v", err)
	} else if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("file mode = %o", got)
	}
}

func TestConfigRootRejectsFilesystemRoot(t *testing.T) {
	t.Setenv(EnvConfigDir, string(filepath.Separator))

	if _, err := ConfigRoot(); err == nil {
		t.Fatal("expected filesystem root rejection")
	}
}

func TestFinalizeTreeRejectsFilesystemRoot(t *testing.T) {
	if err := FinalizeTree(string(filepath.Separator)); err == nil {
		t.Fatal("expected filesystem root rejection")
	}
}

func TestSafeFilenamePartCannotCreatePathComponents(t *testing.T) {
	if got := SafeFilenamePart("../../host/en:11\n"); got != "_.._host_en_11" {
		t.Fatalf("SafeFilenamePart = %q", got)
	}
	for _, value := range []string{"", ".", ".."} {
		if got := SafeFilenamePart(value); got != "unknown" {
			t.Errorf("SafeFilenamePart(%q) = %q", value, got)
		}
	}
}

func TestWriteConfigArtifactIsAtomicAndOwnerOnly(t *testing.T) {
	root := t.TempDir()
	t.Setenv(EnvConfigDir, root)
	path := filepath.Join(root, "canvases", "session.canvas")

	if err := WriteConfigArtifact(path, []byte("first")); err != nil {
		t.Fatalf("WriteConfigArtifact first: %v", err)
	}
	if err := WriteConfigArtifact(path, []byte("second")); err != nil {
		t.Fatalf("WriteConfigArtifact replacement: %v", err)
	}
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if string(content) != "second" {
		t.Fatalf("content = %q", content)
	}
	if info, err := os.Stat(filepath.Dir(path)); err != nil {
		t.Fatalf("Stat dir: %v", err)
	} else if got := info.Mode().Perm(); got != 0o700 {
		t.Fatalf("dir mode = %o", got)
	}
	if info, err := os.Stat(path); err != nil {
		t.Fatalf("Stat file: %v", err)
	} else if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("file mode = %o", got)
	}
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	for _, entry := range entries {
		if strings.Contains(entry.Name(), ".tmp-") {
			t.Fatalf("temporary artifact remains: %s", entry.Name())
		}
	}
}

func TestWriteConfigArtifactRejectsEscape(t *testing.T) {
	root := t.TempDir()
	t.Setenv(EnvConfigDir, root)
	outside := filepath.Join(t.TempDir(), "outside.canvas")

	if err := WriteConfigArtifact(outside, []byte("secret")); err == nil {
		t.Fatal("expected path escape rejection")
	}
	if _, err := os.Stat(outside); !os.IsNotExist(err) {
		t.Fatalf("outside artifact exists: %v", err)
	}
}

func TestWriteConfigArtifactRejectsEscapingSymlink(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	t.Setenv(EnvConfigDir, root)
	if err := os.Symlink(outside, filepath.Join(root, "canvases")); err != nil {
		t.Fatalf("Symlink: %v", err)
	}

	path := filepath.Join(root, "canvases", "session.canvas")
	if err := WriteConfigArtifact(path, []byte("secret")); err == nil {
		t.Fatal("expected escaping symlink rejection")
	}
	if _, err := os.Stat(filepath.Join(outside, "session.canvas")); !os.IsNotExist(err) {
		t.Fatalf("outside artifact exists: %v", err)
	}
}

func TestReadAndListConfigArtifactsStayWithinRoot(t *testing.T) {
	root := t.TempDir()
	t.Setenv(EnvConfigDir, root)
	path := filepath.Join(root, "configs", "lab.json")
	if err := WriteConfigArtifact(path, []byte("{}\n")); err != nil {
		t.Fatalf("WriteConfigArtifact: %v", err)
	}

	content, err := ReadConfigArtifact(path, 32)
	if err != nil {
		t.Fatalf("ReadConfigArtifact: %v", err)
	}
	if string(content) != "{}\n" {
		t.Fatalf("content = %q", content)
	}
	names, err := ListConfigArtifacts(filepath.Join(root, "configs"))
	if err != nil {
		t.Fatalf("ListConfigArtifacts: %v", err)
	}
	if len(names) != 1 || names[0] != "lab.json" {
		t.Fatalf("names = %v", names)
	}
	if _, err := ReadConfigArtifact(path, 1); err == nil {
		t.Fatal("expected read limit error")
	}

	outside := t.TempDir()
	outsideFile := filepath.Join(outside, "outside.json")
	if err := os.WriteFile(outsideFile, []byte("{}"), 0o600); err != nil {
		t.Fatalf("WriteFile outside: %v", err)
	}
	link := filepath.Join(root, "outside")
	if err := os.Symlink(outside, link); err != nil {
		t.Fatalf("Symlink: %v", err)
	}
	if _, err := ReadConfigArtifact(filepath.Join(link, "outside.json"), 32); err == nil {
		t.Fatal("expected escaping read symlink rejection")
	}
	if _, err := ListConfigArtifacts(link); err == nil {
		t.Fatal("expected escaping list symlink rejection")
	}
}

func TestReadConfigArtifactRejectsInvalidLimits(t *testing.T) {
	for _, limit := range []int64{-1, math.MaxInt64} {
		if _, err := ReadConfigArtifact("ignored", limit); err == nil {
			t.Errorf("ReadConfigArtifact limit %d succeeded", limit)
		}
	}
}
