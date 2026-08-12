package project

import (
	"archive/zip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"golan/internal/paths"
)

func TestProjectExplicitSaveDirtyAndOpen(t *testing.T) {
	project, err := New(t.TempDir(), "MyLab")
	if err != nil {
		t.Fatal(err)
	}
	if !project.Dirty() {
		t.Fatal("new project is not dirty")
	}
	if _, err := os.Stat(filepath.Join(project.Path(), manifestFile)); !os.IsNotExist(err) {
		t.Fatalf("project metadata was saved implicitly: %v", err)
	}
	if err := project.Save(); err != nil {
		t.Fatal(err)
	}
	if project.Dirty() {
		t.Fatal("saved project remains dirty")
	}
	opened, err := Open(project.Path())
	if err != nil {
		t.Fatal(err)
	}
	if got := opened.Manifest(); got.Name != "MyLab" {
		t.Fatalf("opened manifest = %#v", got)
	}
	opened.SetWorkspace("Rules")
	closed, err := opened.Close(CloseDiscard)
	if err != nil || !closed || opened.Dirty() || opened.Manifest().Preferences.Workspace != "" {
		t.Fatalf("discard close = closed:%v err:%v manifest:%#v", closed, err, opened.Manifest())
	}
}

func TestFinishSavePreservesEditsMadeDuringWrite(t *testing.T) {
	original := Manifest{Version: CurrentVersion, Name: "before"}
	saved := original
	saved.UpdatedAt = time.Unix(2, 0).UTC()
	project := &Project{manifest: cloneManifest(original), dirty: true}
	project.manifest.Name = "edited while saving"

	project.finishSave(original, saved)
	if project.manifest.Name != "edited while saving" || !project.dirty {
		t.Fatalf("concurrent edit was lost: manifest=%#v dirty=%t", project.manifest, project.dirty)
	}
	if project.saved.Name != "before" || !project.saved.UpdatedAt.Equal(saved.UpdatedAt) {
		t.Fatalf("durable baseline=%#v want=%#v", project.saved, saved)
	}

	unchanged := &Project{manifest: cloneManifest(original), dirty: true}
	unchanged.finishSave(original, saved)
	if unchanged.dirty || !unchanged.manifest.UpdatedAt.Equal(saved.UpdatedAt) {
		t.Fatalf("unchanged save did not clear dirty state: manifest=%#v dirty=%t", unchanged.manifest, unchanged.dirty)
	}
}

func TestManifestV2MigrationDropsRetiredPacketMetadataAndReferences(t *testing.T) {
	content := []byte(`{
		"version":2,
		"id":"legacy",
		"name":"Legacy",
		"created_at":"2026-01-01T00:00:00Z",
		"updated_at":"2026-01-01T00:00:00Z",
		"captures":[{"id":"external","name":"external.pcap","path":"/tmp/external.pcap","mode":"reference","format":"pcap","sha256":"0000000000000000000000000000000000000000000000000000000000000000","size":4,"modified_at":"2026-01-01T00:00:00Z","imported_at":"2026-01-01T00:00:00Z","indexed":true}],
		"canvases":[{"capture_id":"external","path":"canvas/external"}],
		"notes":[{"id":"note","text":"retired"}],
		"filters":[{"name":"old","expression":"{}"}],
		"preferences":{"workspace":"Rules","canvas_visible":true}
	}`)
	manifest, err := decodeManifest(content)
	if err != nil {
		t.Fatal(err)
	}
	if manifest.Version != CurrentVersion || len(manifest.Captures) != 0 || manifest.Preferences.Workspace != "Rules" {
		t.Fatalf("migrated manifest=%#v", manifest)
	}
}

func TestProjectRepeatedSaveOpenPreservesStateAndSnapshotIsolation(t *testing.T) {
	project, err := New(t.TempDir(), "CycleProperty")
	if err != nil {
		t.Fatal(err)
	}
	state := uint64(0x6a09e667f3bcc909)
	for cycle := 0; cycle < 8; cycle++ {
		state = state*6364136223846793005 + 1442695040888963407
		project.SetWorkspace(fmt.Sprintf("workspace-%d", state%7))
		source := filepath.Join(t.TempDir(), fmt.Sprintf("config-%02d.json", cycle))
		if err := os.WriteFile(source, []byte(fmt.Sprintf("{\"cycle\":%d}", cycle)), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := project.ImportConfig(source); err != nil {
			t.Fatalf("cycle %d config: %v", cycle, err)
		}
		if err := project.Save(); err != nil {
			t.Fatalf("cycle %d save: %v", cycle, err)
		}
		expected := project.Manifest()
		opened, err := Open(project.Path())
		if err != nil {
			t.Fatalf("cycle %d open: %v", cycle, err)
		}
		if opened.Dirty() || !reflect.DeepEqual(opened.Manifest(), expected) {
			t.Fatalf("cycle %d manifest changed across save/open", cycle)
		}

		snapshot := opened.Manifest()
		snapshot.Configs[0].Name = "mutated-returned-snapshot"
		retained := opened.Manifest()
		if retained.Configs[0].Name == snapshot.Configs[0].Name ||
			retained.Configs[0].Name != expected.Configs[0].Name {
			t.Fatalf("cycle %d returned manifest aliases project state", cycle)
		}
		project = opened
	}
}

func TestConfigSourceUpdatePreservesImmutableSnapshots(t *testing.T) {
	project, err := New(t.TempDir(), "ConfigUpdate")
	if err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(t.TempDir(), "source.json")
	before := []byte(`{"version":2,"active_adapter":"en0","profile":{"Adapters":[{"role":"host","name":"en0","ip":"192.0.2.1"}]}}`)
	if err := os.WriteFile(source, before, 0o600); err != nil {
		t.Fatal(err)
	}
	record, err := project.ImportConfig(source)
	if err != nil {
		t.Fatal(err)
	}
	loaded, snapshot, err := project.ReadConfigSnapshot(record.ID)
	if err != nil || loaded.SHA256 != record.SHA256 || string(snapshot) != string(before) {
		t.Fatalf("read config snapshot=%#v content=%q err=%v", loaded, snapshot, err)
	}
	previous, current, changed, duplicate, err := project.UpdateConfigSource(record.ID, record.SHA256)
	if err != nil || changed || duplicate || previous != record || current != record {
		t.Fatalf("unchanged update previous=%#v current=%#v changed=%v duplicate=%v err=%v", previous, current, changed, duplicate, err)
	}
	after := []byte(`{"version":2,"active_adapter":"en0","profile":{"Adapters":[{"role":"host","name":"en0","ip":"192.0.2.2"}]}}`)
	if err := os.WriteFile(source, after, 0o600); err != nil {
		t.Fatal(err)
	}
	_, _, digest, err := readAndHash(source, maxManifestSize)
	if err != nil {
		t.Fatal(err)
	}
	previous, current, changed, duplicate, err = project.UpdateConfigSource(record.ID, digest)
	if err != nil || !changed || duplicate || previous.ID != record.ID || current.ID == record.ID || len(project.Manifest().Configs) != 2 {
		t.Fatalf("changed update previous=%#v current=%#v changed=%v duplicate=%v configs=%#v err=%v", previous, current, changed, duplicate, project.Manifest().Configs, err)
	}
	if _, oldSnapshot, err := project.ReadConfigSnapshot(record.ID); err != nil || string(oldSnapshot) != string(before) {
		t.Fatalf("old immutable snapshot=%q err=%v", oldSnapshot, err)
	}
	if _, newSnapshot, err := project.ReadConfigSnapshot(current.ID); err != nil || string(newSnapshot) != string(after) {
		t.Fatalf("new immutable snapshot=%q err=%v", newSnapshot, err)
	}
	if _, _, _, _, err := project.UpdateConfigSource(current.ID, strings.Repeat("0", 64)); err == nil || !strings.Contains(err.Error(), "changed after validation") {
		t.Fatalf("mismatched validated fingerprint error=%v", err)
	}
	link := filepath.Join(t.TempDir(), "source-link.json")
	if err := os.Symlink(source, link); err != nil {
		t.Fatal(err)
	}
	if _, err := project.ImportConfig(link); err == nil || !strings.Contains(err.Error(), "non-symlink") {
		t.Fatalf("symlink import error=%v", err)
	}
}

func TestPolicyRevisionIsImmutableVerifiedAndRestored(t *testing.T) {
	project, err := New(t.TempDir(), "PolicyLab")
	if err != nil {
		t.Fatal(err)
	}
	content := []byte("[{\"id\":\"allow\"}]\n")
	record, err := project.SavePolicyRevision("baseline", "Baseline", content)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := project.SavePolicyRevision("baseline", "Renamed", content); err != nil {
		t.Fatalf("idempotent policy save: %v", err)
	}
	if _, err := project.SavePolicyRevision("baseline", "Changed", []byte("[]\n")); err == nil {
		t.Fatal("policy revision name was reused with different content")
	}
	if err := project.SetActivePolicyRevision("missing"); err == nil {
		t.Fatal("unindexed active revision was accepted")
	}
	if err := project.SetActivePolicyRevision("baseline"); err != nil {
		t.Fatal(err)
	}
	if err := project.Save(); err != nil {
		t.Fatal(err)
	}

	opened, err := Open(project.Path())
	if err != nil {
		t.Fatal(err)
	}
	if got := opened.Manifest().Preferences.ActivePolicyRevision; got != "baseline" {
		t.Fatalf("active revision = %q", got)
	}
	got, loaded, err := opened.ReadPolicyRevision("baseline")
	if err != nil || loaded.Revision != record.Revision || string(got) != string(content) {
		t.Fatalf("read policy = %q %#v err=%v", got, loaded, err)
	}
	artifact := filepath.Join(opened.Path(), filepath.FromSlash(record.Path))
	if err := os.WriteFile(artifact, []byte("[]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := opened.ReadPolicyRevision("baseline"); err == nil || !strings.Contains(err.Error(), "checksum mismatch") {
		t.Fatalf("tampered policy read error = %v", err)
	}
}

func TestRecoverUnindexedPoliciesByAttachOrArchive(t *testing.T) {
	project, err := New(t.TempDir(), "PolicyRecovery")
	if err != nil {
		t.Fatal(err)
	}
	if err := project.Save(); err != nil {
		t.Fatal(err)
	}
	policyDir := filepath.Join(project.Path(), "policies")
	attachPath := filepath.Join(policyDir, "interrupted.json")
	archivePath := filepath.Join(policyDir, "declined.json")
	content := []byte("[{\"id\":\"allow\",\"enabled\":true,\"match\":{},\"actions\":[{\"kind\":\"allow\"}]}]\n")
	if err := os.WriteFile(attachPath, content, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(archivePath, []byte("not trusted JSON\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got, err := project.UnindexedPolicies(); err != nil || len(got) != 2 {
		t.Fatalf("unindexed policies = %#v err=%v", got, err)
	}
	validated, digest, err := project.ReadUnindexedPolicy(attachPath)
	if err != nil || string(validated) != string(content) || !validDigest(digest) {
		t.Fatalf("read unindexed policy = %q digest=%q err=%v", validated, digest, err)
	}
	record, err := project.AttachUnindexedPolicy(attachPath, "recovered", "Recovered", digest)
	if err != nil || record.Path != "policies/interrupted.json" || record.SHA256 != digest || !project.Dirty() {
		t.Fatalf("attach policy = %#v dirty=%v err=%v", record, project.Dirty(), err)
	}
	if got, loaded, err := project.ReadPolicyRevision("recovered"); err != nil || loaded.Path != record.Path || string(got) != string(content) {
		t.Fatalf("read recovered policy = %q %#v err=%v", got, loaded, err)
	}
	if _, err := project.AttachUnindexedPolicy(attachPath, "again", "Again", digest); err == nil {
		t.Fatal("already-indexed policy artifact was attached again")
	}
	destination, err := project.ArchiveUnindexedPolicy(archivePath)
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Dir(destination) != filepath.Join(policyDir, "archive") {
		t.Fatalf("policy archive destination = %s", destination)
	}
	if got, err := os.ReadFile(destination); err != nil || string(got) != "not trusted JSON\n" {
		t.Fatalf("archived policy = %q err=%v", got, err)
	}
	if got, err := project.UnindexedPolicies(); err != nil || len(got) != 0 {
		t.Fatalf("unindexed policies after recovery = %#v err=%v", got, err)
	}
}

func TestAttachUnindexedPolicyRejectsChangedOrOutOfScopeArtifact(t *testing.T) {
	project, err := New(t.TempDir(), "PolicyRecoveryScope")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(project.Path(), "policies", "changed.json")
	if err := os.WriteFile(path, []byte("[]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, digest, err := project.ReadUnindexedPolicy(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("[ ]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := project.AttachUnindexedPolicy(path, "changed", "Changed", digest); err == nil || !strings.Contains(err.Error(), "changed after validation") {
		t.Fatalf("changed policy attach error = %v", err)
	}
	outside := filepath.Join(t.TempDir(), "outside.json")
	if err := os.WriteFile(outside, []byte("[]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := project.ReadUnindexedPolicy(outside); err == nil {
		t.Fatal("out-of-scope policy artifact was read for recovery")
	}
}

func TestOpenRejectsManagedArtifactTraversalInManifest(t *testing.T) {
	project, err := New(t.TempDir(), "UnsafeManifest")
	if err != nil {
		t.Fatal(err)
	}
	if err := project.Save(); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(project.Path(), manifestFile)
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var manifest Manifest
	if err := json.Unmarshal(content, &manifest); err != nil {
		t.Fatal(err)
	}
	manifest.Captures = []Capture{{ID: "bad", Name: "bad.pcap", Path: "captures/../../escape.pcap", Mode: ImportCopy, SHA256: strings.Repeat("0", 64)}}
	content, err = json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(project.Path()); err == nil {
		t.Fatal("managed traversal path was accepted")
	}
}

func TestManagedPCAPImportDeduplicatesAndNeverChangesSource(t *testing.T) {
	project, err := New(t.TempDir(), "CaptureLab")
	if err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(t.TempDir(), "evidence.pcap")
	content := append([]byte{0xd4, 0xc3, 0xb2, 0xa1}, []byte("immutable synthetic capture")...)
	if err := os.WriteFile(source, content, 0o600); err != nil {
		t.Fatal(err)
	}
	first, duplicate, err := project.importManagedCapture(context.Background(), source)
	if err != nil || duplicate {
		t.Fatalf("first import = %#v duplicate=%v err=%v", first, duplicate, err)
	}
	second, duplicate, err := project.importManagedCapture(context.Background(), source)
	if err != nil || !duplicate || first.SHA256 != second.SHA256 {
		t.Fatalf("second import = %#v duplicate=%v err=%v", second, duplicate, err)
	}
	if got, err := os.ReadFile(source); err != nil || string(got) != string(content) {
		t.Fatalf("source changed: %q err=%v", got, err)
	}
	managed := filepath.Join(project.Path(), filepath.FromSlash(first.Path))
	if info, err := os.Stat(managed); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("managed capture info=%v err=%v", info, err)
	}
	entries, err := os.ReadDir(filepath.Join(project.Path(), "captures"))
	if err != nil || len(entries) != 1 {
		t.Fatalf("managed capture entries=%d err=%v", len(entries), err)
	}
}

func TestImportSessionCapturesIndexesDirectFinalizedArtifacts(t *testing.T) {
	project, err := New(t.TempDir(), "SessionImport")
	if err != nil {
		t.Fatal(err)
	}
	if err := project.Save(); err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	firstPath := filepath.Join(directory, "host.pcap")
	secondPath := filepath.Join(directory, "forwarded.pcapng")
	if err := os.WriteFile(firstPath, append([]byte{0xd4, 0xc3, 0xb2, 0xa1}, []byte("host")...), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(secondPath, append([]byte{0x0a, 0x0d, 0x0d, 0x0a}, []byte("forwarded")...), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "decisions.jsonl"), []byte("journal\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	nested := filepath.Join(directory, "nested")
	if err := os.Mkdir(nested, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(nested, "ignored.pcap"), []byte{0xd4, 0xc3, 0xb2, 0xa1}, 0o600); err != nil {
		t.Fatal(err)
	}
	symlinkPath := filepath.Join(directory, "unsafe.pcap")
	if err := os.Symlink(firstPath, symlinkPath); err != nil {
		t.Fatal(err)
	}

	results, err := project.ImportSessionCaptures(context.Background(), directory)
	if err != nil {
		t.Fatal(err)
	}
	imported := 0
	failed := 0
	for _, result := range results {
		if result.Err != nil {
			failed++
			continue
		}
		if result.Duplicate {
			t.Fatalf("unexpected duplicate: %#v", result)
		}
		imported++
	}
	if imported != 2 || failed != 1 {
		t.Fatalf("session import results = %#v", results)
	}
	manifest := project.Manifest()
	if len(manifest.Captures) != 2 || !project.Dirty() {
		t.Fatalf("session captures=%#v dirty=%v", manifest.Captures, project.Dirty())
	}
	for _, capture := range manifest.Captures {
		if capture.Mode != ImportCopy || !strings.HasPrefix(capture.Path, "captures/") {
			t.Fatalf("managed session capture = %#v", capture)
		}
		if err := project.VerifyCapture(context.Background(), capture); err != nil {
			t.Fatalf("verify session capture %s: %v", capture.ID, err)
		}
	}
	if got, err := os.ReadFile(firstPath); err != nil || string(got) != string(append([]byte{0xd4, 0xc3, 0xb2, 0xa1}, []byte("host")...)) {
		t.Fatalf("session source changed: %q err=%v", got, err)
	}

	results, err = project.ImportSessionCaptures(context.Background(), directory)
	if err != nil {
		t.Fatal(err)
	}
	duplicates := 0
	for _, result := range results {
		if result.Err == nil && result.Duplicate {
			duplicates++
		}
	}
	if duplicates != 2 || len(project.Manifest().Captures) != 2 {
		t.Fatalf("repeat session import results=%#v captures=%#v", results, project.Manifest().Captures)
	}
}

func TestImportSessionCapturesRejectsSymlinkDirectory(t *testing.T) {
	project, err := New(t.TempDir(), "SessionScope")
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	link := filepath.Join(t.TempDir(), "session-link")
	if err := os.Symlink(directory, link); err != nil {
		t.Fatal(err)
	}
	if _, err := project.ImportSessionCaptures(context.Background(), link); err == nil {
		t.Fatal("symlink session directory was imported")
	}
}

func TestSessionAssociationDiscoversAndCompletesHardCrashRecovery(t *testing.T) {
	configRoot := t.TempDir()
	t.Setenv(paths.EnvConfigDir, configRoot)
	project, err := New(t.TempDir(), "AssociatedSession")
	if err != nil {
		t.Fatal(err)
	}
	runtimeRoot, err := paths.PcapRoot()
	if err != nil {
		t.Fatal(err)
	}
	directory := filepath.Join(runtimeRoot, "interrupted-run")
	if err := os.MkdirAll(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "original.pcap"), append([]byte{0xd4, 0xc3, 0xb2, 0xa1}, []byte("interrupted")...), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := project.AssociateSession(directory); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(directory, sessionAssociationFile)
	if info, err := os.Lstat(marker); err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		t.Fatalf("session marker info=%v err=%v", info, err)
	}
	directories, err := project.RecoverableSessions()
	if err != nil || len(directories) != 1 || directories[0] != directory {
		t.Fatalf("recoverable sessions=%v err=%v", directories, err)
	}
	other, err := New(t.TempDir(), "OtherProject")
	if err != nil {
		t.Fatal(err)
	}
	if got, err := other.RecoverableSessions(); err != nil || len(got) != 0 {
		t.Fatalf("other project sessions=%v err=%v", got, err)
	}
	if err := other.AssociateSession(directory); err == nil {
		t.Fatal("another project replaced the session association")
	}
	if err := project.CompleteSessionAssociation(directory); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(marker); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("completed session marker remains: %v", err)
	}
	if got, err := project.RecoverableSessions(); err != nil || len(got) != 0 {
		t.Fatalf("sessions after completion=%v err=%v", got, err)
	}
}

func TestAssociatedSessionInventoryArchivesOnlyStaleOwnedMarkers(t *testing.T) {
	t.Setenv(paths.EnvConfigDir, t.TempDir())
	project, err := New(t.TempDir(), "SessionInventory")
	if err != nil {
		t.Fatal(err)
	}
	runtimeRoot, err := paths.PcapRoot()
	if err != nil {
		t.Fatal(err)
	}
	stale := filepath.Join(runtimeRoot, "stale-run")
	if err := os.MkdirAll(stale, 0o700); err != nil {
		t.Fatal(err)
	}
	journal := filepath.Join(stale, "decisions.jsonl")
	if err := os.WriteFile(journal, []byte("retained\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := project.AssociateSession(stale); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(stale, sessionAssociationFile)
	markerContent, err := os.ReadFile(marker)
	if err != nil {
		t.Fatal(err)
	}
	sessions, err := project.AssociatedSessions()
	if err != nil || len(sessions) != 1 || sessions[0].Directory != stale || sessions[0].Recoverable || sessions[0].CreatedAt.IsZero() {
		t.Fatalf("associated sessions=%#v err=%v", sessions, err)
	}
	if recoverable, err := project.RecoverableSessions(); err != nil || len(recoverable) != 0 {
		t.Fatalf("recoverable stale sessions=%v err=%v", recoverable, err)
	}
	archive, err := project.ArchiveStaleSessionAssociation(stale)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := os.ReadFile(archive); err != nil || string(got) != string(markerContent) {
		t.Fatalf("archived marker=%q err=%v", got, err)
	}
	if info, err := os.Stat(archive); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("archive info=%v err=%v", info, err)
	}
	if _, err := os.Lstat(marker); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("stale marker remains: %v", err)
	}
	if got, err := os.ReadFile(journal); err != nil || string(got) != "retained\n" {
		t.Fatalf("runtime artifact changed: %q err=%v", got, err)
	}
	if sessions, err := project.AssociatedSessions(); err != nil || len(sessions) != 0 {
		t.Fatalf("sessions after archive=%#v err=%v", sessions, err)
	}

	recoverable := filepath.Join(runtimeRoot, "recoverable-run")
	if err := os.MkdirAll(recoverable, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(recoverable, "original.pcap"), []byte{0xd4, 0xc3, 0xb2, 0xa1}, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := project.AssociateSession(recoverable); err != nil {
		t.Fatal(err)
	}
	if _, err := project.ArchiveStaleSessionAssociation(recoverable); err == nil || !strings.Contains(err.Error(), "recover them before archiving") {
		t.Fatalf("recoverable archive error=%v", err)
	}
	if _, err := os.Stat(filepath.Join(recoverable, sessionAssociationFile)); err != nil {
		t.Fatalf("recoverable marker was removed: %v", err)
	}

	other, err := New(t.TempDir(), "OtherSessionInventory")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := other.ArchiveStaleSessionAssociation(recoverable); err == nil || !strings.Contains(err.Error(), "another project") {
		t.Fatalf("foreign archive error=%v", err)
	}
}

func TestSessionAssociationRejectsOutOfScopeDirectory(t *testing.T) {
	t.Setenv(paths.EnvConfigDir, t.TempDir())
	project, err := New(t.TempDir(), "AssociationScope")
	if err != nil {
		t.Fatal(err)
	}
	if err := project.AssociateSession(t.TempDir()); err == nil {
		t.Fatal("out-of-scope runtime session was associated")
	}
}

func TestRecoverUnindexedCapturesByAttachOrArchive(t *testing.T) {
	project, err := New(t.TempDir(), "RecoveryLab")
	if err != nil {
		t.Fatal(err)
	}
	captureDir := filepath.Join(project.Path(), "captures")
	attachPath := filepath.Join(captureDir, "completed.pcap")
	archivePath := filepath.Join(captureDir, "operator-declined.pcapng")
	if err := os.WriteFile(attachPath, append([]byte{0xd4, 0xc3, 0xb2, 0xa1}, []byte("completed")...), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(archivePath, append([]byte{0x0a, 0x0d, 0x0d, 0x0a}, []byte("archive")...), 0o600); err != nil {
		t.Fatal(err)
	}
	if got, err := project.UnindexedCaptures(); err != nil || len(got) != 2 {
		t.Fatalf("unindexed = %#v err=%v", got, err)
	}
	record, duplicate, err := project.AttachUnindexedCapture(context.Background(), attachPath)
	if err != nil || duplicate || record.Path != "captures/completed.pcap" || !project.Dirty() {
		t.Fatalf("attach = %#v duplicate=%v dirty=%v err=%v", record, duplicate, project.Dirty(), err)
	}
	destination, err := project.ArchiveUnindexedCapture(archivePath)
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Dir(destination) != filepath.Join(captureDir, "archive") {
		t.Fatalf("archive destination = %s", destination)
	}
	if _, err := os.Stat(destination); err != nil {
		t.Fatalf("archived evidence missing: %v", err)
	}
	if got, err := project.UnindexedCaptures(); err != nil || len(got) != 0 {
		t.Fatalf("unindexed after recovery = %#v err=%v", got, err)
	}
}

func TestAttachUnindexedCaptureRejectsOutsideProject(t *testing.T) {
	project, err := New(t.TempDir(), "RecoveryScope")
	if err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(t.TempDir(), "outside.pcap")
	if err := os.WriteFile(outside, []byte{0xd4, 0xc3, 0xb2, 0xa1}, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := project.AttachUnindexedCapture(context.Background(), outside); err == nil {
		t.Fatal("outside capture was attached")
	}
}

func TestFullBundleIncludesManagedCaptureAndImportsSafely(t *testing.T) {
	base := t.TempDir()
	project, err := New(base, "ReferenceLab")
	if err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(t.TempDir(), "external.pcapng")
	content := append([]byte{0x0a, 0x0d, 0x0d, 0x0a}, []byte("synthetic pcapng")...)
	if err := os.WriteFile(source, content, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := project.importManagedCapture(context.Background(), source); err != nil {
		t.Fatal(err)
	}
	if err := project.Save(); err != nil {
		t.Fatal(err)
	}
	bundle := filepath.Join(t.TempDir(), "reference.golanproj")
	if err := project.ExportBundle(context.Background(), bundle, BundleFull); err != nil {
		t.Fatal(err)
	}
	imported, err := ImportBundle(context.Background(), bundle, t.TempDir(), "Imported")
	if err != nil {
		t.Fatal(err)
	}
	manifest := imported.Manifest()
	if len(manifest.Captures) != 1 || manifest.Captures[0].Mode != ImportCopy {
		t.Fatalf("imported captures = %#v", manifest.Captures)
	}
	managed := filepath.Join(imported.Path(), filepath.FromSlash(manifest.Captures[0].Path))
	if got, err := os.ReadFile(managed); err != nil || string(got) != string(content) {
		t.Fatalf("bundled capture = %q err=%v", got, err)
	}
}

func TestManagedCaptureDoesNotDependOnSourceAfterIndexing(t *testing.T) {
	project, err := New(t.TempDir(), "ManagedCapture")
	if err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(t.TempDir(), "source.pcap")
	if err := os.WriteFile(source, []byte{0xd4, 0xc3, 0xb2, 0xa1}, 0o600); err != nil {
		t.Fatal(err)
	}
	capture, duplicate, err := project.importManagedCapture(context.Background(), source)
	if err != nil || duplicate {
		t.Fatalf("capture=%#v duplicate=%v err=%v", capture, duplicate, err)
	}
	if err := os.Remove(source); err != nil {
		t.Fatal(err)
	}
	if err := project.VerifyCapture(context.Background(), capture); err != nil {
		t.Fatal(err)
	}
}

func TestManagedCaptureRejectsSymlinkSource(t *testing.T) {
	project, err := New(t.TempDir(), "CaptureSafety")
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	target := filepath.Join(directory, "target.pcap")
	if err := os.WriteFile(target, []byte{0xd4, 0xc3, 0xb2, 0xa1}, 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(directory, "link.pcap")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, _, err := project.importManagedCapture(context.Background(), link); err == nil || !strings.Contains(err.Error(), "non-symlink") {
		t.Fatalf("symlink import error=%v", err)
	}
}

func TestBundleImportRejectsTraversal(t *testing.T) {
	bundle := filepath.Join(t.TempDir(), "malicious.golanproj")
	file, err := os.Create(bundle)
	if err != nil {
		t.Fatal(err)
	}
	writer := zip.NewWriter(file)
	header := &zip.FileHeader{Name: "../escape", Method: zip.Store}
	header.SetMode(0o600)
	entry, err := writer.CreateHeader(header)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := entry.Write([]byte("escape")); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	destination := t.TempDir()
	if _, err := ImportBundle(context.Background(), bundle, destination, "Unsafe"); err == nil {
		t.Fatal("traversal bundle imported")
	}
	if _, err := os.Stat(filepath.Join(destination, "escape")); !os.IsNotExist(err) {
		t.Fatalf("traversal target exists: %v", err)
	}
}

func TestManagedCaptureRejectsInvalidAndSymlink(t *testing.T) {
	project, err := New(t.TempDir(), "CaptureValidation")
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	valid := filepath.Join(directory, "valid.pcap")
	if err := os.WriteFile(valid, []byte{0xd4, 0xc3, 0xb2, 0xa1}, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := project.importManagedCapture(context.Background(), valid); err != nil {
		t.Fatalf("valid capture: %v", err)
	}
	invalid := filepath.Join(directory, "invalid.pcap")
	if err := os.WriteFile(invalid, []byte("nope"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := project.importManagedCapture(context.Background(), invalid); err == nil || !strings.Contains(err.Error(), "not PCAP") {
		t.Fatalf("invalid capture error = %v", err)
	}
	link := filepath.Join(directory, "link.pcap")
	if err := os.Symlink(valid, link); err != nil {
		t.Fatal(err)
	}
	if _, _, err := project.importManagedCapture(context.Background(), link); err == nil || !strings.Contains(err.Error(), "non-symlink") {
		t.Fatalf("symlink capture error = %v", err)
	}
}
