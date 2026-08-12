package project

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func TestSaveAsContextStreamsLargeManagedCaptureAtomically(t *testing.T) {
	sourceBase := t.TempDir()
	project, err := New(sourceBase, "Original")
	if err != nil {
		t.Fatal(err)
	}
	sourceCapture := filepath.Join(t.TempDir(), "large.pcap")
	writeSparsePCAP(t, sourceCapture, 8<<20)
	capture, duplicate, err := project.importManagedCapture(context.Background(), sourceCapture)
	if err != nil || duplicate {
		t.Fatalf("import capture duplicate=%v err=%v", duplicate, err)
	}
	if err := os.WriteFile(filepath.Join(project.Path(), "exports", "operator.txt"), []byte("preserved\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(project.Path(), ".staging", "interrupted.tmp"), []byte("transient\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := project.Save(); err != nil {
		t.Fatal(err)
	}
	originalID := project.Manifest().ID
	project.SetWorkspace("Rules")

	destinationBase := t.TempDir()
	next, err := project.SaveAsContext(context.Background(), destinationBase, "Large Copy")
	if err != nil {
		t.Fatal(err)
	}
	if next.Path() != filepath.Join(destinationBase, "Large Copy.golan") || next.Dirty() {
		t.Fatalf("saved project path=%q dirty=%v", next.Path(), next.Dirty())
	}
	manifest := next.Manifest()
	if manifest.ID == originalID || manifest.Name != "Large Copy" || manifest.Preferences.Workspace != "Rules" || len(manifest.Captures) != 1 {
		t.Fatalf("saved manifest=%#v", manifest)
	}
	if !project.Dirty() || project.Manifest().ID != originalID || project.Path() == next.Path() {
		t.Fatalf("source changed dirty=%v manifest=%#v path=%q", project.Dirty(), project.Manifest(), project.Path())
	}
	if err := next.VerifyCapture(context.Background(), manifest.Captures[0]); err != nil {
		t.Fatalf("verify copied capture: %v", err)
	}
	managed := filepath.Join(next.Path(), filepath.FromSlash(capture.Path))
	if info, err := os.Stat(managed); err != nil || info.Size() != 8<<20 || info.Mode().Perm() != 0o600 {
		t.Fatalf("managed copy info=%#v err=%v", info, err)
	}
	if got, err := os.ReadFile(filepath.Join(next.Path(), "exports", "operator.txt")); err != nil || string(got) != "preserved\n" {
		t.Fatalf("copied export=%q err=%v", got, err)
	}
	if _, err := os.Stat(filepath.Join(next.Path(), ".staging", "interrupted.tmp")); !os.IsNotExist(err) {
		t.Fatalf("transient staging artifact copied: %v", err)
	}
	assertNoSaveAsStaging(t, destinationBase)
	if opened, err := Open(next.Path()); err != nil || opened.Manifest().ID != manifest.ID {
		t.Fatalf("reopen saved project=%#v err=%v", opened, err)
	}
}

func TestSaveAsContextCancellationRemovesPrivateStaging(t *testing.T) {
	project, err := New(t.TempDir(), "CancelSource")
	if err != nil {
		t.Fatal(err)
	}
	large := filepath.Join(project.Path(), "exports", "large.bin")
	file, err := os.OpenFile(large, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Truncate(4 << 20); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if err := project.Save(); err != nil {
		t.Fatal(err)
	}

	destinationBase := t.TempDir()
	// The eleventh cancellation check occurs after the first bounded chunk of
	// exports/large.bin has been written into private staging.
	ctx := newCancelAfterChecksContext(11)
	next, err := project.SaveAsContext(ctx, destinationBase, "Canceled")
	if next != nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled save-as next=%#v err=%v checks=%d", next, err, ctx.Checks())
	}
	if _, err := os.Lstat(filepath.Join(destinationBase, "Canceled.golan")); !os.IsNotExist(err) {
		t.Fatalf("canceled destination exists: %v", err)
	}
	assertNoSaveAsStaging(t, destinationBase)
	if info, err := os.Stat(large); err != nil || info.Size() != 4<<20 {
		t.Fatalf("source artifact changed info=%#v err=%v", info, err)
	}
	if opened, err := Open(project.Path()); err != nil || opened.Manifest().ID != project.Manifest().ID {
		t.Fatalf("source project no longer opens: %#v err=%v", opened, err)
	}
}

func TestSaveAsContextRejectsUnsafeOrConflictingDestination(t *testing.T) {
	project, err := New(t.TempDir(), "SafetySource")
	if err != nil {
		t.Fatal(err)
	}
	if err := project.Save(); err != nil {
		t.Fatal(err)
	}
	external := filepath.Join(t.TempDir(), "outside.txt")
	if err := os.WriteFile(external, []byte("outside\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(project.Path(), "exports", "unsafe-link")
	if err := os.Symlink(external, link); err != nil {
		t.Fatal(err)
	}
	destinationBase := t.TempDir()
	if _, err := project.SaveAsContext(context.Background(), destinationBase, "Unsafe"); err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("symlink save-as error=%v", err)
	}
	if got, err := os.ReadFile(external); err != nil || string(got) != "outside\n" {
		t.Fatalf("external target changed=%q err=%v", got, err)
	}
	if _, err := os.Lstat(filepath.Join(destinationBase, "Unsafe.golan")); !os.IsNotExist(err) {
		t.Fatalf("unsafe destination exists: %v", err)
	}
	assertNoSaveAsStaging(t, destinationBase)

	nestedBase := filepath.Join(project.Path(), "not-created")
	if _, err := project.SaveAsContext(context.Background(), nestedBase, "Nested"); err == nil || !strings.Contains(err.Error(), "inside the source") {
		t.Fatalf("nested save-as error=%v", err)
	}
	if _, err := os.Lstat(nestedBase); !os.IsNotExist(err) {
		t.Fatalf("nested destination parent was created inside source: %v", err)
	}
	existing := filepath.Join(destinationBase, "Existing.golan")
	if err := os.Mkdir(existing, 0o700); err != nil {
		t.Fatal(err)
	}
	sentinel := filepath.Join(existing, "sentinel")
	if err := os.WriteFile(sentinel, []byte("keep\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := project.SaveAsContext(context.Background(), destinationBase, "Existing"); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("existing save-as error=%v", err)
	}
	if got, err := os.ReadFile(sentinel); err != nil || string(got) != "keep\n" {
		t.Fatalf("existing destination changed=%q err=%v", got, err)
	}
}

func TestSaveAsContextRejectsTamperedManagedCapture(t *testing.T) {
	project, err := New(t.TempDir(), "TamperedSource")
	if err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(t.TempDir(), "evidence.pcap")
	writeSparsePCAP(t, source, 1<<20)
	capture, _, err := project.importManagedCapture(context.Background(), source)
	if err != nil {
		t.Fatal(err)
	}
	if err := project.Save(); err != nil {
		t.Fatal(err)
	}
	managed := filepath.Join(project.Path(), filepath.FromSlash(capture.Path))
	file, err := os.OpenFile(managed, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.WriteAt([]byte{0xff}, capture.Size-1); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	destinationBase := t.TempDir()
	if _, err := project.SaveAsContext(context.Background(), destinationBase, "Tampered"); err == nil || !strings.Contains(err.Error(), "fingerprint differs") {
		t.Fatalf("tampered capture save-as error=%v", err)
	}
	if _, err := os.Lstat(filepath.Join(destinationBase, "Tampered.golan")); !os.IsNotExist(err) {
		t.Fatalf("tampered destination exists: %v", err)
	}
	assertNoSaveAsStaging(t, destinationBase)
}

func TestSaveAsContextRejectsArtifactChangedDuringStreaming(t *testing.T) {
	project, err := New(t.TempDir(), "ChangingSource")
	if err != nil {
		t.Fatal(err)
	}
	changing := filepath.Join(project.Path(), "exports", "large.bin")
	file, err := os.OpenFile(changing, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Truncate(4 << 20); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if err := project.Save(); err != nil {
		t.Fatal(err)
	}

	ctx := newActionAfterChecksContext(11, func() error {
		file, err := os.OpenFile(changing, os.O_WRONLY|os.O_APPEND, 0)
		if err != nil {
			return err
		}
		_, writeErr := file.Write([]byte{1})
		return errors.Join(writeErr, file.Close())
	})
	destinationBase := t.TempDir()
	if _, err := project.SaveAsContext(ctx, destinationBase, "Changing"); err == nil || !strings.Contains(err.Error(), "source changed during copy") {
		t.Fatalf("changing source save-as error=%v", err)
	}
	if err := ctx.ActionError(); err != nil {
		t.Fatalf("mutation action: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(destinationBase, "Changing.golan")); !os.IsNotExist(err) {
		t.Fatalf("changing destination exists: %v", err)
	}
	assertNoSaveAsStaging(t, destinationBase)
}

func writeSparsePCAP(t *testing.T, path string, size int64) {
	t.Helper()
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.Write([]byte{0xd4, 0xc3, 0xb2, 0xa1}); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if err := file.Truncate(size); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
}

func assertNoSaveAsStaging(t *testing.T, base string) {
	t.Helper()
	entries, err := os.ReadDir(base)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".golan-save-as-") {
			t.Fatalf("save-as staging remains: %s", filepath.Join(base, entry.Name()))
		}
	}
}

type cancelAfterChecksContext struct {
	context.Context
	mu       sync.Mutex
	done     chan struct{}
	after    int
	checks   int
	canceled bool
}

func newCancelAfterChecksContext(after int) *cancelAfterChecksContext {
	return &cancelAfterChecksContext{Context: context.Background(), done: make(chan struct{}), after: after}
}

func (ctx *cancelAfterChecksContext) Done() <-chan struct{} {
	ctx.mu.Lock()
	ctx.checks++
	if !ctx.canceled && ctx.checks >= ctx.after {
		ctx.canceled = true
		close(ctx.done)
	}
	ctx.mu.Unlock()
	return ctx.done
}

func (ctx *cancelAfterChecksContext) Err() error {
	ctx.mu.Lock()
	defer ctx.mu.Unlock()
	if ctx.canceled {
		return context.Canceled
	}
	return nil
}

func (ctx *cancelAfterChecksContext) Checks() int {
	ctx.mu.Lock()
	defer ctx.mu.Unlock()
	return ctx.checks
}

type actionAfterChecksContext struct {
	context.Context
	mu        sync.Mutex
	after     int
	checks    int
	action    func() error
	actionErr error
}

func newActionAfterChecksContext(after int, action func() error) *actionAfterChecksContext {
	return &actionAfterChecksContext{Context: context.Background(), after: after, action: action}
}

func (ctx *actionAfterChecksContext) Done() <-chan struct{} {
	ctx.mu.Lock()
	ctx.checks++
	if ctx.action != nil && ctx.checks >= ctx.after {
		action := ctx.action
		ctx.action = nil
		ctx.mu.Unlock()
		err := action()
		ctx.mu.Lock()
		ctx.actionErr = err
	}
	ctx.mu.Unlock()
	return nil
}

func (ctx *actionAfterChecksContext) ActionError() error {
	ctx.mu.Lock()
	defer ctx.mu.Unlock()
	return ctx.actionErr
}
