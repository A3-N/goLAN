package project

import (
	"archive/zip"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golan/internal/policy"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

func TestImportSessionCapturesIndexesVerifiedPairAndComparisonProofs(t *testing.T) {
	project, err := New(t.TempDir(), "SessionPair")
	if err != nil {
		t.Fatal(err)
	}
	session := t.TempDir()
	writePairTestPCAP(
		t,
		filepath.Join(session, "original.pcap"),
		[]uint16{10, 20},
	)
	writePairTestPCAP(
		t,
		filepath.Join(session, "forwarded.pcap"),
		[]uint16{10, 21},
	)
	writePairTestJournal(t, filepath.Join(session, "decisions.jsonl"), []policy.Decision{
		{
			OriginalCaptureOrdinal:   1,
			ForwardedCaptureOrdinals: []uint64{1},
			EffectiveVerdict:         policy.VerdictAllow,
		},
		{
			OriginalCaptureOrdinal:   2,
			ForwardedCaptureOrdinals: []uint64{2},
			EffectiveVerdict:         policy.VerdictAllow,
		},
	})

	results, err := project.ImportSessionCaptures(
		context.Background(),
		session,
	)
	if err != nil {
		t.Fatal(err)
	}
	pairResult := sessionPairResult(results)
	if pairResult == nil ||
		pairResult.Pair == nil ||
		pairResult.PairDuplicate {
		t.Fatalf("session pair result=%#v", pairResult)
	}
	manifest := project.Manifest()
	if len(manifest.Captures) != 2 ||
		len(manifest.CapturePairs) != 1 ||
		manifest.CapturePairs[0].JournalRecords != 2 ||
		!manifest.CapturePairs[0].JournalComplete {
		t.Fatalf("session pair manifest=%#v", manifest)
	}
	pair := manifest.CapturePairs[0]
	if err := project.VerifyCapturePairJournal(
		context.Background(),
		pair,
	); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Join(
		project.Path(),
		filepath.FromSlash(pair.JournalPath),
	))
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("managed journal info=%v err=%v", info, err)
	}
	results, err = project.ImportSessionCaptures(
		context.Background(),
		session,
	)
	if err != nil {
		t.Fatal(err)
	}
	pairResult = sessionPairResult(results)
	if pairResult == nil ||
		pairResult.Pair == nil ||
		!pairResult.PairDuplicate ||
		len(project.Manifest().CapturePairs) != 1 {
		t.Fatalf("repeat session pair result=%#v", pairResult)
	}
	if err := project.Save(); err != nil {
		t.Fatal(err)
	}
	opened, err := Open(project.Path())
	if err != nil {
		t.Fatal(err)
	}
	if len(opened.Manifest().CapturePairs) != 1 {
		t.Fatalf("reopened pair manifest=%#v", opened.Manifest())
	}
}

func TestSessionPairRejectsMalformedJournalAndMarksTruncatedTail(t *testing.T) {
	project, err := New(t.TempDir(), "SessionPairValidation")
	if err != nil {
		t.Fatal(err)
	}
	session := t.TempDir()
	writePairTestPCAP(
		t,
		filepath.Join(session, "original.pcap"),
		[]uint16{10},
	)
	writePairTestPCAP(
		t,
		filepath.Join(session, "forwarded.pcap"),
		[]uint16{10},
	)
	journalPath := filepath.Join(session, "decisions.jsonl")
	if err := os.WriteFile(journalPath, []byte("{bad}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	results, err := project.ImportSessionCaptures(
		context.Background(),
		session,
	)
	if err == nil || len(results) != 2 ||
		len(project.Manifest().CapturePairs) != 0 {
		t.Fatalf(
			"malformed import results=%#v pairs=%#v err=%v",
			results,
			project.Manifest().CapturePairs,
			err,
		)
	}
	valid := pairTestDecisionLine(t, policy.Decision{
		OriginalCaptureOrdinal:   1,
		ForwardedCaptureOrdinals: []uint64{1},
		EffectiveVerdict:         policy.VerdictAllow,
	})
	valid = append(valid, []byte(`{"original_capture_ordinal":2`)...)
	if err := os.WriteFile(journalPath, valid, 0o600); err != nil {
		t.Fatal(err)
	}
	results, err = project.ImportSessionCaptures(
		context.Background(),
		session,
	)
	if err != nil {
		t.Fatal(err)
	}
	pairResult := sessionPairResult(results)
	if pairResult == nil ||
		pairResult.Pair == nil ||
		pairResult.Pair.JournalComplete ||
		pairResult.Pair.JournalRecords != 1 {
		t.Fatalf("truncated pair result=%#v", pairResult)
	}
}

func TestCapturePairBundleScopeAndJournalIntegrity(t *testing.T) {
	project, pair := pairTestProject(t, "PairBundle")
	if err := project.Save(); err != nil {
		t.Fatal(err)
	}

	full := filepath.Join(t.TempDir(), "full.golanproj")
	if _, err := project.ExportBundleWithOptions(
		context.Background(),
		full,
		BundleOptions{Kind: BundleFull},
	); err != nil {
		t.Fatal(err)
	}
	imported, _, err := ImportBundleWithReport(
		context.Background(),
		full,
		t.TempDir(),
		"PairFullImport",
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(imported.Manifest().CapturePairs) != 1 {
		t.Fatalf("full imported pairs=%#v", imported.Manifest().CapturePairs)
	}
	if err := imported.VerifyCapturePairJournal(
		context.Background(),
		imported.Manifest().CapturePairs[0],
	); err != nil {
		t.Fatal(err)
	}

	selective := filepath.Join(t.TempDir(), "selective.golanproj")
	if _, err := project.ExportBundleWithOptions(
		context.Background(),
		selective,
		BundleOptions{
			Kind:       BundleFull,
			CaptureIDs: []string{pair.OriginalCaptureID},
		},
	); err != nil {
		t.Fatal(err)
	}
	selectiveImport, _, err := ImportBundleWithReport(
		context.Background(),
		selective,
		t.TempDir(),
		"PairSelectiveImport",
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(selectiveImport.Manifest().CapturePairs) != 0 ||
		bundleContainsEntry(t, selective, pair.JournalPath) {
		t.Fatalf(
			"selective pair manifest=%#v journal-present=%t",
			selectiveImport.Manifest().CapturePairs,
			bundleContainsEntry(t, selective, pair.JournalPath),
		)
	}

	for _, kind := range []BundleKind{BundleMetadata, BundleSanitized} {
		bundle := filepath.Join(t.TempDir(), string(kind)+".golanproj")
		if _, err := project.ExportBundleWithOptions(
			context.Background(),
			bundle,
			BundleOptions{Kind: kind},
		); err != nil {
			t.Fatal(err)
		}
		withoutEvidence, _, err := ImportBundleWithReport(
			context.Background(),
			bundle,
			t.TempDir(),
			"Pair"+string(kind),
		)
		if err != nil {
			t.Fatal(err)
		}
		if len(withoutEvidence.Manifest().CapturePairs) != 0 ||
			bundleContainsEntry(t, bundle, pair.JournalPath) {
			t.Fatalf(
				"%s pair manifest=%#v",
				kind,
				withoutEvidence.Manifest().CapturePairs,
			)
		}
	}

	tampered := rewriteBundleForTest(t, full, func(entries map[string][]byte) {
		addition := []byte("{}\n")
		entries[pair.JournalPath] = append(
			entries[pair.JournalPath],
			addition...,
		)
		var descriptor bundleDescriptor
		if err := json.Unmarshal(
			entries[bundleDescriptorFile],
			&descriptor,
		); err != nil {
			t.Fatal(err)
		}
		descriptor.Report.Bytes += int64(len(addition))
		entries[bundleDescriptorFile] = marshalBundleTestJSON(
			t,
			descriptor,
		)
	})
	if _, _, err := ImportBundleWithReport(
		context.Background(),
		tampered,
		t.TempDir(),
		"PairTamperedImport",
	); err == nil || !strings.Contains(err.Error(), "fingerprint") {
		t.Fatalf("tampered pair journal error=%v", err)
	}
}

func TestCapturePairInventoryAllowsDistinctJournals(t *testing.T) {
	project, pair := pairTestProject(t, "PairSelection")
	secondJournal := filepath.Join(t.TempDir(), "second.jsonl")
	writePairTestJournal(t, secondJournal, []policy.Decision{
		{
			OriginalCaptureOrdinal:   1,
			ForwardedCaptureOrdinals: []uint64{1},
			EffectiveVerdict:         policy.VerdictAllow,
			Explanation:              "second journal identity",
		},
		{
			OriginalCaptureOrdinal:   2,
			ForwardedCaptureOrdinals: []uint64{2},
			EffectiveVerdict:         policy.VerdictAllow,
		},
	})
	manifest := project.Manifest()
	captures := make(map[string]Capture)
	for _, capture := range manifest.Captures {
		captures[capture.ID] = capture
	}
	second, duplicate, err := project.importCapturePairJournal(
		context.Background(),
		secondJournal,
		captures[pair.OriginalCaptureID],
		captures[pair.ForwardedCaptureID],
	)
	if err != nil || duplicate || second.ID == pair.ID {
		t.Fatalf("second pair=%#v duplicate=%t err=%v", second, duplicate, err)
	}
	if len(project.Manifest().CapturePairs) != 2 {
		t.Fatalf("capture pairs=%#v", project.Manifest().CapturePairs)
	}
}

func TestSaveAsPreservesAndFingerprintVerifiesCapturePairJournal(t *testing.T) {
	project, pair := pairTestProject(t, "PairSaveAs")
	if err := project.Save(); err != nil {
		t.Fatal(err)
	}
	next, err := project.SaveAsContext(
		context.Background(),
		t.TempDir(),
		"PairSaveAsCopy",
	)
	if err != nil {
		t.Fatal(err)
	}
	manifest := next.Manifest()
	if len(manifest.CapturePairs) != 1 ||
		manifest.CapturePairs[0].ID != pair.ID {
		t.Fatalf("saved-as pairs=%#v", manifest.CapturePairs)
	}
	if err := next.VerifyCapturePairJournal(
		context.Background(),
		manifest.CapturePairs[0],
	); err != nil {
		t.Fatal(err)
	}

	journalPath := filepath.Join(
		project.Path(),
		filepath.FromSlash(pair.JournalPath),
	)
	file, err := os.OpenFile(journalPath, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		t.Fatal(err)
	}
	_, writeErr := file.Write([]byte("{}\n"))
	if err := errors.Join(writeErr, file.Close()); err != nil {
		t.Fatal(err)
	}
	destinationBase := t.TempDir()
	if _, err := project.SaveAsContext(
		context.Background(),
		destinationBase,
		"PairTamperedCopy",
	); err == nil || !strings.Contains(err.Error(), "differs from project inventory") {
		t.Fatalf("tampered pair save-as error=%v", err)
	}
}

func TestConcurrentCapturePairImportConvergesOnOneInventoryRecord(t *testing.T) {
	project, err := New(t.TempDir(), "PairConcurrent")
	if err != nil {
		t.Fatal(err)
	}
	originalPath := filepath.Join(t.TempDir(), "original.pcap")
	forwardedPath := filepath.Join(t.TempDir(), "forwarded.pcap")
	writePairTestPCAP(t, originalPath, []uint16{10})
	writePairTestPCAP(t, forwardedPath, []uint16{11})
	original, _, err := project.importManagedCapture(context.Background(), originalPath)
	if err != nil {
		t.Fatal(err)
	}
	forwarded, _, err := project.importManagedCapture(context.Background(), forwardedPath)
	if err != nil {
		t.Fatal(err)
	}
	journal := filepath.Join(t.TempDir(), "decisions.jsonl")
	writePairTestJournal(t, journal, []policy.Decision{{
		OriginalCaptureOrdinal:   1,
		ForwardedCaptureOrdinals: []uint64{1},
		EffectiveVerdict:         policy.VerdictAllow,
	}})
	type result struct {
		pair      CapturePair
		duplicate bool
		err       error
	}
	results := make(chan result, 2)
	for range 2 {
		go func() {
			pair, duplicate, err := project.importCapturePairJournal(
				context.Background(),
				journal,
				original,
				forwarded,
			)
			results <- result{
				pair:      pair,
				duplicate: duplicate,
				err:       err,
			}
		}()
	}
	first := <-results
	second := <-results
	if first.err != nil ||
		second.err != nil ||
		first.pair.ID == "" ||
		first.pair.ID != second.pair.ID ||
		first.duplicate == second.duplicate ||
		len(project.Manifest().CapturePairs) != 1 {
		t.Fatalf(
			"concurrent results=%#v %#v manifest=%#v",
			first,
			second,
			project.Manifest(),
		)
	}
}

func pairTestProject(t *testing.T, name string) (*Project, CapturePair) {
	t.Helper()
	project, err := New(t.TempDir(), name)
	if err != nil {
		t.Fatal(err)
	}
	session := t.TempDir()
	writePairTestPCAP(
		t,
		filepath.Join(session, "original.pcap"),
		[]uint16{10, 20},
	)
	writePairTestPCAP(
		t,
		filepath.Join(session, "forwarded.pcap"),
		[]uint16{10, 21},
	)
	writePairTestJournal(t, filepath.Join(session, "decisions.jsonl"), []policy.Decision{
		{
			OriginalCaptureOrdinal:   1,
			ForwardedCaptureOrdinals: []uint64{1},
			EffectiveVerdict:         policy.VerdictAllow,
		},
		{
			OriginalCaptureOrdinal:   2,
			ForwardedCaptureOrdinals: []uint64{2},
			EffectiveVerdict:         policy.VerdictAllow,
		},
	})
	if _, err := project.ImportSessionCaptures(
		context.Background(),
		session,
	); err != nil {
		t.Fatal(err)
	}
	manifest := project.Manifest()
	if len(manifest.CapturePairs) != 1 {
		t.Fatalf("pair manifest=%#v", manifest)
	}
	return project, manifest.CapturePairs[0]
}

func sessionPairResult(results []SessionCaptureImport) *SessionCaptureImport {
	for index := range results {
		if results[index].Pair != nil {
			return &results[index]
		}
	}
	return nil
}

func writePairTestJournal(
	t *testing.T,
	path string,
	decisions []policy.Decision,
) {
	t.Helper()
	var content []byte
	for _, decision := range decisions {
		content = append(content, pairTestDecisionLine(t, decision)...)
	}
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}
}

func pairTestDecisionLine(t *testing.T, decision policy.Decision) []byte {
	t.Helper()
	data, err := json.Marshal(decision)
	if err != nil {
		t.Fatal(err)
	}
	return append(data, '\n')
}

func writePairTestPCAP(t *testing.T, path string, ports []uint16) {
	t.Helper()
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	writer := pcapgo.NewWriter(file)
	if err := writer.WriteFileHeader(
		65535,
		layers.LinkTypeEthernet,
	); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	for index, port := range ports {
		frame := pairTestFrame(port)
		if err := writer.WritePacket(gopacket.CaptureInfo{
			Timestamp:     time.Unix(int64(index+1), 0),
			CaptureLength: len(frame),
			Length:        len(frame),
		}, frame); err != nil {
			_ = file.Close()
			t.Fatal(err)
		}
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
}

func pairTestFrame(port uint16) []byte {
	frame := make([]byte, 14+20+8)
	copy(frame[0:6], []byte{0x02, 0, 0, 0, 0, 2})
	copy(frame[6:12], []byte{0x02, 0, 0, 0, 0, 1})
	frame[12], frame[13] = 0x08, 0x00
	frame[14], frame[16], frame[23] = 0x45, 0, 17
	frame[17] = byte(len(frame) - 14)
	copy(frame[26:30], []byte{192, 0, 2, 1})
	copy(frame[30:34], []byte{192, 0, 2, 2})
	frame[34], frame[35] = byte(port>>8), byte(port)
	frame[36], frame[37] = 0, 53
	frame[38], frame[39] = 0, 8
	return frame
}

func bundleContainsEntry(t *testing.T, path, name string) bool {
	t.Helper()
	archive, err := zip.OpenReader(path)
	if err != nil {
		t.Fatal(err)
	}
	defer archive.Close()
	for _, file := range archive.File {
		if file.Name == name {
			return true
		}
	}
	return false
}
