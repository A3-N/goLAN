package project

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"golan/internal/dataplane"
	"golan/internal/policy"
	"golan/internal/traffic"
)

func TestImportSessionCaptureJournalIndexesVerifiesAndBundlesEvidence(t *testing.T) {
	project, err := New(t.TempDir(), "PassiveEvidence")
	if err != nil {
		t.Fatal(err)
	}
	session := t.TempDir()
	capturePath := filepath.Join(session, "host-en7.pcap")
	writePairTestPCAP(t, capturePath, []uint16{53, 80})
	sidecar := captureJournalSourceName(capturePath, dataplane.ModeListen)
	writePairTestJournal(t, sidecar, []policy.Decision{
		captureJournalDecision("packet-1", dataplane.ModeListen, 1),
		captureJournalDecision("packet-2", dataplane.ModeListen, 2),
	})

	results, err := project.ImportSessionCaptures(context.Background(), session)
	if err != nil || len(results) != 1 || results[0].Err != nil ||
		results[0].JournalErr != nil || results[0].Journal == nil ||
		results[0].Duplicate || results[0].JournalDuplicate {
		t.Fatalf("results=%#v error=%v", results, err)
	}
	record := *results[0].Journal
	if record.CaptureID != results[0].Capture.ID || record.Mode != string(dataplane.ModeListen) ||
		record.Records != 2 || !record.Complete || record.Path == sidecar {
		t.Fatalf("record=%#v capture=%#v", record, results[0].Capture)
	}
	if err := project.VerifyCaptureJournal(context.Background(), record); err != nil {
		t.Fatal(err)
	}

	results, err = project.ImportSessionCaptures(context.Background(), session)
	if err != nil || len(results) != 1 || !results[0].Duplicate ||
		results[0].Journal == nil || !results[0].JournalDuplicate {
		t.Fatalf("repeat results=%#v error=%v", results, err)
	}
	if len(project.Manifest().CaptureJournals) != 1 {
		t.Fatalf("manifest journals=%#v", project.Manifest().CaptureJournals)
	}
	if err := project.Save(); err != nil {
		t.Fatal(err)
	}

	savedAs, err := project.SaveAsContext(context.Background(), t.TempDir(), "PassiveEvidenceCopy")
	if err != nil {
		t.Fatal(err)
	}
	if copied := savedAs.Manifest().CaptureJournals; len(copied) != 1 {
		t.Fatalf("Save As journals=%#v", copied)
	} else if err := savedAs.VerifyCaptureJournal(context.Background(), copied[0]); err != nil {
		t.Fatal(err)
	}

	fullBundle := filepath.Join(t.TempDir(), "passive-evidence.golanproj")
	if err := project.ExportBundle(context.Background(), fullBundle, BundleFull); err != nil {
		t.Fatal(err)
	}
	imported, _, err := ImportBundleWithReport(context.Background(), fullBundle, t.TempDir(), "PassiveEvidenceImport")
	if err != nil {
		t.Fatal(err)
	}
	importedManifest := imported.Manifest()
	if len(importedManifest.CaptureJournals) != 1 {
		t.Fatalf("imported journals=%#v", importedManifest.CaptureJournals)
	}
	if err := imported.VerifyCaptureJournal(context.Background(), importedManifest.CaptureJournals[0]); err != nil {
		t.Fatal(err)
	}

	metadataBundle := filepath.Join(t.TempDir(), "passive-metadata.golanproj")
	if err := project.ExportBundle(context.Background(), metadataBundle, BundleMetadata); err != nil {
		t.Fatal(err)
	}
	metadata, _, err := ImportBundleWithReport(context.Background(), metadataBundle, t.TempDir(), "PassiveMetadataImport")
	if err != nil {
		t.Fatal(err)
	}
	if len(metadata.Manifest().CaptureJournals) != 0 {
		t.Fatalf("metadata retained capture evidence=%#v", metadata.Manifest().CaptureJournals)
	}
}

func TestImportSessionCaptureJournalAcceptsEmptyAndTruncatedStreams(t *testing.T) {
	for _, test := range []struct {
		name     string
		content  []byte
		records  uint64
		complete bool
	}{
		{name: "empty", complete: true},
		{
			name: "truncated tail",
			content: append(
				pairTestDecisionLine(t, captureJournalDecision("packet-1", dataplane.ModeEdgeObserve, 1)),
				[]byte(`{"packet_id":"unfinished"`)...,
			),
			records: 1, complete: false,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			project, err := New(t.TempDir(), "PassiveTail")
			if err != nil {
				t.Fatal(err)
			}
			session := t.TempDir()
			capturePath := filepath.Join(session, "downstream-en8.pcap")
			writePairTestPCAP(t, capturePath, nil)
			if err := os.WriteFile(captureJournalSourceName(capturePath, dataplane.ModeEdgeObserve), test.content, 0o600); err != nil {
				t.Fatal(err)
			}
			results, err := project.ImportSessionCaptures(context.Background(), session)
			if err != nil || len(results) != 1 || results[0].JournalErr != nil || results[0].Journal == nil {
				t.Fatalf("results=%#v error=%v", results, err)
			}
			if results[0].Journal.Records != test.records || results[0].Journal.Complete != test.complete {
				t.Fatalf("journal=%#v", results[0].Journal)
			}
		})
	}
}

func TestImportSessionCaptureJournalRejectsFalseIdentityClaims(t *testing.T) {
	tests := []struct {
		name     string
		decision policy.Decision
	}{
		{name: "wrong ordinal", decision: captureJournalDecision("packet", dataplane.ModeListen, 2)},
		{name: "wrong mode", decision: captureJournalDecision("packet", dataplane.ModeEdgeObserve, 1)},
		{
			name: "non-packet evidence",
			decision: func() policy.Decision {
				decision := captureJournalDecision("packet", dataplane.ModeListen, 1)
				decision.EvidenceKind = traffic.EvidenceKind("message")
				return decision
			}(),
		},
		{
			name: "forwarding claim",
			decision: func() policy.Decision {
				decision := captureJournalDecision("packet", dataplane.ModeListen, 1)
				decision.ForwardedPacketID = "forwarded"
				return decision
			}(),
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			project, err := New(t.TempDir(), "InvalidPassiveEvidence")
			if err != nil {
				t.Fatal(err)
			}
			session := t.TempDir()
			capturePath := filepath.Join(session, "host-en7.pcap")
			writePairTestPCAP(t, capturePath, []uint16{53})
			writePairTestJournal(
				t,
				captureJournalSourceName(capturePath, dataplane.ModeListen),
				[]policy.Decision{test.decision},
			)
			results, err := project.ImportSessionCaptures(context.Background(), session)
			if err != nil || len(results) != 1 || results[0].JournalErr == nil {
				t.Fatalf("results=%#v error=%v", results, err)
			}
			if len(project.Manifest().CaptureJournals) != 0 {
				t.Fatal("invalid capture journal entered inventory")
			}
		})
	}
}

func TestImportSessionCaptureJournalRejectsSymlinkAndAmbiguousSidecars(t *testing.T) {
	for _, ambiguous := range []bool{false, true} {
		name := "symlink"
		if ambiguous {
			name = "ambiguous"
		}
		t.Run(name, func(t *testing.T) {
			project, err := New(t.TempDir(), "UnsafePassiveEvidence")
			if err != nil {
				t.Fatal(err)
			}
			session := t.TempDir()
			capturePath := filepath.Join(session, "host-en7.pcap")
			writePairTestPCAP(t, capturePath, nil)
			listenPath := captureJournalSourceName(capturePath, dataplane.ModeListen)
			if ambiguous {
				if err := os.WriteFile(listenPath, nil, 0o600); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(captureJournalSourceName(capturePath, dataplane.ModeEdgeObserve), nil, 0o600); err != nil {
					t.Fatal(err)
				}
			} else {
				target := filepath.Join(t.TempDir(), "journal.jsonl")
				if err := os.WriteFile(target, nil, 0o600); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(target, listenPath); err != nil {
					t.Fatal(err)
				}
			}
			results, err := project.ImportSessionCaptures(context.Background(), session)
			if err != nil || len(results) != 1 || results[0].JournalErr == nil {
				t.Fatalf("results=%#v error=%v", results, err)
			}
			if len(project.Manifest().CaptureJournals) != 0 {
				t.Fatal("unsafe capture journal entered inventory")
			}
		})
	}
}

func captureJournalDecision(id string, mode dataplane.Mode, ordinal uint64) policy.Decision {
	return policy.Decision{
		PacketID: traffic.PacketID(id), DataPlane: mode, EvidenceKind: traffic.EvidencePacket,
		OriginalCaptureOrdinal: ordinal, Verdict: policy.VerdictAllow,
		EffectiveVerdict: policy.VerdictAllow, Status: dataplane.StatusShadow,
	}
}
