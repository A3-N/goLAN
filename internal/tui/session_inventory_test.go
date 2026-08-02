package tui

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golan/internal/dataplane"
	"golan/internal/paths"
	"golan/internal/policy"
	workproject "golan/internal/project"
	"golan/internal/traffic"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

func writePCAPEvidenceTestCapture(t *testing.T, path string, frames ...[]byte) {
	t.Helper()
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	writer := pcapgo.NewWriter(file)
	if err := writer.WriteFileHeader(65535, layers.LinkTypeEthernet); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	for index, frame := range frames {
		if err := writer.WritePacket(gopacket.CaptureInfo{
			Timestamp: time.Unix(int64(index+1), 0), CaptureLength: len(frame), Length: len(frame),
		}, frame); err != nil {
			_ = file.Close()
			t.Fatal(err)
		}
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestProjectSessionRecoveryIndexesPassiveCaptureJournal(t *testing.T) {
	project, err := workproject.New(t.TempDir(), "PassiveRecovery")
	if err != nil {
		t.Fatal(err)
	}
	if err := project.Save(); err != nil {
		t.Fatal(err)
	}
	session := t.TempDir()
	capturePath := filepath.Join(session, "host-en7.pcap")
	writePCAPEvidenceTestCapture(t, capturePath, rulePreviewTCPFrame(nil))
	journal, err := policy.OpenJournal(filepath.Join(session, "host-en7.listen.decisions.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if err := journal.Append(policy.Decision{
		PacketID: "listen-packet", DataPlane: dataplane.ModeListen,
		EvidenceKind: traffic.EvidencePacket, OriginalCaptureOrdinal: 1,
		Verdict: policy.VerdictAllow, EffectiveVerdict: policy.VerdictAllow,
		Status: dataplane.StatusShadow,
	}); err != nil {
		t.Fatal(err)
	}
	if err := journal.Close(); err != nil {
		t.Fatal(err)
	}

	m := NewProjectModel(project, true, 100, 30)
	command := m.executeCommand("project recover session " + session)
	if command == nil {
		t.Fatal("session recovery did not start")
	}
	next, _ := m.Update(command())
	m = next.(Model)
	if len(project.Manifest().CaptureJournals) != 1 {
		t.Fatalf("capture journals=%#v", project.Manifest().CaptureJournals)
	}
	output := strings.Join(m.output, "\n")
	if !strings.Contains(output, "capture journal indexed") ||
		!strings.Contains(output, "session capture journals indexed imported=1 deduplicated=0") {
		t.Fatalf("recovery output=%q", output)
	}
	m.executeCommand("project journals capture")
	output = strings.Join(m.output, "\n")
	if !strings.Contains(output, "project: capture journals=1") ||
		!strings.Contains(output, "mode=listen") ||
		!strings.Contains(output, "records=1 complete=true") {
		t.Fatalf("journal inventory output=%q", output)
	}
}

func TestProjectSessionInventoryRendersAndArchivesStaleMarker(t *testing.T) {
	t.Setenv(paths.EnvConfigDir, t.TempDir())
	project, err := workproject.New(t.TempDir(), "SessionWorkbench")
	if err != nil {
		t.Fatal(err)
	}
	runtimeRoot, err := paths.PcapRoot()
	if err != nil {
		t.Fatal(err)
	}
	directory := filepath.Join(runtimeRoot, "stale-ui-run")
	if err := os.MkdirAll(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	journal := filepath.Join(directory, "decisions.jsonl")
	if err := os.WriteFile(journal, []byte("retained\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := project.AssociateSession(directory); err != nil {
		t.Fatal(err)
	}

	m := NewProjectModel(project, true, 100, 30)
	if len(m.projectSessions) != 1 || m.projectSessions[0].Recoverable {
		t.Fatalf("cached sessions=%#v err=%q", m.projectSessions, m.projectSessionErr)
	}
	m.showHealth()
	if !strings.Contains(strings.Join(m.output, "\n"), "project sessions recoverable=0 stale=1") {
		t.Fatalf("Main health output=%v", m.output)
	}

	m.executeCommand("project sessions")
	if output := strings.Join(m.output, "\n"); !strings.Contains(output, "session 1 stale "+directory) {
		t.Fatalf("session inventory output=%q", output)
	}
	m.executeCommand("project sessions archive " + directory)
	if len(m.projectSessions) != 0 {
		t.Fatalf("sessions after archive=%#v", m.projectSessions)
	}
	if output := strings.Join(m.output, "\n"); !strings.Contains(output, "stale session marker archived:") || !strings.Contains(output, "runtime artifacts retained: "+directory) {
		t.Fatalf("archive output=%q", output)
	}
	if got, err := os.ReadFile(journal); err != nil || string(got) != "retained\n" {
		t.Fatalf("runtime journal=%q err=%v", got, err)
	}
}

func TestProjectSessionArchiveRefusesRecoverableMarker(t *testing.T) {
	t.Setenv(paths.EnvConfigDir, t.TempDir())
	project, err := workproject.New(t.TempDir(), "RecoverableSessionWorkbench")
	if err != nil {
		t.Fatal(err)
	}
	runtimeRoot, err := paths.PcapRoot()
	if err != nil {
		t.Fatal(err)
	}
	directory := filepath.Join(runtimeRoot, "recoverable-ui-run")
	if err := os.MkdirAll(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "original.pcap"), []byte{0xd4, 0xc3, 0xb2, 0xa1}, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := project.AssociateSession(directory); err != nil {
		t.Fatal(err)
	}

	m := NewProjectModel(project, true, 100, 30)
	m.executeCommand("project sessions archive " + directory)
	if output := strings.Join(m.output, "\n"); !strings.Contains(output, "recover them before archiving") {
		t.Fatalf("recoverable archive output=%q", output)
	}
	if len(m.projectSessions) != 1 || !m.projectSessions[0].Recoverable {
		t.Fatalf("recoverable session cache=%#v", m.projectSessions)
	}
	if _, err := os.Stat(filepath.Join(directory, ".golan-project.json")); err != nil {
		t.Fatalf("recoverable marker removed: %v", err)
	}
}

func TestProjectSessionCommandCompletion(t *testing.T) {
	m := NewModel()
	m.input = "project sessions "
	m.refreshCompletions()
	if !containsString(m.completions, "archive") || !containsString(m.completions, "list") {
		t.Fatalf("session completions=%v", m.completions)
	}
}
