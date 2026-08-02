package project

import (
	"archive/zip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"
)

func TestBundleVariantsReportAndRoundTripActiveEvidence(t *testing.T) {
	project, err := New(t.TempDir(), "BundleRoundTrip")
	if err != nil {
		t.Fatal(err)
	}
	capture := importBundleTestCapture(t, project, "evidence.pcap", []byte{0xd4, 0xc3, 0xb2, 0xa1})
	if err := project.Save(); err != nil {
		t.Fatal(err)
	}

	fullPath := filepath.Join(t.TempDir(), "full.golanproj")
	full, err := project.ExportBundleWithOptions(context.Background(), fullPath, BundleOptions{Kind: BundleFull})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(full.IncludedCaptures, []string{capture.ID}) || len(full.OmittedCaptures) != 0 {
		t.Fatalf("full report=%#v", full)
	}
	imported, importedReport, err := ImportBundleWithReport(context.Background(), fullPath, t.TempDir(), "ImportedFull")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(importedReport, full) || len(imported.Manifest().Captures) != 1 || imported.Manifest().Captures[0].Mode != ImportCopy {
		t.Fatalf("import report=%#v manifest=%#v", importedReport, imported.Manifest())
	}

	for _, kind := range []BundleKind{BundleMetadata, BundleSanitized} {
		path := filepath.Join(t.TempDir(), string(kind)+".golanproj")
		report, err := project.ExportBundleWithOptions(context.Background(), path, BundleOptions{Kind: kind})
		if err != nil {
			t.Fatal(err)
		}
		if len(report.IncludedCaptures) != 0 || !reflect.DeepEqual(report.OmittedCaptures, []string{capture.ID}) {
			t.Fatalf("%s report=%#v", kind, report)
		}
		entries := readBundleTestEntries(t, path)
		for name := range entries {
			if strings.HasPrefix(name, "captures/") || strings.HasPrefix(name, "journals/") || strings.HasPrefix(name, "observations/") {
				t.Fatalf("%s bundle contains evidence payload %s", kind, name)
			}
		}
	}
}

func TestFullBundleSupportsExplicitNoCaptureSelection(t *testing.T) {
	project, err := New(t.TempDir(), "NoCaptureBundle")
	if err != nil {
		t.Fatal(err)
	}
	capture := importBundleTestCapture(t, project, "evidence.pcap", []byte{0xd4, 0xc3, 0xb2, 0xa1})
	if err := project.Save(); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "none.golanproj")
	report, err := project.ExportBundleWithOptions(context.Background(), path, BundleOptions{Kind: BundleFull, CaptureIDs: []string{}})
	if err != nil {
		t.Fatal(err)
	}
	if len(report.IncludedCaptures) != 0 || !reflect.DeepEqual(report.OmittedCaptures, []string{capture.ID}) {
		t.Fatalf("report=%#v", report)
	}
	imported, _, err := ImportBundleWithReport(context.Background(), path, t.TempDir(), "NoCaptureImport")
	if err != nil {
		t.Fatal(err)
	}
	if len(imported.Manifest().Captures) != 0 {
		t.Fatalf("manifest=%#v", imported.Manifest())
	}
}

func TestBundleSelectionAndDescriptorValidation(t *testing.T) {
	project, err := New(t.TempDir(), "BundleValidation")
	if err != nil {
		t.Fatal(err)
	}
	importBundleTestCapture(t, project, "evidence.pcap", []byte{0xd4, 0xc3, 0xb2, 0xa1})
	if err := project.Save(); err != nil {
		t.Fatal(err)
	}
	invalid := filepath.Join(t.TempDir(), "invalid.golanproj")
	if _, err := project.ExportBundleWithOptions(context.Background(), invalid, BundleOptions{Kind: BundleFull, CaptureIDs: []string{"missing"}}); err == nil {
		t.Fatal("unknown capture selection was accepted")
	}
	if _, err := os.Lstat(invalid); !os.IsNotExist(err) {
		t.Fatalf("invalid destination exists: %v", err)
	}

	valid := filepath.Join(t.TempDir(), "valid.golanproj")
	if _, err := project.ExportBundleWithOptions(context.Background(), valid, BundleOptions{Kind: BundleFull}); err != nil {
		t.Fatal(err)
	}
	tampered := rewriteBundleForTest(t, valid, func(entries map[string][]byte) {
		var descriptor bundleDescriptor
		if err := json.Unmarshal(entries[bundleDescriptorFile], &descriptor); err != nil {
			t.Fatal(err)
		}
		descriptor.Report.IncludedCaptures[0] = "forged-capture-id"
		entries[bundleDescriptorFile] = marshalBundleTestJSON(t, descriptor)
	})
	if _, _, err := ImportBundleWithReport(context.Background(), tampered, t.TempDir(), "Tampered"); err == nil || !strings.Contains(err.Error(), "included captures") {
		t.Fatalf("tampered descriptor error=%v", err)
	}
}

func TestMetadataBundleRejectsInjectedCapturePayload(t *testing.T) {
	project, err := New(t.TempDir(), "MetadataPayload")
	if err != nil {
		t.Fatal(err)
	}
	importBundleTestCapture(t, project, "evidence.pcap", []byte{0xd4, 0xc3, 0xb2, 0xa1})
	if err := project.Save(); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "metadata.golanproj")
	if _, err := project.ExportBundleWithOptions(context.Background(), path, BundleOptions{Kind: BundleMetadata}); err != nil {
		t.Fatal(err)
	}
	injected := rewriteBundleForTest(t, path, func(entries map[string][]byte) {
		payload := []byte{0xd4, 0xc3, 0xb2, 0xa1}
		entries["captures/injected.pcap"] = payload
		var descriptor bundleDescriptor
		if err := json.Unmarshal(entries[bundleDescriptorFile], &descriptor); err != nil {
			t.Fatal(err)
		}
		descriptor.Report.Files++
		descriptor.Report.Bytes += int64(len(payload))
		entries[bundleDescriptorFile] = marshalBundleTestJSON(t, descriptor)
	})
	if _, _, err := ImportBundleWithReport(context.Background(), injected, t.TempDir(), "Injected"); err == nil || !strings.Contains(err.Error(), "unexpectedly contains capture evidence") {
		t.Fatalf("injected payload error=%v", err)
	}
}

func importBundleTestCapture(t *testing.T, project *Project, name string, content []byte) Capture {
	t.Helper()
	source := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(source, content, 0o600); err != nil {
		t.Fatal(err)
	}
	capture, duplicate, err := project.importManagedCapture(context.Background(), source)
	if err != nil || duplicate {
		t.Fatalf("import capture duplicate=%v err=%v", duplicate, err)
	}
	return capture
}

func readBundleTestEntries(t *testing.T, path string) map[string][]byte {
	t.Helper()
	archive, err := zip.OpenReader(path)
	if err != nil {
		t.Fatal(err)
	}
	defer archive.Close()
	entries := make(map[string][]byte, len(archive.File))
	for _, file := range archive.File {
		data, err := readZipFile(file, maxBundleFileSize)
		if err != nil {
			t.Fatal(err)
		}
		entries[file.Name] = data
	}
	return entries
}

func rewriteBundleForTest(t *testing.T, source string, mutate func(map[string][]byte)) string {
	t.Helper()
	entries := readBundleTestEntries(t, source)
	mutate(entries)
	var checksums bundleChecksums
	if err := json.Unmarshal(entries["checksums.json"], &checksums); err != nil {
		t.Fatal(err)
	}
	checksums.Files = make(map[string]string, len(entries)-1)
	for name, data := range entries {
		if name == "checksums.json" {
			continue
		}
		digest := sha256.Sum256(data)
		checksums.Files[name] = hex.EncodeToString(digest[:])
	}
	entries["checksums.json"] = marshalBundleTestJSON(t, checksums)

	destination := filepath.Join(t.TempDir(), "rewritten.golanproj")
	output, err := os.Create(destination)
	if err != nil {
		t.Fatal(err)
	}
	archive := zip.NewWriter(output)
	names := make([]string, 0, len(entries))
	for name := range entries {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		header := &zip.FileHeader{Name: name, Method: zip.Deflate}
		header.SetMode(0o600)
		header.Modified = time.Unix(0, 0).UTC()
		writer, err := archive.CreateHeader(header)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := writer.Write(entries[name]); err != nil {
			t.Fatal(err)
		}
	}
	if err := archive.Close(); err != nil {
		t.Fatal(err)
	}
	if err := output.Close(); err != nil {
		t.Fatal(err)
	}
	return destination
}

func marshalBundleTestJSON(t *testing.T, value any) []byte {
	t.Helper()
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	return append(data, '\n')
}
