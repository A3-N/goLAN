package project

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	networkobs "golan/internal/network"
)

func TestNetworkSessionsAreIncludedOnlyInFullBundles(t *testing.T) {
	project, err := New(t.TempDir(), "NetworkBundle")
	if err != nil {
		t.Fatal(err)
	}
	tracker := networkobs.NewTracker("bundle-session", "listen", time.Unix(1, 0))
	tracker.ObserveDiscovery(networkobs.Discovery{
		Adapter: "en0", Role: "host", DeviceMAC: "02:00:00:00:00:01",
		Field: "ip", Value: "192.0.2.10", Packet: "DHCP",
	})
	if _, err := project.SaveNetworkSession(tracker.Snapshot()); err != nil {
		t.Fatal(err)
	}
	if err := project.Save(); err != nil {
		t.Fatal(err)
	}

	full := filepath.Join(t.TempDir(), "full.golanproj")
	metadata := filepath.Join(t.TempDir(), "metadata.golanproj")
	if err := project.ExportBundle(context.Background(), full, BundleFull); err != nil {
		t.Fatal(err)
	}
	if err := project.ExportBundle(context.Background(), metadata, BundleMetadata); err != nil {
		t.Fatal(err)
	}
	fullProject, err := ImportBundle(context.Background(), full, t.TempDir(), "FullImport")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := fullProject.ReadNetworkSession("bundle-session"); err != nil {
		t.Fatalf("full bundle session: %v", err)
	}
	metadataProject, err := ImportBundle(context.Background(), metadata, t.TempDir(), "MetadataImport")
	if err != nil {
		t.Fatal(err)
	}
	if sessions := metadataProject.Manifest().NetworkSessions; len(sessions) != 0 {
		t.Fatalf("metadata bundle sessions=%#v", sessions)
	}
}

func TestNetworkSessionIsImmutableVerifiedAndRestored(t *testing.T) {
	project, err := New(t.TempDir(), "NetworkSession")
	if err != nil {
		t.Fatal(err)
	}
	tracker := networkobs.NewTracker("observation-1", "listen", time.Unix(10, 0))
	tracker.ObserveDiscovery(networkobs.Discovery{
		Adapter: "en0", Role: "host", DeviceMAC: "02:00:00:00:00:01",
		Field: "ip", Value: "192.0.2.10", Packet: "DHCP",
	})
	tracker.AddCapture("/var/tmp/golan/session/original.pcap")
	tracker.Finish(time.Unix(20, 0))
	session := tracker.Snapshot()

	reference, err := project.SaveNetworkSession(session)
	if err != nil {
		t.Fatal(err)
	}
	if reference.Devices != 1 || reference.Observations != 1 || reference.SHA256 == "" || reference.Size == 0 {
		t.Fatalf("reference=%#v", reference)
	}
	if duplicate, err := project.SaveNetworkSession(session); err != nil || duplicate != reference {
		t.Fatalf("idempotent save reference=%#v err=%v", duplicate, err)
	}
	if err := project.Save(); err != nil {
		t.Fatal(err)
	}

	opened, err := Open(project.Path())
	if err != nil {
		t.Fatal(err)
	}
	restored, restoredReference, err := opened.ReadNetworkSession(session.ID)
	if err != nil {
		t.Fatal(err)
	}
	if restoredReference != reference || len(restored.Devices) != 1 || restored.Devices[0].IPs[0] != "192.0.2.10" ||
		len(restored.CapturePaths) != 1 || restored.CapturePaths[0] != "/var/tmp/golan/session/original.pcap" {
		t.Fatalf("restored=%#v reference=%#v", restored, restoredReference)
	}

	path := filepath.Join(opened.Path(), filepath.FromSlash(reference.Path))
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	content[len(content)/2] ^= 1
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := opened.ReadNetworkSession(session.ID); err == nil {
		t.Fatal("tampered network session passed fingerprint verification")
	}
}

func TestVersionOneProjectMigratesWithEmptyNetworkInventory(t *testing.T) {
	project, err := New(t.TempDir(), "Migration")
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
	content = []byte(string(content))
	for index := 0; index+12 < len(content); index++ {
		if string(content[index:index+12]) == `"version": 2` {
			content[index+11] = '1'
			break
		}
	}
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}
	opened, err := Open(project.Path())
	if err != nil {
		t.Fatal(err)
	}
	manifest := opened.Manifest()
	if manifest.Version != CurrentVersion || len(manifest.NetworkSessions) != 0 {
		t.Fatalf("manifest=%#v", manifest)
	}
}
