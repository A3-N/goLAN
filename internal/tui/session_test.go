package tui

import (
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/mcrn/goLAN/internal/bridge"
	"github.com/mcrn/goLAN/internal/stealth"
)

func TestSessionStorePersistsNotesAndObservedGraphData(t *testing.T) {
	path := filepath.Join(t.TempDir(), "session.json")
	store := NewSessionStore(path)
	now := time.Now()

	store.SetNote("ip:192.168.1.10", "printer closet")
	store.Merge(bridge.BridgeStatus{CaptureFiles: []string{"/tmp/golan-pcaps/test.pcap"}}, stealth.NetworkMapSnapshot{
		Hosts: []stealth.HostSummary{
			{
				MAC:      net.HardwareAddr{0, 1, 2, 3, 4, 5},
				IPs:      []net.IP{net.ParseIP("192.168.1.10")},
				PktCount: 12,
				LastSeen: now,
			},
		},
		Conversations: []stealth.ConversationSummary{
			{
				SrcIP:    net.ParseIP("192.168.1.10"),
				DstIP:    net.ParseIP("192.168.1.1"),
				Protocol: "SNMP",
				DstPort:  161,
				Packets:  3,
				LastSeen: now,
			},
		},
		DNSLog: []stealth.DNSQuery{
			{Name: "printer.lab", Response: []string{"192.168.1.10"}, Timestamp: now},
		},
	})
	if err := store.Save(); err != nil {
		t.Fatalf("save session: %v", err)
	}

	loaded := NewSessionStore(path)
	if got := loaded.Note("ip:192.168.1.10"); got != "printer closet" {
		t.Fatalf("note = %q", got)
	}
	if len(loaded.Data.CaptureFiles) != 1 {
		t.Fatalf("capture files = %v", loaded.Data.CaptureFiles)
	}
	if len(loaded.Data.Edges) == 0 {
		t.Fatalf("expected merged conversation edge")
	}
}

func TestSessionStoreCreatesConfigSessionAndResolvesID(t *testing.T) {
	root := t.TempDir()
	t.Setenv("GOLAN_CONFIG_DIR", root)

	store := NewSessionStore("")
	if store.SessionID() == "" {
		t.Fatalf("expected generated session ID")
	}
	expectedPath := filepath.Join(root, "sessions", store.SessionID(), "session.json")
	if store.SessionPath() != expectedPath {
		t.Fatalf("session path = %q, want %q", store.SessionPath(), expectedPath)
	}
	if _, err := os.Stat(store.SessionPath()); err != nil {
		t.Fatalf("session file was not created: %v", err)
	}
	if _, err := os.Stat(store.PcapDir()); err != nil {
		t.Fatalf("pcap directory was not created: %v", err)
	}

	loaded := NewSessionStore(store.SessionID())
	if loaded.SessionPath() != store.SessionPath() {
		t.Fatalf("resolved path = %q, want %q", loaded.SessionPath(), store.SessionPath())
	}
}
