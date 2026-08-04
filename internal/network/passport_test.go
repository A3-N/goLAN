package network

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestPassportIsPortableChecksummedAndComparable(t *testing.T) {
	now := time.Unix(300, 0).UTC()
	session := comparisonSession("source-session", "192.0.2.1", "02:00:00:00:00:02", []string{"192.0.2.10"}, now)
	session.CapturePaths = []string{"/private/tmp/secret-capture.pcap"}
	session.Devices[0].Hostnames = []string{"client.local"}
	session.Devices[0].Services = []Service{{Type: "_ssh._tcp", Name: "client", Target: "client.local", Port: 22, Protocol: "mDNS", Count: 1}}
	session.Devices[0].Observations = append(session.Devices[0].Observations,
		observationAt("query", "DNS A private.example", "", "DNS", CategoryDNS, SeverityInfo, now))
	passport, err := NewPassport("Lab baseline", session, now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	content, err := EncodePassport(passport)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"secret-capture", "private.example", "capture_paths", "packet_fates", "observations"} {
		if bytes.Contains(content, []byte(forbidden)) {
			t.Fatalf("passport retained %q: %s", forbidden, content)
		}
	}
	decoded, err := DecodePassport(content)
	if err != nil || decoded.Checksum != passport.Checksum {
		t.Fatalf("decoded=%#v err=%v", decoded, err)
	}
	destination := filepath.Join(t.TempDir(), "lab.golanpass")
	if err := WritePassport(destination, passport); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadPassport(destination); err != nil {
		t.Fatal(err)
	}
	if err := WritePassport(destination, passport); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("existing destination err=%v", err)
	}

	current := comparisonSession("current", "192.0.2.254", "02:00:00:00:00:03", []string{"192.0.2.11"}, now.Add(time.Hour))
	report, err := ComparePassport(passport, current)
	if err != nil || report.BaselineID != "passport:Lab baseline" || len(report.Changes) == 0 {
		t.Fatalf("report=%#v err=%v", report, err)
	}

	tampered := append([]byte(nil), content...)
	index := bytes.Index(tampered, []byte("Lab baseline"))
	tampered[index] = 'X'
	if _, err := DecodePassport(tampered); err == nil || !strings.Contains(err.Error(), "checksum") {
		t.Fatalf("tamper err=%v", err)
	}
	if err := os.WriteFile(filepath.Join(t.TempDir(), "tampered.golanpass"), tampered, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestPassportKeepsDuplicateMACRowsScopedToTheirAdapter(t *testing.T) {
	now := time.Unix(400, 0).UTC()
	session := Session{
		Version:   CurrentVersion,
		ID:        "bridge-session",
		Mode:      "controlled-bridge",
		StartedAt: now,
		Devices: []Device{
			{Key: "en0/02:00:00:00:00:01", MAC: "02:00:00:00:00:01", Adapter: "en0", FirstSeen: now, LastSeen: now},
			{Key: "en1/02:00:00:00:00:01", MAC: "02:00:00:00:00:01", Adapter: "en1", FirstSeen: now, LastSeen: now},
		},
	}
	passport, err := NewPassport("bridge", session, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(passport.Devices) != 2 || passport.Devices[0].Scope == passport.Devices[1].Scope {
		t.Fatalf("scoped fingerprints=%#v", passport.Devices)
	}
	report, err := ComparePassport(passport, session)
	if err != nil || len(report.Changes) != 0 {
		t.Fatalf("report=%#v err=%v", report, err)
	}
}
