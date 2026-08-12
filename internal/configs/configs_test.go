package configs

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"golan/internal/profile"
)

func TestSaveListLoad(t *testing.T) {
	t.Setenv(envConfigDir, t.TempDir())

	path, err := Save("lab", Snapshot{
		ActiveAdapter: "en11",
		Profile: profile.Profile{
			Adapters: []profile.AdapterConfig{{AdapterRole: profile.AdapterRoleHost, Name: "en11", IP: "auto"}},
		},
		Settings: &Settings{
			EAPOLLogoffDrop:      false,
			EAPOLDowngradeMACsec: true,
		},
	})
	if err != nil {
		t.Fatalf("Save: %v", err)
	}
	if filepath.Base(path) != "lab.json" {
		t.Fatalf("path = %q", path)
	}
	if info, err := os.Stat(path); err != nil {
		t.Fatalf("Stat: %v", err)
	} else if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("config mode = %o", got)
	}

	names, err := List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(names) != 1 || names[0] != "lab.json" {
		t.Fatalf("names = %v", names)
	}

	snapshot, _, err := Load("lab")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if snapshot.ActiveAdapter != "en11" {
		t.Fatalf("ActiveAdapter = %q", snapshot.ActiveAdapter)
	}
	if len(snapshot.Profile.Adapters) != 1 {
		t.Fatalf("Adapters = %+v", snapshot.Profile.Adapters)
	}
	if snapshot.Settings == nil || snapshot.Settings.CanvasVisible || len(snapshot.Settings.LegacyCanvasArtifacts) != 0 || snapshot.Settings.EAPOLLogoffDrop || !snapshot.Settings.EAPOLDowngradeMACsec || !snapshot.Settings.SecretsRedacted() {
		t.Fatalf("Settings = %+v", snapshot.Settings)
	}
}

func TestNormalizeNameRejectsPath(t *testing.T) {
	if _, err := normalizeName("../bad.json"); err == nil {
		t.Fatal("expected path rejection")
	}
}

func TestRuntimeSettingsRoundTripDefaultsAndValidation(t *testing.T) {
	t.Setenv(envConfigDir, t.TempDir())
	runtime := DefaultRuntimeSettings()
	runtime.EdgeMode = "route"
	runtime.EdgeUpstream = "en0"
	runtime.EdgePortForwards = []PortForward{{Protocol: "tcp", ListenPort: 8080, TargetPort: 80}}
	runtime.ControlledQueueDepth = 512
	runtime.ControlledOverload = "fail-closed"
	settings := DefaultSettings()
	revealSecrets := false
	settings.RedactSecrets = &revealSecrets
	settings.Runtime = &runtime
	if _, err := Save("runtime", Snapshot{Settings: &settings}); err != nil {
		t.Fatal(err)
	}
	loaded, _, err := Load("runtime")
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Settings == nil || !reflect.DeepEqual(loaded.Settings.Runtime, &runtime) || loaded.Settings.SecretsRedacted() {
		t.Fatalf("runtime round trip=%#v want=%#v", loaded.Settings, runtime)
	}

	legacy, err := Decode([]byte(`{"version":2,"profile":{},"settings":{"canvas_visible":true,"eapol_logoff_drop":true,"eapol_downgrade_macsec":true}}`))
	if err != nil || legacy.Settings == nil || !reflect.DeepEqual(legacy.Settings.Runtime, pointerRuntime(DefaultRuntimeSettings())) || !legacy.Settings.SecretsRedacted() {
		t.Fatalf("legacy runtime defaults snapshot=%#v err=%v", legacy, err)
	}

	legacy, err = Decode([]byte(`{"version":2,"profile":{},"settings":{"runtime":{"edge_mode":"intercept","edge_upstream":"auto","controlled_queue_depth":1024,"controlled_overload":"fail-open"}}}`))
	if err != nil || legacy.Settings.Runtime.EdgeMode != "route" {
		t.Fatalf("legacy intercept migration snapshot=%#v err=%v", legacy, err)
	}
	invalid := runtime
	invalid.EdgeMode = "invalid"
	settings.Runtime = &invalid
	if _, err := Save("invalid", Snapshot{Settings: &settings}); err == nil {
		t.Fatal("Save accepted invalid edge mode")
	}
	if _, err := Decode([]byte(`{"version":2,"profile":{},"settings":{"runtime":{"edge_mode":"route","edge_upstream":"auto","edge_proxy_hold_timeout":"5s","controlled_queue_depth":1024,"controlled_overload":"fail-open"}}}`)); err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("retired proxy setting error=%v", err)
	}

	vpn := runtime
	vpn.EdgeEgress = "vpn"
	vpn.EdgeUpstream = "utun4"
	vpn.EdgeVPNDestinations = []string{"10.20.0.0/16"}
	vpn.EdgeDNS = []string{"10.20.0.53"}
	settings.Runtime = &vpn
	if _, err := Save("vpn-runtime", Snapshot{Settings: &settings}); err != nil {
		t.Fatal(err)
	}
	loaded, _, err = Load("vpn-runtime")
	if err != nil || loaded.Settings == nil || !reflect.DeepEqual(loaded.Settings.Runtime, &vpn) {
		t.Fatalf("VPN runtime round trip=%#v err=%v", loaded.Settings, err)
	}
	vpn.EdgeDNS = []string{"192.0.2.53"}
	settings.Runtime = &vpn
	if _, err := Save("vpn-bad-dns", Snapshot{Settings: &settings}); err == nil || !strings.Contains(err.Error(), "outside") {
		t.Fatalf("VPN runtime accepted out-of-scope DNS: %v", err)
	}
	vpn.EdgeDNS = []string{"127.0.0.1"}
	settings.Runtime = &vpn
	if _, err := Save("vpn-loopback-dns", Snapshot{Settings: &settings}); err != nil {
		t.Fatalf("VPN runtime rejected Mac-side loopback DNS relay: %v", err)
	}
	vpn.EdgeDNS = nil
	settings.Runtime = &vpn
	if _, err := Save("vpn-automatic-dns", Snapshot{Settings: &settings}); err != nil {
		t.Fatalf("VPN runtime rejected automatic macOS DNS discovery: %v", err)
	}
}

func pointerRuntime(value RuntimeSettings) *RuntimeSettings {
	return &value
}

func TestLoadRejectsUnknownVersionAndFields(t *testing.T) {
	root := t.TempDir()
	t.Setenv(envConfigDir, root)
	dir := filepath.Join(root, "configs")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}

	tests := map[string]string{
		"future.json":  `{"version":4,"profile":{}}`,
		"unknown.json": `{"version":1,"profile":{},"surprise":true}`,
		"trailing.json": `{"version":1,"profile":{}}
{"version":1,"profile":{}}`,
	}
	for name, content := range tests {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
			t.Fatalf("WriteFile(%s): %v", name, err)
		}
		if _, _, err := Load(name); err == nil {
			t.Errorf("Load(%s) succeeded", name)
		}
	}
}

func TestLoadDropsRetiredV1CanvasSettings(t *testing.T) {
	root := t.TempDir()
	t.Setenv(envConfigDir, root)
	dir := filepath.Join(root, "configs")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	content := `{"version":1,"profile":{},"settings":{"canvas_enabled":true,"canvas_path":"/tmp/legacy.canvas","eapol_logoff_drop":true,"eapol_downgrade_macsec":true}}`
	if err := os.WriteFile(filepath.Join(dir, "legacy.json"), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	snapshot, _, err := Load("legacy")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if snapshot.Version != CurrentVersion || snapshot.Settings == nil || snapshot.Settings.CanvasVisible || len(snapshot.Settings.LegacyCanvasArtifacts) != 0 || snapshot.Settings.CanvasEnabled || snapshot.Settings.CanvasPath != "" {
		t.Fatalf("migrated snapshot = %#v", snapshot)
	}
}

func TestConfigMigrationIsIdempotentAfterJSONRoundTrip(t *testing.T) {
	content := []byte(`{
		"version":1,
		"saved_at":"2026-07-31T00:00:00Z",
		"active_adapter":"en7",
		"profile":{},
		"settings":{
			"canvas_enabled":true,
			"canvas_path":"/tmp/legacy.canvas",
			"legacy_canvas_artifacts":["/tmp/legacy.canvas"],
			"eapol_logoff_drop":true,
			"eapol_downgrade_macsec":true
		}
	}`)
	first, err := Decode(content)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(first)
	if err != nil {
		t.Fatal(err)
	}
	second, err := Decode(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(second, first) {
		t.Fatalf("second migration changed snapshot:\n first=%#v\nsecond=%#v", first, second)
	}
	if first.Settings == nil ||
		len(first.Settings.LegacyCanvasArtifacts) != 0 ||
		first.Settings.CanvasVisible || first.Settings.CanvasEnabled || first.Settings.CanvasPath != "" ||
		!reflect.DeepEqual(first.Settings.Runtime, pointerRuntime(DefaultRuntimeSettings())) {
		t.Fatalf("idempotent migration defaults=%#v", first.Settings)
	}
}

func TestLoadRejectsOversizedConfig(t *testing.T) {
	root := t.TempDir()
	t.Setenv(envConfigDir, root)
	dir := filepath.Join(root, "configs")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	content := strings.Repeat(" ", maxConfigSize+1)
	if err := os.WriteFile(filepath.Join(dir, "large.json"), []byte(content), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	if _, _, err := Load("large"); err == nil {
		t.Fatal("expected oversized config rejection")
	}
}

func TestDecodeLoadFileAndSemanticDiff(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "source.json")
	content := []byte(`{"version":2,"saved_at":"2026-01-01T00:00:00Z","active_adapter":"en0","profile":{"Adapters":[{"role":"host","name":"en0","ip":"192.0.2.1"}]}}`)
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}
	snapshot, raw, digest, err := LoadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != string(content) || len(digest) != 64 || snapshot.ActiveAdapter != "en0" || len(snapshot.Profile.Adapters) != 1 {
		t.Fatalf("loaded file snapshot=%#v raw=%q digest=%q", snapshot, raw, digest)
	}
	decoded, err := Decode(content)
	if err != nil || decoded.Profile.Adapters[0].IP != "192.0.2.1" {
		t.Fatalf("decoded=%#v err=%v", decoded, err)
	}
	link := filepath.Join(directory, "source-link.json")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := LoadFile(link); err == nil || !strings.Contains(err.Error(), "non-symlink") {
		t.Fatalf("symlink load error=%v", err)
	}

	after := snapshot
	after.Version = 1
	after.SavedAt = time.Now().UTC()
	if changes, err := Diff(snapshot, after); err != nil || len(changes) != 0 {
		t.Fatalf("timestamp/version diff=%#v err=%v", changes, err)
	}
	after.Profile.Adapters = append([]profile.AdapterConfig(nil), snapshot.Profile.Adapters...)
	after.Profile.Adapters[0].IP = "192.0.2.2"
	after.ActiveAdapter = "bridge"
	changes, err := Diff(snapshot, after)
	if err != nil || len(changes) != 2 {
		t.Fatalf("semantic diff=%#v err=%v", changes, err)
	}
	if changes[0].Field != "active_adapter" || changes[1].Field != "profile.Adapters[0].ip" {
		t.Fatalf("diff order/fields=%#v", changes)
	}
}
