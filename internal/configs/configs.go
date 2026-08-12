package configs

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"time"

	"golan/internal/paths"
	"golan/internal/profile"
)

const envConfigDir = paths.EnvConfigDir

const (
	// CurrentVersion is the persisted config schema written by this build.
	CurrentVersion = 3
	maxConfigSize  = 1 << 20
)

// Snapshot is the persisted setup state.
type Snapshot struct {
	Version       int             `json:"version"`
	SavedAt       time.Time       `json:"saved_at"`
	ActiveAdapter string          `json:"active_adapter"`
	Profile       profile.Profile `json:"profile"`
	Settings      *Settings       `json:"settings,omitempty"`
}

// Settings is persisted TUI/runtime feature state.
type Settings struct {
	EAPOLLogoffDrop      bool             `json:"eapol_logoff_drop"`
	EAPOLDowngradeMACsec bool             `json:"eapol_downgrade_macsec"`
	RedactSecrets        *bool            `json:"redact_secrets"`
	Runtime              *RuntimeSettings `json:"runtime,omitempty"`

	// Canvas fields are accepted only so old configs can be loaded and rewritten
	// without reviving the retired Canvas workspace or PCAP-derived artifacts.
	CanvasVisible         bool     `json:"canvas_visible,omitempty"`
	LegacyCanvasArtifacts []string `json:"legacy_canvas_artifacts,omitempty"`
	CanvasEnabled         bool     `json:"canvas_enabled,omitempty"`
	CanvasPath            string   `json:"canvas_path,omitempty"`
}

// RuntimeSettings is the portable, staged live-session configuration saved
// with a setup snapshot. Strings keep durations and enums human-readable while
// Decode validates the complete block before it reaches the Workbench model.
type RuntimeSettings struct {
	EdgeMode            string        `json:"edge_mode"`
	EdgeUpstream        string        `json:"edge_upstream"`
	EdgeEgress          string        `json:"edge_egress"`
	EdgeVPNDestinations []string      `json:"edge_vpn_destinations,omitempty"`
	EdgeDNS             []string      `json:"edge_dns,omitempty"`
	EdgePortForwards    []PortForward `json:"edge_port_forwards,omitempty"`

	ControlledQueueDepth int    `json:"controlled_queue_depth"`
	ControlledOverload   string `json:"controlled_overload"`
}

type PortForward struct {
	Protocol   string `json:"protocol"`
	ListenPort uint16 `json:"listen_port"`
	TargetPort uint16 `json:"target_port"`
}

// Change is one deterministic semantic difference between two snapshots.
// Version and save timestamps are excluded from comparisons.
type Change struct {
	Field  string
	Before string
	After  string
}

// DefaultSettings returns safe runtime feature defaults for configs that omit
// settings.
func DefaultSettings() Settings {
	runtime := DefaultRuntimeSettings()
	redactSecrets := true
	return Settings{
		EAPOLLogoffDrop:      true,
		EAPOLDowngradeMACsec: true,
		RedactSecrets:        &redactSecrets,
		Runtime:              &runtime,
	}
}

// SecretsRedacted reports the privacy setting with a safe default for legacy
// snapshots that predate the field.
func (s Settings) SecretsRedacted() bool {
	return s.RedactSecrets == nil || *s.RedactSecrets
}

func DefaultRuntimeSettings() RuntimeSettings {
	return RuntimeSettings{
		EdgeMode:             "observe",
		EdgeUpstream:         "auto",
		EdgeEgress:           "system",
		ControlledQueueDepth: 1024,
		ControlledOverload:   "fail-open",
	}
}

// ConfigDir returns the directory used for golan JSON configs.
func ConfigDir() (string, error) {
	return paths.ConfigDir()
}

// Save writes a setup snapshot as JSON and returns the full path.
func Save(name string, snapshot Snapshot) (string, error) {
	dir, err := ConfigDir()
	if err != nil {
		return "", err
	}
	fileName, err := normalizeName(name)
	if err != nil {
		return "", err
	}
	snapshot.Version = CurrentVersion
	snapshot.SavedAt = time.Now().UTC()
	if snapshot.Settings != nil {
		settings := migrateSettings(*snapshot.Settings)
		if err := validateSettings(settings); err != nil {
			return "", fmt.Errorf("validate settings: %w", err)
		}
		snapshot.Settings = &settings
	}

	content, err := json.MarshalIndent(snapshot, "", "  ")
	if err != nil {
		return "", fmt.Errorf("encode config: %w", err)
	}

	path := filepath.Join(dir, fileName)
	if err := paths.WriteConfigArtifact(path, append(content, '\n')); err != nil {
		return "", fmt.Errorf("write config: %w", err)
	}
	return path, nil
}

// Load reads a JSON setup snapshot and returns it with the full path.
func Load(name string) (Snapshot, string, error) {
	dir, err := ConfigDir()
	if err != nil {
		return Snapshot{}, "", err
	}
	fileName, err := normalizeName(name)
	if err != nil {
		return Snapshot{}, "", err
	}
	path := filepath.Join(dir, fileName)
	content, err := paths.ReadConfigArtifact(path, maxConfigSize)
	if err != nil {
		return Snapshot{}, "", fmt.Errorf("read config: %w", err)
	}
	snapshot, err := Decode(content)
	if err != nil {
		return Snapshot{}, "", err
	}
	return snapshot, path, nil
}

// LoadFile strictly reads a stable, regular non-symlink config outside the
// managed config directory. It returns the decoded snapshot, exact source
// bytes, and SHA-256 fingerprint so a project can snapshot the same revision.
func LoadFile(path string) (Snapshot, []byte, string, error) {
	path, err := filepath.Abs(strings.TrimSpace(path))
	if err != nil {
		return Snapshot{}, nil, "", fmt.Errorf("resolve config: %w", err)
	}
	before, err := os.Lstat(path)
	if err != nil {
		return Snapshot{}, nil, "", fmt.Errorf("inspect config: %w", err)
	}
	if before.Mode()&fs.ModeSymlink != 0 || !before.Mode().IsRegular() || before.Size() > maxConfigSize {
		return Snapshot{}, nil, "", fmt.Errorf("config source must be a regular non-symlink file no larger than %d bytes", maxConfigSize)
	}
	file, err := os.Open(path)
	if err != nil {
		return Snapshot{}, nil, "", fmt.Errorf("open config: %w", err)
	}
	opened, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return Snapshot{}, nil, "", fmt.Errorf("inspect open config: %w", err)
	}
	if !os.SameFile(before, opened) {
		_ = file.Close()
		return Snapshot{}, nil, "", fmt.Errorf("config source changed while opening")
	}
	content, readErr := io.ReadAll(io.LimitReader(file, maxConfigSize+1))
	closeErr := file.Close()
	if readErr != nil || closeErr != nil {
		return Snapshot{}, nil, "", errors.Join(readErr, closeErr)
	}
	if len(content) > maxConfigSize {
		return Snapshot{}, nil, "", fmt.Errorf("config source exceeds %d bytes", maxConfigSize)
	}
	after, err := os.Lstat(path)
	if err != nil || after.Mode()&fs.ModeSymlink != 0 || !os.SameFile(before, after) || before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) {
		return Snapshot{}, nil, "", fmt.Errorf("config source changed while reading")
	}
	snapshot, err := Decode(content)
	if err != nil {
		return Snapshot{}, nil, "", err
	}
	digest := sha256.Sum256(content)
	return snapshot, content, hex.EncodeToString(digest[:]), nil
}

// Decode strictly decodes one bounded config snapshot and applies supported
// schema migration without reading or writing the filesystem.
func Decode(content []byte) (Snapshot, error) {
	if len(content) > maxConfigSize {
		return Snapshot{}, fmt.Errorf("config exceeds %d bytes", maxConfigSize)
	}
	var snapshot Snapshot
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&snapshot); err != nil {
		return Snapshot{}, fmt.Errorf("decode config: %w", err)
	}
	if err := requireJSONEOF(decoder); err != nil {
		return Snapshot{}, fmt.Errorf("decode config: %w", err)
	}
	if snapshot.Version != 1 && snapshot.Version != 2 && snapshot.Version != CurrentVersion {
		return Snapshot{}, fmt.Errorf("unsupported config version %d", snapshot.Version)
	}
	if snapshot.Settings != nil {
		settings := migrateSettings(*snapshot.Settings)
		if err := validateSettings(settings); err != nil {
			return Snapshot{}, fmt.Errorf("validate settings: %w", err)
		}
		snapshot.Settings = &settings
	}
	snapshot.Version = CurrentVersion
	return snapshot, nil
}

// Diff returns a stable field-by-field semantic comparison. Schema version and
// SavedAt are ignored; omitted settings compare as their safe defaults.
func Diff(before, after Snapshot) ([]Change, error) {
	left, err := comparableSnapshot(before)
	if err != nil {
		return nil, err
	}
	right, err := comparableSnapshot(after)
	if err != nil {
		return nil, err
	}
	var changes []Change
	diffJSONValue("", left, right, &changes)
	return changes, nil
}

func comparableSnapshot(snapshot Snapshot) (any, error) {
	snapshot.Version = 0
	snapshot.SavedAt = time.Time{}
	settings := DefaultSettings()
	if snapshot.Settings != nil {
		settings = migrateSettings(*snapshot.Settings)
	}
	if err := validateSettings(settings); err != nil {
		return nil, fmt.Errorf("validate settings: %w", err)
	}
	snapshot.Settings = &settings
	content, err := json.Marshal(snapshot)
	if err != nil {
		return nil, fmt.Errorf("encode config comparison: %w", err)
	}
	var value any
	if err := json.Unmarshal(content, &value); err != nil {
		return nil, fmt.Errorf("decode config comparison: %w", err)
	}
	if object, ok := value.(map[string]any); ok {
		delete(object, "version")
		delete(object, "saved_at")
	}
	return value, nil
}

func diffJSONValue(field string, before, after any, changes *[]Change) {
	beforeObject, beforeIsObject := before.(map[string]any)
	afterObject, afterIsObject := after.(map[string]any)
	if beforeIsObject && afterIsObject {
		keys := make(map[string]bool, len(beforeObject)+len(afterObject))
		for key := range beforeObject {
			keys[key] = true
		}
		for key := range afterObject {
			keys[key] = true
		}
		ordered := make([]string, 0, len(keys))
		for key := range keys {
			ordered = append(ordered, key)
		}
		sort.Strings(ordered)
		for _, key := range ordered {
			diffJSONValue(joinDiffField(field, key), beforeObject[key], afterObject[key], changes)
		}
		return
	}
	beforeArray, beforeIsArray := before.([]any)
	afterArray, afterIsArray := after.([]any)
	if beforeIsArray && afterIsArray {
		for index := 0; index < max(len(beforeArray), len(afterArray)); index++ {
			var beforeValue, afterValue any
			if index < len(beforeArray) {
				beforeValue = beforeArray[index]
			}
			if index < len(afterArray) {
				afterValue = afterArray[index]
			}
			diffJSONValue(fmt.Sprintf("%s[%d]", field, index), beforeValue, afterValue, changes)
		}
		return
	}
	if reflect.DeepEqual(before, after) {
		return
	}
	*changes = append(*changes, Change{Field: field, Before: formatDiffValue(before), After: formatDiffValue(after)})
}

func joinDiffField(parent, child string) string {
	if parent == "" {
		return child
	}
	return parent + "." + child
}

func formatDiffValue(value any) string {
	if value == nil {
		return "<absent>"
	}
	content, err := json.Marshal(value)
	if err != nil {
		return "<unavailable>"
	}
	return string(content)
}

func migrateSettings(settings Settings) Settings {
	if settings.RedactSecrets == nil {
		redactSecrets := true
		settings.RedactSecrets = &redactSecrets
	}
	settings.CanvasVisible = false
	settings.LegacyCanvasArtifacts = nil
	settings.CanvasEnabled = false
	settings.CanvasPath = ""
	if settings.Runtime == nil {
		runtime := DefaultRuntimeSettings()
		settings.Runtime = &runtime
	} else {
		runtime := *settings.Runtime
		if runtime.EdgeMode == "intercept" {
			runtime.EdgeMode = "route"
		}
		if strings.TrimSpace(runtime.EdgeEgress) == "" {
			runtime.EdgeEgress = "system"
		}
		settings.Runtime = &runtime
	}
	return settings
}

func validateSettings(settings Settings) error {
	if settings.RedactSecrets == nil {
		return fmt.Errorf("secret redaction setting is required after migration")
	}
	if settings.Runtime == nil {
		return fmt.Errorf("runtime settings are required after migration")
	}
	runtime := settings.Runtime
	if runtime.EdgeMode != "observe" && runtime.EdgeMode != "route" {
		return fmt.Errorf("edge mode must be observe or route")
	}
	if !validRuntimeAdapter(runtime.EdgeUpstream) {
		return fmt.Errorf("edge upstream must be auto or a valid adapter name")
	}
	if runtime.EdgeEgress != "system" && runtime.EdgeEgress != "vpn" {
		return fmt.Errorf("edge egress must be system or vpn")
	}
	if runtime.EdgeEgress == "vpn" && runtime.EdgeMode != "route" {
		return fmt.Errorf("vpn egress requires edge route mode")
	}
	if runtime.EdgeEgress == "vpn" && strings.EqualFold(strings.TrimSpace(runtime.EdgeUpstream), "auto") {
		return fmt.Errorf("vpn egress requires an explicit tunnel interface")
	}
	destinations := make(map[netip.Prefix]bool, len(runtime.EdgeVPNDestinations))
	allDestinations := false
	for _, raw := range runtime.EdgeVPNDestinations {
		destination, err := netip.ParsePrefix(strings.TrimSpace(raw))
		if err != nil || !destination.Addr().Is4() {
			return fmt.Errorf("invalid edge VPN destination %q", raw)
		}
		destination = destination.Masked()
		if destinations[destination] {
			return fmt.Errorf("duplicate edge VPN destination %s", destination)
		}
		destinations[destination] = true
		allDestinations = allDestinations || destination.Bits() == 0
	}
	if runtime.EdgeEgress == "system" && len(destinations) != 0 {
		return fmt.Errorf("edge VPN destinations require vpn egress")
	}
	if runtime.EdgeEgress == "vpn" && len(destinations) == 0 {
		return fmt.Errorf("vpn egress requires at least one destination or all")
	}
	if allDestinations && len(destinations) != 1 {
		return fmt.Errorf("edge VPN destination all cannot be combined with other prefixes")
	}
	dnsAddresses := make(map[netip.Addr]bool, len(runtime.EdgeDNS))
	for _, raw := range runtime.EdgeDNS {
		address, err := netip.ParseAddr(strings.TrimSpace(raw))
		if err != nil || !address.Is4() || address.IsUnspecified() || address.IsMulticast() {
			return fmt.Errorf("invalid edge DNS address %q", raw)
		}
		if dnsAddresses[address] {
			return fmt.Errorf("duplicate edge DNS address %s", address)
		}
		dnsAddresses[address] = true
		if runtime.EdgeEgress == "vpn" && !address.IsLoopback() && !prefixSetContains(destinations, address) {
			return fmt.Errorf("edge VPN DNS address %s is outside the permitted destinations", address)
		}
	}
	if runtime.ControlledQueueDepth < 1 || runtime.ControlledQueueDepth > 4096 {
		return fmt.Errorf("controlled queue depth must be between 1 and 4096")
	}
	if runtime.ControlledOverload != "fail-open" && runtime.ControlledOverload != "fail-closed" {
		return fmt.Errorf("controlled overload must be fail-open or fail-closed")
	}
	if len(runtime.EdgePortForwards) > 0 && runtime.EdgeMode == "observe" {
		return fmt.Errorf("edge port forwards require route mode")
	}
	seenForwards := make(map[string]bool, len(runtime.EdgePortForwards))
	for _, forward := range runtime.EdgePortForwards {
		protocol := strings.ToLower(forward.Protocol)
		key := fmt.Sprintf("%s/%d", protocol, forward.ListenPort)
		if (protocol != "tcp" && protocol != "udp") || forward.ListenPort == 0 || forward.TargetPort == 0 || seenForwards[key] {
			return fmt.Errorf("invalid or duplicate edge port forward %s", key)
		}
		seenForwards[key] = true
	}
	return nil
}

func prefixSetContains(prefixes map[netip.Prefix]bool, address netip.Addr) bool {
	for prefix := range prefixes {
		if prefix.Contains(address) {
			return true
		}
	}
	return false
}

func validRuntimeAdapter(value string) bool {
	value = strings.TrimSpace(value)
	if strings.EqualFold(value, "auto") {
		return true
	}
	if value == "" || len(value) > 64 {
		return false
	}
	for _, character := range value {
		if character <= ' ' || character == '/' || character == '\\' {
			return false
		}
	}
	return true
}

// List returns saved JSON config filenames.
func List() ([]string, error) {
	dir, err := ConfigDir()
	if err != nil {
		return nil, err
	}
	entries, err := paths.ListConfigArtifacts(dir)
	if err != nil {
		return nil, fmt.Errorf("list configs: %w", err)
	}

	names := make([]string, 0, len(entries))
	for _, name := range entries {
		if strings.EqualFold(filepath.Ext(name), ".json") {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	return names, nil
}

func normalizeName(name string) (string, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return "", fmt.Errorf("filename is required")
	}
	if filepath.Base(name) != name {
		return "", fmt.Errorf("filename must not include a path")
	}
	if name == "." || strings.ContainsAny(name, "\x00\r\n") {
		return "", fmt.Errorf("filename contains invalid characters")
	}
	if filepath.Ext(name) == "" {
		name += ".json"
	}
	if !strings.EqualFold(filepath.Ext(name), ".json") {
		return "", fmt.Errorf("filename must use .json")
	}
	return name, nil
}

func requireJSONEOF(decoder *json.Decoder) error {
	var extra json.RawMessage
	if err := decoder.Decode(&extra); errors.Is(err, io.EOF) {
		return nil
	} else if err != nil {
		return err
	}
	return fmt.Errorf("multiple JSON values")
}
