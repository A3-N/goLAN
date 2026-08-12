package network

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const (
	// PassportVersion is the portable, payload-free network fingerprint schema.
	PassportVersion = 1
	maxPassportSize = 4 << 20
)

// Passport is a portable network fingerprint. It deliberately excludes
// captures, packet outcomes, raw observations, local paths, and secrets.
type Passport struct {
	Version        int                         `json:"version"`
	Name           string                      `json:"name"`
	CreatedAt      time.Time                   `json:"created_at"`
	SourceSession  string                      `json:"source_session"`
	Devices        []DeviceFingerprint         `json:"devices,omitempty"`
	Infrastructure []InfrastructureFingerprint `json:"infrastructure,omitempty"`
	Checksum       string                      `json:"checksum"`
}

// NewPassport creates and checksums one portable fingerprint.
func NewPassport(name string, session Session, now time.Time) (Passport, error) {
	if err := ValidateSession(session); err != nil {
		return Passport{}, err
	}
	name = cleanText(name)
	if name == "" {
		name = session.ID
	}
	passport := Passport{
		Version: PassportVersion, Name: name, CreatedAt: now.UTC(), SourceSession: session.ID,
	}
	for _, device := range session.Devices {
		passport.Devices = append(passport.Devices, FingerprintDevice(device))
	}
	sort.Slice(passport.Devices, func(i, j int) bool {
		return deviceFingerprintKey(passport.Devices[i]) < deviceFingerprintKey(passport.Devices[j])
	})
	passport.Infrastructure = FingerprintInfrastructure(AnalyzeInfrastructure(session).Claims)
	digest, err := passportDigest(passport)
	if err != nil {
		return Passport{}, err
	}
	passport.Checksum = digest
	if err := ValidatePassport(passport); err != nil {
		return Passport{}, err
	}
	return passport, nil
}

// EncodePassport returns a stable, readable portable document.
func EncodePassport(passport Passport) ([]byte, error) {
	if err := ValidatePassport(passport); err != nil {
		return nil, err
	}
	content, err := json.MarshalIndent(passport, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("encode network passport: %w", err)
	}
	content = append(content, '\n')
	if len(content) > maxPassportSize {
		return nil, fmt.Errorf("network passport exceeds %d bytes", maxPassportSize)
	}
	return content, nil
}

// DecodePassport strictly decodes, bounds, and verifies a portable document.
func DecodePassport(content []byte) (Passport, error) {
	if len(content) == 0 || len(content) > maxPassportSize {
		return Passport{}, fmt.Errorf("network passport size is invalid")
	}
	var passport Passport
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&passport); err != nil {
		return Passport{}, fmt.Errorf("decode network passport: %w", err)
	}
	var extra json.RawMessage
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			err = fmt.Errorf("multiple JSON values")
		}
		return Passport{}, fmt.Errorf("decode network passport: %w", err)
	}
	if err := ValidatePassport(passport); err != nil {
		return Passport{}, err
	}
	return passport, nil
}

// ValidatePassport checks content boundaries and checksum integrity.
func ValidatePassport(passport Passport) error {
	if passport.Version != PassportVersion || cleanText(passport.Name) == "" || cleanText(passport.SourceSession) == "" || passport.CreatedAt.IsZero() {
		return fmt.Errorf("network passport identity is invalid")
	}
	if cleanText(passport.Name) != passport.Name || cleanText(passport.SourceSession) != passport.SourceSession || len(passport.Devices) > MaxDevices {
		return fmt.Errorf("network passport identity contains unsafe text")
	}
	previousDevice := ""
	for index, device := range passport.Devices {
		key := deviceFingerprintKey(device)
		if !validUnicastMAC(device.MAC) || cleanText(device.Scope) == "" || cleanText(device.Scope) != device.Scope ||
			index > 0 && previousDevice >= key || len(device.Services) > MaxServicesPerDevice {
			return fmt.Errorf("network passport device %q is invalid", device.MAC)
		}
		previousDevice = key
		if !validSortedPassportText(device.Hostnames) {
			return fmt.Errorf("network passport hostname list is invalid")
		}
		if !validSortedPassportText(device.IPs) {
			return fmt.Errorf("network passport IP list is invalid")
		}
		for _, ip := range device.IPs {
			if !validIP(ip) {
				return fmt.Errorf("network passport IP %q is invalid", ip)
			}
		}
		for index, vlan := range device.VLANs {
			if vlan > 4094 || index > 0 && device.VLANs[index-1] >= vlan {
				return fmt.Errorf("network passport VLAN %d is invalid", vlan)
			}
		}
		for _, value := range []string{device.Access, string(device.Confidence)} {
			if cleanText(value) != value {
				return fmt.Errorf("network passport device contains unsafe text")
			}
		}
		if !validSortedPassportText(device.Services) {
			return fmt.Errorf("network passport service list is invalid")
		}
		switch device.Confidence {
		case ConfidenceLow, ConfidenceMedium, ConfidenceHigh:
		default:
			return fmt.Errorf("network passport confidence %q is invalid", device.Confidence)
		}
	}
	previousClaim := ""
	for index, claim := range passport.Infrastructure {
		key := infrastructureFingerprintKey(claim)
		if !validInfrastructureRole(claim.Role) || cleanText(claim.Value) == "" || cleanText(claim.Value) != claim.Value || cleanText(claim.MAC) != claim.MAC {
			return fmt.Errorf("network passport infrastructure claim is invalid")
		}
		if claim.MAC != "" && !validUnicastMAC(claim.MAC) || index > 0 && previousClaim >= key {
			return fmt.Errorf("network passport infrastructure claim order or MAC is invalid")
		}
		previousClaim = key
	}
	if len(passport.Checksum) != sha256.Size*2 {
		return fmt.Errorf("network passport checksum is invalid")
	}
	if _, err := hex.DecodeString(passport.Checksum); err != nil {
		return fmt.Errorf("network passport checksum is invalid")
	}
	want, err := passportDigest(passport)
	if err != nil {
		return err
	}
	if !strings.EqualFold(want, passport.Checksum) {
		return fmt.Errorf("network passport checksum differs from content")
	}
	return nil
}

// WritePassport writes a new passport atomically and refuses to replace an
// existing destination.
func WritePassport(path string, passport Passport) error {
	content, err := EncodePassport(passport)
	if err != nil {
		return err
	}
	path = strings.TrimSpace(path)
	if path == "" {
		return fmt.Errorf("network passport destination is required")
	}
	path, err = filepath.Abs(path)
	if err != nil || path == "" {
		return fmt.Errorf("resolve network passport destination: %w", err)
	}
	if filepath.Ext(path) == "" {
		path += ".golanpass"
	}
	if _, err := os.Lstat(path); err == nil {
		return fmt.Errorf("network passport destination already exists")
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("inspect network passport destination: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("create network passport directory: %w", err)
	}
	temporary, err := os.CreateTemp(filepath.Dir(path), ".golanpass-*")
	if err != nil {
		return fmt.Errorf("create network passport staging file: %w", err)
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0o600); err != nil {
		temporary.Close()
		return fmt.Errorf("secure network passport staging file: %w", err)
	}
	if _, err := temporary.Write(content); err != nil {
		temporary.Close()
		return fmt.Errorf("write network passport: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return fmt.Errorf("sync network passport: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close network passport: %w", err)
	}
	if err := os.Link(temporaryPath, path); err != nil {
		return fmt.Errorf("publish network passport: %w", err)
	}
	return nil
}

// ReadPassport reads and verifies one portable document.
func ReadPassport(path string) (Passport, error) {
	file, err := os.Open(strings.TrimSpace(path))
	if err != nil {
		return Passport{}, fmt.Errorf("open network passport: %w", err)
	}
	defer file.Close()
	content, err := io.ReadAll(io.LimitReader(file, maxPassportSize+1))
	if err != nil {
		return Passport{}, fmt.Errorf("read network passport: %w", err)
	}
	return DecodePassport(content)
}

// ComparePassport compares a portable fingerprint with a current session.
func ComparePassport(passport Passport, current Session) (ChangeReport, error) {
	if err := ValidatePassport(passport); err != nil {
		return ChangeReport{}, err
	}
	if err := ValidateSession(current); err != nil {
		return ChangeReport{}, err
	}
	beforeDevices := make(map[string]DeviceFingerprint, len(passport.Devices))
	for _, fingerprint := range passport.Devices {
		beforeDevices[deviceFingerprintKey(fingerprint)] = fingerprint
	}
	report := ChangeReport{
		BaselineID: "passport:" + passport.Name,
		CurrentID:  current.ID,
		Changes:    compareDeviceFingerprintMaps(beforeDevices, deviceFingerprints(current)),
	}
	report.Changes = append(report.Changes, compareInfrastructureFingerprints(
		passport.Infrastructure,
		FingerprintInfrastructure(AnalyzeInfrastructure(current).Claims),
	)...)
	sortChanges(report.Changes)
	return report, nil
}

func passportDigest(passport Passport) (string, error) {
	passport.Checksum = ""
	content, err := json.Marshal(passport)
	if err != nil {
		return "", fmt.Errorf("checksum network passport: %w", err)
	}
	digest := sha256.Sum256(content)
	return hex.EncodeToString(digest[:]), nil
}

func validInfrastructureRole(role InfrastructureRole) bool {
	switch role {
	case RoleGateway, RoleDHCPServer, RoleDNSServer, RoleIPv6Router, RoleSwitch, RoleSTPRoot, RoleAuthenticator:
		return true
	default:
		return false
	}
}

func validSortedPassportText(values []string) bool {
	for index, value := range values {
		if cleanText(value) == "" || cleanText(value) != value || index > 0 && values[index-1] >= value {
			return false
		}
	}
	return true
}
