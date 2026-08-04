package network

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"golan/internal/traffic"
)

// IdentityConfidence is an evidence-derived confidence label. It never causes
// devices to be merged; rows remain scoped to their directly observed MAC.
type IdentityConfidence string

const (
	ConfidenceLow    IdentityConfidence = "LOW"
	ConfidenceMedium IdentityConfidence = "MEDIUM"
	ConfidenceHigh   IdentityConfidence = "HIGH"
)

// Identity explains the readable name and evidence attached to one device.
type Identity struct {
	Name       string
	Confidence IdentityConfidence
	Score      int
	Reasons    []string
}

// InfrastructureRole identifies a device or value that influences link-wide
// configuration or access.
type InfrastructureRole string

const (
	RoleGateway       InfrastructureRole = "gateway"
	RoleDHCPServer    InfrastructureRole = "dhcp-server"
	RoleDNSServer     InfrastructureRole = "dns-server"
	RoleIPv6Router    InfrastructureRole = "ipv6-router"
	RoleSwitch        InfrastructureRole = "switch"
	RoleSTPRoot       InfrastructureRole = "stp-root"
	RoleAuthenticator InfrastructureRole = "authenticator"
)

// InfrastructureClaim is one aggregated, payload-free infrastructure fact.
type InfrastructureClaim struct {
	Role  InfrastructureRole
	Value string
	MAC   string
	Count uint64
}

// InfrastructureAlert is one readable control-plane condition that deserves
// attention.
type InfrastructureAlert struct {
	Severity Severity
	Kind     string
	Summary  string
	Evidence string
}

// InfrastructureReport contains stable claims and conflict alerts.
type InfrastructureReport struct {
	Claims []InfrastructureClaim
	Alerts []InfrastructureAlert
}

// ChangeKind describes how current evidence differs from a baseline.
type ChangeKind string

const (
	ChangeNew      ChangeKind = "NEW"
	ChangeMissing  ChangeKind = "MISSING"
	ChangeChanged  ChangeKind = "CHANGED"
	ChangeCritical ChangeKind = "CRITICAL"
)

// Change is one deterministic baseline difference.
type Change struct {
	Kind      ChangeKind
	Severity  Severity
	DeviceMAC string
	Summary   string
	Before    string
	After     string
}

// ChangeReport compares two sanitized sessions without packet replay.
type ChangeReport struct {
	BaselineID string
	CurrentID  string
	Changes    []Change
}

// StageStatus is a human-readable connection explanation state.
type StageStatus string

const (
	StagePass StageStatus = "PASS"
	StageWarn StageStatus = "WARN"
	StageFail StageStatus = "FAIL"
	StageSkip StageStatus = "SKIP"
)

// ExplanationStage is one layer in a causal connectivity explanation.
type ExplanationStage struct {
	Name     string
	Status   StageStatus
	Summary  string
	Evidence string
}

// ConnectionExplanation explains one device from link through application.
type ConnectionExplanation struct {
	Summary string
	Stages  []ExplanationStage
}

// AccessStory is an ordered, redacted 802.1X/MACsec story.
type AccessStory struct {
	Events   []AccessEvent
	Attempts int
	Result   string
	Duration time.Duration
}

// ServiceOwner associates readable services with the directly observed row.
type ServiceOwner struct {
	Device   Device
	Identity Identity
	Services []Service
}

// DeviceFingerprint is the shared, payload-free identity used by session
// comparison and portable passports.
type DeviceFingerprint struct {
	MAC        string             `json:"mac"`
	Scope      string             `json:"scope,omitempty"`
	Hostnames  []string           `json:"hostnames,omitempty"`
	IPs        []string           `json:"ips,omitempty"`
	VLANs      []uint16           `json:"vlans,omitempty"`
	Services   []string           `json:"services,omitempty"`
	Access     string             `json:"access,omitempty"`
	Confidence IdentityConfidence `json:"confidence"`
}

// InfrastructureFingerprint is the stable part of one control-plane claim.
type InfrastructureFingerprint struct {
	Role  InfrastructureRole `json:"role"`
	Value string             `json:"value"`
	MAC   string             `json:"mac,omitempty"`
}

// FindDevice resolves one explicit visible selector without merging rows.
func FindDevice(session Session, selector string) (Device, bool) {
	selector = strings.ToLower(strings.TrimSpace(selector))
	if selector == "" {
		return Device{}, false
	}
	if number, err := strconv.ParseUint(selector, 10, 64); err == nil {
		for _, device := range session.Devices {
			if device.Number == number {
				return device, true
			}
		}
	}
	for _, device := range session.Devices {
		if strings.EqualFold(device.Key, selector) || strings.EqualFold(device.MAC, selector) || containsFold(device.IPs, selector) || containsFold(device.Hostnames, selector) {
			return device, true
		}
	}
	return Device{}, false
}

// DeviceIdentity returns a confidence explanation while retaining the exact
// device row as the identity boundary.
func DeviceIdentity(device Device) Identity {
	identity := Identity{Name: device.MAC, Score: 30, Reasons: []string{"directly observed unicast MAC"}}
	if len(device.IPs) > 0 {
		identity.Score += 20
		identity.Reasons = append(identity.Reasons, fmt.Sprintf("%d directly associated IP address(es)", len(device.IPs)))
	}
	if len(device.Hostnames) > 0 {
		identity.Name = device.Hostnames[0]
		identity.Score += 20
		identity.Reasons = append(identity.Reasons, "hostname evidence "+strings.Join(device.Hostnames, ", "))
	}
	if len(device.Services) > 0 {
		identity.Score += 15
		identity.Reasons = append(identity.Reasons, fmt.Sprintf("%d service identity record(s)", len(device.Services)))
		if identity.Name == device.MAC {
			for _, service := range device.Services {
				if service.Target != "" {
					identity.Name = service.Target
					break
				}
			}
		}
	}
	if len(device.VLANs) > 0 || device.Adapter != "" {
		identity.Score += 10
		identity.Reasons = append(identity.Reasons, "stable link scope evidence")
	}
	identity.Score = min(identity.Score, 100)
	switch {
	case identity.Score >= 70:
		identity.Confidence = ConfidenceHigh
	case identity.Score >= 45:
		identity.Confidence = ConfidenceMedium
	default:
		identity.Confidence = ConfidenceLow
	}
	return identity
}

// FingerprintDevice derives the canonical device comparison record.
func FingerprintDevice(device Device) DeviceFingerprint {
	scope := device.Adapter
	if scope == "" {
		scope = device.Key
	}
	vlans := make(map[uint16]bool, len(device.VLANs))
	for _, vlan := range device.VLANs {
		vlans[vlan] = true
	}
	fingerprint := DeviceFingerprint{
		MAC: strings.ToLower(device.MAC), Scope: cleanText(scope), Hostnames: unionStrings(nil, device.Hostnames),
		IPs: unionStrings(nil, device.IPs), VLANs: sortedUint16Keys(vlans),
		Access: BuildAccessStory(device).Result, Confidence: DeviceIdentity(device).Confidence,
	}
	for _, service := range device.Services {
		fingerprint.Services = unionStrings(fingerprint.Services, []string{serviceFingerprint(service)})
	}
	return fingerprint
}

// FingerprintInfrastructure removes observer-specific and time-varying fields
// from infrastructure claims.
func FingerprintInfrastructure(claims []InfrastructureClaim) []InfrastructureFingerprint {
	result := make([]InfrastructureFingerprint, 0, len(claims))
	seen := make(map[string]bool, len(claims))
	for _, claim := range claims {
		fingerprint := InfrastructureFingerprint{Role: claim.Role, Value: claim.Value, MAC: claim.MAC}
		if addSet(seen, infrastructureFingerprintKey(fingerprint)) {
			result = append(result, fingerprint)
		}
	}
	sort.Slice(result, func(i, j int) bool {
		return infrastructureFingerprintKey(result[i]) < infrastructureFingerprintKey(result[j])
	})
	return result
}

// AnalyzeInfrastructure derives infrastructure actors, configuration values,
// duplicate ownership, and competing control-plane claims.
func AnalyzeInfrastructure(session Session) InfrastructureReport {
	ipOwners := make(map[string][]Device)
	macOwners := make(map[string]Device)
	for _, device := range session.Devices {
		macOwners[strings.ToLower(device.MAC)] = device
		for _, ip := range device.IPs {
			ipOwners[strings.ToLower(ip)] = append(ipOwners[strings.ToLower(ip)], device)
		}
	}
	claims := make(map[string]*InfrastructureClaim)
	add := func(role InfrastructureRole, value string, actor Device, observation Observation) {
		value = cleanText(value)
		if value == "" {
			return
		}
		key := strings.Join([]string{string(role), strings.ToLower(value), strings.ToLower(actor.Key)}, "\x00")
		if existing := claims[key]; existing != nil {
			existing.Count += max(uint64(1), observation.Count)
			return
		}
		claims[key] = &InfrastructureClaim{
			Role: role, Value: value, MAC: actor.MAC, Count: max(uint64(1), observation.Count),
		}
	}
	for _, device := range session.Devices {
		for _, observation := range device.Observations {
			value := observation.Value
			if value == "" {
				value = valueFromSummary(observation)
			}
			switch observation.Kind {
			case "gateway":
				actor := firstDevice(ipOwners[strings.ToLower(value)])
				add(RoleGateway, value, actor, observation)
			case "dns":
				actor := firstDevice(ipOwners[strings.ToLower(value)])
				add(RoleDNSServer, value, actor, observation)
			case "dhcp_server":
				actor := firstDevice(ipOwners[strings.ToLower(value)])
				add(RoleDHCPServer, value, actor, observation)
			case "ipv6_router":
				add(RoleIPv6Router, value, device, observation)
			case "lldp_chassis":
				add(RoleSwitch, value, device, observation)
			case "stp_root":
				rootMAC := value
				if slash := strings.LastIndex(rootMAC, "/"); slash >= 0 {
					rootMAC = rootMAC[slash+1:]
				}
				add(RoleSTPRoot, value, macOwners[strings.ToLower(rootMAC)], observation)
			case "eap_code":
				if strings.EqualFold(value, "Request") {
					add(RoleAuthenticator, device.MAC, device, observation)
				}
			}
		}
	}
	report := InfrastructureReport{Claims: make([]InfrastructureClaim, 0, len(claims))}
	for _, claim := range claims {
		report.Claims = append(report.Claims, *claim)
	}
	sort.Slice(report.Claims, func(i, j int) bool {
		if report.Claims[i].Role == report.Claims[j].Role {
			if report.Claims[i].Value == report.Claims[j].Value {
				return report.Claims[i].MAC < report.Claims[j].MAC
			}
			return report.Claims[i].Value < report.Claims[j].Value
		}
		return report.Claims[i].Role < report.Claims[j].Role
	})
	for ip, owners := range ipOwners {
		if len(owners) < 2 {
			continue
		}
		macs := make([]string, 0, len(owners))
		for _, owner := range owners {
			macs = append(macs, owner.MAC)
		}
		sort.Strings(macs)
		report.Alerts = append(report.Alerts, InfrastructureAlert{
			Severity: SeverityError, Kind: "duplicate-ip", Summary: "IP " + ip + " is claimed by multiple devices",
			Evidence: strings.Join(macs, ", "),
		})
	}
	for _, role := range []InfrastructureRole{RoleDHCPServer, RoleGateway, RoleIPv6Router, RoleSTPRoot} {
		values := uniqueClaimValues(report.Claims, role)
		if len(values) > 1 {
			report.Alerts = append(report.Alerts, InfrastructureAlert{
				Severity: SeverityWarn, Kind: "competing-" + string(role),
				Summary: fmt.Sprintf("multiple %s claims observed", role), Evidence: strings.Join(values, ", "),
			})
		}
	}
	sort.Slice(report.Alerts, func(i, j int) bool {
		if severityRank(report.Alerts[i].Severity) == severityRank(report.Alerts[j].Severity) {
			return report.Alerts[i].Summary < report.Alerts[j].Summary
		}
		return severityRank(report.Alerts[i].Severity) > severityRank(report.Alerts[j].Severity)
	})
	return report
}

// CompareSessions returns readable infrastructure and device drift.
func CompareSessions(baseline, current Session) ChangeReport {
	report := ChangeReport{BaselineID: baseline.ID, CurrentID: current.ID, Changes: compareDeviceSessions(baseline, current)}
	report.Changes = append(report.Changes, compareInfrastructureFingerprints(
		FingerprintInfrastructure(AnalyzeInfrastructure(baseline).Claims),
		FingerprintInfrastructure(AnalyzeInfrastructure(current).Claims),
	)...)
	sortChanges(report.Changes)
	return report
}

func compareDeviceSessions(baseline, current Session) []Change {
	return compareDeviceFingerprintMaps(deviceFingerprints(baseline), deviceFingerprints(current))
}

func compareDeviceFingerprintMaps(beforeDevices, afterDevices map[string]DeviceFingerprint) []Change {
	var changes []Change
	for key, before := range beforeDevices {
		after, ok := afterDevices[key]
		if !ok {
			changes = append(changes, Change{Kind: ChangeMissing, Severity: SeverityInfo, DeviceMAC: before.MAC, Summary: "device no longer observed", Before: before.label()})
			continue
		}
		changes = append(changes, compareFingerprint(before, after)...)
	}
	for key, after := range afterDevices {
		if _, ok := beforeDevices[key]; ok {
			continue
		}
		changes = append(changes, Change{Kind: ChangeNew, Severity: SeverityInfo, DeviceMAC: after.MAC, Summary: "new device observed", After: after.label()})
	}
	return changes
}

func compareInfrastructureFingerprints(before, after []InfrastructureFingerprint) []Change {
	var changes []Change
	matchedBefore := make(map[string]bool)
	matchedAfter := make(map[string]bool)
	for _, role := range []InfrastructureRole{RoleGateway, RoleDHCPServer, RoleDNSServer, RoleIPv6Router, RoleSwitch, RoleSTPRoot, RoleAuthenticator} {
		beforeRole, afterRole := fingerprintsForRole(before, role), fingerprintsForRole(after, role)
		if len(beforeRole) != 1 || len(afterRole) != 1 {
			continue
		}
		beforeKey, afterKey := infrastructureFingerprintKey(beforeRole[0]), infrastructureFingerprintKey(afterRole[0])
		if beforeKey == afterKey {
			continue
		}
		kind, severity := infrastructureChangeSeverity(role)
		changes = append(changes, Change{
			Kind: kind, Severity: severity, DeviceMAC: afterRole[0].MAC, Summary: string(role) + " changed",
			Before: infrastructureFingerprintLabel(beforeRole[0]), After: infrastructureFingerprintLabel(afterRole[0]),
		})
		matchedBefore[beforeKey], matchedAfter[afterKey] = true, true
	}
	beforeClaims := infrastructureFingerprintSet(before)
	afterClaims := infrastructureFingerprintSet(after)
	for key, claim := range beforeClaims {
		if matchedBefore[key] {
			continue
		}
		if _, ok := afterClaims[key]; ok {
			continue
		}
		kind, severity := infrastructureChangeSeverity(claim.Role)
		changes = append(changes, Change{Kind: kind, Severity: severity, DeviceMAC: claim.MAC, Summary: string(claim.Role) + " disappeared", Before: infrastructureFingerprintLabel(claim)})
	}
	for key, claim := range afterClaims {
		if matchedAfter[key] {
			continue
		}
		if _, ok := beforeClaims[key]; ok {
			continue
		}
		kind, severity := infrastructureChangeSeverity(claim.Role)
		changes = append(changes, Change{Kind: kind, Severity: severity, DeviceMAC: claim.MAC, Summary: "new " + string(claim.Role) + " observed", After: infrastructureFingerprintLabel(claim)})
	}
	return changes
}

func sortChanges(changes []Change) {
	sort.Slice(changes, func(i, j int) bool {
		ri, rj := severityRank(changes[i].Severity), severityRank(changes[j].Severity)
		if ri == rj {
			if changes[i].Summary == changes[j].Summary {
				return changes[i].DeviceMAC < changes[j].DeviceMAC
			}
			return changes[i].Summary < changes[j].Summary
		}
		return ri > rj
	})
}

// BuildAccessStory returns an ordered access state machine without identities
// or credential values.
func BuildAccessStory(device Device) AccessStory {
	story := AccessStory{Events: append([]AccessEvent(nil), device.AccessEvents...), Result: "not-observed"}
	sort.SliceStable(story.Events, func(i, j int) bool { return story.Events[i].ObservedAt.Before(story.Events[j].ObservedAt) })
	inAttempt := false
	for _, event := range story.Events {
		label := strings.ToLower(event.Label)
		if (strings.Contains(label, "start") || strings.Contains(label, "request")) && !inAttempt {
			story.Attempts++
			inAttempt = true
		}
		switch {
		case strings.Contains(label, "success"):
			story.Result = "success"
			inAttempt = false
		case strings.Contains(label, "failure"):
			story.Result = "failure"
			inAttempt = false
		}
	}
	if len(story.Events) > 0 {
		story.Duration = story.Events[len(story.Events)-1].ObservedAt.Sub(story.Events[0].ObservedAt)
		if story.Result == "not-observed" {
			story.Result = "pending"
		}
	}
	return story
}

// ExplainConnection creates a causal, readable explanation from the retained
// observation model. Unknown stages are labeled rather than guessed.
func ExplainConnection(session Session, device Device) ConnectionExplanation {
	report := ConnectionExplanation{}
	report.Stages = append(report.Stages, ExplanationStage{Name: "Link", Status: StagePass, Summary: "device observed on " + emptyValue(device.Adapter, "unknown adapter"), Evidence: device.MAC})
	access := BuildAccessStory(device)
	switch access.Result {
	case "success":
		report.Stages = append(report.Stages, ExplanationStage{Name: "Access", Status: StagePass, Summary: "802.1X authentication succeeded", Evidence: fmt.Sprintf("%d event(s)", len(access.Events))})
	case "failure":
		report.Stages = append(report.Stages, ExplanationStage{Name: "Access", Status: StageFail, Summary: "latest 802.1X result is failure", Evidence: fmt.Sprintf("%d attempt(s)", access.Attempts)})
	case "pending":
		report.Stages = append(report.Stages, ExplanationStage{Name: "Access", Status: StageWarn, Summary: "access exchange observed without a final result", Evidence: fmt.Sprintf("%d event(s)", len(access.Events))})
	default:
		report.Stages = append(report.Stages, ExplanationStage{Name: "Access", Status: StageSkip, Summary: "no 802.1X exchange observed"})
	}
	if len(device.IPs) == 0 {
		report.Stages = append(report.Stages, ExplanationStage{Name: "Addressing", Status: StageFail, Summary: "no IP address associated with this device"})
	} else {
		report.Stages = append(report.Stages, ExplanationStage{Name: "Addressing", Status: StagePass, Summary: strings.Join(device.IPs, ", "), Evidence: addressingEvidence(device)})
	}
	if hasObservation(device, func(observation Observation) bool {
		return strings.EqualFold(observation.Protocol, "ARP") || strings.Contains(strings.ToLower(observation.Protocol), "icmpv6")
	}) {
		report.Stages = append(report.Stages, ExplanationStage{Name: "Neighbor", Status: StagePass, Summary: "neighbor resolution evidence observed"})
	} else {
		report.Stages = append(report.Stages, ExplanationStage{Name: "Neighbor", Status: StageWarn, Summary: "no ARP or IPv6 neighbor evidence retained"})
	}
	gateways := observationValues(device, "gateway")
	if len(gateways) == 0 {
		report.Stages = append(report.Stages, ExplanationStage{Name: "Gateway", Status: StageWarn, Summary: "no default gateway learned for this device"})
	} else {
		report.Stages = append(report.Stages, ExplanationStage{Name: "Gateway", Status: StagePass, Summary: strings.Join(gateways, ", "), Evidence: "DHCP or directly observed addressing"})
	}
	if hasObservation(device, func(observation Observation) bool { return observation.Category == CategoryDNS }) || len(observationValues(device, "dns")) > 0 {
		report.Stages = append(report.Stages, ExplanationStage{Name: "DNS", Status: StagePass, Summary: "DNS configuration or query evidence observed"})
	} else {
		report.Stages = append(report.Stages, ExplanationStage{Name: "DNS", Status: StageSkip, Summary: "no DNS evidence retained"})
	}
	fates := PacketFatesForDevice(session, device)
	forwarded, blocked, unresolved := uint64(0), uint64(0), uint64(0)
	lastRule := ""
	for _, fate := range fates {
		forwarded += fate.Forwarded
		blocked += fate.Blocked
		unresolved += fate.Unresolved
		if fate.LastRuleID != "" {
			lastRule = fate.LastRuleID
		}
	}
	switch {
	case blocked > 0 && forwarded == 0:
		report.Stages = append(report.Stages, ExplanationStage{Name: "Transport", Status: StageFail, Summary: fmt.Sprintf("%d packet(s) blocked", blocked), Evidence: emptyValue(lastRule, "policy decision")})
	case forwarded > 0:
		report.Stages = append(report.Stages, ExplanationStage{Name: "Transport", Status: StagePass, Summary: fmt.Sprintf("%d packet(s) forwarded", forwarded), Evidence: fmt.Sprintf("%d flow aggregate(s)", len(fates))})
	case unresolved > 0:
		report.Stages = append(report.Stages, ExplanationStage{Name: "Transport", Status: StageWarn, Summary: fmt.Sprintf("%d packet outcome(s) not directly proven", unresolved)})
	default:
		report.Stages = append(report.Stages, ExplanationStage{Name: "Transport", Status: StageSkip, Summary: "no transport outcome retained"})
	}
	if hasObservation(device, func(observation Observation) bool { return observation.Category == CategoryHTTP }) {
		report.Stages = append(report.Stages, ExplanationStage{Name: "Application", Status: StagePass, Summary: "readable plaintext HTTP evidence observed"})
	} else {
		report.Stages = append(report.Stages, ExplanationStage{Name: "Application", Status: StageSkip, Summary: "no readable application evidence; encrypted payloads are not interpreted"})
	}
	report.Summary = "no proven failure"
	for _, stage := range report.Stages {
		if stage.Status == StageFail {
			report.Summary = "first proven failure: " + stage.Name + " — " + stage.Summary
			break
		}
	}
	return report
}

// PacketFatesForDevice returns flow aggregates attached to a device's MAC or
// directly associated IPs.
func PacketFatesForDevice(session Session, device Device) []PacketFate {
	ipSet := make(map[string]bool, len(device.IPs))
	for _, ip := range device.IPs {
		ipSet[strings.ToLower(ip)] = true
	}
	var result []PacketFate
	for _, fate := range session.PacketFates {
		if endpointMatchesDevice(fate.EndpointA, device.MAC, ipSet) || endpointMatchesDevice(fate.EndpointB, device.MAC, ipSet) {
			result = append(result, fate)
		}
	}
	sort.Slice(result, func(i, j int) bool { return result[i].LastSeen.After(result[j].LastSeen) })
	return result
}

func endpointMatchesDevice(endpoint traffic.Endpoint, mac string, ips map[string]bool) bool {
	return strings.EqualFold(endpoint.MAC, mac) || ips[strings.ToLower(endpoint.IP)]
}

// Services returns only devices with directly observed readable services.
func Services(session Session) []ServiceOwner {
	var result []ServiceOwner
	for _, device := range session.Devices {
		if len(device.Services) == 0 {
			continue
		}
		services := append([]Service(nil), device.Services...)
		sort.Slice(services, func(i, j int) bool {
			if services[i].Type == services[j].Type {
				return services[i].Name < services[j].Name
			}
			return services[i].Type < services[j].Type
		})
		result = append(result, ServiceOwner{Device: device, Identity: DeviceIdentity(device), Services: services})
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Identity.Name < result[j].Identity.Name })
	return result
}

func (f DeviceFingerprint) label() string {
	parts := []string{f.MAC}
	if f.Scope != "" {
		parts = append(parts, "["+f.Scope+"]")
	}
	if len(f.Hostnames) > 0 {
		parts = append(parts, strings.Join(f.Hostnames, ","))
	}
	if len(f.IPs) > 0 {
		parts = append(parts, strings.Join(f.IPs, ","))
	}
	return strings.Join(parts, " ")
}

func deviceFingerprintKey(fingerprint DeviceFingerprint) string {
	return strings.ToLower(fingerprint.MAC) + "\x00" + strings.ToLower(fingerprint.Scope)
}

func serviceFingerprint(service Service) string {
	parts := []string{service.Type}
	if service.Name != "" {
		parts = append(parts, service.Name)
	}
	if service.Target != "" {
		parts = append(parts, service.Target)
	}
	if service.Port != 0 {
		parts = append(parts, fmt.Sprintf("%s/%d", service.Protocol, service.Port))
	} else if service.Protocol != "" {
		parts = append(parts, service.Protocol)
	}
	return cleanText(strings.Join(parts, " "))
}

func deviceFingerprints(session Session) map[string]DeviceFingerprint {
	result := make(map[string]DeviceFingerprint)
	for _, device := range session.Devices {
		fingerprint := FingerprintDevice(device)
		result[deviceFingerprintKey(fingerprint)] = fingerprint
	}
	return result
}

func compareFingerprint(before, after DeviceFingerprint) []Change {
	var result []Change
	appendChange := func(summary string, severity Severity, oldValues, newValues []string) {
		if equalStrings(oldValues, newValues) {
			return
		}
		result = append(result, Change{Kind: ChangeChanged, Severity: severity, DeviceMAC: before.MAC, Summary: summary, Before: strings.Join(oldValues, ", "), After: strings.Join(newValues, ", ")})
	}
	appendChange("IP addresses changed", SeverityWarn, before.IPs, after.IPs)
	if !equalUint16s(before.VLANs, after.VLANs) {
		result = append(result, Change{Kind: ChangeChanged, Severity: SeverityWarn, DeviceMAC: before.MAC, Summary: "VLAN membership changed", Before: formatVLANValues(before.VLANs), After: formatVLANValues(after.VLANs)})
	}
	appendChange("hostname evidence changed", SeverityInfo, before.Hostnames, after.Hostnames)
	appendChange("service map changed", SeverityInfo, before.Services, after.Services)
	if before.Access != after.Access {
		result = append(result, Change{Kind: ChangeChanged, Severity: SeverityWarn, DeviceMAC: before.MAC, Summary: "access result changed", Before: before.Access, After: after.Access})
	}
	return result
}

func equalUint16s(first, second []uint16) bool {
	if len(first) != len(second) {
		return false
	}
	for index := range first {
		if first[index] != second[index] {
			return false
		}
	}
	return true
}

func formatVLANValues(values []uint16) string {
	formatted := make([]string, len(values))
	for index, value := range values {
		formatted[index] = strconv.Itoa(int(value))
	}
	return strings.Join(formatted, ", ")
}

func infrastructureFingerprintSet(claims []InfrastructureFingerprint) map[string]InfrastructureFingerprint {
	result := make(map[string]InfrastructureFingerprint)
	for _, claim := range claims {
		key := infrastructureFingerprintKey(claim)
		result[key] = claim
	}
	return result
}

func infrastructureFingerprintKey(claim InfrastructureFingerprint) string {
	return strings.Join([]string{string(claim.Role), strings.ToLower(claim.Value), strings.ToLower(claim.MAC)}, "\x00")
}

func fingerprintsForRole(claims []InfrastructureFingerprint, role InfrastructureRole) []InfrastructureFingerprint {
	var result []InfrastructureFingerprint
	for _, claim := range claims {
		if claim.Role == role {
			result = append(result, claim)
		}
	}
	return result
}

func infrastructureFingerprintLabel(claim InfrastructureFingerprint) string {
	if claim.MAC == "" {
		return claim.Value
	}
	return claim.Value + " via " + claim.MAC
}

func infrastructureChangeSeverity(role InfrastructureRole) (ChangeKind, Severity) {
	switch role {
	case RoleGateway, RoleDHCPServer, RoleSTPRoot:
		return ChangeCritical, SeverityError
	case RoleDNSServer, RoleIPv6Router, RoleAuthenticator:
		return ChangeChanged, SeverityWarn
	default:
		return ChangeChanged, SeverityInfo
	}
}

func uniqueClaimValues(claims []InfrastructureClaim, role InfrastructureRole) []string {
	var values []string
	for _, claim := range claims {
		if claim.Role == role {
			values = unionStrings(values, []string{claim.Value})
		}
	}
	return values
}

func valueFromSummary(observation Observation) string {
	prefix := strings.ReplaceAll(observation.Kind, "_", " ") + " "
	value := strings.TrimPrefix(observation.Summary, prefix)
	if index := strings.Index(value, " via "); index >= 0 {
		value = value[:index]
	}
	return cleanText(value)
}

func firstDevice(devices []Device) Device {
	if len(devices) == 0 {
		return Device{}
	}
	return devices[0]
}

func containsFold(values []string, value string) bool {
	for _, candidate := range values {
		if strings.EqualFold(candidate, value) {
			return true
		}
	}
	return false
}

func unionStrings(first, second []string) []string {
	seen := make(map[string]bool, len(first)+len(second))
	for _, list := range [][]string{first, second} {
		for _, value := range list {
			value = cleanText(value)
			if value != "" {
				addSet(seen, value)
			}
		}
	}
	return sortedStringKeys(seen)
}

func equalStrings(first, second []string) bool {
	if len(first) != len(second) {
		return false
	}
	for index := range first {
		if first[index] != second[index] {
			return false
		}
	}
	return true
}

func severityRank(severity Severity) int {
	switch severity {
	case SeverityError:
		return 3
	case SeverityWarn:
		return 2
	default:
		return 1
	}
}

func hasObservation(device Device, match func(Observation) bool) bool {
	for _, observation := range device.Observations {
		if match(observation) {
			return true
		}
	}
	return false
}

func observationValues(device Device, kind string) []string {
	var values []string
	for _, observation := range device.Observations {
		if observation.Kind != kind {
			continue
		}
		value := observation.Value
		if value == "" {
			value = valueFromSummary(observation)
		}
		values = unionStrings(values, []string{value})
	}
	return values
}

func addressingEvidence(device Device) string {
	for _, observation := range device.Observations {
		if observation.Kind == "address" && observation.Protocol != "" {
			return observation.Protocol
		}
	}
	return "directly observed source address"
}

func emptyValue(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}
