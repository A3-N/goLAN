package network

import (
	"strings"
	"testing"
	"time"

	"golan/internal/traffic"
)

func TestNetworkIntelligenceExplainsIdentityInfrastructureAccessServicesAndFate(t *testing.T) {
	now := time.Unix(100, 0).UTC()
	client := Device{
		Number: 1, Key: "en0/02:00:00:00:00:01", MAC: "02:00:00:00:00:01", Adapter: "en0",
		IPs: []string{"192.0.2.10"}, Hostnames: []string{"workstation.local"}, VLANs: []uint16{20},
		Services: []Service{{Type: "_ssh._tcp", Name: "workstation", Target: "workstation.local", Port: 22, Protocol: "mDNS", Count: 1}},
		AccessEvents: []AccessEvent{
			{Kind: "eapol", Label: "EAPOL Start", Protocol: "EAPOL", Severity: SeverityInfo, ObservedAt: now},
			{Kind: "eap_code", Label: "EAP Failure", Protocol: "EAPOL", Severity: SeverityWarn, ObservedAt: now.Add(time.Second)},
		},
		Observations: []Observation{
			observationAt("gateway", "gateway 192.0.2.1 via DHCP", "192.0.2.1", "DHCP", CategoryAddressing, SeverityInfo, now),
			observationAt("dns", "dns 192.0.2.53 via DHCP", "192.0.2.53", "DHCP", CategoryAddressing, SeverityInfo, now),
			observationAt("arp", "ARP neighbor resolved", "", "ARP", CategoryAddressing, SeverityInfo, now),
		},
	}
	gateway := Device{Number: 2, Key: "en0/02:00:00:00:00:02", MAC: "02:00:00:00:00:02", Adapter: "en0", IPs: []string{"192.0.2.1"}}
	dns := Device{Number: 3, Key: "en0/02:00:00:00:00:03", MAC: "02:00:00:00:00:03", Adapter: "en0", IPs: []string{"192.0.2.53"}}
	session := Session{
		Version: CurrentVersion, ID: "current", Mode: "controlled-bridge", StartedAt: now,
		Devices: []Device{client, gateway, dns},
		PacketFates: []PacketFate{{
			FlowID: "blocked-web", Protocol: 6,
			EndpointA: traffic.Endpoint{MAC: client.MAC, IP: "192.0.2.10", Port: 49152},
			EndpointB: traffic.Endpoint{MAC: gateway.MAC, IP: "198.51.100.20", Port: 80},
			Observed:  2, Blocked: 2, LastRuleID: "deny-web", Confidence: FateExact, FirstSeen: now, LastSeen: now.Add(time.Second),
		}},
	}

	identity := DeviceIdentity(client)
	if identity.Name != "workstation.local" || identity.Confidence != ConfidenceHigh || identity.Score < 70 {
		t.Fatalf("identity=%#v", identity)
	}
	infrastructure := AnalyzeInfrastructure(session)
	if !hasInfrastructureClaim(infrastructure.Claims, RoleGateway, "192.0.2.1", gateway.MAC) ||
		!hasInfrastructureClaim(infrastructure.Claims, RoleDNSServer, "192.0.2.53", dns.MAC) {
		t.Fatalf("infrastructure=%#v", infrastructure)
	}
	duplicateClaims := append(append([]InfrastructureClaim(nil), infrastructure.Claims...), infrastructure.Claims...)
	if fingerprints := FingerprintInfrastructure(duplicateClaims); len(fingerprints) != len(infrastructure.Claims) {
		t.Fatalf("duplicate infrastructure fingerprints retained: %#v", fingerprints)
	}
	story := BuildAccessStory(client)
	if story.Result != "failure" || story.Attempts != 1 || story.Duration != time.Second {
		t.Fatalf("story=%#v", story)
	}
	repeatedStart := client
	repeatedStart.AccessEvents = append([]AccessEvent{
		{Kind: "eapol", Label: "EAPOL Start", Protocol: "EAPOL", Severity: SeverityInfo, ObservedAt: now},
	}, client.AccessEvents...)
	if attempts := BuildAccessStory(repeatedStart).Attempts; attempts != 1 {
		t.Fatalf("repeated start counted as %d attempts", attempts)
	}
	explanation := ExplainConnection(session, client)
	if !strings.Contains(explanation.Summary, "Access") || explanation.Stages[1].Status != StageFail {
		t.Fatalf("explanation=%#v", explanation)
	}
	if services := Services(session); len(services) != 1 || services[0].Services[0].Port != 22 {
		t.Fatalf("services=%#v", services)
	}
	if fates := PacketFatesForDevice(session, client); len(fates) != 1 || fates[0].Blocked != 2 || fates[0].Confidence != FateExact {
		t.Fatalf("fates=%#v", fates)
	}
}

func TestCompareSessionsPrioritizesInfrastructureAndDeviceDrift(t *testing.T) {
	now := time.Unix(200, 0).UTC()
	baseline := comparisonSession("baseline", "192.0.2.1", "02:00:00:00:00:02", []string{"192.0.2.10"}, now)
	current := comparisonSession("current", "192.0.2.254", "02:00:00:00:00:03", []string{"192.0.2.11"}, now.Add(time.Hour))
	report := CompareSessions(baseline, current)
	if report.BaselineID != "baseline" || report.CurrentID != "current" {
		t.Fatalf("report identity=%#v", report)
	}
	var criticalGateway, changedIP bool
	for _, change := range report.Changes {
		if change.Summary == "gateway changed" && change.Kind == ChangeCritical && change.Severity == SeverityError &&
			strings.Contains(change.Before, "192.0.2.1") && strings.Contains(change.After, "192.0.2.254") {
			criticalGateway = true
		}
		if change.Summary == "IP addresses changed" && change.Severity == SeverityWarn {
			changedIP = true
		}
	}
	if !criticalGateway || !changedIP {
		t.Fatalf("changes=%#v", report.Changes)
	}
}

func comparisonSession(id, gatewayIP, gatewayMAC string, clientIPs []string, now time.Time) Session {
	return Session{
		Version: CurrentVersion, ID: id, Mode: "listen", StartedAt: now,
		Devices: []Device{
			{Key: "en0/02:00:00:00:00:01", MAC: "02:00:00:00:00:01", Adapter: "en0", IPs: clientIPs, Observations: []Observation{
				observationAt("gateway", "gateway "+gatewayIP+" via DHCP", gatewayIP, "DHCP", CategoryAddressing, SeverityInfo, now),
			}},
			{Key: "en0/" + gatewayMAC, MAC: gatewayMAC, Adapter: "en0", IPs: []string{gatewayIP}},
		},
	}
}

func observationAt(kind, summary, value, protocol string, category Category, severity Severity, now time.Time) Observation {
	return Observation{Kind: kind, Summary: summary, Value: value, Protocol: protocol, Category: category, Severity: severity, FirstSeen: now, LastSeen: now, Count: 1}
}

func hasInfrastructureClaim(claims []InfrastructureClaim, role InfrastructureRole, value, mac string) bool {
	for _, claim := range claims {
		if claim.Role == role && claim.Value == value && claim.MAC == mac {
			return true
		}
	}
	return false
}
