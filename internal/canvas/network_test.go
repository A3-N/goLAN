package canvas

import (
	"testing"
	"time"

	networkobs "golan/internal/network"
)

func TestFromNetworkSessionUsesUsefulObservationsAndExcludesRisks(t *testing.T) {
	session := networkobs.Session{
		Version: networkobs.CurrentVersion, ID: "canvas", Mode: "listen", StartedAt: time.Unix(1, 0),
		Devices: []networkobs.Device{{
			Key: "en0/02:00:00:00:00:01", MAC: "02:00:00:00:00:01", Adapter: "en0", Role: "host",
			IPs: []string{"192.0.2.10"}, FirstSeen: time.Unix(1, 0), LastSeen: time.Unix(2, 0),
			Observations: []networkobs.Observation{
				{Category: networkobs.CategoryDNS, Kind: "query", Summary: "DNS A example.test", Protocol: "DNS", Source: "192.0.2.10", Destination: "192.0.2.53", Severity: networkobs.SeverityInfo, Count: 1},
				{Category: networkobs.CategoryRisk, Kind: "ntlm-authentication", Summary: "NTLM authentication observed", Protocol: "NTLM", Source: "192.0.2.10", Destination: "192.0.2.20", Severity: networkobs.SeverityWarn, Count: 1},
			},
		}},
	}
	result := FromNetworkSession(session)
	if len(result.Hosts) != 2 || len(result.Conversations) != 1 {
		t.Fatalf("hosts=%#v conversations=%#v", result.Hosts, result.Conversations)
	}
	for _, conversation := range result.Conversations {
		if conversation.Protocol != "DNS" || conversation.Service != string(networkobs.CategoryDNS) {
			t.Fatalf("conversation=%#v", conversation)
		}
	}
}
