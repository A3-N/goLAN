package policy

import (
	"fmt"
	"strings"

	"golan/internal/traffic"
)

// BuiltinEAPOLRules represents the compatibility EAPOL toggles as ordinary
// typed rules. Disabled toggles remain present for transparent diagnostics.
func BuiltinEAPOLRules(suppressLogoff, downgradeMACsec bool) []Rule {
	return []Rule{
		{
			ID:       "builtin-eapol-suppress-logoff",
			Name:     "Suppress host EAPOL-Logoff",
			Priority: 10000,
			Enabled:  suppressLogoff,
			Match: Match{
				Directions: []traffic.Direction{traffic.DirectionHostToSwitch, traffic.DirectionOutbound},
				EtherTypes: []uint16{0x888e},
				EAPOLTypes: []uint8{2},
			},
			Actions: []Action{{Kind: ActionBlock}},
		},
		{
			ID:       "builtin-eapol-drop-mka",
			Name:     "Drop MACsec MKA",
			Priority: 9999,
			Enabled:  downgradeMACsec,
			Match: Match{
				EtherTypes: []uint16{0x88e5},
			},
			Actions: []Action{{Kind: ActionBlock}},
		},
	}
}

// Preset returns a named starter policy. Presets are ordinary rules and can be
// edited or tested before activation.
func Preset(name string) ([]Rule, error) {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "observe-everything", "observe everything":
		return []Rule{{ID: "observe-everything", Name: "Observe Everything", Enabled: true, Actions: []Action{{Kind: ActionAllow}}}}, nil
	case "open-internet", "open internet":
		return []Rule{{ID: "open-internet", Name: "Open Internet", Enabled: true, Match: Match{Directions: []traffic.Direction{traffic.DirectionOutbound}}, Actions: []Action{{Kind: ActionAllow}}}}, nil
	case "web-only", "web only":
		return webOnlyPreset(), nil
	case "block-internet", "block internet":
		return []Rule{{ID: "block-internet", Name: "Block Internet", Enabled: true, Match: Match{Directions: []traffic.Direction{traffic.DirectionOutbound}, IPVersions: []uint8{4}}, Actions: []Action{{Kind: ActionBlock}}}}, nil
	case "controlled-bridge", "controlled bridge":
		return []Rule{{ID: "controlled-bridge", Name: "Controlled Bridge", Enabled: true, Actions: []Action{{Kind: ActionAllow}}}}, nil
	case "high-latency", "high latency":
		return []Rule{{ID: "high-latency", Name: "High Latency", Enabled: true, Actions: []Action{{Kind: ActionDelay, Duration: 250000000}, {Kind: ActionAllow}}}}, nil
	case "packet-loss", "packet loss":
		return []Rule{{ID: "packet-loss", Name: "Packet Loss", Enabled: true, Actions: []Action{{Kind: ActionLoss, Percent: 5}, {Kind: ActionAllow}}}}, nil
	default:
		return nil, fmt.Errorf("unknown policy preset %q", name)
	}
}

func webOnlyPreset() []Rule {
	return []Rule{
		{ID: "web-only-dhcp", Name: "Allow DHCP", Priority: 400, Enabled: true, Match: Match{Directions: []traffic.Direction{traffic.DirectionOutbound}, Protocols: []uint8{17}, SrcPorts: PortSet{Values: []uint16{67, 68}}, DstPorts: PortSet{Values: []uint16{67, 68}}}, Actions: []Action{{Kind: ActionAllow}}},
		{ID: "web-only-dns-udp", Name: "Allow DNS UDP", Priority: 300, Enabled: true, Match: Match{Directions: []traffic.Direction{traffic.DirectionOutbound}, Protocols: []uint8{17}, DstPorts: PortSet{Values: []uint16{53}}}, Actions: []Action{{Kind: ActionAllow}}},
		{ID: "web-only-dns-tcp", Name: "Allow DNS TCP", Priority: 299, Enabled: true, Match: Match{Directions: []traffic.Direction{traffic.DirectionOutbound}, Protocols: []uint8{6}, DstPorts: PortSet{Values: []uint16{53}}}, Actions: []Action{{Kind: ActionAllow}}},
		{ID: "web-only-web", Name: "Allow HTTP and HTTPS", Priority: 200, Enabled: true, Match: Match{Directions: []traffic.Direction{traffic.DirectionOutbound}, Protocols: []uint8{6}, DstPorts: PortSet{Values: []uint16{80, 443}}}, Actions: []Action{{Kind: ActionAllow}}},
		{ID: "web-only-default", Name: "Block other outbound traffic", Priority: 0, Enabled: true, Match: Match{Directions: []traffic.Direction{traffic.DirectionOutbound}}, Actions: []Action{{Kind: ActionBlock}}},
	}
}
