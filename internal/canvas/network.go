package canvas

import (
	"strings"

	networkobs "golan/internal/network"
)

// FromNetworkSession builds a topology map from sanitized device observations.
// It never accepts packet bytes or categorical risk detail.
func FromNetworkSession(session networkobs.Session) *Map {
	generated := NewMap()
	for _, device := range session.Devices {
		ips := device.IPs
		if len(ips) == 0 {
			ips = []string{""}
		}
		for _, ip := range ips {
			generated.Apply(Observation{
				Kind: "host", IP: ip, MAC: device.MAC,
				Adapter: device.Adapter, Role: device.Role,
				Tag: "observed-device", Note: "network session " + session.ID,
			})
		}
		for _, observation := range device.Observations {
			switch observation.Category {
			case networkobs.CategoryDNS, networkobs.CategoryHTTP, networkobs.CategoryAccess, networkobs.CategoryAction:
			default:
				continue
			}
			if observation.Source == "" || observation.Destination == "" {
				continue
			}
			generated.Apply(Observation{
				Kind: "conversation", SrcIP: observation.Source, SrcMAC: device.MAC,
				DstIP: observation.Destination, Protocol: strings.ToUpper(observation.Protocol),
				Service: string(observation.Category), Note: observation.Summary,
			})
		}
	}
	return generated
}
