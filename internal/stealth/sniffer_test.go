package stealth

import (
	"net"
	"testing"
)

func TestOptionalMACValidatesUsableUnicastAddress(t *testing.T) {
	mac, err := optionalMAC("02:00:00:00:00:11")
	if err != nil {
		t.Fatalf("optionalMAC: %v", err)
	}
	if got := mac.String(); got != "02:00:00:00:00:11" {
		t.Fatalf("MAC = %s", got)
	}
	for _, value := range []string{"bad", "ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00"} {
		if _, err := optionalMAC(value); err == nil {
			t.Errorf("optionalMAC(%q) succeeded", value)
		}
	}
}

func TestCopyIdentityDoesNotAliasMutableState(t *testing.T) {
	original := TargetIdentity{
		MAC:              net.HardwareAddr{0x02, 0, 0, 0, 0, 0x11},
		IP:               net.IPv4(192, 0, 2, 10),
		Netmask:          net.CIDRMask(24, 32),
		Gateway:          net.IPv4(192, 0, 2, 1),
		AuthenticatorMAC: net.HardwareAddr{0x02, 0, 0, 0, 0, 0x22},
		VLANs:            []uint16{100},
	}
	copy := copyIdentity(original)
	copy.MAC[5] = 0xff
	copy.IP[0] = 0
	copy.Netmask[0] = 0
	copy.Gateway[0] = 0
	copy.AuthenticatorMAC[5] = 0xff
	copy.VLANs[0] = 200

	if original.MAC[5] != 0x11 || original.IP.String() != "192.0.2.10" || original.Netmask.String() != "ffffff00" || original.Gateway.String() != "192.0.2.1" || original.AuthenticatorMAC[5] != 0x22 || original.VLANs[0] != 100 {
		t.Fatalf("copy aliased original: %+v", original)
	}
}
