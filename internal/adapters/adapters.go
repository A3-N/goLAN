package adapters

import (
	"context"
	"fmt"
	"net"
	"os/exec"
	"runtime"
	"sort"
	"strings"
	"time"
)

// Adapter is the normalized interface shape used by golan.
type Adapter struct {
	Name         string
	HardwarePort string
	Kind         string
	MAC          string
	MTU          int
	IsUp         bool
	Addrs        []string
	Flags        []string
}

// HardwarePort describes the platform-specific hardware service mapping.
type HardwarePort struct {
	Name   string
	Device string
	MAC    string
}

// Status returns a compact link state label for display.
func (a Adapter) Status() string {
	if a.IsUp {
		return "up"
	}
	return "down"
}

// PrimaryAddr returns the first assigned address, if any.
func (a Adapter) PrimaryAddr() string {
	if len(a.Addrs) == 0 {
		return ""
	}
	return a.Addrs[0]
}

// Discover returns network adapters with stable, portable metadata first and
// optional platform enrichment second.
func Discover(ctx context.Context) ([]Adapter, error) {
	if ctx == nil {
		ctx = context.Background()
	}

	netIfaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("list interfaces: %w", err)
	}

	hardware := discoverHardwarePorts(ctx)
	out := make([]Adapter, 0, len(netIfaces))

	for _, iface := range netIfaces {
		if iface.Flags&net.FlagLoopback != 0 {
			continue
		}

		hw := hardware[iface.Name]
		mac := iface.HardwareAddr.String()
		if mac == "" {
			mac = hw.MAC
		}
		if mac == "" && hw.Name == "" {
			continue
		}

		addrs, _ := iface.Addrs()
		out = append(out, Adapter{
			Name:         iface.Name,
			HardwarePort: hw.Name,
			Kind:         classifyKind(hw.Name, iface.Name),
			MAC:          mac,
			MTU:          iface.MTU,
			IsUp:         iface.Flags&net.FlagUp != 0,
			Addrs:        addrStrings(addrs),
			Flags:        flagStrings(iface.Flags),
		})
	}

	sort.Slice(out, func(i, j int) bool {
		leftPhysical := out[i].HardwarePort != ""
		rightPhysical := out[j].HardwarePort != ""
		if leftPhysical != rightPhysical {
			return leftPhysical
		}
		return out[i].Name < out[j].Name
	})

	return out, nil
}

func discoverHardwarePorts(ctx context.Context) map[string]HardwarePort {
	if runtime.GOOS != "darwin" {
		return map[string]HardwarePort{}
	}

	runCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	out, err := exec.CommandContext(runCtx, "networksetup", "-listallhardwareports").CombinedOutput()
	if err != nil {
		return map[string]HardwarePort{}
	}
	return ParseHardwarePorts(string(out))
}

// ParseHardwarePorts parses the macOS networksetup hardware-port listing.
func ParseHardwarePorts(output string) map[string]HardwarePort {
	ports := make(map[string]HardwarePort)
	var current HardwarePort

	flush := func() {
		if current.Device != "" {
			ports[current.Device] = current
		}
		current = HardwarePort{}
	}

	for _, raw := range strings.Split(output, "\n") {
		line := strings.TrimSpace(raw)
		switch {
		case strings.HasPrefix(line, "Hardware Port:"):
			flush()
			current.Name = strings.TrimSpace(strings.TrimPrefix(line, "Hardware Port:"))
		case strings.HasPrefix(line, "Device:"):
			current.Device = strings.TrimSpace(strings.TrimPrefix(line, "Device:"))
		case strings.HasPrefix(line, "Ethernet Address:"):
			current.MAC = strings.TrimSpace(strings.TrimPrefix(line, "Ethernet Address:"))
		}
	}
	flush()

	return ports
}

func classifyKind(hardwarePort, name string) string {
	value := strings.ToLower(hardwarePort + " " + name)
	switch {
	case strings.Contains(value, "wi-fi") || strings.Contains(value, "wifi") || strings.Contains(value, "airport"):
		return "wifi"
	case strings.Contains(value, "usb"):
		return "usb-ethernet"
	case strings.Contains(value, "thunderbolt"):
		return "thunderbolt"
	case strings.Contains(value, "bridge"):
		return "bridge"
	case strings.Contains(value, "ethernet") || strings.HasPrefix(name, "en"):
		return "ethernet"
	default:
		return "other"
	}
}

func addrStrings(addrs []net.Addr) []string {
	out := make([]string, 0, len(addrs))
	for _, addr := range addrs {
		if addr != nil {
			out = append(out, addr.String())
		}
	}
	sort.Strings(out)
	return out
}

func flagStrings(flags net.Flags) []string {
	var out []string
	if flags&net.FlagUp != 0 {
		out = append(out, "up")
	}
	if flags&net.FlagBroadcast != 0 {
		out = append(out, "broadcast")
	}
	if flags&net.FlagMulticast != 0 {
		out = append(out, "multicast")
	}
	if flags&net.FlagPointToPoint != 0 {
		out = append(out, "point-to-point")
	}
	return out
}
