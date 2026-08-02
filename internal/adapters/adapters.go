package adapters

import (
	"context"
	"errors"
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
	// NetworkService is the separately renameable macOS service accepted by
	// networksetup. It is empty on non-macOS platforms or when no mapping exists.
	NetworkService string
	Kind           string
	MAC            string
	MTU            int
	IsUp           bool
	Addrs          []string
	Flags          []string
}

// HardwarePort describes a physical macOS port and the separately named
// network service that owns it. Network services can be renamed independently
// of their hardware-port label.
type HardwarePort struct {
	Name           string
	Device         string
	MAC            string
	NetworkService string
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
// optional platform enrichment second. It may return a partial adapter list
// with an error when enrichment or one interface address lookup fails.
func Discover(ctx context.Context) ([]Adapter, error) {
	if ctx == nil {
		ctx = context.Background()
	}

	netIfaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("list interfaces: %w", err)
	}

	hardware, hardwareErr := discoverHardwarePorts(ctx)
	out := make([]Adapter, 0, len(netIfaces))
	var discoverErrs []error
	if hardwareErr != nil {
		discoverErrs = append(discoverErrs, hardwareErr)
	}

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

		addrs, err := iface.Addrs()
		if err != nil {
			discoverErrs = append(discoverErrs, fmt.Errorf("list addresses for %s: %w", iface.Name, err))
		}
		out = append(out, Adapter{
			Name:           iface.Name,
			HardwarePort:   hw.Name,
			NetworkService: hw.NetworkService,
			Kind:           classifyKind(hw.Name, iface.Name),
			MAC:            mac,
			MTU:            iface.MTU,
			IsUp:           iface.Flags&net.FlagUp != 0,
			Addrs:          addrStrings(addrs),
			Flags:          flagStrings(iface.Flags),
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

	return out, errors.Join(discoverErrs...)
}

func discoverHardwarePorts(ctx context.Context) (map[string]HardwarePort, error) {
	if runtime.GOOS != "darwin" {
		return map[string]HardwarePort{}, nil
	}

	out, err := runNetworkSetup(ctx, "-listallhardwareports")
	if err != nil {
		output := strings.TrimSpace(string(out))
		if output == "" {
			return map[string]HardwarePort{}, fmt.Errorf("list macOS hardware ports: %w", err)
		}
		return map[string]HardwarePort{}, fmt.Errorf("list macOS hardware ports: %w (%s)", err, output)
	}
	ports := ParseHardwarePorts(string(out))
	serviceOutput, serviceErr := runNetworkSetup(ctx, "-listnetworkserviceorder")
	if serviceErr != nil {
		output := strings.TrimSpace(string(serviceOutput))
		if output == "" {
			return ports, fmt.Errorf("list macOS network services: %w", serviceErr)
		}
		return ports, fmt.Errorf("list macOS network services: %w (%s)", serviceErr, output)
	}
	for device, service := range ParseNetworkServiceOrder(string(serviceOutput)) {
		port, ok := ports[device]
		if !ok {
			continue
		}
		port.NetworkService = service
		ports[device] = port
	}
	return ports, nil
}

func runNetworkSetup(ctx context.Context, args ...string) ([]byte, error) {
	runCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	return exec.CommandContext(runCtx, "networksetup", args...).CombinedOutput()
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

// ParseNetworkServiceOrder maps each macOS interface device to the network
// service name that networksetup accepts for enable/disable operations.
func ParseNetworkServiceOrder(output string) map[string]string {
	services := make(map[string]string)
	current := ""
	for _, raw := range strings.Split(output, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "(") && !strings.HasPrefix(line, "(Hardware Port:") {
			if closeIndex := strings.IndexByte(line, ')'); closeIndex >= 0 {
				current = strings.TrimSpace(line[closeIndex+1:])
			}
			continue
		}
		if current == "" || !strings.HasPrefix(line, "(Hardware Port:") {
			continue
		}
		deviceIndex := strings.Index(line, "Device:")
		if deviceIndex < 0 {
			current = ""
			continue
		}
		device := strings.TrimSpace(line[deviceIndex+len("Device:"):])
		device = strings.TrimSuffix(device, ")")
		if commaIndex := strings.IndexByte(device, ','); commaIndex >= 0 {
			device = device[:commaIndex]
		}
		device = strings.TrimSpace(device)
		if device != "" {
			services[device] = current
		}
		current = ""
	}
	return services
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
