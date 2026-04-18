package bridge

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
)

// InterfaceType represents the kind of network interface.
type InterfaceType string

const (
	TypeWiFi        InterfaceType = "Wi-Fi"
	TypeEthernet    InterfaceType = "Ethernet"
	TypeUSBEthernet InterfaceType = "USB Ethernet"
	TypeThunderbolt InterfaceType = "Thunderbolt"
	TypeBluetooth   InterfaceType = "Bluetooth"
	TypeFirewire    InterfaceType = "FireWire"
	TypeBridge      InterfaceType = "Bridge"
	TypeOther       InterfaceType = "Other"
)

// ShortType returns a compact label for the interface type.
func (t InterfaceType) ShortType() string {
	switch t {
	case TypeWiFi:
		return "Wi-Fi"
	case TypeUSBEthernet:
		return "USB Eth"
	case TypeThunderbolt:
		return "TB Eth"
	case TypeBluetooth:
		return "BT"
	case TypeFirewire:
		return "FW"
	case TypeEthernet:
		return "Ethernet"
	case TypeBridge:
		return "Bridge"
	default:
		return "Other"
	}
}

// NetInterface holds all relevant metadata for a network interface.
type NetInterface struct {
	Name         string
	HardwarePort string        // Human-readable name from networksetup, e.g. "USB 10/100/1000 LAN"
	Type         InterfaceType
	HardwareAddr net.HardwareAddr
	CurrentMAC   string // May differ from permanent if spoofed
	PermanentMAC string // Factory MAC from networksetup
	IsUp         bool
	IsUSB        bool
	IsSpoofed    bool
	MTU          int
	Addrs        []string
	Flags        net.Flags
}

// InterfaceDetail holds live metadata for a network interface's detail panel.
type InterfaceDetail struct {
	IPv4        string
	Netmask     string
	Broadcast   string
	IPv6        string
	Gateway     string
	DNS         []string
	DHCPServer  string
	LeaseTime   string
	MTU         string
	Media       string
	Flags       string
	PktsIn      string
	PktsOut     string
	BytesIn     string
	BytesOut    string
	ErrsIn      string
	ErrsOut     string
	Colls       string
	Dot1XStatus string // "active", "configured", "none"
	Dot1XMethod string // EAP method if available
}

// DiscoverInterfaces returns ALL network interfaces with enriched metadata.
func DiscoverInterfaces() ([]NetInterface, error) {
	// Parse networksetup for hardware port mapping.
	out, err := exec.Command("networksetup", "-listallhardwareports").CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("networksetup: %w", err)
	}

	ifaces := parseHardwarePorts(string(out))

	// Enrich each interface.
	for i := range ifaces {
		ifaces[i].CurrentMAC = getCurrentMAC(ifaces[i].Name)
		// Permanent MAC is now parsed directly from networksetup -listallhardwareports
		ifaces[i].IsUp = isInterfaceUp(ifaces[i].Name)
		ifaces[i].Type = classifyType(ifaces[i].HardwarePort)
		ifaces[i].IsUSB = ifaces[i].Type == TypeUSBEthernet

		if ifaces[i].CurrentMAC != "" && ifaces[i].PermanentMAC != "" &&
			!strings.EqualFold(ifaces[i].CurrentMAC, ifaces[i].PermanentMAC) {
			ifaces[i].IsSpoofed = true
		}

		// Parse HardwareAddr from CurrentMAC.
		if ifaces[i].CurrentMAC != "" {
			if hw, err := net.ParseMAC(ifaces[i].CurrentMAC); err == nil {
				ifaces[i].HardwareAddr = hw
			}
		}

		// Get MTU from net.Interfaces.
		if ni, err := net.InterfaceByName(ifaces[i].Name); err == nil {
			ifaces[i].MTU = ni.MTU
			ifaces[i].Flags = ni.Flags
			addrs, _ := ni.Addrs()
			for _, a := range addrs {
				ifaces[i].Addrs = append(ifaces[i].Addrs, a.String())
			}
		}
	}

	return ifaces, nil
}

// GetInterfaceDetail fetches live metadata for a given interface.
func GetInterfaceDetail(device string) InterfaceDetail {
	var d InterfaceDetail

	// Parse ifconfig output.
	out, err := exec.Command("ifconfig", device).CombinedOutput()
	if err == nil {
		d.parseIfconfig(string(out))
	}

	// Parse netstat for packet/byte counters.
	out, err = exec.Command("netstat", "-bI", device).CombinedOutput()
	if err == nil {
		d.parseNetstat(string(out), device)
	}

	// Gateway.
	out, err = exec.Command("route", "-n", "get", "default").CombinedOutput()
	if err == nil {
		d.parseGateway(string(out))
	}

	// DNS servers.
	out, err = exec.Command("scutil", "--dns").CombinedOutput()
	if err == nil {
		d.parseDNS(string(out))
	}

	// DHCP lease info.
	out, err = exec.Command("ipconfig", "getpacket", device).CombinedOutput()
	if err == nil {
		d.parseDHCP(string(out))
	}

	// 802.1X detection.
	d.detect8021X(device)

	return d
}

// detect8021X checks for 802.1X authentication state on the interface.
func (d *InterfaceDetail) detect8021X(device string) {
	d.Dot1XStatus = "none"

	// Check if eapolclient is actively running for this interface.
	out, err := exec.Command("ps", "aux").CombinedOutput()
	if err == nil {
		for _, line := range strings.Split(string(out), "\n") {
			if strings.Contains(line, "eapolclient") && strings.Contains(line, device) {
				d.Dot1XStatus = "active"
				for _, method := range []string{"PEAP", "TLS", "TTLS", "EAP-FAST", "LEAP", "MD5"} {
					if strings.Contains(strings.ToUpper(line), method) {
						d.Dot1XMethod = method
						break
					}
				}
				break
			}
		}
	}

	// If not actively running, check if 802.1X is configured.
	if d.Dot1XStatus == "none" {
		configPath := "/Library/Preferences/SystemConfiguration/com.apple.network.eapolclient.configuration.plist"
		if _, err := os.Stat(configPath); err == nil {
			out, err := exec.Command("defaults", "read", configPath).CombinedOutput()
			if err == nil && strings.Contains(string(out), device) {
				d.Dot1XStatus = "configured"
			} else if err == nil && len(string(out)) > 10 {
				d.Dot1XStatus = "configured"
			}
		}
	}
}

func (d *InterfaceDetail) parseGateway(output string) {
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "gateway:") {
			d.Gateway = strings.TrimSpace(strings.TrimPrefix(line, "gateway:"))
		}
	}
}

func (d *InterfaceDetail) parseDNS(output string) {
	seen := make(map[string]bool)
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "nameserver[") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				ip := strings.TrimSpace(parts[1])
				if !seen[ip] {
					seen[ip] = true
					d.DNS = append(d.DNS, ip)
				}
			}
		}
	}
}

func (d *InterfaceDetail) parseDHCP(output string) {
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "server_identifier") {
			if idx := strings.LastIndex(line, ":"); idx != -1 {
				d.DHCPServer = strings.TrimSpace(line[idx+1:])
			}
		}
		if strings.HasPrefix(line, "lease_time") {
			if idx := strings.LastIndex(line, ":"); idx != -1 {
				hexVal := strings.TrimSpace(line[idx+1:])
				hexVal = strings.TrimPrefix(hexVal, "0x")
				var secs int64
				if _, err := fmt.Sscanf(hexVal, "%x", &secs); err == nil {
					hours := secs / 3600
					mins := (secs % 3600) / 60
					if hours > 0 {
						d.LeaseTime = fmt.Sprintf("%dh %dm", hours, mins)
					} else {
						d.LeaseTime = fmt.Sprintf("%dm", mins)
					}
				}
			}
		}
	}
}

func (d *InterfaceDetail) parseIfconfig(output string) {
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)

		// Flags and MTU.
		if strings.Contains(line, "flags=") && strings.Contains(line, "<") {
			if start := strings.Index(line, "<"); start != -1 {
				if end := strings.Index(line, ">"); end != -1 && end > start {
					d.Flags = line[start+1 : end]
				}
			}
			if idx := strings.Index(line, "mtu "); idx != -1 {
				d.MTU = strings.Fields(line[idx:])[1]
			}
		}

		// IPv4.
		if strings.HasPrefix(line, "inet ") && !strings.HasPrefix(line, "inet6") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				d.IPv4 = fields[1]
			}
			for i, f := range fields {
				if f == "netmask" && i+1 < len(fields) {
					d.Netmask = hexMaskToDecimal(fields[i+1])
				}
				if f == "broadcast" && i+1 < len(fields) {
					d.Broadcast = fields[i+1]
				}
			}
		}

		// IPv6.
		if strings.HasPrefix(line, "inet6 ") && d.IPv6 == "" {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				addr := fields[1]
				if idx := strings.Index(addr, "%"); idx != -1 {
					addr = addr[:idx]
				}
				d.IPv6 = addr
			}
		}

		// Media.
		if strings.HasPrefix(line, "media:") {
			d.Media = strings.TrimPrefix(line, "media: ")
		}
	}
}

func (d *InterfaceDetail) parseNetstat(output, device string) {
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) < 11 {
			continue
		}
		if fields[0] == device && strings.Contains(fields[2], "Link#") {
			d.PktsIn = FormatNumber(fields[4])
			d.ErrsIn = fields[5]
			d.BytesIn = FormatBytes(fields[6])
			d.PktsOut = fields[7]
			d.ErrsOut = fields[8]
			d.BytesOut = FormatBytes(fields[9])
			d.Colls = fields[10]
			break
		}
	}
}

// ─── Helpers ────────────────────────────────────────────────────────────────

// parseHardwarePorts parses `networksetup -listallhardwareports` output.
func parseHardwarePorts(output string) []NetInterface {
	var ifaces []NetInterface
	var current NetInterface
	inEntry := false

	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "Hardware Port:") {
			if inEntry && current.Name != "" {
				ifaces = append(ifaces, current)
			}
			current = NetInterface{}
			current.HardwarePort = strings.TrimPrefix(line, "Hardware Port: ")
			inEntry = true
		} else if strings.HasPrefix(line, "Device:") {
			current.Name = strings.TrimPrefix(line, "Device: ")
		} else if strings.HasPrefix(line, "Ethernet Address:") {
			current.PermanentMAC = strings.TrimSpace(strings.TrimPrefix(line, "Ethernet Address:"))
		}
	}
	if inEntry && current.Name != "" {
		ifaces = append(ifaces, current)
	}

	return ifaces
}

// classifyType maps a hardware port name to a normalized InterfaceType.
func classifyType(hardwarePort string) InterfaceType {
	hp := strings.ToLower(hardwarePort)
	switch {
	case hp == "wi-fi":
		return TypeWiFi
	case strings.Contains(hp, "usb"):
		return TypeUSBEthernet
	case strings.Contains(hp, "thunderbolt"):
		return TypeThunderbolt
	case strings.Contains(hp, "bluetooth"):
		return TypeBluetooth
	case strings.Contains(hp, "firewire"):
		return TypeFirewire
	case strings.Contains(hp, "ethernet"):
		return TypeEthernet
	default:
		return TypeOther
	}
}

// getCurrentMAC retrieves the current (possibly spoofed) MAC from ifconfig.
func getCurrentMAC(device string) string {
	out, err := exec.Command("ifconfig", device).CombinedOutput()
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "ether ") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				return parts[1]
			}
		}
	}
	return ""
}



// isInterfaceUp checks ifconfig status flags for active status.
func isInterfaceUp(device string) bool {
	out, err := exec.Command("ifconfig", device).CombinedOutput()
	if err != nil {
		return false
	}
	return strings.Contains(string(out), "status: active")
}

// hexMaskToDecimal converts "0xffffff00" to "255.255.255.0".
func hexMaskToDecimal(hex string) string {
	hex = strings.TrimPrefix(hex, "0x")
	if len(hex) != 8 {
		return hex
	}
	var octets [4]byte
	for i := 0; i < 4; i++ {
		var b byte
		_, _ = fmt.Sscanf(hex[i*2:i*2+2], "%x", &b)
		octets[i] = b
	}
	return fmt.Sprintf("%d.%d.%d.%d", octets[0], octets[1], octets[2], octets[3])
}

// FormatBytes converts a byte count string to human-readable.
func FormatBytes(s string) string {
	var n float64
	_, err := fmt.Sscanf(s, "%f", &n)
	if err != nil {
		return s
	}
	switch {
	case n >= 1e12:
		return fmt.Sprintf("%.1f TB", n/1e12)
	case n >= 1e9:
		return fmt.Sprintf("%.1f GB", n/1e9)
	case n >= 1e6:
		return fmt.Sprintf("%.1f MB", n/1e6)
	case n >= 1e3:
		return fmt.Sprintf("%.1f KB", n/1e3)
	default:
		return fmt.Sprintf("%.0f B", n)
	}
}

// FormatNumber adds comma separators to large numbers.
func FormatNumber(s string) string {
	var n int64
	_, err := fmt.Sscanf(s, "%d", &n)
	if err != nil {
		return s
	}
	if n < 1000 {
		return s
	}
	str := fmt.Sprintf("%d", n)
	var result []byte
	for i, c := range str {
		if i > 0 && (len(str)-i)%3 == 0 {
			result = append(result, ',')
		}
		result = append(result, byte(c))
	}
	return string(result)
}
