package hardwaretest

import (
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	acknowledgement = "I_UNDERSTAND_GOLAN_WILL_MUTATE_NETWORK_STATE"

	envAcknowledgement   = "GOLAN_HARDWARE_ACK"
	envCases             = "GOLAN_HARDWARE_CASES"
	envHost              = "GOLAN_HARDWARE_HOST"
	envSwitch            = "GOLAN_HARDWARE_SWITCH"
	envTargetMAC         = "GOLAN_HARDWARE_TARGET_MAC"
	envDownstream        = "GOLAN_HARDWARE_DOWNSTREAM"
	envUpstream          = "GOLAN_HARDWARE_UPSTREAM"
	envDuration          = "GOLAN_HARDWARE_DURATION"
	envActiveTimeout     = "GOLAN_HARDWARE_ACTIVE_TIMEOUT"
	envMinPackets        = "GOLAN_HARDWARE_MIN_PACKETS"
	envExpectEAPOL       = "GOLAN_HARDWARE_EXPECT_EAPOL"
	envExpectVLAN        = "GOLAN_HARDWARE_EXPECT_VLAN"
	envAllowDefaultRoute = "GOLAN_HARDWARE_ALLOW_DEFAULT_ROUTE"
	envNATIP             = "GOLAN_HARDWARE_NAT_IP"
	envNATCIDR           = "GOLAN_HARDWARE_NAT_CIDR"
	envNATGateway        = "GOLAN_HARDWARE_NAT_GATEWAY"
	envNATDNS            = "GOLAN_HARDWARE_NAT_DNS"
	envPortForwardProto  = "GOLAN_HARDWARE_PORT_FORWARD_PROTOCOL"
	envPortForwardListen = "GOLAN_HARDWARE_PORT_FORWARD_LISTEN_PORT"
	envPortForwardTarget = "GOLAN_HARDWARE_PORT_FORWARD_TARGET_PORT"
)

type hardwareCase string

const (
	casePFSyntax      hardwareCase = "pf-syntax"
	caseFast          hardwareCase = "fast"
	caseFastDiscovery hardwareCase = "fast-discovery"
	caseControlled    hardwareCase = "controlled"
	caseNAT           hardwareCase = "nat"
	caseEdgeRoute     hardwareCase = "edge-route"
	caseEdgeForward   hardwareCase = "edge-port-forward"
)

var caseOrder = []hardwareCase{
	casePFSyntax,
	caseFast,
	caseFastDiscovery,
	caseControlled,
	caseNAT,
	caseEdgeRoute,
	caseEdgeForward,
}

type config struct {
	Enabled           bool
	Cases             []hardwareCase
	Host              string
	Switch            string
	TargetMAC         string
	Downstream        string
	Upstream          string
	Duration          time.Duration
	ActiveTimeout     time.Duration
	MinPackets        int
	ExpectEAPOL       bool
	ExpectVLAN        bool
	AllowDefaultRoute bool
	NATIP             string
	NATCIDR           string
	NATGateway        string
	NATDNS            string
	PortForwardProto  string
	PortForwardListen uint16
	PortForwardTarget uint16
}

func loadConfig(getenv func(string) string) (config, error) {
	if getenv == nil {
		return config{}, fmt.Errorf("environment reader is nil")
	}
	ack := strings.TrimSpace(getenv(envAcknowledgement))
	rawCases := strings.TrimSpace(getenv(envCases))
	if ack == "" && rawCases == "" {
		return config{}, nil
	}
	if ack != acknowledgement {
		return config{}, fmt.Errorf("%s must exactly match the documented safety acknowledgement", envAcknowledgement)
	}
	if rawCases == "" {
		return config{}, fmt.Errorf("%s must select at least one explicit case", envCases)
	}

	cases, err := parseCases(rawCases)
	if err != nil {
		return config{}, err
	}
	duration, err := parseDuration(getenv(envDuration), 15*time.Second, time.Second, 5*time.Minute, envDuration)
	if err != nil {
		return config{}, err
	}
	activeTimeout, err := parseDuration(getenv(envActiveTimeout), 90*time.Second, 5*time.Second, 10*time.Minute, envActiveTimeout)
	if err != nil {
		return config{}, err
	}
	minPackets, err := parseBoundedInt(getenv(envMinPackets), 1, 1, 1_000_000, envMinPackets)
	if err != nil {
		return config{}, err
	}
	cfg := config{
		Enabled: true, Cases: cases,
		Host: strings.TrimSpace(getenv(envHost)), Switch: strings.TrimSpace(getenv(envSwitch)),
		TargetMAC:  strings.TrimSpace(getenv(envTargetMAC)),
		Downstream: strings.TrimSpace(getenv(envDownstream)), Upstream: strings.TrimSpace(getenv(envUpstream)),
		Duration: duration, ActiveTimeout: activeTimeout, MinPackets: minPackets,
		NATIP: strings.TrimSpace(getenv(envNATIP)), NATCIDR: strings.TrimSpace(getenv(envNATCIDR)),
		NATGateway: strings.TrimSpace(getenv(envNATGateway)), NATDNS: strings.TrimSpace(getenv(envNATDNS)),
		PortForwardProto: strings.ToLower(strings.TrimSpace(getenv(envPortForwardProto))),
	}
	portForwardListen, err := parseBoundedInt(getenv(envPortForwardListen), 0, 0, 65535, envPortForwardListen)
	if err != nil {
		return config{}, err
	}
	portForwardTarget, err := parseBoundedInt(getenv(envPortForwardTarget), 0, 0, 65535, envPortForwardTarget)
	if err != nil {
		return config{}, err
	}
	cfg.PortForwardListen = uint16(portForwardListen)
	cfg.PortForwardTarget = uint16(portForwardTarget)
	for _, field := range []struct {
		name string
		dst  *bool
	}{
		{envExpectEAPOL, &cfg.ExpectEAPOL},
		{envExpectVLAN, &cfg.ExpectVLAN},
		{envAllowDefaultRoute, &cfg.AllowDefaultRoute},
	} {
		*field.dst, err = parseBool(getenv(field.name), field.name)
		if err != nil {
			return config{}, err
		}
	}
	if err := validateConfig(cfg); err != nil {
		return config{}, err
	}
	return cfg, nil
}

func parseCases(raw string) ([]hardwareCase, error) {
	selected := make(map[hardwareCase]bool)
	for _, value := range strings.Split(raw, ",") {
		candidate := hardwareCase(strings.ToLower(strings.TrimSpace(value)))
		valid := false
		for _, known := range caseOrder {
			if candidate == known {
				valid = true
				break
			}
		}
		if !valid {
			return nil, fmt.Errorf("%s contains unknown case %q", envCases, value)
		}
		selected[candidate] = true
	}
	result := make([]hardwareCase, 0, len(selected))
	for _, candidate := range caseOrder {
		if selected[candidate] {
			result = append(result, candidate)
		}
	}
	return result, nil
}

func parseDuration(raw string, fallback, minimum, maximum time.Duration, name string) (time.Duration, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return fallback, nil
	}
	value, err := time.ParseDuration(raw)
	if err != nil || value < minimum || value > maximum {
		return 0, fmt.Errorf("%s must be a duration between %s and %s", name, minimum, maximum)
	}
	return value, nil
}

func parseBoundedInt(raw string, fallback, minimum, maximum int, name string) (int, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return fallback, nil
	}
	value, err := strconv.Atoi(raw)
	if err != nil || value < minimum || value > maximum {
		return 0, fmt.Errorf("%s must be between %d and %d", name, minimum, maximum)
	}
	return value, nil
}

func parseBool(raw, name string) (bool, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return false, nil
	}
	value, err := strconv.ParseBool(raw)
	if err != nil {
		return false, fmt.Errorf("%s must be true or false", name)
	}
	return value, nil
}

func validateConfig(cfg config) error {
	selected := make(map[hardwareCase]bool, len(cfg.Cases))
	for _, candidate := range cfg.Cases {
		selected[candidate] = true
	}
	needsInline := selected[caseFast] || selected[caseFastDiscovery] || selected[caseControlled] || selected[caseNAT]
	if needsInline && (cfg.Host == "" || cfg.Switch == "") {
		return fmt.Errorf("%s and %s are required for inline cases", envHost, envSwitch)
	}
	if needsInline && strings.EqualFold(cfg.Host, cfg.Switch) {
		return fmt.Errorf("host and switch adapters must differ")
	}
	if selected[caseFast] || selected[caseNAT] {
		if err := validateTargetMAC(cfg.TargetMAC); err != nil {
			return fmt.Errorf("%s: %w", envTargetMAC, err)
		}
	}
	if selected[caseEdgeRoute] || selected[caseEdgeForward] {
		if cfg.Downstream == "" {
			return fmt.Errorf("%s is required for edge cases", envDownstream)
		}
		if cfg.Upstream != "" && strings.EqualFold(cfg.Downstream, cfg.Upstream) {
			return fmt.Errorf("downstream and upstream adapters must differ")
		}
	}
	if selected[caseEdgeForward] {
		if cfg.PortForwardProto != "tcp" && cfg.PortForwardProto != "udp" {
			return fmt.Errorf("%s must be tcp or udp for edge-port-forward", envPortForwardProto)
		}
		if cfg.PortForwardListen == 0 || cfg.PortForwardTarget == 0 {
			return fmt.Errorf("%s and %s must be non-zero for edge-port-forward", envPortForwardListen, envPortForwardTarget)
		}
	}
	if cfg.NATIP == "" && cfg.NATCIDR != "" {
		return fmt.Errorf("%s requires %s", envNATCIDR, envNATIP)
	}
	if cfg.NATIP != "" && cfg.NATCIDR == "" {
		return fmt.Errorf("%s requires %s", envNATIP, envNATCIDR)
	}
	return nil
}

func validateTargetMAC(raw string) error {
	mac, err := net.ParseMAC(strings.TrimSpace(raw))
	if err != nil || len(mac) != 6 {
		return fmt.Errorf("must be a 48-bit MAC address")
	}
	if mac[0]&1 != 0 || isZeroMAC(mac) {
		return fmt.Errorf("must be a non-zero unicast MAC address")
	}
	return nil
}

func isZeroMAC(mac net.HardwareAddr) bool {
	for _, value := range mac {
		if value != 0 {
			return false
		}
	}
	return true
}

func knownCaseNames() []string {
	result := make([]string, 0, len(caseOrder))
	for _, candidate := range caseOrder {
		result = append(result, string(candidate))
	}
	sort.Strings(result)
	return result
}
