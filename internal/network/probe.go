package network

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os/exec"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"
)

// ProbeKind identifies one bounded, mutation-free diagnostic.
type ProbeKind string

const (
	ProbeGateway ProbeKind = "gateway"
	ProbeDNS     ProbeKind = "dns"
	ProbeRoute   ProbeKind = "route"
	ProbeDevice  ProbeKind = "device"
	ProbeDHCP    ProbeKind = "dhcp"
	probeTimeout           = 3 * time.Second
)

// ProbePlan is an inert, validated probe awaiting an explicit run command.
type ProbePlan struct {
	Kind        ProbeKind
	Target      string
	Port        uint16
	Description string
}

// ProbeResult is bounded diagnostic output. It is not persisted in Network
// sessions or passports.
type ProbeResult struct {
	Status   StageStatus
	Summary  string
	Details  []string
	Duration time.Duration
}

// NewProbePlan validates exact user input without touching the network.
func NewProbePlan(kind string, args ...string) (ProbePlan, error) {
	probeKind := ProbeKind(strings.ToLower(strings.TrimSpace(kind)))
	var target string
	var port uint16
	switch probeKind {
	case ProbeGateway, ProbeRoute:
		if len(args) != 1 || net.ParseIP(strings.TrimSpace(args[0])) == nil {
			return ProbePlan{}, fmt.Errorf("%s probe requires one exact IP address", probeKind)
		}
		target = strings.TrimSpace(args[0])
	case ProbeDNS:
		if len(args) != 1 || !validProbeName(args[0]) {
			return ProbePlan{}, fmt.Errorf("dns probe requires one hostname")
		}
		target = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(args[0])), ".")
	case ProbeDevice:
		if len(args) != 2 || net.ParseIP(strings.TrimSpace(args[0])) == nil {
			return ProbePlan{}, fmt.Errorf("device probe requires an exact IP address and TCP port")
		}
		parsedPort, err := strconv.ParseUint(strings.TrimSpace(args[1]), 10, 16)
		if err != nil || parsedPort == 0 {
			return ProbePlan{}, fmt.Errorf("device probe TCP port is invalid")
		}
		target, port = strings.TrimSpace(args[0]), uint16(parsedPort)
	case ProbeDHCP:
		if len(args) != 1 || !validProbeAdapter(args[0]) {
			return ProbePlan{}, fmt.Errorf("dhcp probe requires one macOS adapter name")
		}
		target = strings.TrimSpace(args[0])
	default:
		return ProbePlan{}, fmt.Errorf("probe kind must be gateway, dns, route, device, or dhcp")
	}
	return canonicalProbePlan(probeKind, target, port)
}

// RunProbe executes one validated plan once with a fixed deadline.
func RunProbe(ctx context.Context, plan ProbePlan) ProbeResult {
	started := time.Now()
	result := ProbeResult{Status: StageFail}
	validated, err := canonicalProbePlan(plan.Kind, plan.Target, plan.Port)
	if err != nil || validated != plan {
		result.Summary = "probe plan is invalid"
		return result
	}
	ctx, cancel := context.WithTimeout(ctx, probeTimeout)
	defer cancel()
	switch plan.Kind {
	case ProbeGateway:
		result = runGatewayProbe(ctx, plan)
	case ProbeDNS:
		result = runDNSProbe(ctx, plan)
	case ProbeRoute:
		result = runRouteProbe(ctx, plan)
	case ProbeDevice:
		result = runDeviceProbe(ctx, plan)
	case ProbeDHCP:
		result = runDHCPProbe(ctx, plan)
	}
	result.Duration = time.Since(started)
	return result
}

func runGatewayProbe(ctx context.Context, plan ProbePlan) ProbeResult {
	result := ProbeResult{Status: StageFail}
	if runtime.GOOS != "darwin" {
		result.Status = StageSkip
		result.Summary = "gateway probe is available on macOS"
		return result
	}
	output, err := exec.CommandContext(ctx, "/sbin/ping", "-n", "-c", "1", "-W", "1000", plan.Target).CombinedOutput()
	if err != nil {
		result.Summary = "gateway did not answer the bounded ICMP probe"
		result.Details = boundedProbeLines(string(output), 2)
		return result
	}
	result.Status = StagePass
	result.Summary = "gateway answered one ICMP echo"
	result.Details = boundedProbeLines(string(output), 2)
	return result
}

func runDNSProbe(ctx context.Context, plan ProbePlan) ProbeResult {
	result := ProbeResult{Status: StageFail}
	addresses, err := net.DefaultResolver.LookupHost(ctx, plan.Target)
	if err != nil {
		result.Summary = "system resolver failed: " + cleanText(err.Error())
		return result
	}
	addresses = unionStrings(nil, addresses)
	if len(addresses) > 8 {
		addresses = addresses[:8]
	}
	result.Status = StagePass
	result.Summary = fmt.Sprintf("resolved %d address(es)", len(addresses))
	result.Details = addresses
	return result
}

func runRouteProbe(ctx context.Context, plan ProbePlan) ProbeResult {
	result := ProbeResult{Status: StageFail}
	dialer := net.Dialer{}
	connection, err := dialer.DialContext(ctx, "udp", net.JoinHostPort(plan.Target, "53"))
	if err != nil {
		result.Summary = "route selection failed: " + cleanText(err.Error())
		return result
	}
	local := connection.LocalAddr().String()
	remote := connection.RemoteAddr().String()
	_ = connection.Close()
	result.Status = StagePass
	result.Summary = "kernel selected a route"
	result.Details = []string{"local " + local, "destination " + remote, "no application data sent"}
	return result
}

func runDeviceProbe(ctx context.Context, plan ProbePlan) ProbeResult {
	result := ProbeResult{Status: StageFail}
	address := net.JoinHostPort(plan.Target, strconv.Itoa(int(plan.Port)))
	dialer := net.Dialer{}
	connection, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		result.Summary = "TCP connection failed: " + cleanText(err.Error())
		return result
	}
	local := connection.LocalAddr().String()
	_ = connection.Close()
	result.Status = StagePass
	result.Summary = "TCP connection opened and closed"
	result.Details = []string{"target " + address, "local " + local}
	return result
}

func runDHCPProbe(ctx context.Context, plan ProbePlan) ProbeResult {
	result := ProbeResult{Status: StageFail}
	if runtime.GOOS != "darwin" {
		result.Status = StageSkip
		result.Summary = "DHCP lease inspection is available on macOS"
		return result
	}
	output, err := exec.CommandContext(ctx, "/usr/sbin/ipconfig", "getpacket", plan.Target).CombinedOutput()
	if err != nil {
		result.Summary = "existing DHCP lease is unavailable"
		return result
	}
	result.Details = filteredDHCPLease(string(output))
	if len(result.Details) == 0 {
		result.Status = StageWarn
		result.Summary = "lease exists but no routing fields were readable"
		return result
	}
	result.Status = StagePass
	result.Summary = "existing DHCP lease inspected without renewal"
	return result
}

func canonicalProbePlan(kind ProbeKind, target string, port uint16) (ProbePlan, error) {
	plan := ProbePlan{Kind: kind, Target: target, Port: port}
	switch kind {
	case ProbeGateway:
		if net.ParseIP(target) == nil || port != 0 {
			return ProbePlan{}, fmt.Errorf("gateway probe requires one exact IP address")
		}
		plan.Description = "send one ICMP echo to gateway " + target
	case ProbeDNS:
		if !validProbeName(target) || target != strings.TrimSuffix(strings.ToLower(strings.TrimSpace(target)), ".") || port != 0 {
			return ProbePlan{}, fmt.Errorf("dns probe requires one hostname")
		}
		plan.Description = "perform one bounded system-resolver lookup for " + target
	case ProbeRoute:
		if net.ParseIP(target) == nil || port != 0 {
			return ProbePlan{}, fmt.Errorf("route probe requires one exact IP address")
		}
		plan.Description = "resolve the local route selection for " + target + " without sending application data"
	case ProbeDevice:
		if net.ParseIP(target) == nil || port == 0 {
			return ProbePlan{}, fmt.Errorf("device probe requires an exact IP address and TCP port")
		}
		plan.Description = fmt.Sprintf("attempt one TCP connection to %s", net.JoinHostPort(target, strconv.Itoa(int(port))))
	case ProbeDHCP:
		if !validProbeAdapter(target) || target != strings.TrimSpace(target) || port != 0 {
			return ProbePlan{}, fmt.Errorf("dhcp probe requires one macOS adapter name")
		}
		plan.Description = "read the existing DHCP lease on " + target + " without soliciting a new lease"
	default:
		return ProbePlan{}, fmt.Errorf("probe kind must be gateway, dns, route, device, or dhcp")
	}
	return plan, nil
}

func validProbeName(value string) bool {
	value = strings.TrimSuffix(strings.TrimSpace(value), ".")
	if value == "" || len(value) > 253 || strings.ContainsAny(value, "\x00\r\n /\\") {
		return false
	}
	for _, label := range strings.Split(value, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, character := range label {
			if character != '-' && (character < 'a' || character > 'z') && (character < 'A' || character > 'Z') && (character < '0' || character > '9') {
				return false
			}
		}
	}
	return true
}

func validProbeAdapter(value string) bool {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > 64 {
		return false
	}
	for _, character := range value {
		if character != '-' && character != '_' && character != '.' && character != ':' &&
			(character < 'a' || character > 'z') && (character < 'A' || character > 'Z') && (character < '0' || character > '9') {
			return false
		}
	}
	return true
}

func filteredDHCPLease(output string) []string {
	allowed := map[string]bool{
		"yiaddr": true, "server_identifier": true, "router": true, "domain_name_server": true,
		"subnet_mask": true, "lease_time": true,
	}
	var result []string
	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() && len(result) < 8 {
		line := strings.TrimSpace(scanner.Text())
		key := line
		if index := strings.IndexAny(key, " ={"); index >= 0 {
			key = key[:index]
		}
		if allowed[key] {
			result = append(result, cleanText(line))
		}
	}
	sort.Strings(result)
	return result
}

func boundedProbeLines(output string, limit int) []string {
	var result []string
	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() && len(result) < limit {
		line := cleanText(strings.TrimSpace(scanner.Text()))
		if line != "" {
			result = append(result, line)
		}
	}
	return result
}
