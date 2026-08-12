// Package doctor performs bounded, read-only Workbench readiness checks.
package doctor

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"
	"unicode"

	"golan/internal/adapters"
	"golan/internal/edge"
	workproject "golan/internal/project"
)

const detailLimit = 240

// Status is the bounded result class for one readiness check.
type Status string

const (
	StatusPass Status = "PASS"
	StatusWarn Status = "WARN"
	StatusFail Status = "FAIL"
	StatusSkip Status = "SKIP"
)

// Check is one payload-free diagnostic result.
type Check struct {
	Area   string
	Name   string
	Status Status
	Detail string
}

// Report is the deterministic ordered doctor result.
type Report struct {
	Checks []Check
}

// Restoration describes only pending ownership and cleanup counts.
type Restoration struct {
	RuntimeActive       bool
	RuntimeOperation    string
	InterfaceSnapshots  int
	InterfacePending    int
	LockPending         int
	LockFailed          int
	BridgeCleanup       bool
	EdgeCleanup         bool
	RecoverableSessions int
	StaleSessions       int
}

// Input is an immutable, payload-free snapshot supplied by the Workbench.
type Input struct {
	Platform                string
	EffectiveUID            int
	Adapters                []adapters.Adapter
	AdapterError            error
	AdapterDiscoveryPending bool
	ProjectPath             string
	ProjectDirty            bool
	ProjectCaptures         int
	Restoration             Restoration
	Edge                    EdgePlan
}

// EdgePlan is the staged, non-secret Edge route selection inspected by doctor.
type EdgePlan struct {
	Mode            string
	Egress          string
	Downstream      string
	Upstream        string
	VPNDestinations []string
	DNS             []string
}

// Probes contains the read-only system boundaries used by Run. Tests can
// provide deterministic fakes without changing process-global state.
type Probes struct {
	ProjectRoot          func() (string, error)
	LoadRecents          func() (workproject.RecentState, error)
	Lstat                func(string) (os.FileInfo, error)
	DiscoverDefaultRoute func(context.Context) (edge.Route, error)
	OccupiedIPv4Prefixes func() ([]netip.Prefix, error)
	SelectSubnet         func([]netip.Prefix) (netip.Prefix, error)
	LookPath             func(string) (string, error)
	PFInfo               func(context.Context, string) error
	PFValidate           func(context.Context, string, string) error
	VPNRouteAddress      func(string) (netip.Addr, error)
	DiscoverMacOSDNS     func(context.Context, string) ([]netip.Addr, error)
	InterfaceMTU         func(string) (int, error)
	ProbeDNSResolver     func(context.Context, netip.Addr) error
}

// DefaultProbes returns the production read-only probe set.
func DefaultProbes() Probes {
	return Probes{
		ProjectRoot:          workproject.DefaultRoot,
		LoadRecents:          workproject.LoadRecents,
		Lstat:                os.Lstat,
		DiscoverDefaultRoute: edge.DiscoverDefaultRoute,
		OccupiedIPv4Prefixes: edge.OccupiedIPv4Prefixes,
		SelectSubnet:         edge.SelectSubnet,
		LookPath:             exec.LookPath,
		PFInfo:               probePFInfo,
		PFValidate:           probePFSyntax,
		VPNRouteAddress:      edge.VPNRouteAddress,
		DiscoverMacOSDNS:     edge.DiscoverMacOSDNS,
		InterfaceMTU:         edge.InterfaceMTU,
		ProbeDNSResolver:     edge.ProbeDNSResolver,
	}
}

// Run performs bounded checks without changing project, adapter, route, PF, or
// DHCP state.
func Run(ctx context.Context, input Input, probes Probes) Report {
	if ctx == nil {
		ctx = context.Background()
	}
	if strings.TrimSpace(input.Platform) == "" {
		input.Platform = runtime.GOOS
	}
	probes = completeProbes(probes)

	var report Report
	add := func(area, name string, status Status, detail string) {
		report.Checks = append(report.Checks, Check{
			Area: clean(area), Name: clean(name), Status: status, Detail: clean(detail),
		})
	}

	projectRoot, rootErr := probes.ProjectRoot()
	if rootErr != nil {
		add("projects", "root", StatusFail, "cannot resolve the project root: "+rootErr.Error())
	} else {
		addPathCheck(&report, probes.Lstat, "projects", "root", projectRoot, true)
	}
	if strings.TrimSpace(input.ProjectPath) == "" {
		add("projects", "active", StatusWarn, "no project is open; diagnostics remain read-only")
	} else {
		before := len(report.Checks)
		addPathCheck(&report, probes.Lstat, "projects", "active", input.ProjectPath, false)
		if len(report.Checks) > before && report.Checks[len(report.Checks)-1].Status == StatusPass {
			detail := fmt.Sprintf("manifest loaded; captures=%d dirty=%t", input.ProjectCaptures, input.ProjectDirty)
			status := StatusPass
			report.Checks[len(report.Checks)-1].Status = status
			report.Checks[len(report.Checks)-1].Detail = detail
		}
	}
	if recents, err := probes.LoadRecents(); err != nil {
		add("projects", "recent inventory", StatusFail, "strict recent inventory failed validation: "+err.Error())
	} else {
		availableProjects := 0
		for _, item := range recents.Projects {
			if item.Available {
				availableProjects++
			}
		}
		add("projects", "recent inventory", StatusPass, fmt.Sprintf(
			"projects=%d/%d available",
			availableProjects, len(recents.Projects),
		))
	}

	switch {
	case input.AdapterDiscoveryPending:
		add("adapters", "inventory", StatusWarn, "adapter discovery is still running")
	case len(input.Adapters) == 0 && input.AdapterError != nil:
		add("adapters", "inventory", StatusFail, "adapter discovery failed: "+input.AdapterError.Error())
	case len(input.Adapters) == 0:
		add("adapters", "inventory", StatusWarn, "no non-loopback adapters were discovered")
	default:
		up := 0
		physical := 0
		networkServices := 0
		for _, adapter := range input.Adapters {
			if adapter.IsUp {
				up++
			}
			if adapter.HardwarePort != "" {
				physical++
			}
			if adapter.NetworkService != "" {
				networkServices++
			}
		}
		status := StatusPass
		detail := fmt.Sprintf("usable=%d up=%d physical=%d services=%d", len(input.Adapters), up, physical, networkServices)
		if input.Platform == "darwin" && networkServices < physical {
			status = StatusWarn
			detail += "; one or more physical adapters lack a network-service mapping"
		}
		if input.AdapterError != nil {
			status = StatusWarn
			detail += "; partial discovery: " + input.AdapterError.Error()
		}
		add("adapters", "inventory", status, detail)
	}

	if input.Platform != "darwin" {
		add("routes", "IPv4 default", StatusSkip, "live route checks apply only to macOS")
		add("PF", "readiness", StatusSkip, "Packet Filter checks apply only to macOS")
		add("DHCP", "edge plan", StatusSkip, "live Edge DHCP applies only to macOS")
	} else {
		routeCtx, cancelRoute := context.WithTimeout(ctx, 3*time.Second)
		_, err := probes.DiscoverDefaultRoute(routeCtx)
		cancelRoute()
		if err != nil {
			add("routes", "IPv4 default", StatusFail, "default route is not usable: "+err.Error())
		} else {
			add("routes", "IPv4 default", StatusPass, "default route is readable and complete")
		}

		pfPath, err := probes.LookPath("pfctl")
		switch {
		case err != nil:
			add("PF", "readiness", StatusFail, "pfctl is unavailable")
		case input.EffectiveUID != 0:
			add("PF", "readiness", StatusWarn, "pfctl is present; root is required for live inspection and mutation")
		default:
			pfCtx, cancelPF := context.WithTimeout(ctx, 3*time.Second)
			err = probes.PFInfo(pfCtx, pfPath)
			cancelPF()
			if err != nil {
				add("PF", "readiness", StatusFail, "cannot read PF status: "+err.Error())
			} else {
				add("PF", "readiness", StatusPass, "pfctl status is readable; no rules were changed")
			}
		}

		prefixes, err := probes.OccupiedIPv4Prefixes()
		var edgeSubnet netip.Prefix
		if err == nil {
			edgeSubnet, err = probes.SelectSubnet(prefixes)
		}
		if err != nil {
			add("DHCP", "edge plan", StatusFail, "cannot select a conflict-free Edge lease subnet: "+err.Error())
		} else {
			add("DHCP", "edge plan", StatusPass, "a conflict-free deterministic Edge lease subnet is available")
		}
		if strings.EqualFold(input.Edge.Mode, string(edge.ModeRoute)) {
			addEdgeRouteChecks(ctx, &report, input.Edge, edgeSubnet, pfPath, probes)
		}
	}

	restoration := input.Restoration
	switch {
	case restoration.BridgeCleanup || restoration.EdgeCleanup || restoration.LockFailed > 0:
		add("restoration", "ownership", StatusFail, fmt.Sprintf(
			"bridge-cleanup=%t edge-cleanup=%t lock-failed=%d",
			restoration.BridgeCleanup, restoration.EdgeCleanup, restoration.LockFailed,
		))
	case restoration.InterfacePending > 0 || restoration.LockPending > 0 || strings.TrimSpace(restoration.RuntimeOperation) != "":
		add("restoration", "ownership", StatusWarn, fmt.Sprintf(
			"operation=%s restore-pending=%d lock-pending=%d",
			emptyAs(restoration.RuntimeOperation, "none"), restoration.InterfacePending, restoration.LockPending,
		))
	case restoration.InterfaceSnapshots > 0 && !restoration.RuntimeActive:
		add("restoration", "ownership", StatusWarn, fmt.Sprintf(
			"%d interface restoration snapshots remain without an active runtime",
			restoration.InterfaceSnapshots,
		))
	default:
		detail := "no cleanup or interface restoration is pending"
		if restoration.RuntimeActive {
			detail = fmt.Sprintf("active runtime owns %d restoration snapshots", restoration.InterfaceSnapshots)
		}
		add("restoration", "ownership", StatusPass, detail)
	}
	if restoration.RecoverableSessions > 0 || restoration.StaleSessions > 0 {
		add("restoration", "session evidence", StatusWarn, fmt.Sprintf(
			"recoverable=%d stale=%d; review project sessions",
			restoration.RecoverableSessions, restoration.StaleSessions,
		))
	} else {
		add("restoration", "session evidence", StatusPass, "no project-associated session handoff is pending")
	}

	if err := ctx.Err(); err != nil {
		add("doctor", "context", StatusFail, err.Error())
	}
	return report
}

// Lines renders a bounded text report for the command pane.
func (r Report) Lines() []string {
	lines := make([]string, 0, len(r.Checks)+1)
	for _, check := range r.Checks {
		lines = append(lines, fmt.Sprintf("[%s] %s/%s: %s", check.Status, check.Area, check.Name, check.Detail))
	}
	pass, warn, fail, skip := r.Summary()
	lines = append(lines, fmt.Sprintf("doctor summary: pass=%d warn=%d fail=%d skip=%d", pass, warn, fail, skip))
	return lines
}

// Summary returns check counts in pass, warn, fail, skip order.
func (r Report) Summary() (pass, warn, fail, skip int) {
	for _, check := range r.Checks {
		switch check.Status {
		case StatusPass:
			pass++
		case StatusWarn:
			warn++
		case StatusFail:
			fail++
		case StatusSkip:
			skip++
		}
	}
	return pass, warn, fail, skip
}

func completeProbes(probes Probes) Probes {
	defaults := DefaultProbes()
	if probes.ProjectRoot == nil {
		probes.ProjectRoot = defaults.ProjectRoot
	}
	if probes.LoadRecents == nil {
		probes.LoadRecents = defaults.LoadRecents
	}
	if probes.Lstat == nil {
		probes.Lstat = defaults.Lstat
	}
	if probes.DiscoverDefaultRoute == nil {
		probes.DiscoverDefaultRoute = defaults.DiscoverDefaultRoute
	}
	if probes.OccupiedIPv4Prefixes == nil {
		probes.OccupiedIPv4Prefixes = defaults.OccupiedIPv4Prefixes
	}
	if probes.SelectSubnet == nil {
		probes.SelectSubnet = defaults.SelectSubnet
	}
	if probes.LookPath == nil {
		probes.LookPath = defaults.LookPath
	}
	if probes.PFInfo == nil {
		probes.PFInfo = defaults.PFInfo
	}
	if probes.PFValidate == nil {
		probes.PFValidate = defaults.PFValidate
	}
	if probes.VPNRouteAddress == nil {
		probes.VPNRouteAddress = defaults.VPNRouteAddress
	}
	if probes.DiscoverMacOSDNS == nil {
		probes.DiscoverMacOSDNS = defaults.DiscoverMacOSDNS
	}
	if probes.InterfaceMTU == nil {
		probes.InterfaceMTU = defaults.InterfaceMTU
	}
	if probes.ProbeDNSResolver == nil {
		probes.ProbeDNSResolver = defaults.ProbeDNSResolver
	}
	return probes
}

func addEdgeRouteChecks(ctx context.Context, report *Report, plan EdgePlan, subnet netip.Prefix, pfPath string, probes Probes) {
	add := func(area, name string, status Status, detail string) {
		report.Checks = append(report.Checks, Check{Area: area, Name: name, Status: status, Detail: clean(detail)})
	}
	if !subnet.IsValid() || strings.TrimSpace(plan.Downstream) == "" {
		add("Edge", "staged route", StatusFail, "a valid downstream adapter and lease subnet are required")
		return
	}
	egress := edge.EgressMode(strings.ToLower(strings.TrimSpace(plan.Egress)))
	if egress == "" {
		egress = edge.EgressSystem
	}
	config := edge.Config{
		Mode: edge.ModeRoute, Downstream: strings.TrimSpace(plan.Downstream),
		Upstream: strings.TrimSpace(plan.Upstream), Egress: egress, Subnet: subnet,
	}
	if egress == edge.EgressVPN {
		if config.Upstream == "" || strings.EqualFold(config.Upstream, "auto") {
			add("VPN", "tunnel", StatusFail, "VPN egress requires an explicit tunnel interface")
			return
		}
		nextHop, err := probes.VPNRouteAddress(config.Upstream)
		if err != nil {
			add("VPN", "tunnel", StatusFail, err.Error())
			return
		}
		config.VPNRouteAddress = nextHop
		add("VPN", "tunnel", StatusPass, "interface is up, point-to-point, and has an IPv4 next hop")
		for _, raw := range plan.VPNDestinations {
			destination, parseErr := netip.ParsePrefix(strings.TrimSpace(raw))
			if parseErr != nil || !destination.Addr().Is4() {
				add("VPN", "destinations", StatusFail, "invalid staged IPv4 destination "+raw)
				return
			}
			config.VPNDestinations = append(config.VPNDestinations, destination.Masked())
		}
	}
	for _, raw := range plan.DNS {
		address, err := netip.ParseAddr(strings.TrimSpace(raw))
		if err != nil || !address.Is4() || address.IsUnspecified() || address.IsMulticast() {
			add("DNS", "Edge resolver", StatusFail, "invalid staged IPv4 DNS address")
			return
		}
		config.DNS = append(config.DNS, address)
	}
	if len(config.DNS) == 0 {
		resolverInterface := ""
		if egress == edge.EgressVPN {
			resolverInterface = config.Upstream
		}
		addresses, err := probes.DiscoverMacOSDNS(ctx, resolverInterface)
		if err != nil {
			add("DNS", "Edge resolver", StatusFail, err.Error())
			return
		}
		config.DNS = addresses
	}
	relay := false
	resolverPasses := 0
	var resolverProbeErrs []string
	for _, address := range config.DNS {
		relay = relay || address.IsLoopback()
		probeCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
		err := probes.ProbeDNSResolver(probeCtx, address)
		cancel()
		if err != nil {
			resolverProbeErrs = append(resolverProbeErrs, err.Error())
		} else {
			resolverPasses++
		}
	}
	if resolverPasses == 0 {
		add("DNS", "port 53", StatusFail, strings.Join(resolverProbeErrs, "; "))
		return
	}
	if len(resolverProbeErrs) > 0 {
		add("DNS", "port 53", StatusWarn, fmt.Sprintf("responding=%d failed=%d; %s", resolverPasses, len(resolverProbeErrs), strings.Join(resolverProbeErrs, "; ")))
	} else {
		add("DNS", "port 53", StatusPass, fmt.Sprintf("all %d classic UDP DNS resolver(s) answered", resolverPasses))
	}
	add("DNS", "Edge resolver", StatusPass, fmt.Sprintf("usable IPv4 resolvers=%d loopback-relay=%t", len(config.DNS), relay))
	if egress == edge.EgressSystem && (config.Upstream == "" || strings.EqualFold(config.Upstream, "auto")) {
		route, err := probes.DiscoverDefaultRoute(ctx)
		if err != nil {
			add("Edge", "staged route", StatusFail, err.Error())
			return
		}
		config.Upstream = route.Interface
	}
	mtu, err := probes.InterfaceMTU(config.Upstream)
	if err != nil {
		add("Edge", "egress MTU", StatusFail, err.Error())
		return
	}
	config.EgressMTU = mtu
	add("Edge", "egress MTU", StatusPass, fmt.Sprintf("IPv4 MTU=%d; TCP MSS clamp=%d", config.EgressMTU, config.EgressMTU-40))
	rules, err := edge.CompilePF(config)
	if err != nil {
		add("PF", "staged Edge syntax", StatusFail, err.Error())
		return
	}
	if pfPath == "" {
		add("PF", "staged Edge syntax", StatusFail, "pfctl is unavailable")
		return
	}
	validateCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	err = probes.PFValidate(validateCtx, pfPath, rules)
	cancel()
	if err != nil {
		add("PF", "staged Edge syntax", StatusFail, err.Error())
		return
	}
	add("PF", "staged Edge syntax", StatusPass, "the exact staged anchor parses without changing PF")
	if egress == edge.EgressVPN {
		add("VPN", "provider forwarding", StatusWarn, "macOS cannot prove that the VPN provider accepts forwarded/NATed client traffic until a live packet test")
	}
}

func addPathCheck(report *Report, lstat func(string) (os.FileInfo, error), area, name, path string, missingOK bool) {
	info, err := lstat(path)
	switch {
	case errors.Is(err, os.ErrNotExist) && missingOK:
		report.Checks = append(report.Checks, Check{Area: area, Name: name, Status: StatusPass, Detail: "path is valid and will be created on first save"})
	case err != nil:
		report.Checks = append(report.Checks, Check{Area: area, Name: name, Status: StatusFail, Detail: clean("cannot inspect directory: " + err.Error())})
	case info.Mode()&os.ModeSymlink != 0:
		report.Checks = append(report.Checks, Check{Area: area, Name: name, Status: StatusFail, Detail: "directory must not be a symlink"})
	case !info.IsDir():
		report.Checks = append(report.Checks, Check{Area: area, Name: name, Status: StatusFail, Detail: "path is not a directory"})
	case info.Mode().Perm()&0o077 != 0:
		report.Checks = append(report.Checks, Check{Area: area, Name: name, Status: StatusWarn, Detail: fmt.Sprintf("directory permissions are %04o; owner-only 0700 is recommended", info.Mode().Perm())})
	default:
		report.Checks = append(report.Checks, Check{Area: area, Name: name, Status: StatusPass, Detail: "owner-only directory is ready"})
	}
}

func probePFInfo(ctx context.Context, path string) error {
	command := exec.CommandContext(ctx, path, "-s", "info")
	if err := command.Run(); err != nil {
		return err
	}
	return nil
}

func probePFSyntax(ctx context.Context, path, rules string) error {
	command := exec.CommandContext(ctx, path, "-vnf", "-")
	command.Stdin = strings.NewReader(rules)
	output, err := command.CombinedOutput()
	if err == nil {
		return nil
	}
	return fmt.Errorf("PF syntax validation failed: %w (%s)", err, clean(string(output)))
}

func clean(value string) string {
	value = strings.TrimSpace(strings.Map(func(char rune) rune {
		if unicode.IsControl(char) {
			return ' '
		}
		return char
	}, value))
	fields := strings.Fields(value)
	value = strings.Join(fields, " ")
	runes := []rune(value)
	if len(runes) > detailLimit {
		value = string(runes[:detailLimit-3]) + "..."
	}
	return value
}

func emptyAs(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}
