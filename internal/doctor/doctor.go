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
		if err == nil {
			_, err = probes.SelectSubnet(prefixes)
		}
		if err != nil {
			add("DHCP", "edge plan", StatusFail, "cannot select a conflict-free Edge lease subnet: "+err.Error())
		} else {
			add("DHCP", "edge plan", StatusPass, "a conflict-free deterministic Edge lease subnet is available")
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
	return probes
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
