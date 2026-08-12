package doctor

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"reflect"
	"sort"
	"strings"
	"testing"

	"golan/internal/adapters"
	"golan/internal/edge"
	workproject "golan/internal/project"
)

func TestRunCoversEveryPlannedReadinessArea(t *testing.T) {
	projectRoot := t.TempDir()
	activeProject := t.TempDir()
	for _, path := range []string{projectRoot, activeProject} {
		if err := os.Chmod(path, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	probes := Probes{
		ProjectRoot: func() (string, error) { return projectRoot, nil },
		LoadRecents: func() (workproject.RecentState, error) {
			return workproject.RecentState{
				Version:  1,
				Projects: []workproject.RecentProject{{Name: "Lab", Available: true}},
			}, nil
		},
		Lstat: os.Lstat,
		DiscoverDefaultRoute: func(context.Context) (edge.Route, error) {
			return edge.Route{Interface: "en0", Gateway: netip.MustParseAddr("192.0.2.1"), Default: true}, nil
		},
		OccupiedIPv4Prefixes: func() ([]netip.Prefix, error) { return nil, nil },
		SelectSubnet: func([]netip.Prefix) (netip.Prefix, error) {
			return netip.MustParsePrefix("10.77.0.0/24"), nil
		},
		LookPath: func(string) (string, error) { return "/sbin/pfctl", nil },
		PFInfo:   func(context.Context, string) error { return nil },
	}
	report := Run(context.Background(), Input{
		Platform:     "darwin",
		EffectiveUID: 0,
		Adapters: []adapters.Adapter{{
			Name: "en0", HardwarePort: "Ethernet", NetworkService: "Office LAN", IsUp: true,
		}},
		ProjectPath:     activeProject,
		ProjectCaptures: 2,
		Restoration:     Restoration{},
	}, probes)

	pass, warn, fail, skip := report.Summary()
	if pass != len(report.Checks) || warn != 0 || fail != 0 || skip != 0 {
		t.Fatalf("summary pass=%d warn=%d fail=%d skip=%d checks=%#v", pass, warn, fail, skip, report.Checks)
	}
	wantAreas := []string{"DHCP", "PF", "adapters", "projects", "restoration", "routes"}
	if got := sortedReportAreas(report); !reflect.DeepEqual(got, wantAreas) {
		t.Fatalf("areas=%v want=%v", got, wantAreas)
	}
	joined := strings.Join(report.Lines(), "\n")
	for _, want := range []string{
		"[PASS] projects/root",
		"[PASS] routes/IPv4 default",
		"[PASS] PF/readiness",
		"[PASS] DHCP/edge plan",
		"[PASS] restoration/ownership",
		"doctor summary:",
	} {
		if !strings.Contains(joined, want) {
			t.Fatalf("report missing %q:\n%s", want, joined)
		}
	}
}

func TestRunWarnsWhenPhysicalAdapterHasNoNetworkServiceMapping(t *testing.T) {
	report := Run(context.Background(), Input{
		Platform: "darwin", EffectiveUID: 0,
		Adapters: []adapters.Adapter{{Name: "en7", HardwarePort: "USB Ethernet"}},
	}, Probes{
		ProjectRoot:          func() (string, error) { return t.TempDir(), nil },
		LoadRecents:          func() (workproject.RecentState, error) { return workproject.RecentState{Version: 1}, nil },
		Lstat:                os.Lstat,
		DiscoverDefaultRoute: func(context.Context) (edge.Route, error) { return edge.Route{}, errors.New("none") },
		OccupiedIPv4Prefixes: func() ([]netip.Prefix, error) { return nil, nil },
		SelectSubnet:         func([]netip.Prefix) (netip.Prefix, error) { return netip.MustParsePrefix("10.77.0.0/24"), nil },
		LookPath:             func(string) (string, error) { return "/sbin/pfctl", nil },
		PFInfo:               func(context.Context, string) error { return nil },
	})
	joined := strings.Join(report.Lines(), "\n")
	if !strings.Contains(joined, "[WARN] adapters/inventory") || !strings.Contains(joined, "lack a network-service mapping") {
		t.Fatalf("report=%s", joined)
	}
}

func TestRunAuditsStagedMacOSVPNRouteAndLoopbackDNSRelay(t *testing.T) {
	var validatedRules string
	report := Run(context.Background(), Input{
		Platform: "darwin", EffectiveUID: 0,
		Adapters: []adapters.Adapter{{Name: "en7", HardwarePort: "USB Ethernet", NetworkService: "Target"}},
		Edge: EdgePlan{
			Mode: "route", Egress: "vpn", Downstream: "en7", Upstream: "utun4",
			VPNDestinations: []string{"198.51.100.0/24"}, DNS: []string{"127.0.0.1"},
		},
	}, Probes{
		ProjectRoot: func() (string, error) { return t.TempDir(), nil },
		LoadRecents: func() (workproject.RecentState, error) { return workproject.RecentState{Version: 1}, nil },
		Lstat:       os.Lstat,
		DiscoverDefaultRoute: func(context.Context) (edge.Route, error) {
			return edge.Route{Interface: "en0", Gateway: netip.MustParseAddr("192.0.2.1"), Default: true}, nil
		},
		OccupiedIPv4Prefixes: func() ([]netip.Prefix, error) { return nil, nil },
		SelectSubnet: func([]netip.Prefix) (netip.Prefix, error) {
			return netip.MustParsePrefix("10.77.2.0/24"), nil
		},
		LookPath: func(string) (string, error) { return "/sbin/pfctl", nil },
		PFInfo:   func(context.Context, string) error { return nil },
		PFValidate: func(_ context.Context, _ string, rules string) error {
			validatedRules = rules
			return nil
		},
		VPNRouteAddress:  func(string) (netip.Addr, error) { return netip.MustParseAddr("10.8.0.1"), nil },
		InterfaceMTU:     func(string) (int, error) { return 1280, nil },
		ProbeDNSResolver: func(context.Context, netip.Addr) error { return nil },
	})
	joined := strings.Join(report.Lines(), "\n")
	for _, want := range []string{
		"[PASS] VPN/tunnel",
		"loopback-relay=true",
		"[PASS] DNS/Edge resolver",
		"[PASS] DNS/port 53",
		"[PASS] PF/staged Edge syntax",
		"TCP MSS clamp=1240",
		"[WARN] VPN/provider forwarding",
	} {
		if !strings.Contains(joined, want) {
			t.Fatalf("VPN doctor report missing %q:\n%s", want, joined)
		}
	}
	if !strings.Contains(validatedRules, "to 10.77.2.1 port 53") || strings.Contains(validatedRules, "127.0.0.1") {
		t.Fatalf("validated rules do not use the downstream relay:\n%s", validatedRules)
	}
}

func sortedReportAreas(report Report) []string {
	seen := make(map[string]bool)
	for _, check := range report.Checks {
		seen[check.Area] = true
	}
	areas := make([]string, 0, len(seen))
	for area := range seen {
		areas = append(areas, area)
	}
	sort.Strings(areas)
	return areas
}

func TestRunClassifiesOfflineAndUnsafeStateWithoutLeakingControlText(t *testing.T) {
	missing := t.TempDir() + "/missing"
	report := Run(context.Background(), Input{
		Platform:     "linux",
		EffectiveUID: 1000,
		AdapterError: errors.New("adapter\nprivate detail"),
		Restoration: Restoration{
			LockFailed:          1,
			RecoverableSessions: 2,
			StaleSessions:       1,
		},
	}, Probes{
		ProjectRoot: func() (string, error) { return missing, nil },
		LoadRecents: func() (workproject.RecentState, error) {
			return workproject.RecentState{Version: 1}, nil
		},
		Lstat: os.Lstat,
	})

	_, warn, fail, skip := report.Summary()
	if warn < 2 || fail < 2 || skip != 3 {
		t.Fatalf("warn=%d fail=%d skip=%d checks=%#v", warn, fail, skip, report.Checks)
	}
	joined := strings.Join(report.Lines(), "\n")
	if strings.ContainsAny(joined, "\t\r") || strings.Contains(joined, "adapter\nprivate") {
		t.Fatalf("report retained control text: %q", joined)
	}
}

func TestRunBoundsCanceledProbeDetails(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	long := strings.Repeat("x", detailLimit*2)
	report := Run(ctx, Input{Platform: "darwin"}, Probes{
		ProjectRoot: func() (string, error) { return "", errors.New(long) },
		LoadRecents: func() (workproject.RecentState, error) {
			return workproject.RecentState{}, nil
		},
		Lstat: func(string) (os.FileInfo, error) { return nil, os.ErrNotExist },
		DiscoverDefaultRoute: func(context.Context) (edge.Route, error) {
			return edge.Route{}, context.Canceled
		},
		OccupiedIPv4Prefixes: func() ([]netip.Prefix, error) { return nil, nil },
		SelectSubnet: func([]netip.Prefix) (netip.Prefix, error) {
			return netip.Prefix{}, nil
		},
		LookPath: func(string) (string, error) { return "", os.ErrNotExist },
		PFInfo:   func(context.Context, string) error { return nil },
	})
	for _, check := range report.Checks {
		if len([]rune(check.Detail)) > detailLimit {
			t.Fatalf("unbounded detail length=%d", len([]rune(check.Detail)))
		}
	}
	if report.Checks[len(report.Checks)-1].Area != "doctor" ||
		report.Checks[len(report.Checks)-1].Status != StatusFail {
		t.Fatalf("canceled context was not explicit: %#v", report.Checks)
	}
}
