package bridge

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golan/internal/bridgefilter"
	"golan/internal/dataplane"
	"golan/internal/eapol"
	"golan/internal/inspect"
	"golan/internal/listen"
	"golan/internal/paths"
	"golan/internal/policy"
	"golan/internal/stealth"
	"golan/internal/syncgate"
	"golan/internal/traffic"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
)

const eventDeliveryTimeout = 250 * time.Millisecond

// Bridge event kinds identify lifecycle, capture, discovery, and analysis output.
const (
	KindLog       EventKind = "log"
	KindState     EventKind = "state"
	KindPcap      EventKind = "pcap"
	KindError     EventKind = "error"
	KindDiscovery EventKind = "discovery"
	KindTraffic   EventKind = "traffic"
	KindEvidence  EventKind = "evidence"
	KindSignal    EventKind = "signal"
	KindDecision  EventKind = "decision"
	KindStopped   EventKind = "stopped"
)

// EventKind identifies a bridge event category.
type EventKind string

// Adapter identifies one side of the inline packet bridge.
type Adapter struct {
	Name           string
	Role           string
	HardwarePort   string
	NetworkService string
	LocalMAC       string
	TargetMAC      string
}

// Event describes bridge lifecycle output for the TUI.
type Event struct {
	Kind      EventKind
	Message   string
	State     string
	Adapter   string
	Role      string
	Field     string
	Value     string
	Evidence  string
	Packet    string
	DeviceMAC string
	Path      string
	Err       error
	Frame     traffic.Frame
	Flow      traffic.Flow
	Mode      dataplane.Mode
	Decision  policy.DecisionSummary
}

// Session owns a transparent macOS bridge run.
type Session struct {
	Name       string
	Mode       Mode
	Host       Adapter
	Switch     Adapter
	Dir        string
	BridgeName string
	Events     <-chan Event

	cancel context.CancelFunc
	done   chan struct{}
	events chan Event

	bridgeName        string
	interfaces        []InterfaceRestoreState
	macRestore        []adapterMACRestore
	eapolCancel       context.CancelFunc
	eapolDone         chan struct{}
	eapolRelay        *eapol.Relay
	authSession       *eapol.AuthSession
	eapolPolicy       EAPOLPolicy
	targetMAC         net.HardwareAddr
	nat               *NATState
	takeoverGate      syncgate.Gate
	controlMu         sync.Mutex
	origIPv6Fwd       string
	inspector         *inspect.Inspector
	runner            commandRunner
	resultMu          sync.Mutex
	runtimeErr        error
	cleanupErr        error
	resultErr         error
	cleanupGate       syncgate.Gate
	eventGate         syncgate.Gate
	eventsDone        bool
	policyEngine      *policy.Engine
	controlledOptions ControlledOptions
	controlledStats   *controlledCounters
	fastPFRules       string
	fastPF            fastPolicyBackend
	ipFilter          bridgeIPFilter
	l2Rules           bridgeRuleManager
}

// Mode selects the fast kernel or controlled userspace forwarding path.
type Mode string

// Bridge modes preserve start bridge compatibility by defaulting to fast.
const (
	ModeFast       Mode = "fast"
	ModeControlled Mode = "controlled"
)

type adapterMACRestore struct {
	Name string
	MAC  string
}

type captureResource struct {
	handle *pcap.Handle
	file   *os.File
	path   string
}

// EAPOLPolicy controls transparent 802.1X passthrough behavior.
type EAPOLPolicy struct {
	SuppressLogoff  bool
	DowngradeMACsec bool
}

// DefaultEAPOLPolicy keeps sessions alive and drops MACsec MKA type 5 by default.
func DefaultEAPOLPolicy() EAPOLPolicy {
	return EAPOLPolicy{SuppressLogoff: true, DowngradeMACsec: true}
}

// TakeoverConfig describes the settings used to move the authenticated host
// identity onto the bridge endpoint. NATConfig remains a source-compatible
// alias for older callers and commands.
type TakeoverConfig struct {
	MAC     string
	IP      string
	CIDR    string
	Gateway string
	DNS     string
	DHCP    string
}

// NATConfig is the legacy name for TakeoverConfig.
type NATConfig = TakeoverConfig

// TakeoverState records every reversible identity and PF change made by
// StartTakeover. PF restoration remains explicit and retryable after a partial
// stop; the complete rules themselves are intentionally not exposed.
type TakeoverState struct {
	BridgeName             string
	MAC                    string
	IP                     string
	CIDR                   string
	DHCP                   bool
	OrigMAC                string
	Gateway                string
	RouteAdded             bool
	StaticIPSet            bool
	HostDetached           bool
	HostSTPRestorePending  bool
	Started                bool
	PFAnchor               string
	PFEndpointRules        bool
	PFRestorePending       bool
	PFCreated              bool
	L2EndpointRules        bool
	L2RestorePending       bool
	PolicyRevision         string
	LivePolicyRules        int
	ShadowPolicyRules      int
	UnsupportedPolicyRules int
	takeoverPFRules        string
}

// NATState is the legacy name for TakeoverState.
type NATState = TakeoverState

// StartModeWithPolicyOptions starts a bridge with immutable, preflighted
// controlled forwarding bounds. Fast mode retains them only as session
// evidence and does not create userspace queues.
func StartModeWithPolicyOptions(host, sw Adapter, dir string, mode Mode, eapolPolicy EAPOLPolicy, revision string, rules []policy.Rule, controlledOptions ControlledOptions) (*Session, error) {
	host, sw, err := validateAdapters(host, sw)
	if err != nil {
		return nil, err
	}
	if _, _, err := targetMACSetting(host.TargetMAC); err != nil {
		return nil, err
	}
	if mode != ModeFast && mode != ModeControlled {
		return nil, fmt.Errorf("bridge mode must be fast or controlled")
	}
	controlledOptions = normalizeControlledOptions(controlledOptions)
	if err := ValidateControlledOptions(controlledOptions); err != nil {
		return nil, err
	}
	engine := policy.NewEngine(8192)
	if len(rules) > 0 {
		if err := engine.Policies.Activate(revision, rules); err != nil {
			return nil, fmt.Errorf("compile bridge policy: %w", err)
		}
	}
	var fastPFRules string
	if mode == ModeFast && len(rules) > 0 {
		if err := stealth.ValidateFastBridgeL2Policy(host.Name, sw.Name, rules); err != nil {
			return nil, fmt.Errorf("preflight fast bridge Layer 2 policy: %w", err)
		}
		fastPFRules, err = stealth.CompileFastBridgePF(host.Name, sw.Name, revision, rules)
		if err != nil {
			return nil, fmt.Errorf("preflight fast bridge PF policy: %w", err)
		}
	}
	if dir == "" {
		defaultDir, err := paths.PcapRunDir()
		if err != nil {
			return nil, err
		}
		dir = defaultDir
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("create pcap dir: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	events := make(chan Event, 128)
	s := &Session{
		Name:              "kernel-bridge",
		Mode:              mode,
		Host:              host,
		Switch:            sw,
		Dir:               dir,
		Events:            events,
		cancel:            cancel,
		done:              make(chan struct{}),
		events:            events,
		inspector:         inspect.New(),
		eapolPolicy:       eapolPolicy,
		runner:            execCommandRunner{},
		policyEngine:      engine,
		controlledOptions: controlledOptions,
		controlledStats:   &controlledCounters{},
		fastPFRules:       fastPFRules,
		l2Rules:           systemBridgeRuleManager{},
	}
	if fastPFRules != "" {
		s.fastPF = stealth.NewFastBridgePFBackend()
		s.ipFilter = bridgefilter.New()
	}
	if mode == ModeControlled {
		s.Name = "controlled-bridge"
		go s.runControlled(ctx)
	} else {
		go s.run(ctx)
	}
	return s, nil
}

// ControlledOptions returns the immutable session forwarding bounds.
func (s *Session) ControlledOptions() ControlledOptions {
	if s == nil {
		return ControlledOptions{}
	}
	return s.controlledOptions
}

// ControlledStats returns a concurrency-safe payload-free forwarding and
// queue-pressure snapshot. Fast bridge sessions and nil sessions return zero.
func (s *Session) ControlledStats() ControlledStats {
	if s == nil || s.Mode != ModeControlled || s.controlledStats == nil {
		return ControlledStats{}
	}
	return s.controlledStats.snapshot()
}

func validateAdapters(host, sw Adapter) (Adapter, Adapter, error) {
	normalize := func(side string, adapter Adapter) (Adapter, error) {
		adapter.Name = strings.TrimSpace(adapter.Name)
		adapter.HardwarePort = strings.TrimSpace(adapter.HardwarePort)
		adapter.NetworkService = strings.TrimSpace(adapter.NetworkService)
		adapter.LocalMAC = strings.TrimSpace(adapter.LocalMAC)
		adapter.TargetMAC = strings.TrimSpace(adapter.TargetMAC)
		adapter.Role = side
		if adapter.Name == "" {
			return Adapter{}, fmt.Errorf("%s adapter is required", side)
		}
		if !validInterfaceName(adapter.Name) {
			return Adapter{}, fmt.Errorf("%s adapter name %q is invalid", side, adapter.Name)
		}
		if adapter.HardwarePort == "" {
			return Adapter{}, fmt.Errorf("%s adapter hardware port is required", side)
		}
		if adapter.NetworkService == "" {
			return Adapter{}, fmt.Errorf("%s adapter network service is required", side)
		}
		mac, err := net.ParseMAC(adapter.LocalMAC)
		if err != nil || !validSourceMAC(mac) {
			return Adapter{}, fmt.Errorf("%s adapter local MAC must be a 48-bit unicast address", side)
		}
		adapter.LocalMAC = mac.String()
		return adapter, nil
	}

	host, err := normalize("host", host)
	if err != nil {
		return Adapter{}, Adapter{}, err
	}
	sw, err = normalize("switch", sw)
	if err != nil {
		return Adapter{}, Adapter{}, err
	}
	if strings.EqualFold(host.Name, sw.Name) {
		return Adapter{}, Adapter{}, fmt.Errorf("host and switch adapters must differ")
	}
	if strings.EqualFold(host.LocalMAC, sw.LocalMAC) {
		return Adapter{}, Adapter{}, fmt.Errorf("host and switch adapter local MACs must differ")
	}
	if strings.EqualFold(host.HardwarePort, sw.HardwarePort) {
		return Adapter{}, Adapter{}, fmt.Errorf("host and switch hardware ports must differ")
	}
	if strings.EqualFold(host.NetworkService, sw.NetworkService) {
		return Adapter{}, Adapter{}, fmt.Errorf("host and switch network services must differ")
	}
	return host, sw, nil
}

// Stop tears down the bridge and waits briefly for capture goroutines to exit.
func (s *Session) Stop() error {
	if s == nil {
		return nil
	}
	if s.cancel != nil {
		s.cancel()
	}
	if s.done == nil {
		return nil
	}
	timer := time.NewTimer(8 * time.Second)
	defer timer.Stop()
	select {
	case <-s.done:
		return s.retryCleanup()
	case <-timer.C:
		return fmt.Errorf("bridge stop timed out")
	}
}

func (s *Session) run(ctx context.Context) {
	var runErr error
	startedAt := time.Now().UTC()
	defer func() {
		cleanupErr := s.cleanup()
		manifestErr := s.writeFastManifest(startedAt, time.Now().UTC(), errors.Join(runErr, cleanupErr))
		finalizeErr := paths.FinalizeTree(s.Dir)
		if finalizeErr != nil {
			finalizeErr = fmt.Errorf("finalize pcaps: %w", finalizeErr)
			s.log("warn: " + finalizeErr.Error())
		}
		finalErr := errors.Join(runErr, manifestErr, finalizeErr)
		s.resultMu.Lock()
		s.runtimeErr = errors.Join(finalErr, s.runtimeErr)
		s.cleanupErr = cleanupErr
		s.resultErr = errors.Join(s.runtimeErr, cleanupErr)
		finalErr = s.resultErr
		s.resultMu.Unlock()
		state := "stopped"
		if cleanupErr != nil {
			state = "cleanup-pending"
		}
		s.send(Event{Kind: KindStopped, State: state, Err: finalErr})
		s.closeEvents()
		close(s.done)
	}()

	targetMAC, hasTargetMAC, err := targetMACSetting(s.Host.TargetMAC)
	if err != nil {
		runErr = err
		s.send(Event{Kind: KindError, Err: err})
		return
	}
	journalPath := filepath.Join(s.Dir, "decisions.jsonl")
	journal, err := policy.OpenJournal(journalPath)
	if err != nil {
		runErr = err
		s.send(Event{Kind: KindError, Err: err})
		return
	}
	s.log("fast bridge decision journal: " + journalPath)
	captureReady := false
	defer func() {
		if err := journal.Close(); err != nil {
			s.recordResult(err)
		}
		if !captureReady {
			if err := os.Remove(journalPath); err != nil && !errors.Is(err, os.ErrNotExist) {
				s.recordResult(fmt.Errorf("remove unused fast bridge journal: %w", err))
			}
		}
	}()

	if err := s.prepareInterfaces(ctx); err != nil {
		runErr = err
		s.send(Event{Kind: KindError, Err: err})
		return
	}

	bridgeName, err := s.createBridgeInterface(ctx)
	if err != nil {
		runErr = err
		s.send(Event{Kind: KindError, Err: err})
		return
	}

	var wg sync.WaitGroup
	var captures []*captureResource
	defer func() {
		for _, capture := range captures {
			capture.handle.Close()
		}
		wg.Wait()
		for _, capture := range captures {
			if err := capture.file.Sync(); err != nil {
				s.recordResult(fmt.Errorf("sync pcap %s: %w", capture.path, err))
			}
			if err := capture.file.Close(); err != nil {
				s.recordResult(fmt.Errorf("close pcap %s: %w", capture.path, err))
			}
		}
	}()

	startCapture := func(adapter Adapter) error {
		capture, err := s.startCapture(ctx, adapter, journal, &wg)
		if err != nil {
			return fmt.Errorf("start capture on %s: %w", adapter.Name, err)
		}
		captures = append(captures, capture)
		captureReady = true
		return nil
	}
	if err := startCapture(s.Host); err != nil {
		runErr = err
		s.send(Event{Kind: KindError, Err: err})
		return
	}

	var activated bool
	var activateErr error
	var activateMu sync.Mutex
	activate := func(mac net.HardwareAddr, firstFrame []byte) {
		activateMu.Lock()
		if activated {
			activateMu.Unlock()
			return
		}
		activated = true
		activateMu.Unlock()

		if err := s.activateBridge(ctx, bridgeName, mac, firstFrame); err != nil {
			activateMu.Lock()
			activateErr = err
			activateMu.Unlock()
			s.send(Event{Kind: KindError, Err: err})
			return
		}
		targetMAC = append(net.HardwareAddr(nil), mac...)
		if err := startCapture(Adapter{Name: bridgeName, Role: "bridge", LocalMAC: mac.String()}); err != nil {
			activateMu.Lock()
			activateErr = err
			activateMu.Unlock()
			s.send(Event{Kind: KindError, Err: err})
			return
		}
		if err := startCapture(s.Switch); err != nil {
			activateMu.Lock()
			activateErr = err
			activateMu.Unlock()
			s.send(Event{Kind: KindError, Err: err})
			return
		}
		s.send(Event{Kind: KindState, State: "active"})
		s.log("bridge iface: " + bridgeName)
		s.log("target mac: " + mac.String())
		s.log("kernel bridge active")
		s.log("normal ethernet traffic forwards through the macOS bridge")
		s.log("802.1X EAPOL passthrough relay active")
	}

	if hasTargetMAC {
		activate(targetMAC, nil)
		activateMu.Lock()
		err := activateErr
		activateMu.Unlock()
		if err != nil {
			runErr = err
			return
		}
		<-ctx.Done()
		return
	}

	s.log("host mac: auto; sniffing host side before bridge activation")
	sniffer := stealth.NewSniffer(s.Host.Name)
	id, err := sniffer.Discover(ctx, s.Host.LocalMAC, func(message string) {
		s.log(message)
	}, activate)
	if err != nil {
		if ctx.Err() == nil {
			runErr = fmt.Errorf("host mac discovery: %w", err)
			s.send(Event{Kind: KindError, Err: runErr})
		}
		return
	}
	if id != nil && len(id.MAC) > 0 {
		activate(id.MAC, nil)
	}
	activateMu.Lock()
	err = activateErr
	activateMu.Unlock()
	if err != nil {
		runErr = err
		return
	}

	<-ctx.Done()
}

func (s *Session) cleanup() error {
	release := s.cleanupGate.Enter()
	defer release()
	return s.cleanupLocked()
}

func (s *Session) cleanupLocked() error {
	var errs []error
	if s.eapolCancel != nil {
		s.eapolCancel()
	}
	if s.eapolDone != nil {
		timer := time.NewTimer(2 * time.Second)
		select {
		case <-s.eapolDone:
			timer.Stop()
		case <-timer.C:
			errs = append(errs, fmt.Errorf("EAPOL passthrough stop timed out"))
		}
	}
	if err := s.StopTakeover(); err != nil {
		errs = append(errs, fmt.Errorf("stop takeover: %w", err))
	}
	s.controlMu.Lock()
	takeoverPending := s.nat != nil
	s.controlMu.Unlock()
	boundaryRestored := false
	if takeoverPending {
		errs = append(errs, fmt.Errorf("takeover cleanup remains pending; bridge retained for retry"))
	} else {
		bridgeErr := s.destroyBridge()
		if bridgeErr != nil {
			errs = append(errs, bridgeErr)
		} else if err := s.restoreFastPF(); err != nil {
			errs = append(errs, err)
		} else {
			boundaryRestored = true
		}
	}
	if boundaryRestored {
		if err := s.restoreSysctls(); err != nil {
			errs = append(errs, err)
		}
		if err := s.restoreAdapterMACs(); err != nil {
			errs = append(errs, err)
		}
		if err := s.restoreInterfaces(); err != nil {
			errs = append(errs, err)
		}
	}
	for _, err := range errs {
		s.log("warn: " + err.Error())
	}
	return errors.Join(errs...)
}

func (s *Session) retryCleanup() error {
	release := s.cleanupGate.Enter()
	defer release()

	s.resultMu.Lock()
	needsRetry := s.cleanupErr != nil
	result := s.resultErr
	s.resultMu.Unlock()
	if !needsRetry {
		return result
	}

	retryErr := s.cleanupLocked()
	s.resultMu.Lock()
	s.cleanupErr = retryErr
	s.resultErr = errors.Join(s.runtimeErr, retryErr)
	result = s.resultErr
	s.resultMu.Unlock()
	return result
}

// CleanupPending reports whether the last teardown left reversible state to retry.
func (s *Session) CleanupPending() bool {
	if s == nil {
		return false
	}
	s.resultMu.Lock()
	defer s.resultMu.Unlock()
	return s.cleanupErr != nil
}

func (s *Session) createBridgeInterface(ctx context.Context) (string, error) {
	out, err := s.runCommand(ctx, 5*time.Second, "sysctl", "net.inet6.ip6.forwarding")
	if err != nil {
		return "", commandError("read IPv6 forwarding", out, err)
	}
	s.origIPv6Fwd = sysctlValue(out)
	if s.origIPv6Fwd != "0" && s.origIPv6Fwd != "1" {
		return "", fmt.Errorf("read IPv6 forwarding: unexpected output %q", strings.TrimSpace(out))
	}

	out, err = s.runCommand(ctx, 5*time.Second, "ifconfig", "bridge", "create")
	if err != nil {
		return "", fmt.Errorf("create bridge: %w (%s)", err, strings.TrimSpace(out))
	}
	bridgeName := strings.TrimSpace(out)
	if !validBridgeInterfaceName(bridgeName) {
		return "", fmt.Errorf("create bridge: invalid bridge name %q", bridgeName)
	}
	s.bridgeName = bridgeName
	s.BridgeName = bridgeName
	s.log("bridge created: " + bridgeName)

	if out, err := s.runCommand(ctx, 5*time.Second, "ifconfig", s.Host.Name, "up"); err != nil {
		return "", fmt.Errorf("host adapter up: %w (%s)", err, strings.TrimSpace(out))
	}
	s.log("host adapter up: " + s.Host.Name)

	if out, err := s.runCommand(ctx, 5*time.Second, "sysctl", "-w", "net.inet6.ip6.forwarding=0"); err != nil {
		return "", commandError("disable IPv6 forwarding", out, err)
	}

	return bridgeName, nil
}

func (s *Session) activateBridge(ctx context.Context, bridgeName string, targetMAC net.HardwareAddr, firstFrame []byte) error {
	s.controlMu.Lock()
	s.targetMAC = append(net.HardwareAddr(nil), targetMAC...)
	s.controlMu.Unlock()

	if out, err := s.runCommand(ctx, 5*time.Second, "ifconfig", bridgeName, "ether", targetMAC.String()); err != nil {
		return commandError("set bridge MAC", out, err)
	}
	s.log("bridge mac: " + targetMAC.String())

	spoofed := s.spoofSwitchAdapterMAC(ctx, targetMAC, "before bridge up")

	if out, err := s.runCommand(ctx, 5*time.Second, "ifconfig", bridgeName, "addm", s.Host.Name, "addm", s.Switch.Name); err != nil {
		return fmt.Errorf("attach members: %w (%s)", err, strings.TrimSpace(out))
	}
	s.log(fmt.Sprintf("bridge members: %s %s", s.Host.Name, s.Switch.Name))

	for _, adapter := range []Adapter{s.Host, s.Switch} {
		if out, err := s.runCommand(ctx, 5*time.Second, "ifconfig", bridgeName, "stp", adapter.Name, "disabled"); err != nil {
			return commandError("disable STP for "+adapter.Name, out, err)
		}
	}

	if err := s.installBridgeSafety(bridgeName, targetMAC); err != nil {
		return err
	}
	if active, ok := s.policyEngine.Policies.Active(); ok {
		if err := s.effectiveBridgeRuleManager().InstallPolicy(bridgeName, s.Host.Name, s.Switch.Name, active.Rules()); err != nil {
			return fmt.Errorf("install fast bridge policy: %w", err)
		}
	}
	if err := s.installFastPF(ctx); err != nil {
		return err
	}

	if out, err := s.runCommand(ctx, 5*time.Second, "ifconfig", bridgeName, "up"); err != nil {
		return fmt.Errorf("bridge up: %w (%s)", err, strings.TrimSpace(out))
	}

	if out, err := s.runCommand(ctx, 5*time.Second, "ifconfig", s.Switch.Name, "up"); err != nil {
		return fmt.Errorf("switch adapter up: %w (%s)", err, strings.TrimSpace(out))
	}
	s.log("switch adapter up: " + s.Switch.Name)

	if !spoofed {
		if !s.spoofSwitchAdapterMAC(ctx, targetMAC, "after bridge up") {
			return fmt.Errorf("set switch adapter MAC to target identity")
		}
	}
	if out, err := s.runCommand(ctx, 5*time.Second, "ifconfig", bridgeName, "inet6", "-autoconf"); err != nil {
		s.log(fmt.Sprintf("warn: bridge ipv6 autoconf suppress failed: %v (%s)", err, strings.TrimSpace(out)))
	} else {
		s.log("bridge ipv6 autoconf suppressed")
	}

	return s.startEAPOLPassthrough(ctx, targetMAC, firstFrame)
}

func (s *Session) installFastPF(ctx context.Context) error {
	if strings.TrimSpace(s.fastPFRules) == "" {
		return nil
	}
	if s.fastPF == nil {
		return fmt.Errorf("fast bridge PF backend is unavailable")
	}
	if s.ipFilter == nil {
		return fmt.Errorf("fast bridge member filter is unavailable")
	}
	if err := s.fastPF.Apply(ctx, s.fastPFRules); err != nil {
		return fmt.Errorf("apply fast bridge PF policy: %w", err)
	}
	if err := s.ipFilter.Enable(s.bridgeName); err != nil {
		return fmt.Errorf("enable fast bridge PF member hooks: %w", err)
	}
	s.log("fast bridge PF policy installed: anchor=" + stealth.FastBridgePFAnchor)
	return nil
}

func (s *Session) restoreFastPF() error {
	if s.fastPF == nil {
		return nil
	}
	if err := s.fastPF.Restore(context.Background()); err != nil {
		return fmt.Errorf("restore fast bridge PF policy: %w", err)
	}
	s.fastPF = nil
	s.log("fast bridge PF policy restored")
	return nil
}

func (s *Session) startEAPOLPassthrough(ctx context.Context, targetMAC net.HardwareAddr, firstFrame []byte) error {
	if strings.TrimSpace(s.bridgeName) == "" {
		return fmt.Errorf("bridge interface is not active")
	}
	if err := s.effectiveBridgeRuleManager().SuppressEAPOL(s.bridgeName, s.Host.Name, s.Switch.Name); err != nil {
		return fmt.Errorf("suppress native EAPOL forwarding: %w", err)
	}
	s.log("native bridge EAPOL forwarding suppressed for relay")

	relayCtx, cancel := context.WithCancel(ctx)
	s.eapolCancel = cancel
	s.eapolDone = make(chan struct{})

	session := eapol.NewAuthSession(append(net.HardwareAddr(nil), targetMAC...))
	s.controlMu.Lock()
	s.authSession = session
	s.controlMu.Unlock()

	relay := eapol.NewRelay(s.Host.Name, s.Switch.Name, session, func(message string) {
		s.log(message)
	})
	s.controlMu.Lock()
	policy := s.eapolPolicy
	s.controlMu.Unlock()

	relay.SetModeName("transparent EAPOL passthrough")
	relay.SetInjectStart(false)
	relay.SetSuppressLogoff(policy.SuppressLogoff)
	relay.SetStrictAuthenticator(false)
	relay.SetStrictVLAN(false)
	relay.SetDowngrade(policy.DowngradeMACsec)
	if len(firstFrame) > 0 {
		relay.SetInitialFrame(firstFrame)
	}
	s.controlMu.Lock()
	s.eapolRelay = relay
	s.controlMu.Unlock()

	go func() {
		defer close(s.eapolDone)
		defer func() {
			s.controlMu.Lock()
			if s.eapolRelay == relay {
				s.eapolRelay = nil
			}
			s.controlMu.Unlock()
		}()
		s.log(fmt.Sprintf("EAPOL passthrough active: %s <-> %s", s.Host.Name, s.Switch.Name))
		if err := relay.Start(relayCtx); err != nil && relayCtx.Err() == nil {
			err = fmt.Errorf("eapol relay: %w", err)
			s.recordResult(err)
			s.send(Event{Kind: KindError, Err: err})
			if s.cancel != nil {
				s.cancel()
			}
		}
	}()
	return nil
}

// SetEAPOLPolicy updates passthrough behavior for future relay frames.
func (s *Session) SetEAPOLPolicy(policy EAPOLPolicy) {
	if s == nil {
		return
	}
	s.controlMu.Lock()
	s.eapolPolicy = policy
	relay := s.eapolRelay
	s.controlMu.Unlock()

	if relay != nil {
		relay.SetSuppressLogoff(policy.SuppressLogoff)
		relay.SetDowngrade(policy.DowngradeMACsec)
	}
	if policy.SuppressLogoff {
		s.log("eapol drop-logoff: enable")
	} else {
		s.log("eapol drop-logoff: disable")
	}
	if policy.DowngradeMACsec {
		s.log("eapol macsec-downgrade: enable")
	} else {
		s.log("eapol macsec-downgrade: disable")
	}
}

func (s *Session) spoofSwitchAdapterMAC(ctx context.Context, targetMAC net.HardwareAddr, phase string) bool {
	if s.Switch.Name == "" {
		return false
	}
	if original, err := requiredTargetMAC(s.Switch.LocalMAC); err == nil && !macEqual(original, targetMAC) {
		s.rememberAdapterMAC(s.Switch.Name, original.String())
	}
	if out, err := s.runCommand(ctx, 5*time.Second, "ifconfig", s.Switch.Name, "ether", targetMAC.String()); err != nil {
		s.log(fmt.Sprintf("warn: switch adapter mac set failed for %s %s: %v (%s)", s.Switch.Name, phase, err, strings.TrimSpace(out)))
		return false
	}
	s.log(fmt.Sprintf("switch adapter mac %s: %s", phase, targetMAC.String()))
	return true
}

func (s *Session) rememberAdapterMAC(name, mac string) {
	for _, item := range s.macRestore {
		if strings.EqualFold(item.Name, name) {
			return
		}
	}
	s.macRestore = append(s.macRestore, adapterMACRestore{Name: name, MAC: mac})
}

func (s *Session) installBridgeSafety(bridgeName string, targetMAC net.HardwareAddr) error {
	var errs []error
	protected := s.protectedSourceMACs(targetMAC)
	if len(protected) > 0 {
		if err := s.effectiveBridgeRuleManager().InstallSafety(bridgeName, protected); err != nil {
			errs = append(errs, fmt.Errorf("install local source-MAC safety: %w", err))
		} else {
			s.log("local source-mac safety installed")
		}
	}
	if err := s.effectiveBridgeRuleManager().SuppressLeaks(bridgeName); err != nil {
		errs = append(errs, fmt.Errorf("install L2 discovery leak suppression: %w", err))
	} else {
		s.log("STP/LLDP/CDP leak suppression verified")
	}
	return errors.Join(errs...)
}

func (s *Session) protectedSourceMACs(targetMAC net.HardwareAddr) []net.HardwareAddr {
	var protected []net.HardwareAddr
	seen := make(map[string]bool)
	for _, value := range []string{s.Host.LocalMAC, s.Switch.LocalMAC} {
		mac, err := net.ParseMAC(strings.TrimSpace(value))
		if err != nil || !validSourceMAC(mac) || macEqual(mac, targetMAC) {
			continue
		}
		key := strings.ToLower(mac.String())
		if seen[key] {
			continue
		}
		seen[key] = true
		protected = append(protected, mac)
	}
	return protected
}

func (s *Session) destroyBridge() error {
	bridgeName := strings.TrimSpace(s.bridgeName)
	if bridgeName == "" {
		return nil
	}
	if out, err := s.runCommand(context.Background(), 5*time.Second, "ifconfig", bridgeName, "destroy"); err != nil {
		return commandError("destroy bridge "+bridgeName, out, err)
	}
	s.bridgeName = ""
	s.BridgeName = ""
	s.log("bridge destroyed: " + bridgeName)
	return nil
}

func (s *Session) restoreSysctls() error {
	if s.origIPv6Fwd != "" {
		out, err := s.runCommand(context.Background(), 5*time.Second, "sysctl", "-w", "net.inet6.ip6.forwarding="+s.origIPv6Fwd)
		if err != nil {
			return commandError("restore IPv6 forwarding", out, err)
		}
		s.origIPv6Fwd = ""
	}
	return nil
}

func (s *Session) restoreAdapterMACs() error {
	restore := s.macRestore
	var errs []error
	var failed []adapterMACRestore
	for i := len(restore) - 1; i >= 0; i-- {
		item := restore[i]
		if item.Name == "" || item.MAC == "" {
			continue
		}
		if out, err := s.runCommand(context.Background(), 5*time.Second, "ifconfig", item.Name, "ether", item.MAC); err != nil {
			errs = append(errs, commandError("restore adapter MAC for "+item.Name, out, err))
			failed = append(failed, item)
		} else {
			s.log(fmt.Sprintf("adapter mac restored: %s %s", item.Name, item.MAC))
		}
	}
	for i, j := 0, len(failed)-1; i < j; i, j = i+1, j-1 {
		failed[i], failed[j] = failed[j], failed[i]
	}
	s.macRestore = failed
	return errors.Join(errs...)
}

func (s *Session) startCapture(ctx context.Context, adapter Adapter, journal *policy.Journal, wg *sync.WaitGroup) (*captureResource, error) {
	handle, writer, capture, err := s.openCapture(adapter)
	if err != nil {
		return nil, err
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		s.capture(ctx, adapter, handle, writer, journal)
	}()
	return capture, nil
}

func (s *Session) openCapture(adapter Adapter) (*pcap.Handle, *pcapgo.Writer, *captureResource, error) {
	handle, err := pcap.OpenLive(adapter.Name, 65535, true, pcap.BlockForever)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("open %s: %w", adapter.Name, err)
	}

	path, writer, file, err := pcapWriter(s.Dir, adapter.Role, adapter.Name, handle.LinkType())
	if err != nil {
		handle.Close()
		return nil, nil, nil, err
	}
	s.send(Event{Kind: KindPcap, Adapter: adapter.Name, Role: adapter.Role, Path: path})
	return handle, writer, &captureResource{handle: handle, file: file, path: path}, nil
}

func (s *Session) capture(ctx context.Context, adapter Adapter, handle *pcap.Handle, writer *pcapgo.Writer, journal *policy.Journal) {
	ignoreMAC, err := net.ParseMAC(adapter.LocalMAC)
	if err != nil {
		err = fmt.Errorf("parse local MAC for %s: %w", adapter.Name, err)
		s.recordResult(err)
		s.send(Event{Kind: KindError, Adapter: adapter.Name, Role: adapter.Role, Err: err})
		return
	}
	source := gopacket.NewPacketSource(handle, handle.LinkType())
	var packetCount int
	for {
		packet, err := source.NextPacket()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			err = fmt.Errorf("read capture on %s: %w", adapter.Name, err)
			s.recordResult(err)
			s.send(Event{Kind: KindError, Adapter: adapter.Name, Role: adapter.Role, Err: err})
			if s.cancel != nil {
				s.cancel()
			}
			return
		}
		if packet == nil {
			continue
		}
		data := packet.Data()
		if err := writer.WritePacket(packet.Metadata().CaptureInfo, data); err != nil {
			err = fmt.Errorf("write pcap for %s: %w", adapter.Name, err)
			s.recordResult(err)
			s.send(Event{Kind: KindError, Adapter: adapter.Name, Role: adapter.Role, Err: err})
			if s.cancel != nil {
				s.cancel()
			}
			return
		}
		result, mode, policyErr := s.processFastCapturedPacket(adapter, packet, handle.LinkType(), journal)
		if policyErr != nil {
			err = policyErr
			s.recordResult(err)
			s.send(Event{Kind: KindError, Adapter: adapter.Name, Role: adapter.Role, Err: err})
			if s.cancel != nil {
				s.cancel()
			}
			return
		}
		if result.Decision.RuleRevision != "" {
			s.send(Event{
				Kind: KindDecision, Adapter: adapter.Name, Role: adapter.Role,
				Packet:   string(result.Original.ID),
				Message:  fmt.Sprintf("[%s] %s", result.Decision.Status, result.Decision.Explanation),
				Decision: result.Decision.Summary(),
			})
		}
		packetCount++
		if summary, _ := listen.PacketSummary(packet); summary != "" {
			s.send(Event{
				Kind:    KindTraffic,
				Adapter: adapter.Name,
				Role:    adapter.Role,
				Packet:  string(result.Original.ID),
				Message: fmt.Sprintf("#%d %s/%s %s", packetCount, adapter.Role, adapter.Name, summary),
			})
		}
		s.send(Event{
			Kind: KindEvidence, Frame: result.Original, Flow: result.Flow,
			Mode: mode, Decision: result.Decision.Summary(),
		})
		if s.inspector != nil {
			for _, signal := range s.inspector.AnalyzePacket(packet) {
				s.send(Event{Kind: KindSignal, Adapter: adapter.Name, Role: adapter.Role, Message: signal.Encode()})
			}
		}
		for _, discovery := range listen.AnalyzePacket(packet, ignoreMAC) {
			s.send(Event{
				Kind:      KindDiscovery,
				Adapter:   adapter.Name,
				Role:      adapter.Role,
				Field:     discovery.Field,
				Value:     discovery.Value,
				Evidence:  discovery.Evidence,
				Packet:    discovery.Packet,
				DeviceMAC: discovery.DeviceMAC,
			})
		}
	}
}

func (s *Session) processFastCapturedPacket(adapter Adapter, packet gopacket.Packet, linkType layers.LinkType, journal *policy.Journal) (policy.Result, dataplane.Mode, error) {
	if packet == nil || packet.Metadata() == nil {
		return policy.Result{}, dataplane.ModeFastBridge, fmt.Errorf("fast bridge capture packet is unavailable")
	}
	s.controlMu.Lock()
	targetMAC := append(net.HardwareAddr(nil), s.targetMAC...)
	mode := dataplane.ModeFastBridge
	if s.nat != nil && s.nat.HostDetached {
		mode = dataplane.ModeTakeover
	}
	s.controlMu.Unlock()
	direction := traffic.DirectionUnknown
	if ethernet, ok := packet.Layer(layers.LayerTypeEthernet).(*layers.Ethernet); ok && len(targetMAC) == 6 {
		switch {
		case macEqual(ethernet.SrcMAC, targetMAC):
			if mode == dataplane.ModeTakeover {
				direction = traffic.DirectionOutbound
			} else {
				direction = traffic.DirectionHostToSwitch
			}
		case macEqual(ethernet.DstMAC, targetMAC):
			if mode == dataplane.ModeTakeover {
				direction = traffic.DirectionInbound
			} else {
				direction = traffic.DirectionSwitchToHost
			}
		}
	}
	side := traffic.SideUnknown
	switch strings.ToLower(adapter.Role) {
	case "host":
		side = traffic.SideHost
	case "switch":
		side = traffic.SideSwitch
	case "bridge":
		side = traffic.SideLocal
	}
	captureInfo := packet.Metadata().CaptureInfo
	frame := traffic.Normalize(packet.Data(), traffic.CaptureMetadata{
		Timestamp: captureInfo.Timestamp, CaptureLength: captureInfo.CaptureLength,
		OriginalLength: captureInfo.Length, InterfaceIndex: captureInfo.InterfaceIndex,
		LinkType: int(linkType), Source: s.Dir,
	}, adapter.Name, side, direction)
	result, err := s.policyEngine.Process(frame, dataplane.ForMode(mode))
	if err != nil {
		return result, mode, fmt.Errorf("evaluate bridge policy on %s: %w", adapter.Name, err)
	}
	if err := journal.Append(result.Decision); err != nil {
		return result, mode, fmt.Errorf("journal bridge policy on %s: %w", adapter.Name, err)
	}
	return result, mode, nil
}

func (s *Session) prepareInterfaces(ctx context.Context) error {
	runner := s.effectiveRunner()
	for _, adapter := range []Adapter{s.Host, s.Switch} {
		state, err := snapshotInterfaceState(ctx, runner, adapter.Name, adapter.NetworkService)
		if err != nil {
			return fmt.Errorf("snapshot %s adapter: %w", adapter.Role, err)
		}
		s.interfaces = append(s.interfaces, state)
		if !state.ServiceEnabled {
			continue
		}
		out, err := s.runCommand(ctx, 5*time.Second, "networksetup", "-setnetworkserviceenabled", state.NetworkService, "off")
		if err != nil {
			return commandError("disable service "+state.NetworkService, out, err)
		}
		s.log("service detached: " + state.NetworkService)
	}
	return nil
}

func (s *Session) restoreInterfaces() error {
	restore := s.interfaces
	runner := s.effectiveRunner()
	var errs []error
	var failed []InterfaceRestoreState
	for i := len(restore) - 1; i >= 0; i-- {
		item := restore[i]
		if err := restoreInterfaceState(context.Background(), runner, item); err != nil {
			errs = append(errs, err)
			failed = append(failed, item)
		} else {
			s.log("adapter state restored: " + item.IfName)
		}
	}
	for i, j := 0, len(failed)-1; i < j; i, j = i+1, j-1 {
		failed[i], failed[j] = failed[j], failed[i]
	}
	s.interfaces = failed
	return errors.Join(errs...)
}

func (s *Session) log(message string) {
	s.send(Event{Kind: KindLog, Message: message})
}

func (s *Session) send(event Event) {
	if s == nil || s.events == nil {
		return
	}

	release := s.eventGate.Enter()
	defer release()
	if s.eventsDone {
		return
	}

	if event.Kind == KindLog || event.Kind == KindTraffic || event.Kind == KindEvidence || event.Kind == KindDecision {
		select {
		case s.events <- event:
		default:
		}
		return
	}

	timer := time.NewTimer(eventDeliveryTimeout)
	defer timer.Stop()
	select {
	case s.events <- event:
	case <-timer.C:
		s.recordResult(fmt.Errorf("deliver %s event: timed out", event.Kind))
	}
}

func (s *Session) closeEvents() {
	if s == nil || s.events == nil {
		return
	}
	release := s.eventGate.Enter()
	defer release()
	if s.eventsDone {
		return
	}
	s.eventsDone = true
	close(s.events)
}

func (s *Session) recordResult(err error) {
	if s == nil || err == nil {
		return
	}
	s.resultMu.Lock()
	s.runtimeErr = errors.Join(s.runtimeErr, err)
	s.resultErr = errors.Join(s.runtimeErr, s.cleanupErr)
	s.resultMu.Unlock()
}

func pcapWriter(dir, role, adapter string, linkType layers.LinkType) (string, *pcapgo.Writer, *os.File, error) {
	path := filepath.Join(dir, fmt.Sprintf("%s-%s.pcap", paths.SafeFilenamePart(role), paths.SafeFilenamePart(adapter)))
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return "", nil, nil, fmt.Errorf("create pcap %s: %w", path, err)
	}
	writer := pcapgo.NewWriter(file)
	if err := writer.WriteFileHeader(65535, linkType); err != nil {
		return "", nil, nil, errors.Join(
			fmt.Errorf("write pcap header %s: %w", path, err),
			file.Close(),
			os.Remove(path),
		)
	}
	return path, writer, file, nil
}

func requiredTargetMAC(value string) (net.HardwareAddr, error) {
	value = strings.TrimSpace(value)
	if value == "" || strings.EqualFold(value, "auto") {
		return nil, fmt.Errorf("host mac is required before bridge start")
	}
	mac, err := net.ParseMAC(value)
	if err != nil {
		return nil, fmt.Errorf("host mac %q is invalid: %w", value, err)
	}
	if !validSourceMAC(mac) {
		return nil, fmt.Errorf("host mac %q is not a usable unicast source", value)
	}
	return mac, nil
}

func targetMACSetting(value string) (net.HardwareAddr, bool, error) {
	value = strings.TrimSpace(value)
	if value == "" || strings.EqualFold(value, "auto") {
		return nil, false, nil
	}
	mac, err := requiredTargetMAC(value)
	if err != nil {
		return nil, false, err
	}
	return mac, true, nil
}

func sysctlValue(output string) string {
	output = strings.TrimSpace(output)
	parts := strings.SplitN(output, ":", 2)
	if len(parts) == 2 {
		return strings.TrimSpace(parts[1])
	}
	return output
}

func (s *Session) runCommand(ctx context.Context, timeout time.Duration, name string, args ...string) (string, error) {
	return s.effectiveRunner().Run(ctx, timeout, name, args...)
}

func (s *Session) effectiveRunner() commandRunner {
	if s != nil && s.runner != nil {
		return s.runner
	}
	return execCommandRunner{}
}

type commandRunner interface {
	Run(ctx context.Context, timeout time.Duration, name string, args ...string) (string, error)
}

type execCommandRunner struct{}

func (execCommandRunner) Run(ctx context.Context, timeout time.Duration, name string, args ...string) (string, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	runCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(runCtx, name, args...)
	out, err := cmd.CombinedOutput()
	if runCtx.Err() == context.DeadlineExceeded {
		return string(out), fmt.Errorf("%s %s timed out after %s", name, strings.Join(args, " "), timeout)
	}
	return string(out), err
}

func validSourceMAC(mac net.HardwareAddr) bool {
	if len(mac) != 6 || mac[0]&1 != 0 {
		return false
	}
	for _, b := range mac {
		if b != 0 {
			return true
		}
	}
	return false
}

func macEqual(a, b net.HardwareAddr) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
