package edge

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golan/internal/dataplane"
	"golan/internal/paths"
	"golan/internal/pfutil"
	"golan/internal/policy"
	"golan/internal/syncgate"
	"golan/internal/traffic"

	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// EventKind identifies edge lifecycle and bounded Workbench telemetry.
type EventKind string

const (
	KindState    EventKind = "state"
	KindLog      EventKind = "log"
	KindPcap     EventKind = "pcap"
	KindEvidence EventKind = "evidence"
	KindDecision EventKind = "decision"
	KindError    EventKind = "error"
	KindStopped  EventKind = "stopped"
)

// Event contains payload-free operator state. Evidence events additionally
// carry one immutable frame to the bounded in-process rule-preview buffer; the
// frame is never rendered or logged.
type Event struct {
	Kind     EventKind
	State    string
	Message  string
	Packet   string
	Path     string
	Err      error
	Frame    traffic.Frame
	Flow     traffic.Flow
	Mode     dataplane.Mode
	Decision policy.DecisionSummary
}

// Stats is a concurrency-safe edge session snapshot.
type Stats struct {
	OriginalPackets  uint64 `json:"original_packets"`
	ForwardedPackets uint64 `json:"forwarded_packets"`
	BlockedPackets   uint64 `json:"blocked_packets"`
	DHCPReplies      uint64 `json:"dhcp_replies"`
}

// HealthSnapshot is a payload-free, concurrency-safe edge runtime summary.
// It exposes ownership and pressure state without command output, packet
// content, held-message bytes, or a PF restoration token value.
type HealthSnapshot struct {
	Mode               Mode       `json:"mode"`
	Egress             EgressMode `json:"egress"`
	Downstream         string     `json:"downstream"`
	Upstream           string     `json:"upstream"`
	VPNDestinations    []string   `json:"vpn_destinations,omitempty"`
	VPNRouteAddress    string     `json:"vpn_route_address,omitempty"`
	EgressMTU          int        `json:"egress_mtu,omitempty"`
	Subnet             string     `json:"subnet"`
	LeaseServer        string     `json:"lease_server"`
	LeaseClient        string     `json:"lease_client"`
	LeaseGateway       string     `json:"lease_gateway"`
	DNS                []string   `json:"dns,omitempty"`
	DNSUpstreams       []string   `json:"dns_upstreams,omitempty"`
	DNSRelay           bool       `json:"dns_relay"`
	Stats              Stats      `json:"stats"`
	PF                 PFState    `json:"pf"`
	ForwardingSnapshot bool       `json:"forwarding_snapshot"`
	ForwardingChanged  bool       `json:"forwarding_changed"`
	AliasAdded         bool       `json:"alias_added"`
	InterfaceRaised    bool       `json:"interface_raised"`
	CleanupPending     bool       `json:"cleanup_pending"`
}

type counters struct {
	original  atomic.Uint64
	forwarded atomic.Uint64
	blocked   atomic.Uint64
	dhcp      atomic.Uint64
}

// Session owns one reversible single-adapter routed edge run.
type Session struct {
	Config Config
	Lease  Lease
	Dir    string
	Events <-chan Event
	Engine *policy.Engine

	cancel context.CancelFunc
	done   chan struct{}
	events chan Event
	runner pfutil.Runner
	pf     *PFBackend

	mu                  sync.Mutex
	cleanupGate         syncgate.Gate
	resultErr           error
	persistentErr       error
	cleanupErr          error
	originalForwarding  string
	forwardingChanged   bool
	aliasAdded          bool
	interfaceStateKnown bool
	originalInterfaceUp bool
	interfaceRaised     bool
	stats               counters
}

// Start validates and compiles every value before creating a routed session.
// Observe remains implemented by the passive listener.
func Start(config Config, revision string, rules []policy.Rule) (*Session, error) {
	if config.Mode == ModeObserve {
		return nil, fmt.Errorf("edge observe uses the passive capture session")
	}
	if config.Mode != ModeRoute {
		return nil, fmt.Errorf("edge session mode must be route")
	}
	if len(rules) > 0 {
		if _, err := CompilePFWithPolicy(config, revision, rules); err != nil {
			return nil, err
		}
	} else if _, err := CompilePF(config); err != nil {
		return nil, err
	}
	if config.EffectiveEgress() == EgressVPN {
		if err := validateVPNRoute(config.Upstream, config.VPNRouteAddress, config.EgressMTU); err != nil {
			return nil, err
		}
	}
	if requiresDNSRelay(config.DNS) {
		loopbackCount, responding := 0, 0
		var probeErrs []error
		for _, address := range config.DNS {
			if !address.IsLoopback() {
				continue
			}
			loopbackCount++
			probeCtx, cancelProbe := context.WithTimeout(context.Background(), 2*time.Second)
			probeErr := ProbeDNSResolver(probeCtx, address)
			cancelProbe()
			if probeErr == nil {
				responding++
			} else {
				probeErrs = append(probeErrs, probeErr)
			}
		}
		if loopbackCount == len(config.DNS) && responding == 0 {
			return nil, fmt.Errorf("Mac-side DNS relay has no responding loopback resolver: %w", errors.Join(probeErrs...))
		}
	}
	engine := policy.NewEngine(8192)
	if len(rules) > 0 {
		if err := engine.Policies.Activate(revision, rules); err != nil {
			return nil, fmt.Errorf("compile edge policy: %w", err)
		}
	}
	lease, err := LeaseForSubnet(config.Subnet, config.DNS)
	if err != nil {
		return nil, err
	}
	lease = relayLeaseDNS(lease, config.DNS)
	directory, err := paths.PcapRunDir()
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return nil, fmt.Errorf("create edge artifact directory: %w", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	events := make(chan Event, 128)
	runner := pfutil.ExecRunner{}
	backend := NewPFBackend()
	session := &Session{
		Config: config, Lease: lease, Dir: directory, Events: events, Engine: engine,
		cancel: cancel, done: make(chan struct{}), events: events, runner: runner, pf: backend,
	}
	go session.run(ctx)
	return session, nil
}

// Stop cancels forwarding and waits for artifact finalization and restoration.
// A prior partial cleanup is retried without replaying successful steps.
func (s *Session) Stop() error {
	if s == nil {
		return nil
	}
	if s.cancel != nil {
		s.cancel()
	}
	if s.done != nil {
		timer := time.NewTimer(8 * time.Second)
		select {
		case <-s.done:
			timer.Stop()
		case <-timer.C:
			return fmt.Errorf("edge stop timed out")
		}
	}
	s.mu.Lock()
	pending := s.cleanupErr != nil
	s.mu.Unlock()
	if pending {
		cleanupErr := s.cleanup()
		s.mu.Lock()
		s.cleanupErr = cleanupErr
		s.resultErr = errors.Join(s.persistentErr, cleanupErr)
		s.mu.Unlock()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.resultErr
}

// CleanupPending reports retryable reversible state.
func (s *Session) CleanupPending() bool {
	if s == nil {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.cleanupErr != nil
}

// Stats returns current forwarding counters.
func (s *Session) Stats() Stats {
	if s == nil {
		return Stats{}
	}
	return Stats{OriginalPackets: s.stats.original.Load(), ForwardedPackets: s.stats.forwarded.Load(), BlockedPackets: s.stats.blocked.Load(), DHCPReplies: s.stats.dhcp.Load()}
}

// Health returns an immutable payload-free session health snapshot.
func (s *Session) Health() HealthSnapshot {
	if s == nil {
		return HealthSnapshot{PF: PFState{Anchor: PFAnchor}}
	}
	pfState := PFState{Anchor: PFAnchor}
	if s.pf != nil {
		pfState = s.pf.State()
	}
	health := HealthSnapshot{
		Mode:            s.Config.Mode,
		Egress:          s.Config.EffectiveEgress(),
		Downstream:      s.Config.Downstream,
		Upstream:        s.Config.Upstream,
		VPNRouteAddress: validAddrString(s.Config.VPNRouteAddress),
		EgressMTU:       s.Config.EgressMTU,
		Subnet:          s.Config.Subnet.String(),
		LeaseServer:     s.Lease.ServerIP.String(),
		LeaseClient:     s.Lease.ClientIP.String(),
		LeaseGateway:    s.Lease.Gateway.String(),
		Stats:           s.Stats(),
		PF:              pfState,
	}
	for _, destination := range s.Config.VPNDestinations {
		health.VPNDestinations = append(health.VPNDestinations, destination.Masked().String())
	}
	health.DNS = make([]string, 0, len(s.Lease.DNS))
	for _, address := range s.Lease.DNS {
		health.DNS = append(health.DNS, address.String())
	}
	health.DNSRelay = requiresDNSRelay(s.Config.DNS)
	for _, address := range s.Config.DNS {
		health.DNSUpstreams = append(health.DNSUpstreams, address.String())
	}

	s.mu.Lock()
	health.ForwardingSnapshot = s.originalForwarding != ""
	health.ForwardingChanged = s.forwardingChanged
	health.AliasAdded = s.aliasAdded
	health.InterfaceRaised = s.interfaceRaised
	health.CleanupPending = s.cleanupErr != nil
	s.mu.Unlock()
	return health
}

// SetPolicy atomically changes the active edge revision.
func (s *Session) SetPolicy(revision string, rules []policy.Rule) error {
	if s == nil || s.Engine == nil {
		return fmt.Errorf("edge policy engine is unavailable")
	}
	if _, err := policy.Compile(revision, rules); err != nil {
		return err
	}
	pfRules, err := CompilePFWithPolicy(s.Config, revision, rules)
	if err != nil {
		return err
	}
	if err := s.pf.Apply(context.Background(), pfRules); err != nil {
		return fmt.Errorf("apply edge policy revision: %w", err)
	}
	return s.Engine.Policies.Activate(revision, rules)
}

type liveHandle struct {
	*pcap.Handle
	once sync.Once
}

func (h *liveHandle) close() { h.once.Do(func() { h.Handle.Close() }) }

func (s *Session) run(ctx context.Context) {
	started := time.Now().UTC()
	var runErr error
	defer func() {
		cleanupErr := s.cleanup()
		manifestErr := s.writeManifest(started, time.Now().UTC(), errors.Join(runErr, cleanupErr))
		finalizeErr := paths.FinalizeTree(s.Dir)
		s.mu.Lock()
		s.persistentErr = errors.Join(runErr, manifestErr, finalizeErr)
		s.cleanupErr = cleanupErr
		s.resultErr = errors.Join(s.persistentErr, cleanupErr)
		s.mu.Unlock()
		state := "stopped"
		if cleanupErr != nil {
			state = "cleanup-pending"
		}
		s.send(Event{Kind: KindStopped, State: state, Err: s.resultErr})
		close(s.events)
		close(s.done)
	}()

	serverInterface, err := net.InterfaceByName(s.Config.Downstream)
	if err != nil {
		runErr = fmt.Errorf("read downstream adapter: %w", err)
		s.send(Event{Kind: KindError, Err: runErr})
		return
	}
	serverMAC := append(net.HardwareAddr(nil), serverInterface.HardwareAddr...)
	if len(serverMAC) != 6 || serverMAC[0]&1 != 0 {
		runErr = fmt.Errorf("downstream adapter has no usable Ethernet MAC")
		s.send(Event{Kind: KindError, Err: runErr})
		return
	}
	if s.Config.EffectiveEgress() == EgressVPN {
		if err := validateVPNRoute(s.Config.Upstream, s.Config.VPNRouteAddress, s.Config.EgressMTU); err != nil {
			runErr = err
			s.send(Event{Kind: KindError, Err: err})
			return
		}
	}
	// Arm both BPF readers while the isolated downstream interface is still
	// down. macOS clients commonly transmit DHCP immediately on link-up; opening
	// capture only after prepare raised the interface could miss that first
	// DISCOVER and leave the client waiting for its retransmission backoff.
	ingress, err := openDirectionalHandle(s.Config.Downstream, pcap.DirectionIn)
	if err != nil {
		runErr = err
		s.send(Event{Kind: KindError, Err: err})
		return
	}
	defer ingress.close()
	outbound, err := openDirectionalHandle(s.Config.Downstream, pcap.DirectionOut)
	if err != nil {
		runErr = err
		s.send(Event{Kind: KindError, Err: err})
		return
	}
	defer outbound.close()
	record, err := openRecorder(s.Dir, ingress.LinkType())
	if err != nil {
		runErr = err
		s.send(Event{Kind: KindError, Err: err})
		return
	}
	defer func() {
		runErr = errors.Join(runErr, record.Close())
	}()
	if err := s.prepare(ctx); err != nil {
		runErr = err
		s.send(Event{Kind: KindError, Err: err})
		return
	}
	var relay *dnsRelay
	if requiresDNSRelay(s.Config.DNS) {
		relay, err = startDNSRelay(s.Lease.ServerIP, s.Config.DNS)
		if err != nil {
			runErr = err
			s.send(Event{Kind: KindError, Err: err})
			return
		}
		defer relay.Close()
	}
	s.send(Event{Kind: KindPcap, Path: filepath.Join(s.Dir, "original.pcap"), Message: "original"})
	s.send(Event{Kind: KindPcap, Path: filepath.Join(s.Dir, "forwarded.pcap"), Message: "forwarded"})
	s.send(Event{Kind: KindState, State: "active", Message: "edge route active"})

	componentCount := 2
	if s.Config.EffectiveEgress() == EgressVPN {
		componentCount++
	}
	if relay != nil {
		componentCount++
	}
	errCh := make(chan error, componentCount)
	go func() { errCh <- s.captureOriginal(ctx, ingress, record, serverMAC) }()
	go func() { errCh <- s.captureForwarded(ctx, outbound, record) }()
	if s.Config.EffectiveEgress() == EgressVPN {
		go func() { errCh <- s.monitorVPNEgress(ctx) }()
	}
	if relay != nil {
		go func() { errCh <- relay.Run(ctx) }()
	}
	go func() {
		<-ctx.Done()
		ingress.close()
		outbound.close()
	}()
	for index := 0; index < componentCount; index++ {
		componentErr := <-errCh
		if componentErr != nil && !errors.Is(componentErr, io.EOF) && ctx.Err() == nil {
			runErr = errors.Join(runErr, componentErr)
			s.send(Event{Kind: KindError, Err: componentErr})
		}
		if index == 0 && s.cancel != nil {
			s.cancel()
		}
	}
}

func (s *Session) monitorVPNEgress(ctx context.Context) error {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			if err := validateVPNRoute(s.Config.Upstream, s.Config.VPNRouteAddress, s.Config.EgressMTU); err != nil {
				return fmt.Errorf("VPN egress lost; client routing stopped fail-closed: %w", err)
			}
		}
	}
}

func validateVPNRoute(interfaceName string, expected netip.Addr, expectedMTU int) error {
	current, err := VPNRouteAddress(interfaceName)
	if err != nil {
		return err
	}
	if current != expected {
		return fmt.Errorf("VPN tunnel interface %s IPv4 route address changed from %s to %s", interfaceName, expected, current)
	}
	if expectedMTU > 0 {
		currentMTU, mtuErr := InterfaceMTU(interfaceName)
		if mtuErr != nil {
			return mtuErr
		}
		if currentMTU != expectedMTU {
			return fmt.Errorf("VPN tunnel interface %s MTU changed from %d to %d", interfaceName, expectedMTU, currentMTU)
		}
	}
	return nil
}

func openDirectionalHandle(name string, direction pcap.Direction) (*liveHandle, error) {
	inactive, err := pcap.NewInactiveHandle(name)
	if err != nil {
		return nil, fmt.Errorf("create edge capture on %s: %w", name, err)
	}
	defer inactive.CleanUp()
	if err := inactive.SetSnapLen(65535); err != nil {
		return nil, fmt.Errorf("set edge capture length on %s: %w", name, err)
	}
	if err := inactive.SetPromisc(true); err != nil {
		return nil, fmt.Errorf("set edge capture promiscuous mode on %s: %w", name, err)
	}
	if err := inactive.SetTimeout(pcap.BlockForever); err != nil {
		return nil, fmt.Errorf("set edge capture timeout on %s: %w", name, err)
	}
	// Immediate mode is important on macOS BPF: without it, libpcap can batch a
	// lone DHCP DISCOVER until the read timeout instead of returning it at once.
	if err := inactive.SetImmediateMode(true); err != nil {
		return nil, fmt.Errorf("enable immediate edge capture on %s: %w", name, err)
	}
	handle, err := inactive.Activate()
	if err != nil {
		return nil, fmt.Errorf("activate edge capture on %s: %w", name, err)
	}
	if err := handle.SetDirection(direction); err != nil {
		handle.Close()
		return nil, fmt.Errorf("set edge capture direction on %s: %w", name, err)
	}
	if handle.LinkType() != layers.LinkTypeEthernet {
		handle.Close()
		return nil, fmt.Errorf("edge adapter %s uses unsupported link type %s", name, handle.LinkType())
	}
	return &liveHandle{Handle: handle}, nil
}

func (s *Session) prepare(ctx context.Context) error {
	readCtx, cancelRead := context.WithTimeout(ctx, commandTimeout)
	output, err := s.runner.Run(readCtx, "sysctl", []string{"-n", "net.inet.ip.forwarding"}, "")
	cancelRead()
	if err != nil {
		return pfutil.CommandError("read IPv4 forwarding", output, err)
	}
	value := strings.TrimSpace(output)
	if value != "0" && value != "1" {
		return fmt.Errorf("read IPv4 forwarding: unexpected value %q", value)
	}
	s.mu.Lock()
	s.originalForwarding = value
	s.mu.Unlock()

	interfaceCtx, cancelInterface := context.WithTimeout(ctx, commandTimeout)
	interfaceOutput, interfaceErr := s.runner.Run(interfaceCtx, "ifconfig", []string{s.Config.Downstream}, "")
	cancelInterface()
	if interfaceErr != nil {
		return pfutil.CommandError("read downstream adapter state", interfaceOutput, interfaceErr)
	}
	originalInterfaceUp, err := parseInterfaceAdminUp(interfaceOutput)
	if err != nil {
		return fmt.Errorf("read downstream adapter state: %w", err)
	}
	s.mu.Lock()
	s.originalInterfaceUp = originalInterfaceUp
	s.interfaceStateKnown = true
	s.mu.Unlock()

	serverCIDR := s.Lease.ServerIP.String() + "/" + strconv.Itoa(s.Lease.Subnet.Bits())
	aliasCtx, cancelAlias := context.WithTimeout(ctx, commandTimeout)
	aliasOutput, aliasErr := s.runner.Run(aliasCtx, "ifconfig", []string{s.Config.Downstream, "inet", serverCIDR, "alias"}, "")
	cancelAlias()
	if aliasErr != nil {
		return pfutil.CommandError("assign downstream edge address", aliasOutput, aliasErr)
	}
	s.mu.Lock()
	s.aliasAdded = true
	s.mu.Unlock()

	rules, err := CompilePF(s.Config)
	if active, ok := s.Engine.Policies.Active(); ok {
		rules, err = CompilePFWithPolicy(s.Config, active.Revision(), active.Rules())
	}
	if err != nil {
		return err
	}
	if err := s.pf.Apply(ctx, rules); err != nil {
		return err
	}
	if value != "1" {
		forwardCtx, cancelForward := context.WithTimeout(ctx, commandTimeout)
		forwardOutput, forwardErr := s.runner.Run(forwardCtx, "sysctl", []string{"-w", "net.inet.ip.forwarding=1"}, "")
		cancelForward()
		if forwardErr != nil {
			return pfutil.CommandError("enable IPv4 forwarding", forwardOutput, forwardErr)
		}
		s.mu.Lock()
		s.forwardingChanged = true
		s.mu.Unlock()
	}
	if !originalInterfaceUp {
		upCtx, cancelUp := context.WithTimeout(ctx, commandTimeout)
		upOutput, upErr := s.runner.Run(upCtx, "ifconfig", []string{s.Config.Downstream, "up"}, "")
		cancelUp()
		if upErr != nil {
			return pfutil.CommandError("bring downstream edge adapter up", upOutput, upErr)
		}
		s.mu.Lock()
		s.interfaceRaised = true
		s.mu.Unlock()
	}
	return nil
}

func parseInterfaceAdminUp(output string) (bool, error) {
	for _, line := range strings.Split(output, "\n") {
		start := strings.IndexByte(line, '<')
		end := strings.IndexByte(line, '>')
		if start < 0 || end <= start {
			continue
		}
		for _, flag := range strings.Split(line[start+1:end], ",") {
			if strings.TrimSpace(flag) == "UP" {
				return true, nil
			}
		}
		return false, nil
	}
	return false, fmt.Errorf("interface flags are missing")
}

func (s *Session) captureOriginal(ctx context.Context, handle *liveHandle, record *recorder, serverMAC net.HardwareAddr) error {
	for {
		data, info, err := handle.ReadPacketData()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("read edge ingress: %w", err)
		}
		// DHCP is Edge control-plane traffic and PF explicitly permits it before
		// staged data-plane policy. Reply before capture I/O, normalization,
		// policy diagnostics, and UI event delivery so address acquisition never
		// waits behind evidence processing.
		reply, isDHCP, err := BuildDHCPReply(data, serverMAC, s.Lease)
		if err != nil {
			return err
		}
		if isDHCP {
			if err := handle.WritePacketData(reply); err != nil {
				return fmt.Errorf("inject DHCP reply: %w", err)
			}
			s.stats.dhcp.Add(1)
		}
		s.stats.original.Add(1)
		originalOrdinal, err := record.WriteOriginal(info, data)
		if err != nil {
			return err
		}
		frame := traffic.Normalize(data, traffic.CaptureMetadata{Timestamp: info.Timestamp, CaptureLength: info.CaptureLength, OriginalLength: info.Length, LinkType: int(handle.LinkType()), Source: s.Dir}, s.Config.Downstream, traffic.SideDownstream, traffic.DirectionOutbound)
		result, err := s.Engine.Process(frame, dataplane.ForMode(dataplane.ModeEdgeRoute))
		if err != nil {
			return fmt.Errorf("evaluate edge route policy: %w", err)
		}
		result.Decision.OriginalCaptureOrdinal = originalOrdinal
		if err := record.WriteDecision(result.Decision); err != nil {
			return err
		}
		s.send(Event{
			Kind: KindDecision, Packet: string(frame.ID),
			Message:  fmt.Sprintf("[%s] %s", result.Decision.Status, result.Decision.Explanation),
			Decision: result.Decision.Summary(),
		})
		s.send(Event{
			Kind: KindEvidence, Frame: result.Original, Flow: result.Flow,
			Mode: s.evidenceMode(), Decision: result.Decision.Summary(),
		})
		if result.Decision.EffectiveVerdict == policy.VerdictBlock {
			s.stats.blocked.Add(1)
			continue
		}
	}
}

func (s *Session) captureForwarded(ctx context.Context, handle *liveHandle, record *recorder) error {
	for {
		data, info, err := handle.ReadPacketData()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("read edge egress: %w", err)
		}
		if _, err := record.WriteForwarded(info, data); err != nil {
			return err
		}
		s.stats.forwarded.Add(1)
		frame := traffic.Normalize(data, traffic.CaptureMetadata{Timestamp: info.Timestamp, CaptureLength: info.CaptureLength, OriginalLength: info.Length, LinkType: int(handle.LinkType()), Source: s.Dir}, s.Config.Downstream, traffic.SideDownstream, traffic.DirectionInbound)
		result, err := s.Engine.Process(frame, dataplane.ForMode(dataplane.ModeEdgeRoute))
		if err != nil {
			return fmt.Errorf("evaluate edge return policy: %w", err)
		}
		if err := record.WriteDecision(result.Decision); err != nil {
			return err
		}
		s.send(Event{
			Kind: KindDecision, Packet: string(frame.ID),
			Message:  fmt.Sprintf("[%s] %s", result.Decision.Status, result.Decision.Explanation),
			Decision: result.Decision.Summary(),
		})
		s.send(Event{
			Kind: KindEvidence, Frame: result.Original, Flow: result.Flow,
			Mode: s.evidenceMode(), Decision: result.Decision.Summary(),
		})
	}
}

func (s *Session) evidenceMode() dataplane.Mode {
	return dataplane.ModeEdgeRoute
}

func (s *Session) cleanup() error {
	if s == nil || s.runner == nil {
		return nil
	}
	release := s.cleanupGate.Enter()
	defer release()

	s.mu.Lock()
	interfaceRaised := s.interfaceRaised
	forwardingChanged := s.forwardingChanged
	originalForwarding := s.originalForwarding
	aliasAdded := s.aliasAdded
	s.mu.Unlock()

	var errs []error
	if interfaceRaised {
		commandCtx, cancel := context.WithTimeout(context.Background(), commandTimeout)
		output, err := s.runner.Run(commandCtx, "ifconfig", []string{s.Config.Downstream, "down"}, "")
		cancel()
		if err != nil {
			errs = append(errs, pfutil.CommandError("return downstream adapter to isolation", output, err))
		} else {
			s.mu.Lock()
			s.interfaceRaised = false
			s.mu.Unlock()
		}
	}
	if forwardingChanged {
		commandCtx, cancel := context.WithTimeout(context.Background(), commandTimeout)
		output, err := s.runner.Run(commandCtx, "sysctl", []string{"-w", "net.inet.ip.forwarding=" + originalForwarding}, "")
		cancel()
		if err != nil {
			errs = append(errs, pfutil.CommandError("restore IPv4 forwarding", output, err))
		} else {
			s.mu.Lock()
			s.forwardingChanged = false
			s.mu.Unlock()
		}
	}
	if err := s.pf.Restore(context.Background()); err != nil {
		errs = append(errs, err)
	}
	if aliasAdded {
		commandCtx, cancel := context.WithTimeout(context.Background(), commandTimeout)
		output, err := s.runner.Run(commandCtx, "ifconfig", []string{s.Config.Downstream, "inet", s.Lease.ServerIP.String(), "-alias"}, "")
		cancel()
		if err != nil {
			errs = append(errs, pfutil.CommandError("remove downstream edge address", output, err))
		} else {
			s.mu.Lock()
			s.aliasAdded = false
			s.mu.Unlock()
		}
	}
	return errors.Join(errs...)
}

func (s *Session) writeManifest(started, stopped time.Time, sessionErr error) error {
	manifest := struct {
		Version         int        `json:"version"`
		Mode            Mode       `json:"mode"`
		Egress          EgressMode `json:"egress"`
		StartedAt       time.Time  `json:"started_at"`
		StoppedAt       time.Time  `json:"stopped_at"`
		Downstream      string     `json:"downstream"`
		Upstream        string     `json:"upstream"`
		VPNDestinations []string   `json:"vpn_destinations,omitempty"`
		VPNRouteAddress string     `json:"vpn_route_address,omitempty"`
		EgressMTU       int        `json:"egress_mtu,omitempty"`
		Subnet          string     `json:"subnet"`
		Server          string     `json:"server"`
		Client          string     `json:"client"`
		Capabilities    []string   `json:"capabilities"`
		Stats           Stats      `json:"stats"`
		Error           string     `json:"error,omitempty"`
	}{
		Version: 1, Mode: s.Config.Mode, Egress: s.Config.EffectiveEgress(), StartedAt: started, StoppedAt: stopped,
		Downstream: s.Config.Downstream, Upstream: s.Config.Upstream,
		VPNRouteAddress: validAddrString(s.Config.VPNRouteAddress),
		EgressMTU:       s.Config.EgressMTU,
		Subnet:          s.Config.Subnet.String(), Server: s.Lease.ServerIP.String(), Client: s.Lease.ClientIP.String(),
		Capabilities: dataplane.ForMode(dataplane.ModeEdgeRoute).Summary(), Stats: s.Stats(),
	}
	for _, destination := range s.Config.VPNDestinations {
		manifest.VPNDestinations = append(manifest.VPNDestinations, destination.Masked().String())
	}
	if sessionErr != nil {
		manifest.Error = edgeSessionErrorMarker(sessionErr)
	}
	content, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return err
	}
	path := filepath.Join(s.Dir, "session.json")
	temporary := path + ".tmp"
	if err := os.WriteFile(temporary, append(content, '\n'), 0o600); err != nil {
		return err
	}
	return os.Rename(temporary, path)
}

func validAddrString(address netip.Addr) string {
	if address.IsValid() {
		return address.String()
	}
	return ""
}

func edgeSessionErrorMarker(err error) string {
	if err == nil {
		return ""
	}
	return "session ended with an error; details were reported at runtime"
}

func (s *Session) send(event Event) {
	if s == nil || s.events == nil {
		return
	}
	if event.Kind == KindLog || event.Kind == KindEvidence || event.Kind == KindDecision {
		select {
		case s.events <- event:
		default:
		}
		return
	}
	select {
	case s.events <- event:
	case <-time.After(250 * time.Millisecond):
		s.mu.Lock()
		s.resultErr = errors.Join(s.resultErr, fmt.Errorf("deliver %s event: timed out", event.Kind))
		s.mu.Unlock()
	}
}
