package bridge

import (
	"context"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"golan/internal/dataplane"
	"golan/internal/paths"
	"golan/internal/policy"
	"golan/internal/recording"
	"golan/internal/traffic"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

const (
	controlledQueueDepth = 1024
)

const (
	MinControlledQueueDepth = 1
	MaxControlledQueueDepth = 4096
)

// OverloadBehavior controls controlled-bridge forwarding when its bounded
// policy queue is full.
type OverloadBehavior string

// Controlled forwarding defaults to fail-open while preserving capture.
const (
	OverloadFailOpen   OverloadBehavior = "fail-open"
	OverloadFailClosed OverloadBehavior = "fail-closed"
)

// PacketPort is the minimal full-duplex capture/injection boundary used by the
// controlled bridge. Tests can provide deterministic in-memory ports.
type PacketPort interface {
	Name() string
	LinkType() layers.LinkType
	ReadPacketData() ([]byte, gopacket.CaptureInfo, error)
	WritePacketData([]byte) error
	Close() error
}

// ControlledOptions configures bounded forwarding queues.
type ControlledOptions struct {
	QueueDepth int              `json:"queue_depth"`
	Overload   OverloadBehavior `json:"overload"`
}

// DefaultControlledOptions returns bounded fail-open forwarding defaults.
func DefaultControlledOptions() ControlledOptions {
	return ControlledOptions{
		QueueDepth: controlledQueueDepth, Overload: OverloadFailOpen,
	}
}

// ValidateControlledOptions rejects unsafe or ambiguous session bounds before
// any adapter or forwarding state is changed.
func ValidateControlledOptions(options ControlledOptions) error {
	if options.QueueDepth < MinControlledQueueDepth || options.QueueDepth > MaxControlledQueueDepth {
		return fmt.Errorf("controlled queue depth must be between %d and %d", MinControlledQueueDepth, MaxControlledQueueDepth)
	}
	if options.Overload != OverloadFailOpen && options.Overload != OverloadFailClosed {
		return fmt.Errorf("controlled overload behavior must be %s or %s", OverloadFailOpen, OverloadFailClosed)
	}
	return nil
}

// ControlledStats is a concurrency-safe forwarding snapshot.
type ControlledStats struct {
	OriginalPackets  uint64 `json:"original_packets"`
	ForwardedPackets uint64 `json:"forwarded_packets"`
	BlockedPackets   uint64 `json:"blocked_packets"`
	OverloadPackets  uint64 `json:"overload_packets"`
	QueueHighWater   uint64 `json:"queue_high_water"`
}

type controlledCounters struct {
	original  atomic.Uint64
	forwarded atomic.Uint64
	blocked   atomic.Uint64
	overload  atomic.Uint64
	highWater atomic.Uint64
}

type queuedFrame struct {
	data            []byte
	capture         gopacket.CaptureInfo
	originalOrdinal uint64
	from            PacketPort
	to              PacketPort
	side            traffic.TopologySide
	direction       traffic.Direction
	overload        OverloadBehavior
}

type controlledRecorder = recording.PairRecorder

type pcapPacketPort struct {
	name   string
	handle *pcap.Handle
	once   sync.Once
}

func (p *pcapPacketPort) Name() string              { return p.name }
func (p *pcapPacketPort) LinkType() layers.LinkType { return p.handle.LinkType() }
func (p *pcapPacketPort) ReadPacketData() ([]byte, gopacket.CaptureInfo, error) {
	return p.handle.ReadPacketData()
}
func (p *pcapPacketPort) WritePacketData(data []byte) error { return p.handle.WritePacketData(data) }
func (p *pcapPacketPort) Close() error {
	p.once.Do(func() { p.handle.Close() })
	return nil
}

// SetPolicy atomically changes the shared bridge revision. A compile error
// leaves the prior revision active.
func (s *Session) SetPolicy(revision string, rules []policy.Rule) error {
	if s == nil || s.policyEngine == nil {
		return fmt.Errorf("bridge policy engine is unavailable")
	}
	if s.Mode == ModeFast {
		return fmt.Errorf("fast bridge policy is immutable while running; stop and restart the bridge to apply a revision")
	}
	return s.policyEngine.Policies.Activate(revision, rules)
}

func (s *Session) runControlled(ctx context.Context) {
	var runErr error
	startedAt := time.Now().UTC()
	counters := s.controlledStats
	if counters == nil {
		counters = &controlledCounters{}
		s.controlledStats = counters
	}
	defer func() {
		cleanupErr := s.cleanup()
		finalErr := errors.Join(runErr, cleanupErr)
		manifestErr := s.writeControlledManifest(startedAt, time.Now().UTC(), counters.snapshot(), finalErr)
		finalizeErr := paths.FinalizeTree(s.Dir)
		finalErr = errors.Join(finalErr, manifestErr, finalizeErr)
		s.resultMu.Lock()
		s.runtimeErr = errors.Join(s.runtimeErr, runErr, manifestErr, finalizeErr)
		s.cleanupErr = cleanupErr
		s.resultErr = errors.Join(s.runtimeErr, cleanupErr)
		s.resultMu.Unlock()
		state := "stopped"
		if cleanupErr != nil {
			state = "cleanup-pending"
		}
		s.send(Event{Kind: KindStopped, State: state, Err: finalErr})
		s.closeEvents()
		close(s.done)
	}()

	if err := s.prepareInterfaces(ctx); err != nil {
		runErr = err
		s.send(Event{Kind: KindError, Err: err})
		return
	}
	for _, adapter := range []Adapter{s.Host, s.Switch} {
		if output, err := s.runCommand(ctx, 5*time.Second, "ifconfig", adapter.Name, "up"); err != nil {
			runErr = commandError("bring controlled adapter up "+adapter.Name, output, err)
			s.send(Event{Kind: KindError, Err: runErr})
			return
		}
	}
	hostPort, err := openControlledPort(s.Host.Name)
	if err != nil {
		runErr = err
		s.send(Event{Kind: KindError, Err: err})
		return
	}
	switchPort, err := openControlledPort(s.Switch.Name)
	if err != nil {
		_ = hostPort.Close()
		runErr = err
		s.send(Event{Kind: KindError, Err: err})
		return
	}
	recorder, err := openControlledRecorder(s.Dir)
	if err != nil {
		_ = hostPort.Close()
		_ = switchPort.Close()
		runErr = err
		s.send(Event{Kind: KindError, Err: err})
		return
	}
	s.send(Event{Kind: KindPcap, Role: "original", Path: filepath.Join(s.Dir, "original.pcap")})
	s.send(Event{Kind: KindPcap, Role: "forwarded", Path: filepath.Join(s.Dir, "forwarded.pcap")})
	s.send(Event{Kind: KindState, State: "active"})
	s.log("controlled bridge active")
	s.log("bounded userspace forwarding armed in both directions")
	options := normalizeControlledOptions(s.controlledOptions)
	s.log(fmt.Sprintf("controlled settings queue-depth=%d overload=%s", options.QueueDepth, options.Overload))
	runErr = s.forwardControlled(ctx, hostPort, switchPort, recorder, options, counters)
	runErr = errors.Join(runErr, recorder.Close(), hostPort.Close(), switchPort.Close())
}

func openControlledPort(name string) (PacketPort, error) {
	handle, err := pcap.OpenLive(name, 65535, true, pcap.BlockForever)
	if err != nil {
		return nil, fmt.Errorf("open controlled ingress on %s: %w", name, err)
	}
	if err := handle.SetDirection(pcap.DirectionIn); err != nil {
		handle.Close()
		return nil, fmt.Errorf("set ingress-only capture on %s: %w", name, err)
	}
	if handle.LinkType() != layers.LinkTypeEthernet {
		handle.Close()
		return nil, fmt.Errorf("controlled adapter %s uses unsupported link type %s", name, handle.LinkType())
	}
	return &pcapPacketPort{name: name, handle: handle}, nil
}

func (s *Session) forwardControlled(ctx context.Context, host, sw PacketPort, recorder *controlledRecorder, options ControlledOptions, counters *controlledCounters) error {
	options = normalizeControlledOptions(options)
	if err := ValidateControlledOptions(options); err != nil {
		return err
	}
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	hostQueue := make(chan queuedFrame, options.QueueDepth)
	switchQueue := make(chan queuedFrame, options.QueueDepth)
	var resultMu sync.Mutex
	var resultErr error
	recordError := func(err error) {
		if err == nil {
			return
		}
		resultMu.Lock()
		resultErr = errors.Join(resultErr, err)
		resultMu.Unlock()
		cancel()
	}

	var workerWG sync.WaitGroup
	worker := func(queue <-chan queuedFrame) {
		defer workerWG.Done()
		failed := false
		for queued := range queue {
			var err error
			if failed || runCtx.Err() != nil {
				err = s.recordStoppedControlled(queued, recorder, counters)
			} else if queued.overload != "" {
				err = s.processControlledOverload(queued, recorder, counters)
			} else {
				err = s.processControlled(runCtx, queued, recorder, counters)
			}
			if err != nil {
				recordError(err)
				failed = true
			}
		}
	}
	workerWG.Add(2)
	go worker(hostQueue)
	go worker(switchQueue)

	var readerWG sync.WaitGroup
	reader := func(from, to PacketPort, side traffic.TopologySide, direction traffic.Direction, queue chan<- queuedFrame) {
		defer readerWG.Done()
		for {
			data, captureInfo, err := from.ReadPacketData()
			if err != nil {
				if runCtx.Err() == nil && !errors.Is(err, io.EOF) {
					recordError(fmt.Errorf("read controlled ingress on %s: %w", from.Name(), err))
				}
				return
			}
			owned := append([]byte(nil), data...)
			counters.original.Add(1)
			originalOrdinal, err := recorder.WriteOriginal(captureInfo, owned)
			if err != nil {
				recordError(err)
				return
			}
			queued := queuedFrame{
				data: owned, capture: captureInfo,
				originalOrdinal: originalOrdinal,
				from:            from, to: to, side: side, direction: direction,
			}
			select {
			case queue <- queued:
				updateHighWater(&counters.highWater, uint64(len(queue)))
			default:
				counters.overload.Add(1)
				queued.overload = options.Overload
				s.send(Event{Kind: KindLog, Message: "controlled overload queued in order: " + string(options.Overload)})
				// Once an original frame is durable, always hand it to the
				// direction worker. Workers drain captured frames after
				// cancellation so every original receives one terminal journal
				// record without allowing a later frame to overtake it.
				queue <- queued
				updateHighWater(&counters.highWater, uint64(len(queue)))
			}
		}
	}
	readerWG.Add(2)
	go reader(host, sw, traffic.SideHost, traffic.DirectionHostToSwitch, hostQueue)
	go reader(sw, host, traffic.SideSwitch, traffic.DirectionSwitchToHost, switchQueue)

	watchDone := make(chan struct{})
	go func() {
		defer close(watchDone)
		<-runCtx.Done()
		_ = host.Close()
		_ = sw.Close()
	}()
	readerWG.Wait()
	close(hostQueue)
	close(switchQueue)
	workerWG.Wait()
	cancel()
	<-watchDone
	resultMu.Lock()
	defer resultMu.Unlock()
	return resultErr
}

func (s *Session) processControlled(ctx context.Context, queued queuedFrame, recorder *controlledRecorder, counters *controlledCounters) (resultErr error) {
	frame := traffic.Normalize(queued.data, traffic.CaptureMetadata{
		Timestamp: queued.capture.Timestamp.UTC(), CaptureLength: queued.capture.CaptureLength,
		OriginalLength: queued.capture.Length, LinkType: int(queued.from.LinkType()), Source: s.Dir,
	}, queued.from.Name(), queued.side, queued.direction)
	result := s.policyEngine.Evaluate(frame, dataplane.ForMode(dataplane.ModeControlledBridge))
	result.Decision.OriginalCaptureOrdinal = queued.originalOrdinal
	forwardedPhysical := false
	blockedCounted := false
	defer func() {
		if resultErr != nil {
			if forwardedPhysical {
				result.Decision.Explanation += "; runtime failure after partial forwarding"
			} else {
				result.Decision.EffectiveVerdict = policy.VerdictBlock
				result.Decision.Explanation += "; runtime failure before forwarding"
				if !blockedCounted {
					counters.blocked.Add(1)
					blockedCounted = true
				}
			}
		}
		resultErr = errors.Join(resultErr, recorder.WriteDecision(result.Decision))
		s.send(Event{
			Kind: KindEvidence, Frame: result.Original, Flow: result.Flow,
			Mode:     dataplane.ModeControlledBridge,
			Decision: result.Decision.Summary(),
		})
	}()
	if result.Decision.EffectiveVerdict == policy.VerdictAllow && len(result.Decision.Transformations) > 0 {
		forwarded, err := policy.ApplyTransformations(frame, result.Decision)
		if err != nil {
			return fmt.Errorf("apply controlled policy: %w", err)
		}
		result.Forwarded = forwarded
		result.Decision.ForwardedPacketID = forwarded.ID
		result.Decision.Edited = forwarded.ID != frame.ID
	}
	if result.Decision.EffectiveVerdict == policy.VerdictBlock {
		counters.blocked.Add(1)
		blockedCounted = true
		return nil
	}
	data := result.Forwarded.RawBytes()
	shape := policy.PlanTrafficShaping(result.Decision, result.Original.ID, len(data))
	if shape.Drop {
		result.Decision.EffectiveVerdict = policy.VerdictBlock
		result.Decision.Explanation += "; deterministic loss action dropped frame"
		counters.blocked.Add(1)
		blockedCounted = true
		return nil
	}
	if shape.Delay > 0 {
		timer := time.NewTimer(shape.Delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
		result.Decision.Explanation += "; shaped delay " + shape.Delay.String()
	}
	forwardedInfo := queued.capture
	forwardedInfo.CaptureLength = len(data)
	forwardedInfo.Length = len(data)
	for copyIndex := 0; copyIndex < shape.Copies; copyIndex++ {
		if err := queued.to.WritePacketData(data); err != nil {
			return fmt.Errorf("inject controlled frame on %s: %w", queued.to.Name(), err)
		}
		forwardedPhysical = true
		ordinal, err := recorder.WriteForwarded(forwardedInfo, data)
		if err != nil {
			return err
		}
		if queued.originalOrdinal != 0 {
			result.Decision.ForwardedCaptureOrdinals = append(
				result.Decision.ForwardedCaptureOrdinals,
				ordinal,
			)
		}
		counters.forwarded.Add(1)
	}
	if shape.Copies > 1 {
		result.Decision.Explanation += fmt.Sprintf("; duplicated %d copies", shape.Copies)
	}
	if result.Decision.ForwardedPacketID == "" {
		result.Decision.ForwardedPacketID = result.Forwarded.ID
	}
	s.send(Event{
		Kind: KindDecision, Message: result.Decision.Explanation,
		Packet: string(result.Original.ID), Decision: result.Decision.Summary(),
	})
	return nil
}

func (s *Session) recordStoppedControlled(queued queuedFrame, recorder *controlledRecorder, counters *controlledCounters) error {
	frame := traffic.Normalize(queued.data, traffic.CaptureMetadata{
		Timestamp: queued.capture.Timestamp.UTC(), CaptureLength: queued.capture.CaptureLength,
		OriginalLength: queued.capture.Length, LinkType: int(queued.from.LinkType()), Source: s.Dir,
	}, queued.from.Name(), queued.side, queued.direction)
	result := s.policyEngine.Evaluate(frame, dataplane.ForMode(dataplane.ModeControlledBridge))
	result.Decision.OriginalCaptureOrdinal = queued.originalOrdinal
	result.Decision.EffectiveVerdict = policy.VerdictBlock
	result.Decision.Explanation += "; session stopped after capture and before forwarding"
	counters.blocked.Add(1)
	err := recorder.WriteDecision(result.Decision)
	s.send(Event{
		Kind: KindEvidence, Frame: result.Original, Flow: result.Flow,
		Mode: dataplane.ModeControlledBridge, Decision: result.Decision.Summary(),
	})
	return err
}

func (s *Session) processControlledOverload(queued queuedFrame, recorder *controlledRecorder, counters *controlledCounters) (resultErr error) {
	info := queued.capture
	frame := traffic.Normalize(queued.data, traffic.CaptureMetadata{Timestamp: info.Timestamp, CaptureLength: info.CaptureLength, OriginalLength: info.Length, LinkType: int(queued.from.LinkType()), Source: s.Dir}, queued.from.Name(), queued.side, queued.direction)
	flow := s.policyEngine.Flows.Observe(frame)
	behavior := queued.overload
	decision := policy.Decision{
		PacketID: frame.ID, DataPlane: dataplane.ModeControlledBridge,
		EvidenceKind: traffic.EvidencePacket, Status: dataplane.StatusLive,
		EvaluatedAt:            info.Timestamp.UTC(),
		OriginalCaptureOrdinal: queued.originalOrdinal,
	}
	forwardedPhysical := false
	blockedCounted := false
	defer func() {
		if resultErr != nil {
			if forwardedPhysical {
				decision.Explanation += "; runtime failure after partial forwarding"
			} else {
				if decision.Verdict == "" {
					decision.Verdict = policy.VerdictBlock
				}
				decision.EffectiveVerdict = policy.VerdictBlock
				decision.Explanation += "; runtime failure before forwarding"
				if !blockedCounted {
					counters.blocked.Add(1)
					blockedCounted = true
				}
			}
		}
		resultErr = errors.Join(resultErr, recorder.WriteDecision(decision))
		s.send(Event{
			Kind: KindEvidence, Frame: frame, Flow: flow,
			Mode:     dataplane.ModeControlledBridge,
			Decision: decision.Summary(),
		})
	}()
	switch behavior {
	case OverloadFailOpen:
		decision.Verdict = policy.VerdictAllow
		decision.EffectiveVerdict = policy.VerdictAllow
		decision.Explanation = "controlled queue overload; ordered fail-open forwarding"
		if err := queued.to.WritePacketData(queued.data); err != nil {
			return fmt.Errorf("ordered fail-open inject on %s: %w", queued.to.Name(), err)
		}
		forwardedPhysical = true
		decision.ForwardedPacketID = frame.ID
		ordinal, err := recorder.WriteForwarded(info, queued.data)
		if err != nil {
			return err
		}
		counters.forwarded.Add(1)
		decision.ForwardedPacketID = frame.ID
		if queued.originalOrdinal != 0 {
			decision.ForwardedCaptureOrdinals = []uint64{ordinal}
		}
	case OverloadFailClosed:
		counters.blocked.Add(1)
		blockedCounted = true
		decision.Verdict = policy.VerdictBlock
		decision.EffectiveVerdict = policy.VerdictBlock
		decision.Explanation = "controlled queue overload; ordered fail-closed drop"
	default:
		return fmt.Errorf("controlled queue overload behavior %q is invalid", queued.overload)
	}
	return nil
}

func normalizeControlledOptions(options ControlledOptions) ControlledOptions {
	defaults := DefaultControlledOptions()
	if options.QueueDepth == 0 {
		options.QueueDepth = defaults.QueueDepth
	}
	if options.Overload == "" {
		options.Overload = defaults.Overload
	}
	return options
}

func openControlledRecorder(dir string) (*controlledRecorder, error) {
	return recording.OpenPair(dir, layers.LinkTypeEthernet, "controlled")
}

func (s *Session) writeControlledManifest(started, stopped time.Time, stats ControlledStats, runErr error) error {
	manifest := struct {
		Version      int               `json:"version"`
		Mode         Mode              `json:"mode"`
		StartedAt    time.Time         `json:"started_at"`
		StoppedAt    time.Time         `json:"stopped_at"`
		Host         string            `json:"host_adapter"`
		Switch       string            `json:"switch_adapter"`
		Capabilities []string          `json:"capabilities"`
		Options      ControlledOptions `json:"controlled_options"`
		Stats        ControlledStats   `json:"stats"`
		Error        string            `json:"error,omitempty"`
	}{
		Version: 1, Mode: ModeControlled, StartedAt: started, StoppedAt: stopped,
		Host: s.Host.Name, Switch: s.Switch.Name,
		Capabilities: dataplane.ForMode(dataplane.ModeControlledBridge).Summary(),
		Options:      normalizeControlledOptions(s.controlledOptions), Stats: stats,
	}
	if runErr != nil {
		manifest.Error = sessionErrorMarker(runErr)
	}
	return writeBridgeManifest(filepath.Join(s.Dir, "session.json"), manifest)
}

func (c *controlledCounters) snapshot() ControlledStats {
	return ControlledStats{
		OriginalPackets: c.original.Load(), ForwardedPackets: c.forwarded.Load(),
		BlockedPackets:  c.blocked.Load(),
		OverloadPackets: c.overload.Load(), QueueHighWater: c.highWater.Load(),
	}
}

func updateHighWater(value *atomic.Uint64, candidate uint64) {
	for {
		current := value.Load()
		if candidate <= current || value.CompareAndSwap(current, candidate) {
			return
		}
	}
}
