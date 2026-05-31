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

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
	"golan/internal/canvas"
	"golan/internal/eapol"
	"golan/internal/inspect"
	"golan/internal/listen"
	"golan/internal/paths"
	"golan/internal/stealth"
)

const (
	KindLog       = "log"
	KindState     = "state"
	KindPcap      = "pcap"
	KindError     = "error"
	KindDiscovery = "discovery"
	KindTraffic   = "traffic"
	KindFinding   = "finding"
	KindCanvas    = canvas.EventKind
	KindStopped   = "stopped"
)

// Adapter identifies one side of the inline packet bridge.
type Adapter struct {
	Name         string
	Role         string
	HardwarePort string
	LocalMAC     string
	TargetMAC    string
}

// Event describes bridge lifecycle output for the TUI.
type Event struct {
	Kind     string
	Message  string
	State    string
	Adapter  string
	Role     string
	Field    string
	Value    string
	Evidence string
	Packet   string
	Path     string
	Err      error
}

// Session owns a transparent macOS bridge run.
type Session struct {
	Name       string
	Host       Adapter
	Switch     Adapter
	Dir        string
	BridgeName string
	Events     <-chan Event

	cancel context.CancelFunc
	done   chan struct{}
	events chan Event

	bridgeName  string
	restore     []serviceRestore
	macRestore  []adapterMACRestore
	eapolCancel context.CancelFunc
	eapolDone   chan struct{}
	origForward string
	origIPv6Fwd string
	inspector   *inspect.Inspector
}

type serviceRestore struct {
	HardwarePort string
	Known        bool
	Enabled      bool
}

type adapterMACRestore struct {
	Name string
	MAC  string
}

// Start begins a transparent macOS bridge run using a kernel bridge for normal
// Ethernet forwarding and a userspace EAPOL relay for 802.1X frames the kernel
// bridge does not reliably pass.
func Start(host, sw Adapter, dir string) (*Session, error) {
	if strings.TrimSpace(host.Name) == "" {
		return nil, fmt.Errorf("host adapter is required")
	}
	if strings.TrimSpace(sw.Name) == "" {
		return nil, fmt.Errorf("switch adapter is required")
	}
	if strings.EqualFold(host.Name, sw.Name) {
		return nil, fmt.Errorf("host and switch adapters must differ")
	}
	if _, _, err := targetMACSetting(host.TargetMAC); err != nil {
		return nil, err
	}
	if dir == "" {
		defaultDir, err := paths.PcapRunDir()
		if err != nil {
			return nil, err
		}
		dir = defaultDir
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("create pcap dir: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	events := make(chan Event, 128)
	s := &Session{
		Name:      "kernel-bridge",
		Host:      host,
		Switch:    sw,
		Dir:       dir,
		Events:    events,
		cancel:    cancel,
		done:      make(chan struct{}),
		events:    events,
		inspector: inspect.New(),
	}
	go s.run(ctx)
	return s, nil
}

// Stop tears down the bridge and waits briefly for capture goroutines to exit.
func (s *Session) Stop() error {
	if s == nil {
		return nil
	}
	s.cancel()
	select {
	case <-s.done:
		return nil
	case <-time.After(8 * time.Second):
		return fmt.Errorf("bridge stop timed out")
	}
}

func (s *Session) run(ctx context.Context) {
	defer close(s.events)
	defer close(s.done)
	defer func() {
		if err := paths.FinalizeTree(s.Dir); err != nil {
			s.log(fmt.Sprintf("warn: pcap permission finalization failed: %v", err))
		}
	}()
	defer func() {
		if s.eapolCancel != nil {
			s.eapolCancel()
		}
		if s.eapolDone != nil {
			select {
			case <-s.eapolDone:
			case <-time.After(2 * time.Second):
				s.log("warn: EAPOL passthrough stop timed out")
			}
		}
		s.destroyBridge()
		s.restoreSysctls()
		s.restoreAdapterMACs()
		stealth.RestoreL2Services()
		s.restoreServices()
		s.send(Event{Kind: KindStopped})
	}()

	targetMAC, hasTargetMAC, err := targetMACSetting(s.Host.TargetMAC)
	if err != nil {
		s.send(Event{Kind: KindError, Err: err})
		return
	}

	s.disableServices(ctx)

	bridgeName, err := s.createBridgeInterface(ctx)
	if err != nil {
		s.send(Event{Kind: KindError, Err: err})
		return
	}

	var wg sync.WaitGroup
	var closeCaptures []func()
	defer func() {
		for _, closeCapture := range closeCaptures {
			closeCapture()
		}
		wg.Wait()
	}()

	startCapture := func(adapter Adapter) {
		closeCapture, err := s.startCapture(ctx, adapter, &wg)
		if err != nil {
			s.log(fmt.Sprintf("warn: capture unavailable on %s: %v", adapter.Name, err))
			return
		}
		closeCaptures = append(closeCaptures, closeCapture)
	}
	startCapture(s.Host)

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
			activateErr = err
			s.send(Event{Kind: KindError, Err: err})
			return
		}
		targetMAC = append(net.HardwareAddr(nil), mac...)
		startCapture(Adapter{Name: bridgeName, Role: "bridge", LocalMAC: mac.String()})
		startCapture(s.Switch)
		s.send(Event{Kind: KindState, State: "active"})
		s.log("bridge iface: " + bridgeName)
		s.log("target mac: " + mac.String())
		s.log("kernel bridge active")
		s.log("normal ethernet traffic forwards through the macOS bridge")
		s.log("802.1X EAPOL passthrough relay active")
	}

	if hasTargetMAC {
		activate(targetMAC, nil)
		if activateErr != nil {
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
			s.send(Event{Kind: KindError, Err: fmt.Errorf("host mac discovery: %w", err)})
		}
		return
	}
	if id != nil && len(id.MAC) > 0 {
		activate(id.MAC, nil)
	}
	if activateErr != nil {
		return
	}

	<-ctx.Done()
}

func (s *Session) createBridgeInterface(ctx context.Context) (string, error) {
	if out, err := runCommand(ctx, 5*time.Second, "sysctl", "net.inet.ip.forwarding"); err == nil {
		s.origForward = sysctlValue(out)
	}
	if out, err := runCommand(ctx, 5*time.Second, "sysctl", "net.inet6.ip6.forwarding"); err == nil {
		s.origIPv6Fwd = sysctlValue(out)
	}

	out, err := runCommand(ctx, 5*time.Second, "ifconfig", "bridge", "create")
	if err != nil {
		return "", fmt.Errorf("create bridge: %w (%s)", err, strings.TrimSpace(out))
	}
	bridgeName := strings.TrimSpace(out)
	if bridgeName == "" {
		return "", fmt.Errorf("create bridge: empty bridge name")
	}
	s.bridgeName = bridgeName
	s.BridgeName = bridgeName
	s.log("bridge created: " + bridgeName)

	if out, err := runCommand(ctx, 5*time.Second, "ifconfig", s.Host.Name, "up"); err != nil {
		return "", fmt.Errorf("host adapter up: %w (%s)", err, strings.TrimSpace(out))
	}
	s.log("host adapter up: " + s.Host.Name)

	if out, err := runCommand(ctx, 5*time.Second, "sysctl", "-w", "net.inet6.ip6.forwarding=0"); err != nil {
		s.log(fmt.Sprintf("warn: ipv6 forwarding suppress failed: %v (%s)", err, strings.TrimSpace(out)))
	}

	return bridgeName, nil
}

func (s *Session) activateBridge(ctx context.Context, bridgeName string, targetMAC net.HardwareAddr, firstFrame []byte) error {
	if out, err := runCommand(ctx, 5*time.Second, "ifconfig", bridgeName, "ether", targetMAC.String()); err != nil {
		s.log(fmt.Sprintf("warn: bridge mac set failed: %v (%s)", err, strings.TrimSpace(out)))
	} else {
		s.log("bridge mac: " + targetMAC.String())
	}

	spoofed := s.spoofSwitchAdapterMAC(ctx, targetMAC, "before bridge up")

	if out, err := runCommand(ctx, 5*time.Second, "ifconfig", bridgeName, "addm", s.Host.Name, "addm", s.Switch.Name); err != nil {
		return fmt.Errorf("attach members: %w (%s)", err, strings.TrimSpace(out))
	}
	s.log(fmt.Sprintf("bridge members: %s %s", s.Host.Name, s.Switch.Name))

	for _, adapter := range []Adapter{s.Host, s.Switch} {
		if out, err := runCommand(ctx, 5*time.Second, "ifconfig", bridgeName, "stp", adapter.Name, "disabled"); err != nil {
			s.log(fmt.Sprintf("warn: stp disable failed for %s: %v (%s)", adapter.Name, err, strings.TrimSpace(out)))
		}
	}

	s.installBridgeSafety(ctx, bridgeName, targetMAC)

	if out, err := runCommand(ctx, 5*time.Second, "ifconfig", bridgeName, "up"); err != nil {
		return fmt.Errorf("bridge up: %w (%s)", err, strings.TrimSpace(out))
	}

	if out, err := runCommand(ctx, 5*time.Second, "ifconfig", s.Switch.Name, "up"); err != nil {
		return fmt.Errorf("switch adapter up: %w (%s)", err, strings.TrimSpace(out))
	}
	s.log("switch adapter up: " + s.Switch.Name)

	if !spoofed {
		s.spoofSwitchAdapterMAC(ctx, targetMAC, "after bridge up")
	}
	if out, err := runCommand(ctx, 5*time.Second, "ifconfig", bridgeName, "inet6", "-autoconf"); err != nil {
		s.log(fmt.Sprintf("warn: bridge ipv6 autoconf suppress failed: %v (%s)", err, strings.TrimSpace(out)))
	} else {
		s.log("bridge ipv6 autoconf suppressed")
	}

	s.startEAPOLPassthrough(ctx, targetMAC, firstFrame)
	return nil
}

func (s *Session) startEAPOLPassthrough(ctx context.Context, targetMAC net.HardwareAddr, firstFrame []byte) {
	if strings.TrimSpace(s.bridgeName) == "" {
		return
	}
	if err := stealth.SuppressNativeEAPOL(s.bridgeName, s.Host.Name, s.Switch.Name); err != nil {
		s.log(fmt.Sprintf("warn: native EAPOL suppression degraded: %v", err))
	} else {
		s.log("native bridge EAPOL forwarding suppressed for relay")
	}

	relayCtx, cancel := context.WithCancel(ctx)
	s.eapolCancel = cancel
	s.eapolDone = make(chan struct{})

	session := eapol.NewAuthSession(append(net.HardwareAddr(nil), targetMAC...))
	relay := eapol.NewRelay(s.Host.Name, s.Switch.Name, session, func(message string) {
		s.log(message)
	})
	relay.SetModeName("transparent EAPOL passthrough")
	relay.SetInjectStart(false)
	relay.SetSuppressLogoff(false)
	relay.SetStrictAuthenticator(false)
	relay.SetStrictVLAN(false)
	if len(firstFrame) > 0 {
		relay.SetInitialFrame(firstFrame)
	}

	go func() {
		defer close(s.eapolDone)
		s.log(fmt.Sprintf("EAPOL passthrough active: %s <-> %s", s.Host.Name, s.Switch.Name))
		if err := relay.Start(relayCtx); err != nil && relayCtx.Err() == nil {
			s.send(Event{Kind: KindError, Err: fmt.Errorf("eapol relay: %w", err)})
		}
	}()
}

func (s *Session) spoofSwitchAdapterMAC(ctx context.Context, targetMAC net.HardwareAddr, phase string) bool {
	if s.Switch.Name == "" {
		return false
	}
	if original, err := requiredTargetMAC(s.Switch.LocalMAC); err == nil && !macEqual(original, targetMAC) {
		s.rememberAdapterMAC(s.Switch.Name, original.String())
	}
	if out, err := runCommand(ctx, 5*time.Second, "ifconfig", s.Switch.Name, "ether", targetMAC.String()); err != nil {
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

func (s *Session) installBridgeSafety(ctx context.Context, bridgeName string, targetMAC net.HardwareAddr) {
	protected := s.protectedSourceMACs(targetMAC)
	if len(protected) > 0 {
		if err := installSourceMACRules(ctx, bridgeName, protected); err != nil {
			s.log(fmt.Sprintf("warn: local source-mac safety degraded: %v", err))
		} else {
			s.log("local source-mac safety installed")
		}
	}
	if err := stealth.SuppressL2Leaks(bridgeName); err != nil {
		s.log(fmt.Sprintf("warn: L2 discovery leak suppression degraded: %v", err))
	} else {
		s.log("STP/LLDP/CDP leak suppression verified")
	}
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

func installSourceMACRules(ctx context.Context, bridgeName string, macs []net.HardwareAddr) error {
	var errs []string
	for _, mac := range macs {
		out, err := runCommand(ctx, 5*time.Second, "ifconfig", bridgeName, "rule", "block", "out", "src", strings.ToLower(mac.String()))
		if err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v (%s)", mac.String(), err, strings.TrimSpace(out)))
		}
	}
	if out, err := runCommand(ctx, 5*time.Second, "ifconfig", bridgeName, "rule", "show"); err != nil {
		errs = append(errs, fmt.Sprintf("show: %v (%s)", err, strings.TrimSpace(out)))
	}
	if len(errs) > 0 {
		return errors.New(strings.Join(errs, " | "))
	}
	return nil
}

func (s *Session) destroyBridge() {
	bridgeName := strings.TrimSpace(s.bridgeName)
	if bridgeName == "" {
		return
	}
	s.bridgeName = ""
	s.BridgeName = ""
	if out, err := runCommand(context.Background(), 5*time.Second, "ifconfig", bridgeName, "destroy"); err != nil {
		s.log(fmt.Sprintf("warn: bridge destroy failed for %s: %v (%s)", bridgeName, err, strings.TrimSpace(out)))
	} else {
		s.log("bridge destroyed: " + bridgeName)
	}
}

func (s *Session) restoreSysctls() {
	if s.origForward != "" {
		_, _ = runCommand(context.Background(), 5*time.Second, "sysctl", "-w", "net.inet.ip.forwarding="+s.origForward)
	}
	if s.origIPv6Fwd != "" {
		_, _ = runCommand(context.Background(), 5*time.Second, "sysctl", "-w", "net.inet6.ip6.forwarding="+s.origIPv6Fwd)
	}
}

func (s *Session) restoreAdapterMACs() {
	restore := s.macRestore
	s.macRestore = nil
	for i := len(restore) - 1; i >= 0; i-- {
		item := restore[i]
		if item.Name == "" || item.MAC == "" {
			continue
		}
		if out, err := runCommand(context.Background(), 5*time.Second, "ifconfig", item.Name, "ether", item.MAC); err != nil {
			s.log(fmt.Sprintf("warn: adapter mac restore failed for %s: %v (%s)", item.Name, err, strings.TrimSpace(out)))
		} else {
			s.log(fmt.Sprintf("adapter mac restored: %s %s", item.Name, item.MAC))
		}
	}
}

func (s *Session) startCapture(ctx context.Context, adapter Adapter, wg *sync.WaitGroup) (func(), error) {
	handle, writer, closeCapture, err := s.openCapture(adapter)
	if err != nil {
		return nil, err
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		s.capture(ctx, adapter, handle, writer)
	}()
	return closeCapture, nil
}

func (s *Session) openCapture(adapter Adapter) (*pcap.Handle, *pcapgo.Writer, func(), error) {
	handle, err := pcap.OpenLive(adapter.Name, 65535, true, pcap.BlockForever)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("open %s: %w", adapter.Name, err)
	}

	path, writer, closeFile, err := pcapWriter(s.Dir, adapter.Role, adapter.Name, handle.LinkType())
	if err != nil {
		handle.Close()
		return nil, nil, nil, err
	}
	s.send(Event{Kind: KindPcap, Adapter: adapter.Name, Role: adapter.Role, Path: path})

	closeAll := func() {
		handle.Close()
		closeFile()
	}
	return handle, writer, closeAll, nil
}

func (s *Session) capture(ctx context.Context, adapter Adapter, handle *pcap.Handle, writer *pcapgo.Writer) {
	ignoreMAC, _ := net.ParseMAC(adapter.LocalMAC)
	source := gopacket.NewPacketSource(handle, handle.LinkType())
	var packetCount int
	for {
		select {
		case <-ctx.Done():
			return
		case packet, ok := <-source.Packets():
			if !ok || packet == nil {
				return
			}
			data := packet.Data()
			if err := writer.WritePacket(packet.Metadata().CaptureInfo, data); err != nil {
				s.send(Event{Kind: KindError, Adapter: adapter.Name, Role: adapter.Role, Err: err})
				return
			}
			packetCount++
			if summary, _ := listen.PacketSummary(packet); summary != "" {
				s.send(Event{
					Kind:    KindTraffic,
					Adapter: adapter.Name,
					Role:    adapter.Role,
					Message: fmt.Sprintf("#%d %s/%s %s", packetCount, adapter.Role, adapter.Name, summary),
				})
			}
			if s.inspector != nil {
				for _, finding := range s.inspector.AnalyzePacket(packet) {
					s.send(Event{Kind: KindFinding, Adapter: adapter.Name, Role: adapter.Role, Message: finding.Encode()})
				}
			}
			for _, observation := range canvas.ObservePacket(packet, adapter.Name, adapter.Role) {
				s.send(Event{Kind: KindCanvas, Adapter: adapter.Name, Role: adapter.Role, Message: observation.Encode()})
			}
			for _, discovery := range listen.AnalyzePacket(packet, ignoreMAC) {
				s.send(Event{
					Kind:     KindDiscovery,
					Adapter:  adapter.Name,
					Role:     adapter.Role,
					Field:    discovery.Field,
					Value:    discovery.Value,
					Evidence: discovery.Evidence,
					Packet:   discovery.Packet,
				})
			}
		}
	}
}

func (s *Session) disableServices(ctx context.Context) {
	seen := make(map[string]bool)
	for _, adapter := range []Adapter{s.Host, s.Switch} {
		port := strings.TrimSpace(adapter.HardwarePort)
		if port == "" {
			s.log("warn: no service mapping for " + adapter.Name)
			continue
		}
		if seen[port] {
			continue
		}
		seen[port] = true
		restore := serviceRestore{HardwarePort: port}
		out, err := runCommand(ctx, 5*time.Second, "networksetup", "-getnetworkserviceenabled", port)
		if err == nil {
			switch strings.ToLower(strings.TrimSpace(out)) {
			case "enabled":
				restore.Known = true
				restore.Enabled = true
			case "disabled":
				restore.Known = true
			}
		}
		s.restore = append(s.restore, restore)
		if out, err := runCommand(ctx, 5*time.Second, "networksetup", "-setnetworkserviceenabled", port, "off"); err != nil {
			s.log(fmt.Sprintf("warn: service detach failed for %s: %v (%s)", port, err, strings.TrimSpace(out)))
		} else {
			s.log("service detached: " + port)
		}
	}
}

func (s *Session) restoreServices() {
	restore := s.restore
	s.restore = nil
	for i := len(restore) - 1; i >= 0; i-- {
		item := restore[i]
		if !item.Known || item.HardwarePort == "" {
			continue
		}
		state := "off"
		if item.Enabled {
			state = "on"
		}
		if out, err := runCommand(context.Background(), 5*time.Second, "networksetup", "-setnetworkserviceenabled", item.HardwarePort, state); err != nil {
			s.log(fmt.Sprintf("warn: service restore failed for %s: %v (%s)", item.HardwarePort, err, strings.TrimSpace(out)))
		} else {
			s.log("service restored: " + item.HardwarePort)
		}
	}
}

func (s *Session) log(message string) {
	s.send(Event{Kind: KindLog, Message: message})
}

func (s *Session) send(event Event) {
	defer func() {
		_ = recover()
	}()
	select {
	case s.events <- event:
	default:
	}
}

func pcapWriter(dir, role, adapter string, linkType layers.LinkType) (string, *pcapgo.Writer, func(), error) {
	path := filepath.Join(dir, fmt.Sprintf("%s-%s.pcap", safeName(role), safeName(adapter)))
	file, err := os.Create(path)
	if err != nil {
		return "", nil, nil, fmt.Errorf("create pcap %s: %w", path, err)
	}
	closeFile := func() { _ = file.Close() }
	writer := pcapgo.NewWriter(file)
	if err := writer.WriteFileHeader(65535, linkType); err != nil {
		closeFile()
		return "", nil, nil, fmt.Errorf("write pcap header %s: %w", path, err)
	}
	return path, writer, closeFile, nil
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

func runCommand(ctx context.Context, timeout time.Duration, name string, args ...string) (string, error) {
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

func safeName(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return "unknown"
	}
	replacer := strings.NewReplacer("/", "_", "\\", "_", ":", "_", " ", "_")
	return replacer.Replace(value)
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
