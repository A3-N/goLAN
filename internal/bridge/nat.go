package bridge

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"golan/internal/dataplane"
	"golan/internal/eapol"
	"golan/internal/policy"
	"golan/internal/stealth"
)

// StartTakeover turns the active bridge interface into the local endpoint for
// the authenticated host identity while leaving the bridge and member links
// up. The complete endpoint PF ruleset is preflighted before any network
// mutation and remains covered during the host-member transition.
func (s *Session) StartTakeover(cfg TakeoverConfig) (err error) {
	if s == nil {
		return fmt.Errorf("bridge is not running")
	}
	release := s.takeoverGate.Enter()
	defer release()

	s.controlMu.Lock()
	if s.nat != nil {
		if s.nat.Started {
			s.controlMu.Unlock()
			return nil
		}
		s.controlMu.Unlock()
		return fmt.Errorf("takeover cleanup is pending; stop takeover before retrying")
	}
	mode := s.Mode
	bridgeName := strings.TrimSpace(s.bridgeName)
	s.controlMu.Unlock()
	if mode != "" && mode != ModeFast {
		return fmt.Errorf("takeover requires a fast bridge")
	}
	if bridgeName == "" {
		return fmt.Errorf("bridge interface is not active")
	}

	mac, err := s.resolveTakeoverMAC(cfg.MAC)
	if err != nil {
		return err
	}
	ip := cleanAuto(cfg.IP)
	cidr := cleanAuto(cfg.CIDR)
	useDHCP := ip == "" && strings.EqualFold(cleanDefault(cfg.DHCP, "auto"), "auto")
	if ip == "" && !useDHCP {
		return fmt.Errorf("bridge ip is required unless dhcp is auto")
	}
	if ip != "" && net.ParseIP(ip).To4() == nil {
		return fmt.Errorf("bridge ip %q is not an IPv4 address", ip)
	}
	if ip != "" && cidr == "" {
		return fmt.Errorf("bridge cidr is required with a static ip")
	}
	staticNetmask := ""
	if ip != "" {
		staticNetmask, err = cidrNetmask(cidr)
		if err != nil {
			return err
		}
	}
	gateway := cleanAuto(cfg.Gateway)
	if gateway != "" && net.ParseIP(gateway).To4() == nil {
		return fmt.Errorf("bridge gateway %q is not an IPv4 address", gateway)
	}

	policyRevision, policyRules := s.takeoverPolicy()
	takeoverPFRules, err := stealth.CompileTakeoverPF(bridgeName, policyRevision, policyRules)
	if err != nil {
		return fmt.Errorf("preflight takeover PF policy: %w", err)
	}

	ctx := context.Background()
	origMAC, err := s.currentMAC(ctx, bridgeName)
	if err != nil {
		return fmt.Errorf("snapshot bridge MAC: %w", err)
	}
	state := &NATState{
		BridgeName:      bridgeName,
		MAC:             mac.String(),
		IP:              ip,
		CIDR:            cidr,
		OrigMAC:         origMAC,
		Gateway:         gateway,
		PFAnchor:        stealth.FastBridgePFAnchor,
		PolicyRevision:  policyRevision,
		takeoverPFRules: takeoverPFRules,
	}
	for _, rule := range policyRules {
		if !rule.Enabled {
			continue
		}
		status, _, _ := policy.Compatibility(rule, dataplane.ForMode(dataplane.ModeTakeover))
		switch status {
		case dataplane.StatusLive:
			state.LivePolicyRules++
		case dataplane.StatusShadow:
			state.ShadowPolicyRules++
		case dataplane.StatusUnsupported:
			state.UnsupportedPolicyRules++
		}
	}
	s.controlMu.Lock()
	s.nat = state
	s.controlMu.Unlock()

	success := false
	defer func() {
		if !success {
			if rollbackErr := s.stopTakeoverSerialized(context.Background()); rollbackErr != nil {
				err = errors.Join(err, fmt.Errorf("rollback takeover: %w", rollbackErr))
			}
		}
	}()

	if s.fastPF == nil {
		if strings.TrimSpace(s.fastPFRules) != "" {
			return fmt.Errorf("takeover PF backend is unavailable")
		}
		s.fastPF = stealth.NewFastBridgePFBackend()
		s.updateTakeoverState(state, func(current *NATState) { current.PFCreated = true })
	}
	s.updateTakeoverState(state, func(current *NATState) { current.PFRestorePending = true })
	transitionRules := joinTakeoverPFRules(s.fastPFRules, state.takeoverPFRules)
	if err := s.fastPF.Apply(ctx, transitionRules); err != nil {
		return fmt.Errorf("install takeover PF transition policy: %w", err)
	}
	s.updateTakeoverState(state, func(current *NATState) { current.PFEndpointRules = true })
	s.log("takeover PF transition policy installed: anchor=" + state.PFAnchor)

	if err := s.detachHostMember(ctx, state); err != nil {
		return err
	}
	if err := s.installTakeoverL2Rules(state); err != nil {
		return err
	}
	if strings.TrimSpace(s.fastPFRules) != "" {
		if err := s.fastPF.Apply(ctx, state.takeoverPFRules); err != nil {
			return fmt.Errorf("install takeover endpoint PF policy: %w", err)
		}
	}
	s.log("takeover endpoint PF policy active")
	if out, err := s.runCommand(ctx, 5*time.Second, "ifconfig", bridgeName, "ether", mac.String()); err != nil {
		return fmt.Errorf("bridge mac takeover: %w (%s)", err, strings.TrimSpace(out))
	}
	s.log("takeover bridge mac: " + mac.String())

	if useDHCP {
		s.updateTakeoverState(state, func(current *NATState) { current.DHCP = true })
		if out, err := s.runCommand(ctx, 15*time.Second, "ipconfig", "set", bridgeName, "DHCP"); err != nil {
			return fmt.Errorf("bridge dhcp: %w (%s)", err, strings.TrimSpace(out))
		}
		s.log("takeover bridge dhcp: requested")
	} else {
		if out, err := s.runCommand(ctx, 5*time.Second, "ifconfig", bridgeName, "inet", ip, "netmask", staticNetmask); err != nil {
			return fmt.Errorf("bridge ip takeover: %w (%s)", err, strings.TrimSpace(out))
		}
		s.updateTakeoverState(state, func(current *NATState) { current.StaticIPSet = true })
		s.log(fmt.Sprintf("takeover bridge ip: %s/%s", ip, cidr))
	}

	if state.Gateway != "" {
		if out, err := s.runCommand(ctx, 5*time.Second, "route", "-n", "add", "default", state.Gateway); err != nil {
			lowerOut := strings.ToLower(out)
			if !strings.Contains(lowerOut, "file exists") && !strings.Contains(lowerOut, "already in table") {
				return fmt.Errorf("default route add: %w (%s)", err, strings.TrimSpace(out))
			}
			s.log("takeover default route: already present")
		} else {
			s.updateTakeoverState(state, func(current *NATState) { current.RouteAdded = true })
			s.log("takeover default route: " + state.Gateway)
		}
	}
	if dns := cleanAuto(cfg.DNS); dns != "" {
		s.log("takeover dns: configured value retained; macOS resolver unchanged: " + dns)
	}
	success = true
	s.updateTakeoverState(state, func(current *NATState) { current.Started = true })
	s.log("takeover: on")
	return nil
}

// StartNAT is the legacy alias for StartTakeover.
func (s *Session) StartNAT(cfg NATConfig) error {
	return s.StartTakeover(cfg)
}

// StopTakeover reverses StartTakeover without tearing down the bridge.
func (s *Session) StopTakeover() error {
	if s == nil {
		return nil
	}
	release := s.takeoverGate.Enter()
	defer release()
	return s.stopTakeoverSerialized(context.Background())
}

// StopNAT is the legacy alias for StopTakeover.
func (s *Session) StopNAT() error {
	return s.StopTakeover()
}

// TakeoverSnapshot is a payload-free view of endpoint identity and PF
// ownership. It does not expose PF text, enable tokens, packet content, or DNS
// values.
type TakeoverSnapshot struct {
	Active                 bool   `json:"active"`
	CleanupPending         bool   `json:"cleanup_pending"`
	BridgeName             string `json:"bridge_name,omitempty"`
	AddressMode            string `json:"address_mode,omitempty"`
	PFAnchor               string `json:"pf_anchor,omitempty"`
	PFEndpointRules        bool   `json:"pf_endpoint_rules"`
	PFRestorationOwned     bool   `json:"pf_restoration_owned"`
	L2EndpointRules        bool   `json:"l2_endpoint_rules"`
	L2RestorationOwned     bool   `json:"l2_restoration_owned"`
	PolicyRevision         string `json:"policy_revision,omitempty"`
	LivePolicyRules        int    `json:"live_policy_rules"`
	ShadowPolicyRules      int    `json:"shadow_policy_rules"`
	UnsupportedPolicyRules int    `json:"unsupported_policy_rules"`
}

// TakeoverSnapshot returns a concurrency-safe, payload-free runtime summary.
func (s *Session) TakeoverSnapshot() TakeoverSnapshot {
	if s == nil {
		return TakeoverSnapshot{}
	}
	s.controlMu.Lock()
	if s.nat == nil {
		s.controlMu.Unlock()
		return TakeoverSnapshot{}
	}
	state := *s.nat
	s.controlMu.Unlock()
	addressMode := "static"
	if state.DHCP {
		addressMode = "dhcp"
	}
	return TakeoverSnapshot{
		Active: state.Started, CleanupPending: !state.Started,
		BridgeName: state.BridgeName, AddressMode: addressMode,
		PFAnchor: state.PFAnchor, PFEndpointRules: state.PFEndpointRules,
		PFRestorationOwned: state.PFRestorePending,
		L2EndpointRules:    state.L2EndpointRules,
		L2RestorationOwned: state.L2RestorePending,
		PolicyRevision:     state.PolicyRevision, LivePolicyRules: state.LivePolicyRules,
		ShadowPolicyRules:      state.ShadowPolicyRules,
		UnsupportedPolicyRules: state.UnsupportedPolicyRules,
	}
}

func (s *Session) stopTakeoverSerialized(ctx context.Context) error {
	s.controlMu.Lock()
	state := s.nat
	if state == nil {
		s.controlMu.Unlock()
		return nil
	}
	state.Started = false
	s.controlMu.Unlock()

	var errs []error
	if state.RouteAdded && state.Gateway != "" {
		if out, err := s.runCommand(ctx, 5*time.Second, "route", "-n", "delete", "default", state.Gateway); err != nil {
			if isMissingRouteError(out) {
				s.log("nat default route: already gone")
				s.updateTakeoverState(state, func(current *NATState) { current.RouteAdded = false })
			} else {
				errs = append(errs, fmt.Errorf("default route delete: %w (%s)", err, strings.TrimSpace(out)))
			}
		} else {
			s.updateTakeoverState(state, func(current *NATState) { current.RouteAdded = false })
		}
	}
	if state.StaticIPSet && state.IP != "" {
		if out, err := s.runCommand(ctx, 5*time.Second, "ifconfig", state.BridgeName, "inet", state.IP, "delete"); err != nil {
			if isMissingAddressError(out) {
				s.log("nat bridge ip: already clear")
				s.updateTakeoverState(state, func(current *NATState) { current.StaticIPSet = false })
			} else {
				errs = append(errs, fmt.Errorf("bridge ip remove: %w (%s)", err, strings.TrimSpace(out)))
			}
		} else {
			s.updateTakeoverState(state, func(current *NATState) { current.StaticIPSet = false })
		}
	}
	if state.DHCP {
		if err := s.clearBridgeDHCP(ctx, state.BridgeName); err != nil {
			errs = append(errs, err)
		} else {
			s.updateTakeoverState(state, func(current *NATState) { current.DHCP = false })
		}
	}
	if state.OrigMAC != "" {
		if out, err := s.runCommand(ctx, 5*time.Second, "ifconfig", state.BridgeName, "ether", state.OrigMAC); err != nil {
			errs = append(errs, fmt.Errorf("bridge mac restore: %w (%s)", err, strings.TrimSpace(out)))
		} else {
			s.updateTakeoverState(state, func(current *NATState) { current.OrigMAC = "" })
		}
	}
	if state.HostDetached {
		transitionErr := errors.Join(
			s.prepareTakeoverPFRestore(ctx, state),
			s.restoreFastL2Rules(state),
		)
		if transitionErr != nil {
			errs = append(errs, transitionErr)
		} else if out, err := s.runCommand(ctx, 5*time.Second, "ifconfig", state.BridgeName, "addm", s.Host.Name); err != nil {
			errs = append(errs, fmt.Errorf("host bridge reattach: %w (%s)", err, strings.TrimSpace(out)))
		} else {
			s.updateTakeoverState(state, func(current *NATState) {
				current.HostDetached = false
				current.HostSTPRestorePending = true
			})
			s.log("takeover host member restored: " + s.Host.Name)
		}
	}
	if !state.HostDetached && state.HostSTPRestorePending {
		if out, err := s.runCommand(ctx, 5*time.Second, "ifconfig", state.BridgeName, "stp", s.Host.Name, "disabled"); err != nil {
			errs = append(errs, fmt.Errorf("disable STP for restored host member: %w (%s)", err, strings.TrimSpace(out)))
		} else {
			s.updateTakeoverState(state, func(current *NATState) { current.HostSTPRestorePending = false })
		}
	}
	if !state.HostDetached && state.PFRestorePending {
		if err := s.finishTakeoverPFRestore(ctx, state); err != nil {
			errs = append(errs, err)
		}
	}

	cleanupErr := errors.Join(errs...)
	s.controlMu.Lock()
	finished := s.nat == state && !state.RouteAdded && !state.StaticIPSet && !state.DHCP && state.OrigMAC == "" && !state.HostDetached && !state.HostSTPRestorePending && !state.PFRestorePending && !state.L2RestorePending
	if finished {
		s.nat = nil
	}
	s.controlMu.Unlock()
	if finished {
		s.log("takeover: off")
	}
	return cleanupErr
}

func (s *Session) updateTakeoverState(state *NATState, update func(*NATState)) {
	if s == nil || state == nil || update == nil {
		return
	}
	s.controlMu.Lock()
	if s.nat == nil || s.nat == state {
		update(state)
	}
	s.controlMu.Unlock()
}

func (s *Session) takeoverPolicy() (string, []policy.Rule) {
	if s.policyEngine == nil || s.policyEngine.Policies == nil {
		return "", nil
	}
	active, ok := s.policyEngine.Policies.Active()
	if !ok {
		return "", nil
	}
	return active.Revision(), active.Rules()
}

func joinTakeoverPFRules(first, second string) string {
	first = strings.TrimSpace(first)
	second = strings.TrimSpace(second)
	switch {
	case first == "":
		return second + "\n"
	case second == "":
		return first + "\n"
	default:
		return first + "\n" + second + "\n"
	}
}

func (s *Session) installTakeoverL2Rules(state *NATState) error {
	if state == nil {
		return fmt.Errorf("install takeover Layer 2 policy: state is unavailable")
	}
	// Reset may partially change the bridge filter before returning an error.
	s.updateTakeoverState(state, func(current *NATState) { current.L2RestorePending = true })
	manager := s.effectiveBridgeRuleManager()
	if err := manager.Reset(state.BridgeName); err != nil {
		return fmt.Errorf("reset fast bridge Layer 2 policy for takeover: %w", err)
	}
	var errs []error
	if err := s.installBridgeSafety(state.BridgeName, s.currentTargetMAC()); err != nil {
		errs = append(errs, err)
	}
	if err := manager.SuppressEAPOL(state.BridgeName, s.Host.Name, s.Switch.Name); err != nil {
		errs = append(errs, fmt.Errorf("suppress native EAPOL during takeover: %w", err))
	}
	if err := errors.Join(errs...); err != nil {
		return fmt.Errorf("install takeover Layer 2 policy: %w", err)
	}
	s.updateTakeoverState(state, func(current *NATState) {
		current.L2EndpointRules = true
	})
	s.log("takeover Layer 2 safety policy active")
	return nil
}

func (s *Session) restoreFastL2Rules(state *NATState) error {
	if state == nil || !state.L2RestorePending {
		return nil
	}
	manager := s.effectiveBridgeRuleManager()
	if err := manager.Reset(state.BridgeName); err != nil {
		return fmt.Errorf("reset takeover Layer 2 policy: %w", err)
	}
	var errs []error
	if err := s.installBridgeSafety(state.BridgeName, s.currentTargetMAC()); err != nil {
		errs = append(errs, err)
	}
	_, rules := s.takeoverPolicy()
	if err := manager.InstallPolicy(state.BridgeName, s.Host.Name, s.Switch.Name, rules); err != nil {
		errs = append(errs, fmt.Errorf("restore fast bridge Layer 2 policy: %w", err))
	}
	if err := manager.SuppressEAPOL(state.BridgeName, s.Host.Name, s.Switch.Name); err != nil {
		errs = append(errs, fmt.Errorf("restore native EAPOL suppression: %w", err))
	}
	if err := errors.Join(errs...); err != nil {
		return err
	}
	s.updateTakeoverState(state, func(current *NATState) {
		current.L2EndpointRules = false
		current.L2RestorePending = false
	})
	s.log("fast bridge Layer 2 policy restored")
	return nil
}

func (s *Session) prepareTakeoverPFRestore(ctx context.Context, state *NATState) error {
	if state == nil || !state.PFRestorePending || state.PFCreated {
		return nil
	}
	if s.fastPF == nil || strings.TrimSpace(s.fastPFRules) == "" {
		return fmt.Errorf("restore fast bridge PF transition: backend or rules are unavailable")
	}
	if err := s.fastPF.Apply(ctx, joinTakeoverPFRules(s.fastPFRules, state.takeoverPFRules)); err != nil {
		return fmt.Errorf("restore fast bridge PF transition: %w", err)
	}
	s.log("takeover PF transition policy restored")
	return nil
}

func (s *Session) finishTakeoverPFRestore(ctx context.Context, state *NATState) error {
	if state == nil || !state.PFRestorePending {
		return nil
	}
	if s.fastPF == nil {
		return fmt.Errorf("restore takeover PF policy: backend is unavailable")
	}
	if state.PFCreated {
		if err := s.fastPF.Restore(ctx); err != nil {
			return fmt.Errorf("restore takeover PF policy: %w", err)
		}
		s.fastPF = nil
	} else {
		if strings.TrimSpace(s.fastPFRules) == "" {
			return fmt.Errorf("restore fast bridge PF policy: rules are unavailable")
		}
		if err := s.fastPF.Apply(ctx, s.fastPFRules); err != nil {
			return fmt.Errorf("restore fast bridge PF policy: %w", err)
		}
	}
	s.updateTakeoverState(state, func(current *NATState) {
		current.PFEndpointRules = false
		current.PFRestorePending = false
	})
	s.log("takeover PF policy restored")
	return nil
}

func (s *Session) clearBridgeDHCP(ctx context.Context, bridgeName string) error {
	out, err := s.runCommand(ctx, 5*time.Second, "ipconfig", "set", bridgeName, "NONE")
	if err == nil {
		s.log("takeover bridge dhcp: cleared")
		return nil
	}
	s.log(fmt.Sprintf("warn: takeover bridge dhcp clear via ipconfig failed: %v (%s)", err, strings.TrimSpace(out)))

	ip, err := s.currentInterfaceIPv4(ctx, bridgeName)
	if err != nil {
		return fmt.Errorf("clear bridge DHCP: %w", err)
	}
	if ip == "" {
		s.log("takeover bridge dhcp: already clear")
		return nil
	}
	if out, err := s.runCommand(ctx, 5*time.Second, "ifconfig", bridgeName, "inet", ip, "delete"); err != nil {
		if isMissingAddressError(out) {
			s.log("takeover bridge dhcp: already clear")
			return nil
		}
		return fmt.Errorf("clear bridge DHCP address: %w (%s)", err, strings.TrimSpace(out))
	}
	s.log("takeover bridge dhcp: cleared")
	return nil
}

func (s *Session) detachHostMember(ctx context.Context, state *NATState) error {
	if strings.TrimSpace(s.Host.Name) == "" {
		return fmt.Errorf("host adapter is not known")
	}
	if out, err := s.runCommand(ctx, 5*time.Second, "ifconfig", state.BridgeName, "deletem", s.Host.Name); err != nil {
		return fmt.Errorf("host bridge detach: %w (%s)", err, strings.TrimSpace(out))
	}
	s.updateTakeoverState(state, func(current *NATState) { current.HostDetached = true })
	s.log("takeover host member detached: " + s.Host.Name + " (link kept up for EAPOL)")
	return nil
}

func (s *Session) resolveTakeoverMAC(value string) (net.HardwareAddr, error) {
	if mac, err := requiredTargetMAC(value); err == nil {
		authenticated := s.currentTargetMAC()
		if authenticated != nil && !macEqual(mac, authenticated) {
			return nil, fmt.Errorf("takeover MAC %s differs from authenticated identity %s", mac, authenticated)
		}
		return mac, nil
	}
	if strings.TrimSpace(value) != "" && !strings.EqualFold(value, "auto") {
		return nil, fmt.Errorf("bridge mac %q is invalid", value)
	}
	mac := s.currentTargetMAC()
	if mac == nil {
		return nil, fmt.Errorf("bridge mac is required before takeover")
	}
	return mac, nil
}

func (s *Session) currentTargetMAC() net.HardwareAddr {
	if s == nil {
		return nil
	}
	s.controlMu.Lock()
	target := append(net.HardwareAddr(nil), s.targetMAC...)
	authSession := s.authSession
	s.controlMu.Unlock()
	if len(target) == 6 {
		return target
	}
	if authSession != nil {
		snap := authSession.Snapshot()
		if len(snap.SupplicantMAC) == 6 {
			return append(net.HardwareAddr(nil), snap.SupplicantMAC...)
		}
	}
	return nil
}

// SendEAPOLStart injects an EAPOL-Start toward the switch side of the active bridge.
func (s *Session) SendEAPOLStart() error {
	if s == nil {
		return fmt.Errorf("bridge is not running")
	}
	s.controlMu.Lock()
	switchName := s.Switch.Name
	authSession := s.authSession
	s.controlMu.Unlock()
	mac := s.currentTargetMAC()
	var vlanID uint16
	if authSession != nil {
		vlanID = authSession.Snapshot().VLANID
	}

	if strings.TrimSpace(switchName) == "" {
		return fmt.Errorf("switch adapter is not known")
	}
	if mac == nil {
		return fmt.Errorf("host mac is not known")
	}
	return eapol.InjectEAPOLStartWithVLAN(switchName, mac, vlanID, s.log)
}

func cleanAuto(value string) string {
	value = strings.TrimSpace(value)
	if value == "" || strings.EqualFold(value, "auto") {
		return ""
	}
	return value
}

func cleanDefault(value, fallback string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return fallback
	}
	return value
}

func (s *Session) currentInterfaceIPv4(ctx context.Context, name string) (string, error) {
	out, err := s.runCommand(ctx, 5*time.Second, "ifconfig", name)
	if err != nil {
		return "", fmt.Errorf("ifconfig %s: %w (%s)", name, err, strings.TrimSpace(out))
	}
	return parseInterfaceIPv4(out), nil
}

func (s *Session) currentMAC(ctx context.Context, name string) (string, error) {
	out, err := s.runCommand(ctx, 5*time.Second, "ifconfig", name)
	if err != nil {
		return "", commandError("read MAC for "+name, out, err)
	}
	mac := parseCurrentMAC(out)
	if mac == "" {
		return "", fmt.Errorf("read MAC for %s: no ether address", name)
	}
	return mac, nil
}

func parseCurrentMAC(output string) string {
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(strings.TrimSpace(line))
		if len(fields) >= 2 && fields[0] == "ether" {
			if mac, err := requiredTargetMAC(fields[1]); err == nil {
				return strings.ToLower(mac.String())
			}
		}
	}
	return ""
}

func parseInterfaceIPv4(output string) string {
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "inet ") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) >= 2 {
			return fields[1]
		}
	}
	return ""
}

func isMissingAddressError(output string) bool {
	lower := strings.ToLower(output)
	return strings.Contains(lower, "can't assign requested address") ||
		strings.Contains(lower, "cannot assign requested address") ||
		strings.Contains(lower, "invalid argument") ||
		strings.Contains(lower, "not found")
}

func isMissingRouteError(output string) bool {
	lower := strings.ToLower(output)
	return strings.Contains(lower, "not in table") ||
		strings.Contains(lower, "not found") ||
		strings.Contains(lower, "no such process")
}

func cidrNetmask(value string) (string, error) {
	prefix, err := strconv.Atoi(strings.TrimSpace(value))
	if err != nil || prefix < 0 || prefix > 32 {
		return "", fmt.Errorf("bridge cidr must be between 0 and 32")
	}
	mask := net.CIDRMask(prefix, 32)
	return net.IP(mask).String(), nil
}
