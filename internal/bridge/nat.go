package bridge

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"golan/internal/eapol"
)

// StartNAT turns the active bridge interface into the local endpoint for the
// authenticated host identity while leaving the bridge and member links up.
func (s *Session) StartNAT(cfg NATConfig) error {
	if s == nil {
		return fmt.Errorf("bridge is not running")
	}

	s.controlMu.Lock()
	defer s.controlMu.Unlock()

	if s.nat != nil {
		return nil
	}
	bridgeName := strings.TrimSpace(s.bridgeName)
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

	state := &NATState{
		BridgeName: bridgeName,
		MAC:        mac.String(),
		IP:         ip,
		CIDR:       cidr,
		DHCP:       useDHCP,
		OrigMAC:    getCurrentMAC(bridgeName),
		Gateway:    cleanAuto(cfg.Gateway),
	}
	s.nat = state

	success := false
	defer func() {
		if !success {
			if err := s.stopNATLocked(context.Background()); err != nil {
				s.log(fmt.Sprintf("warn: nat rollback failed: %v", err))
			}
		}
	}()

	ctx := context.Background()
	if err := s.detachHostMember(ctx, state); err != nil {
		return err
	}
	if out, err := runCommand(ctx, 5*time.Second, "ifconfig", bridgeName, "ether", mac.String()); err != nil {
		return fmt.Errorf("bridge mac takeover: %w (%s)", err, strings.TrimSpace(out))
	}
	s.log("nat bridge mac: " + mac.String())

	if state.DHCP {
		if out, err := runCommand(ctx, 15*time.Second, "ipconfig", "set", bridgeName, "DHCP"); err != nil {
			return fmt.Errorf("bridge dhcp: %w (%s)", err, strings.TrimSpace(out))
		}
		s.log("nat bridge dhcp: requested")
	} else {
		netmask, err := cidrNetmask(cidr)
		if err != nil {
			return err
		}
		if out, err := runCommand(ctx, 5*time.Second, "ifconfig", bridgeName, "inet", ip, "netmask", netmask); err != nil {
			return fmt.Errorf("bridge ip takeover: %w (%s)", err, strings.TrimSpace(out))
		}
		state.StaticIPSet = true
		s.log(fmt.Sprintf("nat bridge ip: %s/%s", ip, cidr))
	}

	if state.Gateway != "" {
		if net.ParseIP(state.Gateway).To4() == nil {
			return fmt.Errorf("bridge gateway %q is not an IPv4 address", state.Gateway)
		}
		if out, err := runCommand(ctx, 5*time.Second, "route", "-n", "add", "default", state.Gateway); err != nil {
			lowerOut := strings.ToLower(out)
			if !strings.Contains(lowerOut, "file exists") && !strings.Contains(lowerOut, "already in table") {
				return fmt.Errorf("default route add: %w (%s)", err, strings.TrimSpace(out))
			}
			s.log("nat default route: already present")
		} else {
			state.RouteAdded = true
			s.log("nat default route: " + state.Gateway)
		}
	}
	if dns := cleanAuto(cfg.DNS); dns != "" {
		s.log("nat dns: configured value retained; macOS resolver unchanged: " + dns)
	}

	success = true
	s.log("nat: on")
	return nil
}

// StopNAT reverses StartNAT without tearing down the bridge.
func (s *Session) StopNAT() error {
	if s == nil {
		return nil
	}
	s.controlMu.Lock()
	defer s.controlMu.Unlock()
	return s.stopNATLocked(context.Background())
}

func (s *Session) stopNATLocked(ctx context.Context) error {
	if s.nat == nil {
		return nil
	}
	state := s.nat

	var errs []error
	if state.RouteAdded && state.Gateway != "" {
		if out, err := runCommand(ctx, 5*time.Second, "route", "-n", "delete", "default", state.Gateway); err != nil {
			if isMissingRouteError(out) {
				s.log("nat default route: already gone")
			} else {
				errs = append(errs, fmt.Errorf("default route delete: %w (%s)", err, strings.TrimSpace(out)))
			}
		}
	}
	if state.StaticIPSet && state.IP != "" {
		if out, err := runCommand(ctx, 5*time.Second, "ifconfig", state.BridgeName, "inet", state.IP, "delete"); err != nil {
			if isMissingAddressError(out) {
				s.log("nat bridge ip: already clear")
			} else {
				errs = append(errs, fmt.Errorf("bridge ip remove: %w (%s)", err, strings.TrimSpace(out)))
			}
		}
	}
	if state.DHCP {
		s.clearBridgeDHCP(ctx, state.BridgeName)
	}
	if state.OrigMAC != "" {
		if out, err := runCommand(ctx, 5*time.Second, "ifconfig", state.BridgeName, "ether", state.OrigMAC); err != nil {
			errs = append(errs, fmt.Errorf("bridge mac restore: %w (%s)", err, strings.TrimSpace(out)))
		}
	}
	if state.HostDetached {
		if out, err := runCommand(ctx, 5*time.Second, "ifconfig", state.BridgeName, "addm", s.Host.Name); err != nil {
			errs = append(errs, fmt.Errorf("host bridge reattach: %w (%s)", err, strings.TrimSpace(out)))
		} else {
			if out, err := runCommand(ctx, 5*time.Second, "ifconfig", state.BridgeName, "stp", s.Host.Name, "disabled"); err != nil {
				s.log(fmt.Sprintf("warn: stp disable failed for %s: %v (%s)", s.Host.Name, err, strings.TrimSpace(out)))
			}
			s.log("nat host member restored: " + s.Host.Name)
		}
	}

	if err := errors.Join(errs...); err != nil {
		return err
	}
	s.nat = nil
	s.log("nat: off")
	return nil
}

func (s *Session) clearBridgeDHCP(ctx context.Context, bridgeName string) {
	if out, err := runCommand(ctx, 5*time.Second, "ipconfig", "set", bridgeName, "NONE"); err == nil {
		s.log("nat bridge dhcp: cleared")
		return
	} else {
		s.log(fmt.Sprintf("warn: bridge dhcp clear via ipconfig failed: %v (%s)", err, strings.TrimSpace(out)))
	}

	ip, err := currentInterfaceIPv4(ctx, bridgeName)
	if err != nil {
		s.log(fmt.Sprintf("warn: bridge dhcp clear lookup failed: %v", err))
		return
	}
	if ip == "" {
		s.log("nat bridge dhcp: already clear")
		return
	}
	if out, err := runCommand(ctx, 5*time.Second, "ifconfig", bridgeName, "inet", ip, "delete"); err != nil {
		if isMissingAddressError(out) {
			s.log("nat bridge dhcp: already clear")
			return
		}
		s.log(fmt.Sprintf("warn: bridge dhcp clear failed: %v (%s)", err, strings.TrimSpace(out)))
		return
	}
	s.log("nat bridge dhcp: cleared")
}

func (s *Session) detachHostMember(ctx context.Context, state *NATState) error {
	if strings.TrimSpace(s.Host.Name) == "" {
		return fmt.Errorf("host adapter is not known")
	}
	if out, err := runCommand(ctx, 5*time.Second, "ifconfig", state.BridgeName, "deletem", s.Host.Name); err != nil {
		return fmt.Errorf("host bridge detach: %w (%s)", err, strings.TrimSpace(out))
	}
	state.HostDetached = true
	s.log("nat host member detached: " + s.Host.Name + " (link kept up for EAPOL)")
	return nil
}

func (s *Session) resolveTakeoverMAC(value string) (net.HardwareAddr, error) {
	if mac, err := requiredTargetMAC(value); err == nil {
		return mac, nil
	}
	if strings.TrimSpace(value) != "" && !strings.EqualFold(value, "auto") {
		return nil, fmt.Errorf("bridge mac %q is invalid", value)
	}
	mac := s.currentTargetMACLocked()
	if mac == nil {
		return nil, fmt.Errorf("bridge mac is required before nat")
	}
	return mac, nil
}

func (s *Session) currentTargetMACLocked() net.HardwareAddr {
	if len(s.targetMAC) == 6 {
		return append(net.HardwareAddr(nil), s.targetMAC...)
	}
	if s.authSession != nil {
		snap := s.authSession.Snapshot()
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
	mac := s.currentTargetMACLocked()
	var vlanID uint16
	if s.authSession != nil {
		vlanID = s.authSession.Snapshot().VLANID
	}
	s.controlMu.Unlock()

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

func currentInterfaceIPv4(ctx context.Context, name string) (string, error) {
	out, err := runCommand(ctx, 5*time.Second, "ifconfig", name)
	if err != nil {
		return "", fmt.Errorf("ifconfig %s: %w (%s)", name, err, strings.TrimSpace(out))
	}
	return parseInterfaceIPv4(out), nil
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
