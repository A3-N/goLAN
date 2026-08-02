package stealth

import (
	"fmt"
	"net"
	"sort"
	"strings"

	"golan/internal/policy"
	"golan/internal/traffic"
)

// InstallPolicyRules compiles compatible ordered Layer 2 rules into macOS
// bridge-local filters. Incompatible rules remain SHADOW and are not passed to
// ifconfig.
func InstallPolicyRules(bridgeName, hostInterface, switchInterface string, rules []policy.Rule) error {
	if err := validateInterfaceName(hostInterface); err != nil {
		return err
	}
	if err := validateInterfaceName(switchInterface); err != nil {
		return err
	}
	compiled, err := compilePolicyRules(bridgeName, hostInterface, switchInterface, rules)
	if err != nil {
		return err
	}
	if len(compiled) == 0 {
		return nil
	}
	return applyBridgeRules(systemCommandRunner{}, bridgeName, compiled)
}

// ValidateFastBridgeL2Policy proves that all bridge-local rule expansions fit
// the bounded command surface before a bridge or adapter is mutated.
func ValidateFastBridgeL2Policy(hostInterface, switchInterface string, rules []policy.Rule) error {
	if err := validateInterfaceName(hostInterface); err != nil {
		return fmt.Errorf("host interface: %w", err)
	}
	if err := validateInterfaceName(switchInterface); err != nil {
		return fmt.Errorf("switch interface: %w", err)
	}
	_, err := compilePolicyRules("bridge0", strings.TrimSpace(hostInterface), strings.TrimSpace(switchInterface), rules)
	return err
}

func compilePolicyRules(bridgeName, hostInterface, switchInterface string, rules []policy.Rule) ([][]string, error) {
	if err := validateBridgeName(bridgeName); err != nil {
		return nil, err
	}
	var compiled [][]string
	for _, rule := range rules {
		if !rule.Enabled || !policy.FastBridgeL2Compatible(rule) || strings.HasPrefix(rule.ID, "builtin-eapol-suppress-logoff") {
			continue
		}
		verdict := ""
		for _, action := range rule.Actions {
			switch action.Kind {
			case policy.ActionAllow:
				verdict = "pass"
			case policy.ActionBlock:
				verdict = "block"
			}
		}
		if verdict == "" {
			continue
		}
		outInterfaces := policyRuleOutputs(rule, hostInterface, switchInterface)
		sources := normalizedMACs(rule.Match.SrcMAC)
		destinations := normalizedMACs(rule.Match.DstMAC)
		etherTypes := append([]uint16(nil), rule.Match.EtherTypes...)
		if len(sources) == 0 {
			sources = []string{""}
		}
		if len(destinations) == 0 {
			destinations = []string{""}
		}
		if len(etherTypes) == 0 {
			etherTypes = []uint16{0}
		}
		if len(outInterfaces)*len(sources)*len(destinations)*len(etherTypes) > 256 {
			return nil, fmt.Errorf("rule %s expands beyond 256 bridge filters", rule.ID)
		}
		for _, output := range outInterfaces {
			for _, source := range sources {
				for _, destination := range destinations {
					for _, etherType := range etherTypes {
						args := []string{bridgeName, "rule", verdict, "out", "on", output}
						if source != "" {
							args = append(args, "src", source)
						}
						if destination != "" {
							args = append(args, "dst", destination)
						}
						if etherType != 0 {
							args = append(args, "mac-type", fmt.Sprintf("0x%04x", etherType))
						}
						compiled = append(compiled, args)
					}
				}
			}
		}
	}
	return compiled, nil
}

func policyRuleOutputs(rule policy.Rule, hostInterface, switchInterface string) []string {
	outputs := make(map[string]bool)
	for _, direction := range rule.Match.Directions {
		switch direction {
		case traffic.DirectionHostToSwitch, traffic.DirectionOutbound:
			outputs[switchInterface] = true
		case traffic.DirectionSwitchToHost, traffic.DirectionInbound:
			outputs[hostInterface] = true
		}
	}
	for _, side := range rule.Match.Topologies {
		switch side {
		case traffic.SideHost, traffic.SideDownstream:
			outputs[switchInterface] = true
		case traffic.SideSwitch, traffic.SideUpstream:
			outputs[hostInterface] = true
		}
	}
	if len(outputs) == 0 {
		outputs[hostInterface] = true
		outputs[switchInterface] = true
	}
	values := make([]string, 0, len(outputs))
	for value := range outputs {
		values = append(values, value)
	}
	sort.Strings(values)
	return values
}

func normalizedMACs(values []string) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		mac, err := net.ParseMAC(value)
		if err == nil && len(mac) == 6 {
			out = append(out, strings.ToLower(mac.String()))
		}
	}
	sort.Strings(out)
	return out
}
