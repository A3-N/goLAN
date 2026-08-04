package bridge

import (
	"net"

	"golan/internal/policy"
	"golan/internal/stealth"
)

// bridgeRuleManager owns only rules on the per-session bridge interface. The
// indirection keeps NAT transitions testable without invoking ifconfig.
type bridgeRuleManager interface {
	Reset(string) error
	InstallSafety(string, []net.HardwareAddr) error
	SuppressLeaks(string) error
	SuppressEAPOL(string, string, string) error
	InstallPolicy(string, string, string, []policy.Rule) error
}

type systemBridgeRuleManager struct{}

func (systemBridgeRuleManager) Reset(bridgeName string) error {
	return stealth.ResetBridgeRules(bridgeName)
}

func (systemBridgeRuleManager) InstallSafety(bridgeName string, macs []net.HardwareAddr) error {
	return stealth.InstallL2SafetyRules(bridgeName, macs)
}

func (systemBridgeRuleManager) SuppressLeaks(bridgeName string) error {
	return stealth.SuppressL2Leaks(bridgeName)
}

func (systemBridgeRuleManager) SuppressEAPOL(bridgeName, hostInterface, switchInterface string) error {
	return stealth.SuppressNativeEAPOL(bridgeName, hostInterface, switchInterface)
}

func (systemBridgeRuleManager) InstallPolicy(bridgeName, hostInterface, switchInterface string, rules []policy.Rule) error {
	return stealth.InstallPolicyRules(bridgeName, hostInterface, switchInterface, rules)
}

func (s *Session) effectiveBridgeRuleManager() bridgeRuleManager {
	if s != nil && s.l2Rules != nil {
		return s.l2Rules
	}
	return systemBridgeRuleManager{}
}
