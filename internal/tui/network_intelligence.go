package tui

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	networkobs "golan/internal/network"
	"golan/internal/traffic"

	tea "github.com/charmbracelet/bubbletea"
)

func (m Model) currentNetworkSession() (networkobs.Session, error) {
	if m.networkTracker == nil {
		return networkobs.Session{}, fmt.Errorf("no current or saved Network session")
	}
	return m.networkTracker.Snapshot(), nil
}

func (m Model) resolveNetworkDevice(selector string) (networkobs.Session, networkobs.Device, error) {
	session, err := m.currentNetworkSession()
	if err != nil {
		return networkobs.Session{}, networkobs.Device{}, err
	}
	device, ok := networkobs.FindDevice(session, selector)
	if !ok {
		return networkobs.Session{}, networkobs.Device{}, fmt.Errorf("device is not present in this view")
	}
	return session, device, nil
}

func (m *Model) showNetworkInfrastructure(args []string) {
	if len(args) != 0 {
		m.print("use: network infrastructure")
		return
	}
	session, err := m.currentNetworkSession()
	if err != nil {
		m.print("network infrastructure err: " + err.Error())
		return
	}
	report := networkobs.AnalyzeInfrastructure(session)
	m.print(fmt.Sprintf("network infrastructure: claims=%d alerts=%d", len(report.Claims), len(report.Alerts)))
	for _, alert := range report.Alerts {
		m.print(fmt.Sprintf("  [%s] %s · %s", networkSeverityStatus(alert.Severity), alert.Summary, emptyNetworkValue(alert.Evidence)))
	}
	for _, claim := range report.Claims {
		actor := claim.MAC
		if actor == "" {
			actor = "unresolved actor"
		}
		m.print(fmt.Sprintf("  %-13s %-24s actor=%s seen=%d", claim.Role, claim.Value, actor, claim.Count))
	}
}

func (m *Model) showNetworkServices(args []string) {
	if len(args) != 0 {
		m.print("use: network services")
		return
	}
	session, err := m.currentNetworkSession()
	if err != nil {
		m.print("network services err: " + err.Error())
		return
	}
	owners := networkobs.Services(session)
	count := 0
	for _, owner := range owners {
		count += len(owner.Services)
	}
	m.print(fmt.Sprintf("network services: devices=%d services=%d", len(owners), count))
	for _, owner := range owners {
		m.print(fmt.Sprintf("  %s [%s %d] mac=%s", owner.Identity.Name, owner.Identity.Confidence, owner.Identity.Score, owner.Device.MAC))
		for _, service := range owner.Services {
			endpoint := service.Target
			if service.Port != 0 {
				endpoint = fmt.Sprintf("%s:%d", emptyNetworkValue(endpoint), service.Port)
			}
			m.print(fmt.Sprintf("    %-12s %-24s %s via %s", service.Type, emptyNetworkValue(service.Name), endpoint, service.Protocol))
		}
	}
}

func (m *Model) showNetworkDeviceIntelligence(kind string, args []string) {
	if len(args) != 1 {
		m.print("use: network " + kind + " <device-number|mac|ip|hostname>")
		return
	}
	session, device, err := m.resolveNetworkDevice(args[0])
	if err != nil {
		m.print("network " + kind + " err: " + err.Error())
		return
	}
	switch kind {
	case "identity":
		identity := networkobs.DeviceIdentity(device)
		m.print(fmt.Sprintf("network identity: %s confidence=%s score=%d mac=%s", identity.Name, identity.Confidence, identity.Score, device.MAC))
		for _, reason := range identity.Reasons {
			m.print("  " + reason)
		}
	case "explain":
		explanation := networkobs.ExplainConnection(session, device)
		m.print("network explain: " + explanation.Summary)
		for _, stage := range explanation.Stages {
			line := fmt.Sprintf("  [%s] %-12s %s", stage.Status, stage.Name, stage.Summary)
			if stage.Evidence != "" {
				line += " · " + stage.Evidence
			}
			m.print(line)
		}
	case "access":
		story := networkobs.BuildAccessStory(device)
		m.print(fmt.Sprintf("network access: device=%s result=%s attempts=%d duration=%s", device.MAC, story.Result, story.Attempts, story.Duration.Round(time.Millisecond)))
		for _, event := range story.Events {
			m.print(fmt.Sprintf("  %s [%s] %s · %s", event.ObservedAt.UTC().Format("15:04:05.000"), networkSeverityStatus(event.Severity), event.Protocol, event.Label))
		}
	case "fate":
		fates := networkobs.PacketFatesForDevice(session, device)
		m.print(fmt.Sprintf("network fate: device=%s flows=%d", device.MAC, len(fates)))
		for _, fate := range fates {
			m.print(fmt.Sprintf("  %s <-> %s protocol=%d observed=%d forwarded=%d blocked=%d edited=%d unresolved=%d confidence=%s rule=%s",
				formatFateEndpoint(fate.EndpointA), formatFateEndpoint(fate.EndpointB),
				fate.Protocol, fate.Observed, fate.Forwarded, fate.Blocked, fate.Edited, fate.Unresolved, fate.Confidence, emptyNetworkValue(fate.LastRuleID)))
		}
	}
}

func (m *Model) executeNetworkBaseline(args []string) {
	usage := "use: network baseline show | network baseline set <session-id> | network baseline clear"
	if m.project == nil {
		m.print("network baseline err: open a project first")
		return
	}
	if len(args) == 1 && strings.EqualFold(args[0], "show") {
		if reference, ok := m.project.NetworkBaseline(); ok {
			m.print(fmt.Sprintf("network baseline: %s devices=%d observations=%d started=%s", reference.ID, reference.Devices, reference.Observations, reference.StartedAt.UTC().Format(time.RFC3339)))
		} else {
			m.print("network baseline: none")
		}
		return
	}
	if len(args) == 2 && strings.EqualFold(args[0], "set") {
		if err := m.project.SetNetworkBaseline(args[1]); err != nil {
			m.print("network baseline err: " + err.Error())
			return
		}
		m.print("network baseline: " + args[1] + " (PROJECT*)")
		return
	}
	if len(args) == 1 && strings.EqualFold(args[0], "clear") {
		if err := m.project.SetNetworkBaseline(""); err != nil {
			m.print("network baseline err: " + err.Error())
			return
		}
		m.print("network baseline: cleared (PROJECT*)")
		return
	}
	m.print(usage)
}

func (m *Model) executeNetworkCompare(args []string) {
	usage := "use: network compare baseline | network compare session <session-id>"
	if m.project == nil {
		m.print("network compare err: open a project first")
		return
	}
	current, err := m.currentNetworkSession()
	if err != nil {
		m.print("network compare err: " + err.Error())
		return
	}
	var id string
	switch {
	case len(args) == 1 && strings.EqualFold(args[0], "baseline"):
		reference, ok := m.project.NetworkBaseline()
		if !ok {
			m.print("network compare err: no project baseline; use: network baseline set <session-id>")
			return
		}
		id = reference.ID
	case len(args) == 2 && strings.EqualFold(args[0], "session"):
		id = args[1]
	default:
		m.print(usage)
		return
	}
	baseline, _, err := m.project.ReadNetworkSession(id)
	if err != nil {
		m.print("network compare err: " + err.Error())
		return
	}
	m.printNetworkChanges(networkobs.CompareSessions(baseline, current))
}

func (m *Model) executeNetworkPassport(args []string) {
	usage := "use: network passport save <destination.golanpass> | network passport verify <path.golanpass> | network passport compare <path.golanpass>"
	if len(args) != 2 {
		m.print(usage)
		return
	}
	switch strings.ToLower(args[0]) {
	case "save":
		session, err := m.currentNetworkSession()
		if err != nil {
			m.print("network passport err: " + err.Error())
			return
		}
		name := session.ID
		if m.project != nil {
			name = m.project.Manifest().Name
		}
		passport, err := networkobs.NewPassport(name, session, time.Now().UTC())
		if err == nil {
			err = networkobs.WritePassport(args[1], passport)
		}
		if err != nil {
			m.print("network passport err: " + err.Error())
			return
		}
		m.print(fmt.Sprintf("network passport: saved %s devices=%d checksum=%s", args[1], len(passport.Devices), passport.Checksum))
	case "verify":
		passport, err := networkobs.ReadPassport(args[1])
		if err != nil {
			m.print("network passport [FAIL] " + err.Error())
			return
		}
		m.print(fmt.Sprintf("network passport [PASS] name=%s source=%s devices=%d checksum=%s", passport.Name, passport.SourceSession, len(passport.Devices), passport.Checksum))
	case "compare":
		current, err := m.currentNetworkSession()
		if err != nil {
			m.print("network passport err: " + err.Error())
			return
		}
		passport, err := networkobs.ReadPassport(args[1])
		if err != nil {
			m.print("network passport [FAIL] " + err.Error())
			return
		}
		report, err := networkobs.ComparePassport(passport, current)
		if err != nil {
			m.print("network passport err: " + err.Error())
			return
		}
		m.printNetworkChanges(report)
	default:
		m.print(usage)
	}
}

func (m *Model) executeNetworkProbe(args []string) tea.Cmd {
	usage := "use: network probe plan gateway <ip> | network probe plan dns <name> | network probe plan route <ip> | network probe plan device <ip> <port> | network probe plan dhcp <adapter> | network probe run"
	if len(args) >= 2 && strings.EqualFold(args[0], "plan") {
		if m.networkProbeRunning {
			m.print("network probe err: wait for the running probe to finish")
			return nil
		}
		plan, err := networkobs.NewProbePlan(args[1], args[2:]...)
		if err != nil {
			m.print("network probe err: " + err.Error())
			return nil
		}
		m.pendingNetworkProbe = &plan
		m.print("network probe planned: " + plan.Description)
		m.print("  no probe has run; review the target, then use: network probe run")
		return nil
	}
	if len(args) == 1 && strings.EqualFold(args[0], "run") {
		if m.networkProbeRunning {
			m.print("network probe err: a probe is already running")
			return nil
		}
		if m.pendingNetworkProbe == nil {
			m.print("network probe err: no pending plan; use: network probe plan <kind> ...")
			return nil
		}
		plan := *m.pendingNetworkProbe
		m.networkProbeRunning = true
		m.print("network probe running: " + plan.Description)
		return func() tea.Msg {
			return networkProbeMsg{result: networkobs.RunProbe(context.Background(), plan)}
		}
	}
	m.print(usage)
	return nil
}

func (m *Model) printNetworkProbeResult(result networkobs.ProbeResult) {
	m.print(fmt.Sprintf("network probe [%s] %s duration=%s", result.Status, result.Summary, result.Duration.Round(time.Millisecond)))
	for _, detail := range result.Details {
		m.print("  " + detail)
	}
}

func (m *Model) executeNetworkRule(args []string) {
	if len(args) != 2 || !strings.EqualFold(args[0], "draft") {
		m.print("use: network rule draft <device-number|mac|ip|hostname>")
		return
	}
	_, device, err := m.resolveNetworkDevice(args[1])
	if err != nil {
		m.print("network rule err: " + err.Error())
		return
	}
	m.openRuleEditor(false)
	identity := networkobs.DeviceIdentity(device)
	m.ruleEditor.draft.name = "Review observed device " + identity.Name
	m.ruleEditor.draft.conditions = []guidedCondition{{Kind: conditionSrcMAC, Value: device.MAC}}
	if len(device.VLANs) > 0 {
		m.ruleEditor.draft.conditions = append(m.ruleEditor.draft.conditions, guidedCondition{Kind: conditionVLAN, Value: strconv.Itoa(int(device.VLANs[0]))})
	}
	evidence := latestRuleEvidence(device)
	if evidence.Protocol != "" {
		if protocol := ruleProtocol(evidence.Protocol); protocol != "" {
			m.ruleEditor.draft.conditions = append(m.ruleEditor.draft.conditions, guidedCondition{Kind: conditionProtocol, Value: protocol})
		}
	}
	if port := ruleDestinationPort(evidence); port != 0 {
		m.ruleEditor.draft.conditions = append(m.ruleEditor.draft.conditions, guidedCondition{Kind: conditionDstPort, Value: strconv.Itoa(int(port))})
	}
	if strings.EqualFold(evidence.Protocol, "EAPOL") {
		m.ruleEditor.draft.conditions = append(m.ruleEditor.draft.conditions, guidedCondition{Kind: conditionEtherType, Value: "0x888e"})
	}
	m.ruleEditor.draft.action = "block"
	m.refreshRuleDiagnostic()
	m.ruleEditor.evidence = []string{
		"draft source: " + emptyNetworkValue(evidence.Summary),
		"device: " + device.MAC + " · review scope before Ctrl+S commits",
	}
	m.workspace = workspaceRules
	m.activeCard = cardOutput
	m.print("network rule: opened a review-only draft; no policy was committed or enforced")
}

func (m *Model) printNetworkChanges(report networkobs.ChangeReport) {
	m.print(fmt.Sprintf("network compare: baseline=%s current=%s changes=%d", report.BaselineID, report.CurrentID, len(report.Changes)))
	if len(report.Changes) == 0 {
		m.print("  [PASS] no retained network differences")
		return
	}
	for _, change := range report.Changes {
		line := fmt.Sprintf("  [%s] %-8s %s", networkSeverityStatus(change.Severity), change.Kind, change.Summary)
		if change.DeviceMAC != "" {
			line += " · " + change.DeviceMAC
		}
		m.print(line)
		if change.Before != "" || change.After != "" {
			m.print("    before=" + emptyNetworkValue(change.Before) + " after=" + emptyNetworkValue(change.After))
		}
	}
}

func networkSeverityStatus(severity networkobs.Severity) string {
	switch severity {
	case networkobs.SeverityError:
		return "FAIL"
	case networkobs.SeverityWarn:
		return "WARN"
	default:
		return "PASS"
	}
}

func formatFateEndpoint(endpoint traffic.Endpoint) string {
	value := endpoint.IP
	if value == "" {
		value = endpoint.MAC
	}
	if value == "" {
		value = "unknown"
	}
	if endpoint.Port != 0 {
		return fmt.Sprintf("%s:%d", value, endpoint.Port)
	}
	return value
}

func latestRuleEvidence(device networkobs.Device) networkobs.Observation {
	var selected networkobs.Observation
	selectedRank := -1
	for _, observation := range device.Observations {
		rank := ruleEvidenceRank(observation)
		if rank > selectedRank || rank == selectedRank && observation.LastSeen.After(selected.LastSeen) {
			selected = observation
			selectedRank = rank
		}
	}
	return selected
}

func ruleEvidenceRank(observation networkobs.Observation) int {
	rank := 0
	if observation.Category == networkobs.CategoryRisk {
		rank += 6
	}
	if observation.Category == networkobs.CategoryAction {
		rank += 3
	}
	switch observation.Severity {
	case networkobs.SeverityError:
		rank += 3
	case networkobs.SeverityWarn:
		rank += 2
	default:
		rank++
	}
	return rank
}

func ruleProtocol(protocol string) string {
	switch strings.ToLower(strings.TrimSpace(protocol)) {
	case "tcp", "http", "ntlm":
		return "tcp"
	case "udp", "dns", "dhcp", "snmp", "mdns", "ssdp":
		return "udp"
	case "icmp":
		return "icmp"
	case "icmpv6":
		return "icmpv6"
	default:
		return ""
	}
}

func ruleDestinationPort(observation networkobs.Observation) uint16 {
	switch strings.ToLower(observation.Protocol) {
	case "http":
		return 80
	case "dns":
		return 53
	case "mdns":
		return 5353
	case "snmp":
		return 161
	case "ssdp":
		return 1900
	default:
		return 0
	}
}
