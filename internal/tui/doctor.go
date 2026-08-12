package tui

import (
	"context"
	"os"
	"runtime"
	"time"

	"golan/internal/adapters"
	"golan/internal/doctor"

	tea "github.com/charmbracelet/bubbletea"
)

const doctorTimeout = 8 * time.Second

type doctorMsg struct {
	epoch  uint64
	report doctor.Report
}

func (m *Model) startDoctor(args []string) tea.Cmd {
	if len(args) != 0 {
		m.print("use: doctor")
		return nil
	}
	m.doctorEpoch++
	epoch := m.doctorEpoch
	input := m.doctorInput()
	m.print("doctor: running read-only checks")
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), doctorTimeout)
		defer cancel()
		return doctorMsg{
			epoch:  epoch,
			report: doctor.Run(ctx, input, doctor.DefaultProbes()),
		}
	}
}

func (m Model) doctorInput() doctor.Input {
	input := doctor.Input{
		Platform:                runtime.GOOS,
		EffectiveUID:            os.Geteuid(),
		Adapters:                append([]adapters.Adapter(nil), m.adapters...),
		AdapterError:            m.err,
		AdapterDiscoveryPending: m.loading || m.refreshPending,
		Restoration: doctor.Restoration{
			RuntimeActive:      m.listener != nil || m.bridge != nil || m.edgeSession != nil,
			RuntimeOperation:   m.runtimeOperation,
			InterfaceSnapshots: len(m.restoreState),
			InterfacePending:   len(m.restorePending),
			LockPending:        len(m.lockPending),
			LockFailed:         len(m.lockFailed),
		},
		Edge: doctor.EdgePlan{
			Mode: m.edgeConfiguredMode, Egress: m.edgeEgress, Upstream: m.edgeUpstream,
			VPNDestinations: append([]string(nil), m.edgeVPNDestinations...),
			DNS:             append([]string(nil), m.edgeDNS...),
		},
	}
	if targets := m.listenTargets(); len(targets) > 0 {
		input.Edge.Downstream = targets[0].Name
	}
	if m.bridge != nil {
		input.Restoration.BridgeCleanup = m.bridge.CleanupPending()
	}
	if m.edgeSession != nil {
		input.Restoration.EdgeCleanup = m.edgeSession.CleanupPending()
	}
	for _, session := range m.projectSessions {
		if session.Recoverable {
			input.Restoration.RecoverableSessions++
		} else {
			input.Restoration.StaleSessions++
		}
	}
	if m.project != nil {
		manifest := m.project.Manifest()
		input.ProjectPath = m.project.Path()
		input.ProjectDirty = m.project.Dirty()
		input.ProjectCaptures = len(manifest.Captures)
	}
	return input
}
