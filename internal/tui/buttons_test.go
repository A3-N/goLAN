package tui

import (
	"fmt"
	"strings"
	"testing"
	"time"

	networkobs "golan/internal/network"
	"golan/internal/policy"
	"golan/internal/traffic"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

func TestTextButtonBarRendersStableClickableCells(t *testing.T) {
	bar := textButtonBar{
		Prefix: "VIEW 2/4  ",
		Buttons: []textButton{
			{ID: "all", Label: "All", Active: true},
			{ID: "error", Label: "Error", Tone: buttonDanger},
			{ID: "disabled", Label: "Disabled", Disabled: true},
		},
		Suffix: "  search=none",
	}
	rendered := renderTextButtonBar(bar)
	for _, want := range []string{"VIEW 2/4", "[All]", "[Error]", "[Disabled]", "search=none"} {
		if !strings.Contains(rendered, want) {
			t.Fatalf("button bar missing %q: %q", want, rendered)
		}
	}
	plainWidth := len([]rune("VIEW 2/4  [All] [Error] [Disabled]  search=none"))
	if got := lipgloss.Width(rendered); got != plainWidth {
		t.Fatalf("styled button width=%d want=%d", got, plainWidth)
	}
	for _, want := range []string{"all", "error", "disabled"} {
		column := textButtonCenter(t, bar, want)
		button, ok := textButtonAt(bar, column)
		if !ok || button.ID != want {
			t.Fatalf("column=%d button=%#v ok=%t want=%s", column, button, ok, want)
		}
	}
	if _, ok := textButtonAt(bar, 0); ok {
		t.Fatal("prefix was treated as a button")
	}
}

func TestNetworkFilterButtonsAreClickableWithoutChangingPaneLayout(t *testing.T) {
	m := NewModelWithSize(180, 40)
	m.workspace = workspaceNetwork
	m.activeCard = cardOutput
	frame := traffic.Normalize(
		rulePreviewTCPFrame([]byte("GET /private HTTP/1.1\r\nHost: example.test\r\n\r\n")),
		traffic.CaptureMetadata{Timestamp: time.Unix(1, 0)},
		"en0", traffic.SideHost, traffic.DirectionOutbound,
	)
	m.networkTracker = networkobs.NewTracker("buttons", "edge-route", time.Unix(1, 0))
	m.networkTracker.ObserveFrame(frame, "host", policy.DecisionSummary{})
	m.ensureNetworkSelection()
	pane, ok := paneForCard(m.workbenchGeometry(), cardOutput)
	if !ok {
		t.Fatal("Network device pane is missing")
	}
	bar := m.networkButtonBar(1, 1)
	m = updateMouseModel(t, m, tea.MouseEvent{
		X:      pane.Rect.X + 1 + textButtonCenter(t, bar, string(networkobs.CategoryHTTP)),
		Y:      pane.Rect.Y + 1,
		Action: tea.MouseActionPress,
		Button: tea.MouseButtonLeft,
	})
	if m.networkFilter != networkobs.CategoryHTTP || m.maximized {
		t.Fatalf("Network button filter=%q maximized=%t", m.networkFilter, m.maximized)
	}
}

func TestDenseNetworkTableKeepsControlsPinnedWhileRowsScroll(t *testing.T) {
	m := NewModelWithSize(100, 40)
	m.workspace = workspaceNetwork
	m.activeCard = cardOutput
	session := networkobs.Session{ID: "dense", Mode: "listen", StartedAt: time.Unix(1, 0)}
	for index := 0; index < 24; index++ {
		mac := fmt.Sprintf("02:00:00:00:00:%02x", index+1)
		session.Devices = append(session.Devices, networkobs.Device{
			Key: "en0/" + mac, MAC: mac, Adapter: "en0", Role: "host",
			FirstSeen: time.Unix(int64(index+1), 0), LastSeen: time.Unix(int64(index+1), 0),
			Protocols:    []string{"HTTP"},
			Observations: []networkobs.Observation{{Category: networkobs.CategoryHTTP, Protocol: "HTTP", Summary: "GET example.test/index", Count: 1}},
		})
	}
	m.networkTracker = networkobs.LoadTracker(session)
	m.ensureNetworkSelection()
	pane, ok := paneForCard(m.workbenchGeometry(), cardOutput)
	if !ok {
		t.Fatal("Network list pane is missing")
	}
	view := m.renderNetworkDevices(pane.Rect.Width, pane.Rect.Height)
	for _, want := range []string{"VIEW 24/24", "[HTTP]", "MAC", "PROTOCOLS", "ALERTS"} {
		if !strings.Contains(view, want) {
			t.Fatalf("scrolled Network table lost pinned control %q:\n%s", want, view)
		}
	}
	bar := m.networkButtonBar(24, 24)
	beforeFilter := m.networkFilter
	beforeSelection := m.selectedNetworkDevice
	m = updateMouseModel(t, m, tea.MouseEvent{
		X:      pane.Rect.X + 1 + textButtonCenter(t, bar, string(networkobs.CategoryHTTP)),
		Y:      pane.Rect.Y + 4,
		Action: tea.MouseActionPress,
		Button: tea.MouseButtonLeft,
	})
	if m.networkFilter != beforeFilter || m.selectedNetworkDevice == beforeSelection || !m.maximized {
		t.Fatalf(
			"data-row click filter=%q/%q selected=%s/%s maximized=%t",
			m.networkFilter,
			beforeFilter,
			m.selectedNetworkDevice,
			beforeSelection,
			m.maximized,
		)
	}
}

func textButtonCenter(t *testing.T, bar textButtonBar, id string) int {
	t.Helper()
	position := len([]rune(bar.Prefix))
	for index, button := range bar.Buttons {
		if index > 0 {
			position++
		}
		width := len([]rune("[" + button.Label + "]"))
		if button.ID == id {
			return position + width/2
		}
		position += width
	}
	t.Fatalf("button %q not found in %#v", id, bar)
	return 0
}
