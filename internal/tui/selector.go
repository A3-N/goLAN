package tui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/mcrn/goLAN/internal/bridge"

	tea "github.com/charmbracelet/bubbletea"
)

// activeSide tracks which half of the split-screen is focused.
type activeSide int

const (
	sideA activeSide = iota // Left panel — LAN 1 (Device)
	sideB                   // Right panel — LAN 2 (Switch)
)

// SelectorModel is a split-screen Bubbletea model for choosing two interfaces.
type SelectorModel struct {
	interfaces []bridge.NetInterface

	cursorA   int // Cursor position in left panel (Device)
	cursorB   int // Cursor position in right panel (Switch)
	active    activeSide
	confirmed bool

	width  int
	height int
	err    error
}

// SelectorResult is the message sent when the user confirms their selection.
type SelectorResult struct {
	IfaceA bridge.NetInterface // Device port
	IfaceB bridge.NetInterface // Switch port
}

// NewSelectorModel creates the split-screen selector.
func NewSelectorModel() SelectorModel {
	return SelectorModel{
		cursorA: 0,
		cursorB: 1,
		active:  sideA,
	}
}

// discoverMsg carries discovered interfaces to the model.
type discoverMsg struct {
	interfaces []bridge.NetInterface
	err        error
}

// discoverInterfaces is a tea.Cmd that discovers all network interfaces.
func discoverInterfaces() tea.Msg {
	ifaces, err := bridge.DiscoverInterfaces()
	return discoverMsg{interfaces: ifaces, err: err}
}

func (m SelectorModel) Init() tea.Cmd {
	return discoverInterfaces
}

func (m SelectorModel) Update(msg tea.Msg) (SelectorModel, tea.Cmd) {
	switch msg := msg.(type) {
	case discoverMsg:
		m.interfaces = msg.interfaces
		m.err = msg.err
		if len(m.interfaces) > 1 {
			m.cursorB = 1
		}
		return m, nil

	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		return m, nil

	case tea.KeyMsg:
		switch msg.String() {
		case "tab", "right", "l":
			if m.active == sideA {
				m.active = sideB
			} else {
				m.active = sideA
			}
		case "shift+tab", "left", "h":
			if m.active == sideB {
				m.active = sideA
			} else {
				m.active = sideB
			}
		case "up", "k":
			m.moveCursor(-1)
		case "down", "j":
			m.moveCursor(1)
		case "enter":
			return m.handleConfirm()
		}
	}
	return m, nil
}

func (m *SelectorModel) moveCursor(delta int) {
	if len(m.interfaces) == 0 {
		return
	}
	maxIdx := len(m.interfaces) - 1

	if m.active == sideA {
		m.cursorA += delta
		if m.cursorA < 0 {
			m.cursorA = 0
		}
		if m.cursorA > maxIdx {
			m.cursorA = maxIdx
		}
	} else {
		m.cursorB += delta
		if m.cursorB < 0 {
			m.cursorB = 0
		}
		if m.cursorB > maxIdx {
			m.cursorB = maxIdx
		}
	}
}

func (m SelectorModel) handleConfirm() (SelectorModel, tea.Cmd) {
	if len(m.interfaces) < 2 {
		return m, nil
	}
	if m.cursorA == m.cursorB {
		return m, nil
	}
	return m, func() tea.Msg {
		return SelectorResult{
			IfaceA: m.interfaces[m.cursorA],
			IfaceB: m.interfaces[m.cursorB],
		}
	}
}

func (m SelectorModel) View() string {
	if m.width == 0 {
		return ""
	}

	var sb strings.Builder

	// ── Error State ─────────────────────────────────────────────
	if m.err != nil {
		sb.WriteString("\n" + styleError.Render("  ✗ Error discovering interfaces:") + "\n")
		sb.WriteString(styleError.Render("    "+m.err.Error()) + "\n")
		return sb.String()
	}

	// ── Loading State ───────────────────────────────────────────
	if m.interfaces == nil {
		sb.WriteString("\n" + styleDim.Render("  ⟳ Discovering network interfaces..."))
		return sb.String()
	}

	// ── Not enough interfaces ───────────────────────────────────
	if len(m.interfaces) < 2 {
		sb.WriteString("\n" + styleWarning.Render("  ⚠ Need at least 2 network interfaces to create a bridge.") + "\n")
		sb.WriteString(styleDim.Render(fmt.Sprintf("  Found %d interface(s).", len(m.interfaces))) + "\n")
		return sb.String()
	}

	// ── Conflict detection ──────────────────────────────────────
	sameIface := m.cursorA == m.cursorB

	// ── Split-screen panels ─────────────────────────────────────
	panelWidth := (m.width - 5) / 2
	if panelWidth < 40 {
		panelWidth = 40
	}

	leftPanel := m.renderPanel(sideA, panelWidth, sameIface)
	rightPanel := m.renderPanel(sideB, panelWidth, sameIface)

	split := lipgloss.JoinHorizontal(lipgloss.Top, leftPanel, "  ", rightPanel)
	sb.WriteString(split)
	sb.WriteString("\n")

	// ── Footer ──────────────────────────────────────────────────
	var footerParts []string
	footerParts = append(footerParts, keyHint("Tab", "switch panel"))
	footerParts = append(footerParts, keyHint("↑↓", "navigate"))
	if sameIface {
		footerParts = append(footerParts, styleError.Render("⚠ Same interface selected on both sides"))
	} else {
		footerParts = append(footerParts, keyHint("Enter", "create bridge"))
	}
	footerParts = append(footerParts, keyHint("Esc/q", "quit"))

	footer := styleFooter.Width(m.width - 4).Render("  " + strings.Join(footerParts, "   "))
	sb.WriteString(footer)

	return sb.String()
}

// renderPanel renders one half of the split-screen.
// sideA = LAN 1 (Device port, left), sideB = LAN 2 (Switch port, right).
func (m SelectorModel) renderPanel(side activeSide, width int, conflict bool) string {
	isActive := m.active == side
	cursor := m.cursorA
	if side == sideB {
		cursor = m.cursorB
	}


	// Determine the highlight color for this panel.
	var highlightColor lipgloss.Color
	if conflict {
		highlightColor = colorConflict // Red when both on same row
	} else if side == sideA {
		highlightColor = colorDevice // Orange for Device
	} else {
		highlightColor = colorSwitch // Magenta for Switch
	}

	var sb strings.Builder

	// Panel header.
	var headerStyle lipgloss.Style
	var label string
	if side == sideA {
		headerStyle = stylePanelHeaderDevice
		label = "▎ LAN 1 — Device Port"
	} else {
		headerStyle = stylePanelHeaderSwitch
		label = "▎ LAN 2 — Switch Port"
	}
	if isActive {
		label += "  ◀"
	}
	sb.WriteString("  " + headerStyle.Render(label) + "\n\n")

	// Table header.
	innerWidth := width - 4
	colSt := 3
	colIface := 9
	colType := 10
	colMAC := 19
	colStatus := 8

	header := fmt.Sprintf("%-*s %-*s %-*s %-*s %-*s",
		colSt, "ST",
		colIface, "IFACE",
		colType, "TYPE",
		colMAC, "MAC",
		colStatus, "STATUS",
	)
	sb.WriteString("  " + styleTableHeader.Render(header) + "\n")

	sep := "  " + strings.Repeat("─", innerWidth)
	sb.WriteString(lipgloss.NewStyle().Foreground(colorBorder).Render(sep) + "\n")

	// ── Interface Rows ──────────────────────────────────────────
	for i, iface := range m.interfaces {
		isSelected := i == cursor

		// Status icon.
		var stIcon string
		if iface.IsUp {
			stIcon = "●"
		} else {
			stIcon = "○"
		}

		mac := iface.CurrentMAC
		if mac == "" {
			mac = "—"
		}

		var statusPlain string
		if iface.IsSpoofed {
			statusPlain = "SPOOFED"
		} else if iface.IsUp {
			statusPlain = "NATIVE"
		} else {
			statusPlain = "DOWN"
		}

		ifaceType := string(iface.Type.ShortType())

		// All rows use the same structure — only colors change.
		namePadded := fmt.Sprintf("%-*s", colIface, trunc(iface.Name, colIface-1))
		typePadded := fmt.Sprintf("%-*s", colType, trunc(ifaceType, colType-1))
		macPadded := fmt.Sprintf("%-*s", colMAC, mac)
		statusPadded := fmt.Sprintf("%-*s", colStatus, statusPlain)

		var stStyled, nameStyled, typeStyled, macStyled, statusStyled string

		if isSelected {
			// Selected row: everything in the highlight color.
			hlStyle := lipgloss.NewStyle().Foreground(highlightColor).Bold(true)
			stStyled = hlStyle.Render(stIcon)
			nameStyled = hlStyle.Render(namePadded)
			typeStyled = hlStyle.Render(typePadded)
			macStyled = hlStyle.Render(macPadded)
			statusStyled = hlStyle.Render(statusPadded)
		} else {
			// Normal row: each part gets its own color.
			if iface.IsUp {
				stStyled = styleUp.Render(stIcon)
			} else {
				stStyled = styleDown.Render(stIcon)
			}
			nameStyled = namePadded
			if iface.IsUSB {
				typeStyled = styleUSB.Render(typePadded)
			} else {
				typeStyled = typePadded
			}
			macStyled = macPadded
			if iface.IsSpoofed {
				statusStyled = styleSpoofed.Render(statusPadded)
			} else if iface.IsUp {
				statusStyled = styleUp.Render(statusPadded)
			} else {
				statusStyled = styleDown.Render(statusPadded)
			}
		}

		row := fmt.Sprintf("  %s   %s %s %s %s",
			stStyled, nameStyled, typeStyled, macStyled, statusStyled,
		)
		sb.WriteString(row + "\n")
	}

	// ── Detail Panel for Selected Interface ─────────────────────
	if cursor >= 0 && cursor < len(m.interfaces) {
		sel := m.interfaces[cursor]
		detail := bridge.GetInterfaceDetail(sel.Name)

		sb.WriteString("\n")
		detailSep := "  " + strings.Repeat("─", innerWidth)
		sb.WriteString(lipgloss.NewStyle().Foreground(colorBorder).Render(detailSep) + "\n")

		detailLabel := sel.Name + " — " + sel.HardwarePort
		if sel.HardwarePort == "" {
			detailLabel = sel.Name
		}
		sb.WriteString("  " + styleLabel.Render(detailLabel) + "\n\n")

		col1 := 16

		// IP info.
		if detail.IPv4 != "" {
			addr := detail.IPv4
			if detail.Netmask != "" {
				addr += "/" + detail.Netmask
			}
			sb.WriteString(fmt.Sprintf("  %-*s %s\n", col1, styleKeyDesc.Render("IPv4:"), styleVal.Render(addr)))
		}
		if detail.IPv6 != "" {
			sb.WriteString(fmt.Sprintf("  %-*s %s\n", col1, styleKeyDesc.Render("IPv6:"), styleVal.Render(detail.IPv6)))
		}
		if detail.IPv4 == "" && detail.IPv6 == "" {
			sb.WriteString(fmt.Sprintf("  %-*s %s\n", col1, styleKeyDesc.Render("IP:"), styleDown.Render("no address assigned")))
		}

		// Gateway.
		if detail.Gateway != "" {
			sb.WriteString(fmt.Sprintf("  %-*s %s\n", col1, styleKeyDesc.Render("Gateway:"), styleVal.Render(detail.Gateway)))
		}

		// DNS.
		if len(detail.DNS) > 0 {
			dnsStr := strings.Join(detail.DNS, ", ")
			sb.WriteString(fmt.Sprintf("  %-*s %s\n", col1, styleKeyDesc.Render("DNS:"), styleVal.Render(dnsStr)))
		}

		// DHCP.
		if detail.DHCPServer != "" {
			dhcpLine := detail.DHCPServer
			if detail.LeaseTime != "" {
				dhcpLine += "  " + styleKeyDesc.Render("lease:") + " " + detail.LeaseTime
			}
			sb.WriteString(fmt.Sprintf("  %-*s %s\n", col1, styleKeyDesc.Render("DHCP Server:"), styleVal.Render(dhcpLine)))
		}

		// 802.1X.
		if detail.Dot1XStatus != "none" {
			var dot1xStyled string
			switch detail.Dot1XStatus {
			case "active":
				dot1xStyled = styleWarning.Render("● ACTIVE")
			case "configured":
				dot1xStyled = styleKeyDesc.Render("configured")
			default:
				dot1xStyled = styleVal.Render(detail.Dot1XStatus)
			}
			if detail.Dot1XMethod != "" {
				dot1xStyled += "  " + styleKeyDesc.Render("method:") + " " + styleVal.Render(detail.Dot1XMethod)
			}
			sb.WriteString(fmt.Sprintf("  %-*s %s\n", col1, styleKeyDesc.Render("802.1X:"), dot1xStyled))
		} else {
			sb.WriteString(fmt.Sprintf("  %-*s %s\n", col1, styleKeyDesc.Render("802.1X:"), styleDim.Render("none")))
		}

		// Media / MTU.
		if detail.Media != "" {
			sb.WriteString(fmt.Sprintf("  %-*s %s\n", col1, styleKeyDesc.Render("Media:"), styleVal.Render(detail.Media)))
		}
		if detail.MTU != "" {
			sb.WriteString(fmt.Sprintf("  %-*s %s\n", col1, styleKeyDesc.Render("MTU:"), styleVal.Render(detail.MTU)))
		}

		// Traffic stats.
		if detail.PktsIn != "" {
			sb.WriteString("\n")
			sb.WriteString(fmt.Sprintf("  %-*s %s %s    %s %s\n",
				col1, styleKeyDesc.Render("Packets:"),
				styleUp.Render("▼"), styleVal.Render(detail.PktsIn+" in"),
				styleKey.Render("▲"), styleVal.Render(detail.PktsOut+" out"),
			))
			sb.WriteString(fmt.Sprintf("  %-*s %s %s    %s %s\n",
				col1, styleKeyDesc.Render("Data:"),
				styleUp.Render("▼"), styleVal.Render(detail.BytesIn+" in"),
				styleKey.Render("▲"), styleVal.Render(detail.BytesOut+" out"),
			))
		}
	}

	// ── Wrap in bordered panel ──────────────────────────────────
	content := sb.String()

	var borderStyle lipgloss.Style
	if isActive {
		if side == sideA {
			borderStyle = stylePanelBorderDevice.Width(width)
		} else {
			borderStyle = stylePanelBorderSwitch.Width(width)
		}
	} else {
		borderStyle = stylePanelBorder.Width(width)
	}

	return borderStyle.Render(content)
}

// trunc truncates a string to a given length.
func trunc(s string, length int) string {
	runes := []rune(s)
	if len(runes) > length {
		return string(runes[:length-1]) + "…"
	}
	return s
}
