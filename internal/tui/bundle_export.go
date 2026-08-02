package tui

import (
	"context"
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	workproject "golan/internal/project"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

type bundleExportView int

const (
	bundleExportPath bundleExportView = iota
	bundleExportKind
	bundleExportCaptures
	bundleExportReport
)

const bundleExportOperation = "bundle export"

var bundleKinds = []workproject.BundleKind{
	workproject.BundleFull,
	workproject.BundleMetadata,
	workproject.BundleSanitized,
}

type bundleExportState struct {
	open        bool
	view        bundleExportView
	input       string
	destination string
	kindCursor  int
	cursor      int
	selected    map[string]bool
	report      workproject.BundleReport
	err         string
}

func (m *Model) openBundleExport() {
	if m.project == nil {
		m.print("project err: no active project")
		return
	}
	name := strings.TrimSuffix(filepath.Base(m.project.Path()), filepath.Ext(m.project.Path()))
	destination := filepath.Join(m.project.Path(), "exports", name+".golanproj")
	m.bundleExport = bundleExportState{open: true, view: bundleExportPath, input: destination}
}

func (m Model) updateBundleExport(key tea.KeyMsg) (tea.Model, tea.Cmd) {
	name := key.String()
	if name == "ctrl+c" {
		return m, tea.Quit
	}
	if m.runtimeOperation == bundleExportOperation {
		return m, nil
	}
	if name == "?" {
		m.openHelp()
		return m, nil
	}
	if m.bundleExport.view == bundleExportPath {
		return m.updateBundleExportPath(key)
	}
	switch name {
	case "esc":
		switch m.bundleExport.view {
		case bundleExportKind:
			m.bundleExport.view = bundleExportPath
		case bundleExportCaptures:
			m.bundleExport.view = bundleExportKind
		case bundleExportReport:
			m.bundleExport = bundleExportState{}
		default:
			m.bundleExport = bundleExportState{}
		}
		m.bundleExport.err = ""
	case "up", "k":
		m.moveBundleExportCursor(-1)
	case "down", "j":
		m.moveBundleExportCursor(1)
	case " ":
		if m.bundleExport.view == bundleExportCaptures {
			m.toggleBundleCapture()
		}
	case "a":
		if m.bundleExport.view == bundleExportCaptures {
			m.selectAllBundleCaptures(true)
		}
	case "n":
		if m.bundleExport.view == bundleExportCaptures {
			m.selectAllBundleCaptures(false)
		}
	case "enter":
		return m.selectBundleExportItem()
	}
	return m, nil
}

func (m Model) updateBundleExportPath(key tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch key.String() {
	case "esc":
		m.bundleExport = bundleExportState{}
	case "enter":
		destination := strings.TrimSpace(m.bundleExport.input)
		if !strings.EqualFold(filepath.Ext(destination), ".golanproj") {
			m.bundleExport.err = "Bundle destination must use .golanproj."
			return m, nil
		}
		m.bundleExport.destination = destination
		m.bundleExport.view = bundleExportKind
		m.bundleExport.err = ""
	case "backspace", "ctrl+h":
		m.bundleExport.input = trimLastRune(m.bundleExport.input)
		m.bundleExport.err = ""
	case "ctrl+u":
		m.bundleExport.input = ""
		m.bundleExport.err = ""
	default:
		if len(m.bundleExport.input) < 8192 {
			m.bundleExport.input = appendInput(m.bundleExport.input, key)
		}
	}
	return m, nil
}

func (m *Model) moveBundleExportCursor(delta int) {
	switch m.bundleExport.view {
	case bundleExportKind:
		m.bundleExport.kindCursor = (m.bundleExport.kindCursor + delta + len(bundleKinds)) % len(bundleKinds)
	case bundleExportCaptures:
		count := len(m.project.Manifest().Captures)
		if count > 0 {
			m.bundleExport.cursor = (m.bundleExport.cursor + delta + count) % count
		}
	}
	m.bundleExport.err = ""
}

func (m *Model) toggleBundleCapture() {
	captures := m.project.Manifest().Captures
	if len(captures) == 0 {
		return
	}
	index := clamp(m.bundleExport.cursor, 0, len(captures)-1)
	id := captures[index].ID
	m.bundleExport.selected[id] = !m.bundleExport.selected[id]
}

func (m *Model) selectAllBundleCaptures(selected bool) {
	for _, capture := range m.project.Manifest().Captures {
		m.bundleExport.selected[capture.ID] = selected
	}
}

func (m Model) selectBundleExportItem() (tea.Model, tea.Cmd) {
	switch m.bundleExport.view {
	case bundleExportKind:
		kind := bundleKinds[clamp(m.bundleExport.kindCursor, 0, len(bundleKinds)-1)]
		if kind == workproject.BundleFull {
			m.bundleExport.view = bundleExportCaptures
			m.bundleExport.cursor = 0
			m.bundleExport.selected = make(map[string]bool)
			m.selectAllBundleCaptures(true)
			return m, nil
		}
		return m, m.startBundleExport(m.bundleExport.destination, kind, nil, true)
	case bundleExportCaptures:
		ids := make([]string, 0, len(m.bundleExport.selected))
		for id, selected := range m.bundleExport.selected {
			if selected {
				ids = append(ids, id)
			}
		}
		sort.Strings(ids)
		return m, m.startBundleExport(m.bundleExport.destination, workproject.BundleFull, ids, true)
	case bundleExportReport:
		m.bundleExport = bundleExportState{}
	}
	return m, nil
}

func (m *Model) startBundleExport(destination string, kind workproject.BundleKind, captureIDs []string, showReport bool) tea.Cmd {
	if m.project == nil {
		m.print("project err: no active project")
		return nil
	}
	if pending := m.pendingRuntimeOperation(); pending != "" {
		m.print("project err: cannot export bundle while " + pending)
		return nil
	}
	project := m.project
	options := workproject.BundleOptions{Kind: kind, CaptureIDs: captureIDs}
	m.beginRuntimeOperation(bundleExportOperation)
	if showReport {
		m.bundleExport.err = ""
	}
	return m.trackEffect(func() tea.Msg {
		report, err := project.ExportBundleWithOptions(context.Background(), destination, options)
		return bundleExportMsg{project: project, destination: destination, report: report, showReport: showReport, err: err}
	})
}

func (m *Model) applyBundleExport(msg bundleExportMsg) {
	m.clearRuntimeOperation(bundleExportOperation)
	if msg.err != nil {
		m.print("project err: export bundle " + msg.err.Error())
		if msg.showReport && m.bundleExport.open {
			m.bundleExport.err = msg.err.Error()
		}
		return
	}
	m.print("project: bundle exported " + msg.destination)
	m.printBundleReport("export", msg.report)
	if msg.showReport && msg.project == m.project && m.bundleExport.open {
		m.bundleExport.view = bundleExportReport
		m.bundleExport.report = msg.report
		m.bundleExport.err = ""
	}
}

func (m *Model) printBundleReport(action string, report workproject.BundleReport) {
	m.print(fmt.Sprintf(
		"project: bundle %s report kind=%s files=%d bytes=%d captures-included=%d/%d omitted=%d",
		action, report.Kind, report.Files, report.Bytes, len(report.IncludedCaptures), report.SourceCaptures,
		len(report.OmittedCaptures),
	))
	if len(report.IncludedCaptures) > 0 {
		m.print("project: bundle included capture ids=" + strings.Join(report.IncludedCaptures, ","))
	}
	if len(report.OmittedCaptures) > 0 {
		m.print("project: bundle omitted capture ids=" + strings.Join(report.OmittedCaptures, ","))
	}
}

func (m Model) renderBundleExport() string {
	terminalCols := terminalWidth(m.width)
	width := renderWidth(terminalCols)
	height := renderHeight(terminalHeight(m.height))
	margin := horizontalMargin(terminalCols)
	title, rows := m.bundleExportRows()
	if m.runtimeOperation == bundleExportOperation {
		rows = append(rows, "", styleWarn.Render("Hashing and writing selected evidence…"))
	}
	if m.bundleExport.err != "" {
		rows = append(rows, "", styleError.Render(m.bundleExport.err))
	}
	footer := " ↑/↓ or j/k move   Space toggle   a all   n none   Enter continue   Esc back   F1 help "
	content := box(title, rows, width, max(4, height-1), true)
	view := lipgloss.JoinVertical(lipgloss.Left, content, styleFooterBar.Render(fit(footer, width)))
	return insetBlock(clampBlock(view, width, height), margin)
}

func (m Model) bundleExportRows() (string, []string) {
	switch m.bundleExport.view {
	case bundleExportPath:
		cursor := " "
		if m.cursorVisible {
			cursor = "|"
		}
		return "EXPORT PORTABLE BUNDLE", []string{
			"Choose a new .golanproj destination. Existing files are never overwritten.",
			"",
			"Destination",
			styleText.Render("> " + m.bundleExport.input + cursor),
		}
	case bundleExportKind:
		rows := []string{"Choose how much project evidence to include.", ""}
		descriptions := []string{
			"Full — choose which managed live-session captures to include",
			"Metadata — omit capture bytes but retain their fingerprints",
			"Sanitized — sharing-oriented metadata without detailed evidence files",
		}
		for index, description := range descriptions {
			rows = append(rows, startupCursorRow(index == m.bundleExport.kindCursor, description, false))
		}
		return "BUNDLE EVIDENCE LEVEL", rows
	case bundleExportCaptures:
		captures := m.project.Manifest().Captures
		selected := 0
		for _, capture := range captures {
			if m.bundleExport.selected[capture.ID] {
				selected++
			}
		}
		rows := []string{fmt.Sprintf("Choose immutable evidence: %d of %d selected.", selected, len(captures)), "Space toggles; a selects all; n selects none; Enter exports.", ""}
		start, end := bundleCaptureWindow(m.bundleExport.cursor, len(captures), 12)
		if start > 0 {
			rows = append(rows, styleMuted.Render(fmt.Sprintf("… %d earlier captures", start)))
		}
		for index := start; index < end; index++ {
			capture := captures[index]
			mark := "[ ]"
			if m.bundleExport.selected[capture.ID] {
				mark = "[x]"
			}
			label := fmt.Sprintf("%s %s  %s  %s", mark, capture.ID, capture.Name, capture.Mode)
			rows = append(rows, startupCursorRow(index == m.bundleExport.cursor, label, false))
		}
		if end < len(captures) {
			rows = append(rows, styleMuted.Render(fmt.Sprintf("… %d later captures", len(captures)-end)))
		}
		if len(captures) == 0 {
			rows = append(rows, "No indexed captures. Enter creates a full bundle without capture evidence.")
		}
		return "SELECT BUNDLE CAPTURES", rows
	case bundleExportReport:
		report := m.bundleExport.report
		rows := []string{
			styleSuccess.Render("Bundle exported and checksum inventory finalized."),
			"",
			"Destination  " + m.bundleExport.destination,
			fmt.Sprintf("Kind         %s", report.Kind),
			fmt.Sprintf("Payload      %d files · %s", report.Files, bundleByteCount(report.Bytes)),
			fmt.Sprintf("Captures     %d included · %d omitted · %d source", len(report.IncludedCaptures), len(report.OmittedCaptures), report.SourceCaptures),
		}
		if len(report.IncludedCaptures) > 0 {
			rows = append(rows, "", "Included  "+strings.Join(report.IncludedCaptures, ", "))
		}
		if len(report.OmittedCaptures) > 0 {
			rows = append(rows, "Omitted   "+strings.Join(report.OmittedCaptures, ", "))
		}
		rows = append(rows, "", "Enter or Esc closes this report.")
		return "BUNDLE EXPORT REPORT", rows
	default:
		return "EXPORT PORTABLE BUNDLE", nil
	}
}

func bundleCaptureWindow(cursor, count, limit int) (int, int) {
	if count <= limit {
		return 0, count
	}
	start := clamp(cursor-limit/2, 0, count-limit)
	return start, start + limit
}

func bundleByteCount(bytes int64) string {
	const (
		kib = 1 << 10
		mib = 1 << 20
		gib = 1 << 30
	)
	switch {
	case bytes >= gib:
		return fmt.Sprintf("%.2f GiB", float64(bytes)/gib)
	case bytes >= mib:
		return fmt.Sprintf("%.2f MiB", float64(bytes)/mib)
	case bytes >= kib:
		return fmt.Sprintf("%.2f KiB", float64(bytes)/kib)
	default:
		return fmt.Sprintf("%d B", bytes)
	}
}
