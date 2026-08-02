package tui

import tea "github.com/charmbracelet/bubbletea"

type cellRect struct {
	X      int
	Y      int
	Width  int
	Height int
}

func (r cellRect) contains(x, y int) bool {
	return r.Width > 0 &&
		r.Height > 0 &&
		x >= r.X &&
		x < r.X+r.Width &&
		y >= r.Y &&
		y < r.Y+r.Height
}

type workspaceTabCell struct {
	Workspace workspace
	Label     string
	Rect      cellRect
}

type paneCell struct {
	Card cardFocus
	Rect cellRect
}

type workbenchLayoutMode int

const (
	layoutMaximized workbenchLayoutMode = iota
	layoutNarrow
	layoutMedium
	layoutDesktop
)

type workbenchGeometry struct {
	TerminalCols int
	ContentWidth int
	Margin       int
	Height       int
	MainHeight   int
	MainY        int
	Mode         workbenchLayoutMode
	Tabs         []workspaceTabCell
	Panes        []paneCell
}

func visibleSelectionStart(selectedRow, totalRows, availableRows int) int {
	if availableRows <= 0 || totalRows <= availableRows {
		return 0
	}
	if selectedRow >= availableRows {
		return min(totalRows-availableRows, selectedRow-availableRows+1)
	}
	return 0
}

func workspaceTabRows(width int) [][]workspaceTabCell {
	if width <= 0 {
		return nil
	}
	rows := make([][]workspaceTabCell, 1)
	x := 0
	for _, candidate := range workspaces {
		label := " " + workspaceShortcutLabel(candidate) + " " + string(candidate) + " "
		cellWidth := len([]rune(label))
		if x > 0 && x+cellWidth > width {
			rows = append(rows, nil)
			x = 0
		}
		row := len(rows) - 1
		rows[row] = append(rows[row], workspaceTabCell{
			Workspace: candidate,
			Label:     label,
			Rect: cellRect{
				X:      x,
				Y:      row,
				Width:  min(cellWidth, width),
				Height: 1,
			},
		})
		x += cellWidth + 1
	}
	return rows
}

func (m Model) workbenchGeometry() workbenchGeometry {
	terminalCols := terminalWidth(m.width)
	width := renderWidth(terminalCols)
	margin := horizontalMargin(terminalCols)
	height := renderHeight(terminalHeight(m.height))
	tabRows := workspaceTabRows(width)
	tabHeight := max(1, len(tabRows))
	mainY := 1 + tabHeight
	mainHeight := max(4, mainAreaHeight(height, 1)-1-tabHeight)

	geometry := workbenchGeometry{
		TerminalCols: terminalCols,
		ContentWidth: width,
		Margin:       margin,
		Height:       height,
		MainHeight:   mainHeight,
		MainY:        mainY,
	}
	for _, row := range tabRows {
		for _, tab := range row {
			tab.Rect.X += margin
			tab.Rect.Y++
			geometry.Tabs = append(geometry.Tabs, tab)
		}
	}

	mainWorkspace := m.workspace == workspaceMain
	cliHeight := 0
	if mainWorkspace {
		cliHeight = clamp(mainHeight/4, 4, 8)
		if mainHeight-cliHeight < 4 {
			cliHeight = max(4, mainHeight-4)
		}
	}
	outputHeight := max(4, mainHeight-cliHeight)
	inspectorVisible := m.workspaceInspectorVisible()
	addPane := func(card cardFocus, x, y, paneWidth, paneHeight int) {
		geometry.Panes = append(geometry.Panes, paneCell{
			Card: card,
			Rect: cellRect{
				X:      margin + x,
				Y:      mainY + y,
				Width:  paneWidth,
				Height: paneHeight,
			},
		})
	}

	switch {
	case m.maximized:
		geometry.Mode = layoutMaximized
		card := m.activeCard
		if !m.cardVisible(card) {
			card = cardOutput
		}
		addPane(card, 0, 0, width, mainHeight)
	case terminalCols < 80:
		geometry.Mode = layoutNarrow
		drawerHeight := 0
		if inspectorVisible {
			drawerHeight = max(4, mainHeight/2)
		}
		primaryHeight := max(4, mainHeight-drawerHeight)
		addPane(cardOutput, 0, 0, width, max(4, primaryHeight-cliHeight))
		if mainWorkspace {
			addPane(cardCLI, 0, primaryHeight-cliHeight, width, cliHeight)
		}
		if drawerHeight > 0 {
			addPane(cardInspector, 0, primaryHeight, width, drawerHeight)
		}
	case terminalCols < 120:
		geometry.Mode = layoutMedium
		primaryHeight := max(4, mainHeight*2/3)
		if !inspectorVisible {
			primaryHeight = mainHeight
		}
		secondaryHeight := max(4, mainHeight-primaryHeight)
		mediumOutputHeight := max(4, primaryHeight-cliHeight)
		addPane(cardOutput, 0, 0, width, mediumOutputHeight)
		if mainWorkspace {
			addPane(cardCLI, 0, mediumOutputHeight, width, cliHeight)
		}
		if inspectorVisible {
			addPane(cardInspector, 0, primaryHeight, width, secondaryHeight)
		}
	default:
		geometry.Mode = layoutDesktop
		if !inspectorVisible {
			addPane(cardOutput, 0, 0, width, outputHeight)
			if mainWorkspace {
				addPane(cardCLI, 0, outputHeight, width, cliHeight)
			}
			break
		}
		primaryWidth := max(1, (width-1)*55/100)
		inspectorWidth := max(1, width-1-primaryWidth)
		addPane(cardOutput, 0, 0, primaryWidth, mainHeight)
		x := primaryWidth + 1
		addPane(cardInspector, x, 0, inspectorWidth, mainHeight)
	}

	return geometry
}

func (m *Model) updateWorkbenchMouse(msg tea.MouseMsg) tea.Cmd {
	event := tea.MouseEvent(msg)
	geometry := m.workbenchGeometry()

	for _, tab := range geometry.Tabs {
		if !tab.Rect.contains(event.X, event.Y) {
			continue
		}
		if event.Action == tea.MouseActionPress && event.Button == tea.MouseButtonLeft {
			m.selectWorkspace(tab.Workspace)
			m.maximized = false
		}
		return nil
	}

	for _, pane := range geometry.Panes {
		if !pane.Rect.contains(event.X, event.Y) {
			continue
		}
		m.activeCard = pane.Card
		switch event.Button {
		case tea.MouseButtonWheelUp:
			m.handleVerticalMove(-1)
		case tea.MouseButtonWheelDown:
			m.handleVerticalMove(1)
		case tea.MouseButtonLeft:
			if event.Action == tea.MouseActionPress {
				command, handledControl := m.selectWorkspacePaneRow(pane, event.X, event.Y)
				if !handledControl {
					m.maximized = true
				}
				return command
			}
		}
		return nil
	}
	return nil
}

func (m *Model) selectWorkspacePaneRow(pane paneCell, mouseX, mouseY int) (tea.Cmd, bool) {
	contentRow := mouseY - pane.Rect.Y - 1
	if contentRow < 0 {
		return nil, false
	}
	contentColumn := mouseX - pane.Rect.X - 1
	available := max(1, pane.Rect.Height-3)
	switch {
	case m.workspace == workspaceNetwork && pane.Card == cardOutput:
		if contentRow == 0 {
			devices := m.networkDevices()
			allCount := 0
			if m.networkTracker != nil {
				allCount = len(m.networkTracker.Snapshot().Devices)
			}
			if button, ok := textButtonAt(m.networkButtonBar(len(devices), allCount), contentColumn); ok {
				m.networkFilter = networkCategoryForButton(button.ID)
				m.ensureNetworkSelection()
				return nil, true
			}
		}
		devices := m.networkDevices()
		selectedItem := 0
		for index, device := range devices {
			if device.Key == m.selectedNetworkDevice {
				selectedItem = index
				break
			}
		}
		listAvailable := max(1, available-2)
		start := visibleSelectionStart(selectedItem, len(devices), listAvailable)
		itemIndex := start + contentRow - 2
		if itemIndex >= 0 && itemIndex < len(devices) {
			m.selectedNetworkDevice = devices[itemIndex].Key
		}
	case m.workspace == workspaceNetwork && pane.Card == cardInspector:
		if contentRow >= 7 && contentRow < 7+len(networkCategories) {
			m.networkSection = contentRow - 6
			m.toggleNetworkSection()
			return nil, true
		}
	case m.workspace == workspaceRules && pane.Card == cardOutput:
		rules, _ := m.activeRules()
		index := contentRow - 1
		if index >= 0 && index < len(rules) {
			m.selectedRuleID = rules[index].ID
		}
	}
	return nil, false
}

func (m *Model) updateHelpMouse(msg tea.MouseMsg) {
	event := tea.MouseEvent(msg)
	switch event.Button {
	case tea.MouseButtonWheelUp:
		m.help.scroll = max(0, m.help.scroll-1)
	case tea.MouseButtonWheelDown:
		m.help.scroll++
	case tea.MouseButtonLeft:
		if event.Action != tea.MouseActionPress || event.Y < 1 || event.Y >= terminalHeight(m.height)-1 {
			return
		}
		document := helpTreeDocument(m.help)
		available := max(1, terminalHeight(m.height)-2)
		start := clamp(m.help.scroll, 0, max(0, len(document)-available))
		index := start + event.Y - 1
		if index < 0 || index >= len(document) || !document[index].Selectable {
			return
		}
		m.help.selected = document[index].ID
		m.toggleHelpSelection()
	}
}
