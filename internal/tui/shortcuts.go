package tui

type workbenchShortcutID string

const (
	shortcutPanePrevious      workbenchShortcutID = "pane-previous"
	shortcutPaneNext          workbenchShortcutID = "pane-next"
	shortcutWorkspacePrevious workbenchShortcutID = "workspace-previous"
	shortcutWorkspaceNext     workbenchShortcutID = "workspace-next"
	shortcutPaneMaximize      workbenchShortcutID = "pane-maximize"
	shortcutInspectorToggle   workbenchShortcutID = "inspector-toggle"
	shortcutCommandPalette    workbenchShortcutID = "command-palette"
)

type workbenchShortcut struct {
	ID          workbenchShortcutID
	Key         string
	Label       string
	Topic       string
	Description string
}

type workspaceShortcut struct {
	Workspace workspace
	Key       string
	Label     string
}

// workspaceShortcuts gives every Workbench page a visible, direct binding.
// F1 remains reserved for Help; the three product workspaces occupy F2-F4 in
// the same order as the tab strip.
var workspaceShortcuts = []workspaceShortcut{
	{Workspace: workspaceMain, Key: "f2", Label: "F2"},
	{Workspace: workspaceNetwork, Key: "f3", Label: "F3"},
	{Workspace: workspaceRules, Key: "f4", Label: "F4"},
}

// workbenchShortcuts is the single source of truth for global Workbench
// navigation. Bindings use function, Control, Shift, and arrow keys that
// macOS terminals report directly; Option is deliberately excluded because
// it commonly composes printable Unicode text instead of a modifier chord.
// Printable, workspace-specific actions remain contextual and are only active
// while a non-CLI pane has focus.
var workbenchShortcuts = []workbenchShortcut{
	{
		ID:          shortcutPanePrevious,
		Key:         "shift+left",
		Label:       "Shift+←",
		Topic:       "Previous pane",
		Description: "Focus the previous visible pane",
	},
	{
		ID:          shortcutPaneNext,
		Key:         "shift+right",
		Label:       "Shift+→",
		Topic:       "Next pane",
		Description: "Focus the next visible pane",
	},
	{
		ID:          shortcutWorkspacePrevious,
		Key:         "ctrl+shift+left",
		Label:       "Ctrl+Shift+←",
		Topic:       "Previous workspace",
		Description: "Switch to the previous workspace",
	},
	{
		ID:          shortcutWorkspaceNext,
		Key:         "ctrl+shift+right",
		Label:       "Ctrl+Shift+→",
		Topic:       "Next workspace",
		Description: "Switch to the next workspace",
	},
	{
		ID:          shortcutPaneMaximize,
		Key:         "ctrl+shift+up",
		Label:       "Ctrl+Shift+↑",
		Topic:       "Pane maximize",
		Description: "Maximize or restore the focused pane",
	},
	{
		ID:          shortcutInspectorToggle,
		Key:         "ctrl+t",
		Label:       "Ctrl+T",
		Topic:       "Inspector",
		Description: "Show or hide the synchronized workspace inspector",
	},
	{
		ID:          shortcutCommandPalette,
		Key:         "ctrl+p",
		Label:       "Ctrl+P",
		Topic:       "Command palette",
		Description: "Fuzzily find a documented command and stage it in the CLI without running it",
	},
}

func workbenchShortcutForKey(key string) (workbenchShortcutID, bool) {
	for _, shortcut := range workbenchShortcuts {
		if shortcut.Key == key {
			return shortcut.ID, true
		}
	}
	return "", false
}

func workbenchShortcutLabels(ids ...workbenchShortcutID) []string {
	labels := make([]string, 0, len(ids))
	for _, id := range ids {
		for _, shortcut := range workbenchShortcuts {
			if shortcut.ID == id {
				labels = append(labels, shortcut.Label)
				break
			}
		}
	}
	return labels
}

func workbenchShortcutLabel(id workbenchShortcutID) string {
	labels := workbenchShortcutLabels(id)
	if len(labels) == 0 {
		return ""
	}
	return labels[0]
}

func workspaceShortcutForKey(key string) (workspace, bool) {
	for _, shortcut := range workspaceShortcuts {
		if shortcut.Key == key {
			return shortcut.Workspace, true
		}
	}
	return "", false
}

func workspaceShortcutLabel(target workspace) string {
	for _, shortcut := range workspaceShortcuts {
		if shortcut.Workspace == target {
			return shortcut.Label
		}
	}
	return ""
}

func workspaceShortcutLabels() []string {
	labels := make([]string, 0, len(workspaceShortcuts))
	for _, shortcut := range workspaceShortcuts {
		labels = append(labels, shortcut.Label+" "+string(shortcut.Workspace))
	}
	return labels
}
