package tui

import (
	"fmt"
	"sort"
	"strings"
)

type helpEntry struct {
	Topic       string
	Command     string
	Description string
	Details     []string
	Keys        []string
	Workspaces  []workspace
	Category    string
	Group       string
}

var helpRegistry = []helpEntry{
	{Topic: "Start here", Description: "Open one category, then one group, then one topic; detail stays hidden until you ask for it.", Details: []string{"Enter or Right opens the selected branch. Left closes it. The selected topic always shows what it does, its binds, exact command syntax, and where it applies."}, Keys: []string{"F1", "Enter", "Left/Right"}, Category: "Start here", Group: "Basics"},
	{Topic: "Search this manual", Description: "Search topic names, explanations, commands, binds, details, categories, and workspace contexts.", Details: []string{"Press / and type. Enter ends typing. n and N move through results. Esc first clears a search, then closes Help."}, Keys: []string{"/", "n/N", "Esc"}, Category: "Start here", Group: "Basics"},
	{Topic: "CLI help reference", Command: "help | ?", Description: "Print the complete categorized manual into Main Output using neutral help styling.", Details: []string{"The printed reference is deliberately isolated from runtime token colors, so command words never look like statuses and no command family is accidentally muted."}, Workspaces: []workspace{workspaceMain}, Category: "Start here", Group: "Basics"},
	{Topic: "Command palette", Description: "Fuzzily find documented commands, then stage the chosen command in Main's CLI without executing it.", Details: []string{"Type to filter; Up/Down, Page Up/Page Down, Home, and End navigate. Enter stages. Esc or Ctrl+P cancels."}, Keys: append(workbenchShortcutLabels(shortcutCommandPalette), "Up/Down", "Enter", "Esc"), Category: "Start here", Group: "Basics"},
	{Topic: "Workspace map", Description: "Main owns Output and CLI. Network owns devices and observations. Rules owns typed rules and diagnostics.", Details: []string{"Main contains the only CLI. Canvas, Doctor, Health, Settings, and project operations are guided surfaces or Main commands; they never become extra workspaces."}, Keys: workspaceShortcutLabels(), Category: "Start here", Group: "Layout"},
	{Topic: "Startup chooser", Description: "Choose a recent project, create or open a project, load saved setup, enter offline work, or begin a guided live session.", Details: []string{"Up/Down selects, Enter opens the next choice, Esc goes back or closes, and ? opens this manual. Text prompts also support Backspace/Ctrl+H and Ctrl+U."}, Keys: []string{"Up/Down or j/k", "Enter", "Esc", "?", "Backspace/Ctrl+H", "Ctrl+U"}, Category: "Start here", Group: "Startup"},
	{Topic: "Guided live startup", Description: "Choose the live mode, required adapter or adapter pair, then review the complete plan before starting.", Details: []string{"Selection itself does not mutate the host. The final review still passes through platform, privilege, adapter, role, and runtime safety validation."}, Keys: []string{"Up/Down or j/k", "Enter", "Esc", "?"}, Category: "Start here", Group: "Startup"},

	{Topic: "Pane focus", Description: "Move to the previous or next visible pane without changing workspace.", Details: []string{"Esc unfocuses the current pane and returns to the all-pane overview. Esc does nothing from overview and never opens the CLI."}, Keys: append(workbenchShortcutLabels(shortcutPanePrevious, shortcutPaneNext), "Esc"), Category: "Navigation", Group: "Panes"},
	{Topic: "Workspace navigation", Description: "Open Main, Network, or Rules directly, or cycle workspaces while retaining a sensible pane focus.", Keys: append(workbenchShortcutLabels(shortcutWorkspacePrevious, shortcutWorkspaceNext), workspaceShortcutLabels()...), Category: "Navigation", Group: "Workspaces"},
	{Topic: "Maximize pane", Description: "Toggle the focused pane between its normal layout and a full-workspace view.", Details: []string{"The bind does nothing from overview because there is no focused pane to maximize."}, Keys: workbenchShortcutLabels(shortcutPaneMaximize), Category: "Navigation", Group: "Panes"},
	{Topic: "Inspector visibility", Description: "Show or hide the synchronized Network or Rules Inspector.", Details: []string{"Main has no Inspector. Hiding an Inspector returns focus to the remaining workspace pane."}, Keys: workbenchShortcutLabels(shortcutInspectorToggle), Category: "Navigation", Group: "Panes"},
	{Topic: "Mouse navigation", Description: "Click panes and rows to focus or select them; click an already focused pane header to maximize or restore it.", Details: []string{"The wheel scrolls the pane or guided list under the pointer. Hidden panes are never mouse targets."}, Keys: []string{"Click", "Wheel"}, Category: "Navigation", Group: "Mouse"},
	{Topic: "Main CLI editing", Description: "Type commands only in Main's CLI; printable input from Main overview focuses the CLI, while Network and Rules remain selection-first.", Details: []string{"Enter runs, Tab completes, Up/Down walks history, Backspace or Ctrl+H deletes, and Ctrl+U clears the line."}, Keys: []string{"Enter", "Tab", "Up/Down", "Backspace/Ctrl+H", "Ctrl+U"}, Workspaces: []workspace{workspaceMain}, Category: "Navigation", Group: "CLI"},
	{Topic: "Main Output scrolling", Description: "Scroll older or newer Main command output while Output has focus.", Details: []string{"New output returns the pane to its newest rows. Clear removes Output; Esc only unfocuses the pane."}, Keys: []string{"Up/Down", "Wheel"}, Workspaces: []workspace{workspaceMain}, Category: "Navigation", Group: "Panes"},
	{Topic: "Help navigation keys", Description: "Navigate the manual with arrows or familiar letter keys while retaining progressive disclosure.", Details: []string{"Up/Down or j/k selects; Enter or Space toggles; Right or l opens/descends; Left or h closes/ascends; Page Up/Page Down or Ctrl+U/Ctrl+D pages; Home/End jumps; q, ?, F1, or Esc closes when no search needs clearing."}, Keys: []string{"Up/Down or j/k", "Enter/Space", "Left/Right or h/l", "PgUp/PgDn", "Ctrl+U/Ctrl+D", "Home/End", "q/?/F1/Esc"}, Category: "Navigation", Group: "Help"},
	{Topic: "macOS modifier safety", Description: "goLAN intentionally has no Option or Alt bindings because macOS terminals may turn those chords into printable characters.", Details: []string{"Use function keys, Control, Shift, arrows, and the visible contextual single-key actions instead."}, Category: "Navigation", Group: "Keys"},

	{Topic: "Doctor", Command: "doctor", Description: "Run bounded read-only environment, project, adapter, route, PF, DHCP-plan, and restoration checks in Main Output.", Details: []string{"PASS, WARN, FAIL, and SKIP are labeled and colored. Wrapped details use a hanging indent after the status badge. Doctor never changes networking."}, Workspaces: []workspace{workspaceMain}, Category: "Main", Group: "Status"},
	{Topic: "Health", Command: "show health", Description: "Print a payload-free runtime and cleanup summary, including ownership, queues, packets, and project-session state.", Details: []string{"Use this when a stop failed or before deciding whether a live mode is still active."}, Workspaces: []workspace{workspaceMain}, Category: "Main", Group: "Status"},
	{Topic: "Adapter inventory", Command: "show adapters", Description: "List discovered macOS adapters, link state, service mapping, and staged role context.", Workspaces: []workspace{workspaceMain}, Category: "Main", Group: "Status"},
	{Topic: "Configuration summary", Command: "show config", Description: "Print the staged adapter and bridge configuration that a future live start will validate and apply.", Workspaces: []workspace{workspaceMain}, Category: "Main", Group: "Status"},
	{Topic: "Runtime summaries", Command: "show bridge | show takeover | show edge", Description: "Inspect the selected live runtime, including controlled-bridge state where applicable.", Details: []string{"These commands report state only; start and stop own lifecycle changes."}, Workspaces: []workspace{workspaceMain}, Category: "Main", Group: "Status"},
	{Topic: "Captured evidence paths", Command: "show captures [session-id]", Description: "Print automatically saved PCAP paths for the current or selected Network session.", Details: []string{"goLAN shows and bundles its own capture output but does not import, replay, inspect, or derive packet timelines from PCAP files."}, Workspaces: []workspace{workspaceMain, workspaceNetwork}, Category: "Main", Group: "Status"},

	{Topic: "Transactional settings", Command: "settings", Description: "Open a staged editor for session, addressing, policy, privacy, and performance values.", Details: []string{"Nothing changes until Ctrl+S validates and commits the whole draft. Esc cancels exactly. Ctrl+R restores the opening snapshot."}, Keys: []string{"s in Main", "Up/Down", "Left/Right", "Enter", "Ctrl+R", "Ctrl+S", "Esc"}, Workspaces: []workspace{workspaceMain}, Category: "Main", Group: "Setup"},
	{Topic: "Select configuration context", Command: "conf <adapter|bridge>", Description: "Choose which staged adapter or bridge profile later set commands edit.", Details: []string{"Selecting context does not bring an interface up and does not begin capture."}, Workspaces: []workspace{workspaceMain}, Category: "Main", Group: "Setup"},
	{Topic: "Set staged values", Command: "set <property> <value> | set adapter <name> [host|switch] | set bridge queue-depth|overload <value> | set edge mode|upstream|port-forward ...", Description: "Stage adapter, bridge, and Edge values with command completion and validation.", Details: []string{"Use settings for the guided transaction or set for direct command-first staging. Live mutation still waits for an explicit start."}, Workspaces: []workspace{workspaceMain}, Category: "Main", Group: "Setup"},
	{Topic: "Remove staged adapter", Command: "unset adapter <name>", Description: "Remove one adapter from the staged profile after runtime-safety checks.", Workspaces: []workspace{workspaceMain}, Category: "Main", Group: "Setup"},
	{Topic: "Adapter link state", Command: "up | down", Description: "Request the active adapter link state through the reversible mutation boundary.", Details: []string{"This requires macOS root privileges and is rejected while conflicting runtime work is active or pending."}, Workspaces: []workspace{workspaceMain}, Category: "Main", Group: "Setup"},
	{Topic: "Refresh adapters", Command: "refresh", Description: "Rediscover adapter metadata after pending isolation and mutation work is clear.", Workspaces: []workspace{workspaceMain}, Category: "Main", Group: "Setup"},
	{Topic: "Load setup", Command: "load [name]", Description: "Restore versioned staged adapter and runtime settings without starting networking.", Details: []string{"Ctrl+S saves the active project when a project is open or enters the guided setup-save flow when no project is active."}, Keys: []string{"Ctrl+S"}, Workspaces: []workspace{workspaceMain}, Category: "Main", Group: "Setup"},
	{Topic: "Clear Output", Command: "clear", Description: "Clear Main Output and its bounded live rule-preview sample; it does not stop a runtime or delete project evidence.", Workspaces: []workspace{workspaceMain}, Category: "Main", Group: "Session"},
	{Topic: "Quit safely", Command: "quit | exit", Description: "Leave the Workbench through shutdown, which stops owned runtimes and retries owned restoration before exit.", Keys: []string{"Ctrl+C"}, Category: "Main", Group: "Session"},

	{Topic: "Device inventory", Description: "Select one directly observed Layer 2 device; repeated facts update counts instead of creating packet rows.", Details: []string{"Wide layouts show MAC, IPs, VLANs, protocols, alerts, and last-seen time. Narrow layouts retain the most identifying columns."}, Keys: []string{"Up/Down", "Wheel"}, Workspaces: []workspace{workspaceNetwork}, Category: "Network", Group: "Observe"},
	{Topic: "Network view", Command: "network show | network filter <all|addressing|dns|http|access|risks|actions> | network search <term|clear> | network reset", Description: "Filter the device inventory, search it, or print its summary without deleting retained observations.", Details: []string{"Reset clears only the view filter and search term; it does not erase a live or saved session."}, Workspaces: []workspace{workspaceNetwork}, Category: "Network", Group: "Observe"},
	{Topic: "Network sessions", Command: "network session list | network session show <id>", Description: "List sanitized sessions in the active project or replace the current Network view with one saved session.", Details: []string{"Loading a saved session clears all transient live secrets because those values are never persisted."}, Workspaces: []workspace{workspaceNetwork}, Category: "Network", Group: "Observe"},
	{Topic: "Device Inspector", Description: "Expand Identity, Addressing, DNS, HTTP, Access, Risks, or Actions for the selected device.", Details: []string{"Only one observation section remains expanded at a time. At most a bounded recent subset is shown; complete packet detail remains in the automatic capture."}, Keys: []string{"Up/Down", "Enter"}, Workspaces: []workspace{workspaceNetwork}, Category: "Network", Group: "Inspector"},
	{Topic: "Addressing observations", Description: "Show strong MAC/IP/VLAN relationships plus useful DHCP and ARP discoveries.", Details: []string{"Discovery values are bounded, normalized, repeat-aggregated, and attached to the directly observed device."}, Workspaces: []workspace{workspaceNetwork}, Category: "Network", Group: "Observation types"},
	{Topic: "DNS observations", Description: "Show readable DNS query names and record types associated with a device.", Details: []string{"This is an observation summary, not a transaction or packet timeline."}, Workspaces: []workspace{workspaceNetwork}, Category: "Network", Group: "Observation types"},
	{Topic: "HTTP observations", Description: "Show plaintext HTTP method, host, query-free path, or response status when readable.", Details: []string{"Query strings and fragments are excluded from saved Network observations."}, Workspaces: []workspace{workspaceNetwork}, Category: "Network", Group: "Observation types"},
	{Topic: "Access observations", Description: "Show EAPOL and MACsec access-state events useful for link-authentication troubleshooting.", Workspaces: []workspace{workspaceNetwork}, Category: "Network", Group: "Observation types"},
	{Topic: "Risk observations", Description: "Show categorical risky-authentication detections such as HTTP Basic, NTLM, cleartext login, SNMP community authentication, or weak EAP methods.", Details: []string{"When a plaintext secret can be extracted, it is redacted by default and is retained only in transient memory for the current live session."}, Workspaces: []workspace{workspaceNetwork}, Category: "Network", Group: "Observation types"},
	{Topic: "Action observations", Description: "Show notable rule outcomes such as block, redirect, edit, or unsupported behavior without creating routine packet rows.", Workspaces: []workspace{workspaceNetwork}, Category: "Network", Group: "Observation types"},

	{Topic: "Listen runtime", Command: "start listen | stop listen", Description: "Start or stop passive multi-adapter observation, shadow rule evaluation, and automatic PCAP saving.", Details: []string{"Listen does not forward packets. Stop finalizes evidence and restores any owned adapter state."}, Workspaces: []workspace{workspaceMain, workspaceNetwork}, Category: "Network", Group: "Runtime"},
	{Topic: "Bridge runtime", Command: "start bridge [fast|controlled] | stop bridge", Description: "Run reversible two-sided forwarding using the fast kernel path or bounded controlled userspace path.", Details: []string{"Fast and controlled modes expose different honest rule capabilities. Controlled overload behavior is visible in Settings and Health."}, Workspaces: []workspace{workspaceMain, workspaceNetwork}, Category: "Network", Group: "Runtime"},
	{Topic: "Takeover runtime", Command: "start takeover | show takeover | stop takeover", Description: "Run the reversible authenticated-identity forwarding path; nat is accepted as a compatibility alias.", Details: []string{"Owned PF state is scoped to goLAN anchors and is restored without flushing unrelated rules."}, Workspaces: []workspace{workspaceMain, workspaceNetwork}, Category: "Network", Group: "Runtime"},
	{Topic: "Edge runtime", Command: "start edge <observe|route> | stop edge", Description: "Run single-adapter passive observation or routed DHCPv4/NAT service with explicit port forwards.", Details: []string{"Route mode validates upstream selection and a conflict-free deterministic lease subnet before mutation."}, Workspaces: []workspace{workspaceMain, workspaceNetwork}, Category: "Network", Group: "Runtime"},
	{Topic: "Stop runtime", Command: "stop listen|bridge|takeover|nat|edge", Description: "Stop exactly one owned live mode, finalize its artifacts, and retry any incomplete restoration.", Details: []string{"If cleanup remains pending, use show health and repeat the matching stop command."}, Workspaces: []workspace{workspaceMain}, Category: "Network", Group: "Runtime"},
	{Topic: "Send EAPOL start", Command: "send eapol start", Description: "Send the explicit EAPOL-Start action through the active compatible runtime.", Details: []string{"The command is rejected when the required link context is absent."}, Workspaces: []workspace{workspaceMain, workspaceNetwork}, Category: "Network", Group: "Runtime"},

	{Topic: "Rules list", Command: "show rules", Description: "Review ordered active rules, LIVE/SHADOW/UNSUPPORTED compatibility, and diagnostics.", Keys: []string{"Up/Down"}, Workspaces: []workspace{workspaceRules}, Category: "Rules", Group: "Review"},
	{Topic: "Guided rule editor", Description: "Create a typed rule through condition, protocol, ports, action, and bounded transformation fields.", Details: []string{"Up/Down selects, Left/Right cycles, Enter edits, a/d adds or removes a condition, ! negates, Shift+Up/Down reorders, Ctrl+S commits, and Esc cancels."}, Keys: []string{"r", "Up/Down", "Left/Right", "Enter", "a/d", "!", "Shift+Up/Down", "Ctrl+S", "Esc"}, Workspaces: []workspace{workspaceRules}, Category: "Rules", Group: "Editing"},
	{Topic: "Replace editor", Description: "Open the focused match-and-replace workflow for bounded length-preserving frame-local edits.", Details: []string{"Semantic stream, DNS-message, HTTP-message, and length-changing edits remain unsupported."}, Keys: []string{"M"}, Workspaces: []workspace{workspaceRules}, Category: "Rules", Group: "Editing"},
	{Topic: "Advanced rule JSON", Description: "Toggle between guided fields and strict typed JSON when a rule can round-trip safely.", Details: []string{"Home/End jumps, o inserts a line, d deletes, Shift+Up/Down reorders, Enter edits, T previews, Ctrl+S commits, and Esc cancels."}, Keys: []string{"Tab", "Home/End", "o", "d", "Shift+Up/Down", "Enter", "T", "Ctrl+S", "Esc"}, Workspaces: []workspace{workspaceRules}, Category: "Rules", Group: "Editing"},
	{Topic: "Live rule preview", Description: "Test the draft against the private bounded in-memory sample collected by the current live runtime.", Details: []string{"Preview never opens a packet file. It reports sample source, matches, compatibility, impacts, and a bounded evidence diff."}, Keys: []string{"T"}, Workspaces: []workspace{workspaceRules}, Category: "Rules", Group: "Preview"},
	{Topic: "Rule lifecycle", Command: "enable rule <id> | disable rule <id> | delete rule <id>", Description: "Create an explicit immutable policy revision that changes one rule's state or removes it.", Workspaces: []workspace{workspaceRules}, Category: "Rules", Group: "Editing"},
	{Topic: "EAPOL policy controls", Command: "enable|disable eapol drop-logoff|macsec-downgrade", Description: "Toggle live EAPOL logoff suppression or MACsec downgrade policy through validated settings.", Workspaces: []workspace{workspaceMain, workspaceRules}, Category: "Rules", Group: "Editing"},
	{Topic: "Policy revisions", Command: "policy use <preset> | policy history | policy compare [from] <to> | policy rollback <revision>", Description: "Activate a preset, inspect immutable history, compare revisions, or create a rollback revision.", Details: []string{"A rollback never rewrites old history; it commits a new active revision from the chosen state."}, Workspaces: []workspace{workspaceRules}, Category: "Rules", Group: "Revisions"},

	{Topic: "Project lifecycle", Command: "project new <name> | project open <directory.golan> | project open-recent <index> | project recent | project save | project save-as <directory.golan>", Description: "Create, open, copy, discover, or save a project without implicitly starting networking.", Keys: []string{"Ctrl+S"}, Workspaces: []workspace{workspaceMain}, Category: "Projects", Group: "Lifecycle"},
	{Topic: "Project close", Command: "project close [save|discard|cancel]", Description: "Close a clean project immediately or resolve unsaved work explicitly.", Details: []string{"Cancel preserves the project. Discard abandons only staged project metadata; it does not delete external capture output."}, Workspaces: []workspace{workspaceMain}, Category: "Projects", Group: "Lifecycle"},
	{Topic: "Project config sources", Command: "project config list|update <source-id>|export <name.json>", Description: "List immutable config snapshots, refresh one source, or export current staged configuration into the project.", Details: []string{"Sensitive profile diffs stay redacted in Output."}, Workspaces: []workspace{workspaceMain}, Category: "Projects", Group: "Evidence"},
	{Topic: "Project journals", Command: "project journals [list|capture]", Description: "List bounded decision journals or attach finalized session decision evidence owned by goLAN.", Workspaces: []workspace{workspaceMain}, Category: "Projects", Group: "Evidence"},
	{Topic: "Project sessions", Command: "project sessions [list|archive <artifact-directory>]", Description: "Review recoverable/stale runtime handoff directories or archive one after explicit selection.", Workspaces: []workspace{workspaceMain}, Category: "Projects", Group: "Recovery"},
	{Topic: "Project recovery", Command: "project recover [capture] attach|archive <capture-path> | project recover policy attach <revision> <path> | project recover policy archive <path> | project recover session <directory>", Description: "Resolve goLAN-owned interrupted-session artifacts through an explicit attach or archive decision.", Details: []string{"Recovery does not import arbitrary packet analysis; it only reconciles artifacts created by goLAN runtimes."}, Workspaces: []workspace{workspaceMain}, Category: "Projects", Group: "Recovery"},
	{Topic: "Project import", Command: "project import config|bundle <path> [name]", Description: "Import a supported goLAN setup config or portable project bundle after validation.", Details: []string{"PCAP files and external capture references are not accepted as Workbench inputs."}, Workspaces: []workspace{workspaceMain}, Category: "Projects", Group: "Portability"},
	{Topic: "Portable bundle", Command: "project export bundle [<destination.golanproj> [metadata|sanitized|full]]", Description: "Use the guided exporter or direct syntax to create a verified portable project bundle.", Details: []string{"Metadata omits observations and captures. Sanitized carries safe observations. Full may include selected automatic captures; transient revealed secrets are never included."}, Keys: []string{"Up/Down", "Space", "a/n", "Enter", "Esc", "?"}, Workspaces: []workspace{workspaceMain}, Category: "Projects", Group: "Portability"},

	{Topic: "Canvas build", Command: "canvas build|rebuild [network-session-id]", Description: "Build deterministic topology only from sanitized current or saved Network observations.", Details: []string{"Build uses the current view when no ID is supplied. Rebuild replaces generated topology while preserving the command-only Canvas product shape."}, Workspaces: []workspace{workspaceMain}, Category: "Canvas", Group: "Build"},
	{Topic: "Canvas layout", Command: "canvas auto-layout | canvas reset-generated confirm", Description: "Arrange generated hosts deterministically or explicitly clear generated placement.", Details: []string{"Reset requires the confirm word to prevent accidental loss of generated layout state."}, Workspaces: []workspace{workspaceMain}, Category: "Canvas", Group: "Layout"},
	{Topic: "Canvas output", Command: "canvas snapshot|export <destination.canvas>", Description: "Write the current Network-derived topology to a validated Canvas destination.", Details: []string{"Canvas never receives transient secrets, raw detector values, or packet payloads."}, Workspaces: []workspace{workspaceMain}, Category: "Canvas", Group: "Export"},

	{Topic: "Settings impacts", Description: "Read right-aligned impact badges before committing a staged value.", Details: []string{"[LIVE] applies without restarting. [RECONFIGURE LINK] requires a safe inactive boundary. [DISRUPTS CONNECTIONS] warns that existing connectivity will be interrupted."}, Workspaces: []workspace{workspaceMain}, Category: "Settings", Group: "Transactions"},
	{Topic: "Settings inventory", Description: "Add or remove Edge port-forward rows inside the same settings transaction.", Details: []string{"Select Port forwards, press a, then enter <tcp|udp> <listen-port> <client-port>. Select a concrete row and press d to remove it."}, Keys: []string{"a", "d", "Enter", "Esc"}, Workspaces: []workspace{workspaceMain}, Category: "Settings", Group: "Transactions"},
	{Topic: "Secret redaction setting", Description: "Toggle Redact observed secrets while keeping redaction on by default.", Details: []string{"The setting is [LIVE]. On renders observed [REDACTED]. Off renders observed [<secret>] only when the current live detector extracted an unambiguous plaintext value."}, Keys: []string{"Left/Right", "Enter", "Ctrl+S"}, Workspaces: []workspace{workspaceMain, workspaceNetwork}, Category: "Settings", Group: "Privacy"},

	{Topic: "Transient secret boundary", Description: "Revealed secrets exist only in bounded memory for the current live Network session.", Details: []string{"They are cleared when sessions or projects change and never enter saved Network sessions, Canvas, project manifests, journals, bundles, or config diffs."}, Category: "Evidence and privacy", Group: "Secrets"},
	{Topic: "Categorical risks", Description: "Protocols without a safely extractable plaintext value remain categorical even when reveal is enabled.", Details: []string{"NTLM, Kerberos, EAP challenges, MSSQL login exchanges, and other opaque material are not decoded into credential stores."}, Category: "Evidence and privacy", Group: "Secrets"},
	{Topic: "TLS and HTTPS", Description: "Encrypted HTTPS/TLS traffic does not create application observations because goLAN cannot read its encrypted contents.", Details: []string{"Use the automatically saved PCAP in an authorized external analyzer when deeper packet work is required."}, Category: "Evidence and privacy", Group: "Traffic"},
	{Topic: "Automatic PCAP boundary", Description: "Live modes save complete packet evidence automatically, while the Workbench remains a readable observation and rule tool.", Details: []string{"There is no PCAP import, replay, file preview, packet filter/export, comparison, annotation, or timeline surface."}, Category: "Evidence and privacy", Group: "Traffic"},

	{Topic: "Privilege boundary", Description: "Live adapter, bridge, route, DHCP, PF, and forwarding changes require macOS root privileges.", Details: []string{"Offline project, help, settings, Rules, and saved Network review remain available without starting networking."}, Category: "Safety", Group: "Runtime"},
	{Topic: "Owned restoration", Description: "Every live mode snapshots before mutation and restores only state it owns in reverse dependency order.", Details: []string{"goLAN never flushes unrelated PF state. Partial cleanup remains visible instead of being silently forgotten."}, Category: "Safety", Group: "Runtime"},
	{Topic: "Cleanup", Description: "Use show health and retry the matching stop command whenever cleanup or restoration remains pending.", Details: []string{"Doctor also reports restoration ownership without mutating it."}, Category: "Safety", Group: "Recovery"},
}

type helpState struct {
	open       bool
	searching  bool
	query      string
	scroll     int
	selected   string
	expanded   map[string]bool
	matches    []string
	matchIndex int
	returnTo   helpReturnState
}

type helpReturnState struct {
	workspace      workspace
	activeCard     cardFocus
	outputScroll   int
	selectedRuleID string
	input          string
	inputMode      inputMode
}

func (m *Model) openHelp() {
	if m.help.open {
		return
	}
	category := helpCategoryID("Start here")
	group := helpGroupID("Start here", "Basics")
	topic := helpTopicID(helpRegistry[0])
	m.help = helpState{
		open: true, matchIndex: -1, selected: category,
		expanded: map[string]bool{category: true, group: true, topic: true},
		returnTo: helpReturnState{
			workspace: m.workspace, activeCard: m.activeCard, outputScroll: m.outputScroll,
			selectedRuleID: m.selectedRuleID, input: m.input, inputMode: m.inputMode,
		},
	}
}

func (m *Model) closeHelp() {
	if !m.help.open {
		return
	}
	state := m.help.returnTo
	m.workspace, m.activeCard, m.outputScroll = state.workspace, state.activeCard, state.outputScroll
	m.selectedRuleID, m.input, m.inputMode = state.selectedRuleID, state.input, state.inputMode
	m.help = helpState{}
}

func (m *Model) updateHelpKey(key string) {
	if m.help.searching {
		switch key {
		case "enter":
			m.help.searching = false
		case "esc":
			m.help.searching = false
		case "backspace", "ctrl+h":
			m.help.query = trimLastRune(m.help.query)
			m.refreshHelpMatches()
		default:
			if len(key) == 1 {
				m.help.query += key
				m.refreshHelpMatches()
			}
		}
		return
	}
	switch key {
	case "f1", "?", "q":
		m.closeHelp()
	case "/":
		m.help.searching = true
	case "esc":
		if m.help.query == "" {
			m.closeHelp()
		} else {
			m.help.query, m.help.matches, m.help.matchIndex = "", nil, -1
			m.help.selected, m.help.scroll = helpCategoryID("Start here"), 0
		}
	case "n":
		m.moveHelpMatch(1)
	case "N":
		m.moveHelpMatch(-1)
	case "up", "k":
		m.moveHelpSelection(-1)
	case "down", "j":
		m.moveHelpSelection(1)
	case "enter", " ":
		m.toggleHelpSelection()
	case "right", "l":
		m.expandOrDescendHelpSelection()
	case "left", "h":
		m.collapseOrAscendHelpSelection()
	case "pgup", "ctrl+u":
		m.moveHelpSelection(-max(1, terminalHeight(m.height)/2))
	case "pgdown", "ctrl+d":
		m.moveHelpSelection(max(1, terminalHeight(m.height)/2))
	case "home":
		m.moveHelpSelectionTo(false)
	case "end":
		m.moveHelpSelectionTo(true)
	}
}

type helpLineKind int

const (
	helpLineText helpLineKind = iota
	helpLineShortcut
	helpLineCommand
	helpLineDescription
	helpLineContext
	helpLineTreeCategory
	helpLineTreeGroup
	helpLineTreeTopic
)

type helpDocumentLine struct {
	Text       string
	Kind       helpLineKind
	ID         string
	ParentID   string
	Selectable bool
	Expandable bool
	Expanded   bool
	Match      bool
}

func helpCategoryID(category string) string { return "category:" + strings.ToLower(category) }
func helpGroupID(category, group string) string {
	return helpCategoryID(category) + "/group:" + strings.ToLower(group)
}
func helpTopicID(entry helpEntry) string { return "topic:" + strings.ToLower(entry.Topic) }

func helpEntryMatches(entry helpEntry, query string) bool {
	values := []string{entry.Topic, entry.Command, entry.Description, entry.Category, entry.Group, helpWorkspaceContext(entry.Workspaces)}
	values = append(values, entry.Keys...)
	values = append(values, entry.Details...)
	return strings.Contains(strings.ToLower(strings.Join(values, "\n")), query)
}

func helpCategoryOrder() []string {
	seen := make(map[string]bool)
	var categories []string
	for _, entry := range helpRegistry {
		if !seen[entry.Category] {
			seen[entry.Category] = true
			categories = append(categories, entry.Category)
		}
	}
	return categories
}

func helpTreeDocument(state helpState) []helpDocumentLine {
	query := strings.ToLower(strings.TrimSpace(state.query))
	catalog := make(map[string]map[string][]helpEntry)
	for _, entry := range helpRegistry {
		if query != "" && !helpEntryMatches(entry, query) {
			continue
		}
		if catalog[entry.Category] == nil {
			catalog[entry.Category] = make(map[string][]helpEntry)
		}
		catalog[entry.Category][entry.Group] = append(catalog[entry.Category][entry.Group], entry)
	}
	lines := []helpDocumentLine{{Text: "Choose a category, group, and topic. Enter opens one level; Left closes one level.", Kind: helpLineDescription}}
	for _, category := range helpCategoryOrder() {
		groups := catalog[category]
		if len(groups) == 0 {
			continue
		}
		categoryID := helpCategoryID(category)
		categoryOpen := state.expanded[categoryID] || query != ""
		lines = append(lines, helpDocumentLine{Text: disclosure(categoryOpen) + " " + category, Kind: helpLineTreeCategory, ID: categoryID, Selectable: true, Expandable: true, Expanded: categoryOpen})
		if !categoryOpen {
			continue
		}
		groupNames := make([]string, 0, len(groups))
		for group := range groups {
			groupNames = append(groupNames, group)
		}
		sort.Strings(groupNames)
		for _, group := range groupNames {
			groupID := helpGroupID(category, group)
			groupOpen := state.expanded[groupID] || query != ""
			lines = append(lines, helpDocumentLine{Text: "  " + disclosure(groupOpen) + " " + group, Kind: helpLineTreeGroup, ID: groupID, ParentID: categoryID, Selectable: true, Expandable: true, Expanded: groupOpen})
			if !groupOpen {
				continue
			}
			entries := append([]helpEntry(nil), groups[group]...)
			sort.SliceStable(entries, func(i, j int) bool { return entries[i].Topic < entries[j].Topic })
			for _, entry := range entries {
				topicID := helpTopicID(entry)
				topicOpen := state.expanded[topicID]
				lines = append(lines, helpDocumentLine{Text: "    " + disclosure(topicOpen) + " " + entry.Topic, Kind: helpLineTreeTopic, ID: topicID, ParentID: groupID, Selectable: true, Expandable: true, Expanded: topicOpen, Match: query != ""})
				if topicOpen {
					lines = append(lines, helpTopicDetailLines(topicID, entry)...)
				}
			}
		}
	}
	if len(lines) == 1 {
		lines = append(lines, helpDocumentLine{Text: "No help topics match this search.", Kind: helpLineDescription})
	}
	return lines
}

func disclosure(open bool) string {
	if open {
		return "[-]"
	}
	return "[+]"
}

func helpTopicDetailLines(parent string, entry helpEntry) []helpDocumentLine {
	lines := []helpDocumentLine{{Text: "      What it does: " + entry.Description, Kind: helpLineDescription, ParentID: parent}}
	for _, detail := range entry.Details {
		lines = append(lines, helpDocumentLine{Text: "      Detail: " + detail, Kind: helpLineDescription, ParentID: parent})
	}
	if len(entry.Keys) > 0 {
		lines = append(lines, helpDocumentLine{Text: "      Bind: " + strings.Join(entry.Keys, " · "), Kind: helpLineShortcut, ParentID: parent})
	}
	if entry.Command != "" {
		lines = append(lines, helpDocumentLine{Text: "      Command: " + entry.Command, Kind: helpLineCommand, ParentID: parent})
	}
	return append(lines, helpDocumentLine{Text: "      " + helpWorkspaceContext(entry.Workspaces), Kind: helpLineContext, ParentID: parent})
}

func (m *Model) refreshHelpMatches() {
	query := strings.ToLower(strings.TrimSpace(m.help.query))
	m.help.matches, m.help.matchIndex = nil, -1
	if query == "" {
		m.help.selected, m.help.scroll = helpCategoryID("Start here"), 0
		return
	}
	for _, entry := range helpRegistry {
		if helpEntryMatches(entry, query) {
			m.help.matches = append(m.help.matches, helpTopicID(entry))
		}
	}
	if len(m.help.matches) > 0 {
		m.help.matchIndex, m.help.selected = 0, m.help.matches[0]
		m.ensureHelpSelectionVisible()
	}
}

func (m *Model) moveHelpMatch(delta int) {
	if len(m.help.matches) == 0 {
		return
	}
	m.help.matchIndex = (m.help.matchIndex + delta + len(m.help.matches)) % len(m.help.matches)
	m.help.selected = m.help.matches[m.help.matchIndex]
	m.ensureHelpSelectionVisible()
}

func (m *Model) helpSelectedLine() (helpDocumentLine, bool) {
	for _, line := range helpTreeDocument(m.help) {
		if line.Selectable && line.ID == m.help.selected {
			return line, true
		}
	}
	return helpDocumentLine{}, false
}

func (m *Model) setHelpExpanded(id string, expanded bool) {
	if m.help.expanded == nil {
		m.help.expanded = make(map[string]bool)
	}
	if expanded {
		m.help.expanded[id] = true
	} else {
		delete(m.help.expanded, id)
	}
}

func (m *Model) toggleHelpSelection() {
	if line, ok := m.helpSelectedLine(); ok {
		m.setHelpExpanded(line.ID, !line.Expanded)
		m.ensureHelpSelectionVisible()
	}
}

func (m *Model) expandOrDescendHelpSelection() {
	line, ok := m.helpSelectedLine()
	if !ok {
		return
	}
	if !line.Expanded {
		m.setHelpExpanded(line.ID, true)
		m.ensureHelpSelectionVisible()
		return
	}
	for _, candidate := range helpTreeDocument(m.help) {
		if candidate.Selectable && candidate.ParentID == line.ID {
			m.help.selected = candidate.ID
			m.ensureHelpSelectionVisible()
			return
		}
	}
}

func (m *Model) collapseOrAscendHelpSelection() {
	line, ok := m.helpSelectedLine()
	if !ok {
		return
	}
	if line.Expanded && strings.TrimSpace(m.help.query) == "" {
		m.setHelpExpanded(line.ID, false)
	} else if line.ParentID != "" {
		m.help.selected = line.ParentID
	}
	m.ensureHelpSelectionVisible()
}

func selectableHelpLines(document []helpDocumentLine) []helpDocumentLine {
	var lines []helpDocumentLine
	for _, line := range document {
		if line.Selectable {
			lines = append(lines, line)
		}
	}
	return lines
}

func (m *Model) moveHelpSelection(delta int) {
	lines := selectableHelpLines(helpTreeDocument(m.help))
	if len(lines) == 0 {
		return
	}
	index := 0
	for candidate, line := range lines {
		if line.ID == m.help.selected {
			index = candidate
			break
		}
	}
	m.help.selected = lines[clamp(index+delta, 0, len(lines)-1)].ID
	m.ensureHelpSelectionVisible()
}

func (m *Model) moveHelpSelectionTo(end bool) {
	lines := selectableHelpLines(helpTreeDocument(m.help))
	if len(lines) == 0 {
		return
	}
	index := 0
	if end {
		index = len(lines) - 1
	}
	m.help.selected = lines[index].ID
	m.ensureHelpSelectionVisible()
}

func (m *Model) ensureHelpSelectionVisible() {
	document := helpDisplayDocument(m.help, terminalWidth(m.width))
	selected := -1
	for index, line := range document {
		if line.Selectable && line.ID == m.help.selected {
			selected = index
			break
		}
	}
	if selected < 0 {
		return
	}
	available := max(1, terminalHeight(m.height)-2)
	if selected < m.help.scroll {
		m.help.scroll = selected
	} else if selected >= m.help.scroll+available {
		m.help.scroll = selected - available + 1
	}
}

func (m Model) renderHelp() string {
	width, height := terminalWidth(m.width), terminalHeight(m.height)
	document := helpDisplayDocument(m.help, width)
	header := "HELP"
	if m.help.searching {
		header += "  /" + m.help.query + "|"
	} else if m.help.query != "" {
		header += fmt.Sprintf("  /%s  %d matches", m.help.query, len(m.help.matches))
	}
	footer := " Up/Down select   Enter open   Left close   Right descend   / search   n/N result   Esc/q/F1 close "
	available := max(1, height-2)
	start := clamp(m.help.scroll, 0, max(0, len(document)-available))
	end := min(len(document), start+available)
	rows := []string{renderStyleLayer(styleTopBar, fit(styleBrand.Render(" goLAN ")+styleProduct.Render(" "+header), width))}
	for _, line := range document[start:end] {
		rendered := renderHelpDocumentLine(line)
		if line.Selectable && line.ID == m.help.selected {
			rendered = styleFocus.Render(line.Text)
		}
		rows = append(rows, renderStyleLayer(stylePaneBody, fit(rendered, width)))
	}
	for len(rows) < height-1 {
		rows = append(rows, stylePaneBody.Render(strings.Repeat(" ", width)))
	}
	return strings.Join(append(rows, styleFooterBar.Render(fit(footer, width))), "\n")
}

func helpDisplayDocument(state helpState, width int) []helpDocumentLine {
	document := helpTreeDocument(state)
	if width <= 0 {
		return document
	}
	var display []helpDocumentLine
	for _, line := range document {
		firstPrefix, continuationPrefix := helpWrapPrefixes(line.Text)
		wrapped := wrapLineWithPrefixes(line.Text, width, firstPrefix, continuationPrefix)
		for index, text := range wrapped {
			part := line
			part.Text = text
			if index > 0 {
				part.ID = ""
				part.Selectable = false
				part.Expandable = false
			}
			display = append(display, part)
		}
	}
	return display
}

func helpWrapPrefixes(line string) (string, string) {
	leading := line[:len(line)-len(strings.TrimLeft(line, " "))]
	trimmed := strings.TrimLeft(line, " ")
	for _, label := range []string{"What it does: ", "Detail: ", "Bind: ", "Command: ", "Context: "} {
		if strings.HasPrefix(trimmed, label) {
			return leading, leading + strings.Repeat(" ", len(label))
		}
	}
	if strings.HasPrefix(trimmed, "[+") || strings.HasPrefix(trimmed, "[-") {
		if close := strings.Index(trimmed, "] "); close >= 0 {
			return leading, leading + strings.Repeat(" ", close+2)
		}
	}
	return leading, leading
}

func renderHelpDocumentLine(line helpDocumentLine) string {
	switch line.Kind {
	case helpLineShortcut, helpLineTreeCategory:
		return styleShortcut.Render(line.Text)
	case helpLineCommand, helpLineTreeGroup:
		return styleCommand.Render(line.Text)
	case helpLineContext:
		return styleContext.Render(line.Text)
	case helpLineDescription:
		return styleMuted.Render(line.Text)
	default:
		return styleText.Render(line.Text)
	}
}

func commandHelpLines() []string {
	lines := []string{"HELP REFERENCE", "Every current feature is listed below. F1 opens the searchable, progressively disclosed manual."}
	lastCategory, lastGroup := "", ""
	for _, entry := range helpRegistry {
		if entry.Category != lastCategory {
			lines = append(lines, "", "["+entry.Category+"]")
			lastCategory, lastGroup = entry.Category, ""
		}
		if entry.Group != lastGroup {
			lines = append(lines, "  "+entry.Group)
			lastGroup = entry.Group
		}
		lines = append(lines, "    "+entry.Topic)
		lines = append(lines, "      What it does: "+entry.Description)
		for _, detail := range entry.Details {
			lines = append(lines, "      Detail: "+detail)
		}
		if len(entry.Keys) > 0 {
			lines = append(lines, "      Bind: "+strings.Join(entry.Keys, " · "))
		}
		if entry.Command != "" {
			lines = append(lines, "      Command: "+entry.Command)
		}
		lines = append(lines, "      "+helpWorkspaceContext(entry.Workspaces))
	}
	return lines
}

func footerHelp(workspace workspace) []string {
	context := "Up/Down select"
	switch workspace {
	case workspaceMain:
		context = "s settings · Ctrl+S save"
	case workspaceNetwork:
		context = "Up/Down devices · Enter expand"
	case workspaceRules:
		context = "Up/Down rules · r edit · M replace"
	}
	return []string{
		context,
		workbenchShortcutLabel(shortcutCommandPalette) + " palette",
		"Shift+Left/Right pane",
		"F2-F4 workspace",
		"Esc overview",
		workbenchShortcutLabel(shortcutPaneMaximize) + " fullscreen",
		"F1 help",
	}
}

func helpWorkspaceContext(workspaces []workspace) string {
	if len(workspaces) == 0 {
		return "Context: all workspaces"
	}
	names := make([]string, len(workspaces))
	for index, value := range workspaces {
		names[index] = string(value)
	}
	return "Context: " + strings.Join(names, ", ")
}

func containsWorkspace(values []workspace, target workspace) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
