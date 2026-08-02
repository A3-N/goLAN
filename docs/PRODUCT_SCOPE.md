# Product scope

This document is the normative boundary for goLAN. If code, documentation, or
UI behavior conflicts with it, this document wins.

## Product shape

goLAN is a macOS-first terminal Workbench for authorized live network
observation and rule operation. It has exactly three workspaces:

- Main owns operational Output and the only CLI.
- Network owns the readable device inventory and guided observation Inspector.
- Rules owns ordered typed rules, compatibility, editing, and live-sample
  previews.

Canvas, Doctor, and Health are commands that report through Main. They are not
workspaces. Canvas is derived only from sanitized Network sessions.

## Interaction contract

`Esc` unfocuses the current pane and returns to the current workspace overview.
From an overview it does nothing. It never opens Main or the CLI. F2 through F4
select Main, Network, and Rules; Shift+Left/Right moves panes; Ctrl+Shift+arrow
keys move workspaces or toggle pane full screen. There are no Option or Alt
bindings because macOS terminals may emit those chords as text.

Help and complex operations must disclose detail progressively: category,
group, then topic or guided choice. Every current command, shortcut, editor,
setting impact, evidence boundary, and recovery path must remain discoverable
through categorized help, completion, and Ctrl+P.

## Live observation contract

Network records durable, human-readable facts rather than a packet timeline:

- directly observed MAC, IP, VLAN, DHCP, ARP, DNS, and device identity facts;
- plaintext HTTP method, host, query-free path, and response status;
- EAPOL and MACsec access events;
- categorical risky-authentication signals, with default-redacted transient
  plaintext values only when extraction is unambiguous;
- notable rule outcomes such as block, redirect, edit, or unsupported action.

Repeated facts increase a count. Routine transport packets do not create rows.
Encrypted HTTPS/TLS traffic does not create application observations. Raw
packet bytes, hashes, opaque challenges, card data, and detector detail do not
enter the UI. The default-on `Redact observed secrets` setting may be disabled
to reveal a bounded, unambiguously plaintext secret in the current live
Network Inspector. Such values are transient only and must never enter saved
Network sessions, Canvas, projects, journals, bundles, configs, diffs, or Main
Output.

## PCAP boundary

Live modes automatically save PCAP files as immutable output evidence. The
Workbench may index those files, show their paths, verify fingerprints, and
carry them in a full project bundle. It must not import arbitrary PCAP files,
offer external capture references, replay captures, filter or export derived
captures, inspect packet files, compare captures, or build packet timelines.
Wireshark and other dedicated analyzers own those workflows.

Rules preview only the bounded in-memory sample from the current live session.
Canvas builds only from sanitized current or saved Network sessions.

## Runtime and safety

Supported modes are Listen, Fast bridge, Controlled bridge, Takeover, Edge
Observe, and Edge Route. Capability reporting must distinguish LIVE, SHADOW,
and UNSUPPORTED without overstating enforcement. Live state changes require
macOS and root and must be reversible. Stop and shutdown restore only state the
session owns; incomplete restoration remains visible and retryable.

Opening a project, browsing data, running Doctor, and routine tests must not
start networking or mutate host network state.

## Retired features

The following are not product features: Repeater, Interceptor, Flow, Findings,
Logger, a separate Live workspace, a Canvas workspace, offline packet replay,
PCAP import, packet-file previews, packet navigation, packet annotations,
saved packet filters, PCAP-derived Canvas mapping/comparison, or hidden
Option/Alt shortcuts. Schema migration may recognize retired fields only long
enough to discard them safely.

## Acceptance checks

Changes must preserve the three-workspace contract, explicit dark backgrounds,
guided help, honest live-mode capabilities, bounded observation data, automatic
capture output, and safe restoration. Routine verification is `go vet ./...`,
`go test -shuffle=on -count=1 ./...`, `go test -race -shuffle=on -count=1
./...`, and `go build -trimpath ./...`.
