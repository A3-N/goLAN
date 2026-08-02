# goLAN

goLAN is a macOS-oriented network observation and rule Workbench for authorized
lab traffic. It combines reversible live capture and forwarding, a readable
device inventory, typed packet rules, automatic PCAP saving, and project-backed
observation sessions in one terminal UI.

The product deliberately does not import, replay, or inspect PCAP files. Saved
captures are outputs for Wireshark or another dedicated packet analyzer. See
[`docs/PRODUCT_SCOPE.md`](docs/PRODUCT_SCOPE.md) for the normative boundary.

## Start

```bash
# Offline project and rule work
golan

# Project entry points
golan new MyLab
golan open ~/.config/goLAN/projects/MyLab.golan

# Live macOS Workbench
sudo golan
```

Opening a project never starts networking. Live interface, bridge, PF, route,
and forwarding changes require macOS and root.

## UI tour

The top bar has three direct destinations:

- `F2 Main` — operational Output above the only CLI.
- `F3 Network` — a device inventory and guided Inspector.
- `F4 Rules` — ordered rules and a compatibility/diagnostic Inspector.

Network is not a packet timeline. Each directly observed Layer 2 device gets
one row with its MAC, associated IPs and VLANs, useful protocols, alert count,
and last-seen time. Repeated facts update counts instead of adding traffic
rows. The Inspector uses collapsible Addressing, DNS, HTTP, Access, Risk, and
Action sections so only one detail branch needs attention at a time.

Help follows the same progressive pattern: category, group, then one topic.
`Ctrl+P` searches documented commands and stages the selected command in
Main's CLI without executing it.

## Keyboard and focus

| Binding | Result |
| --- | --- |
| `F1` | Open guided help |
| `F2`–`F4` | Open Main, Network, or Rules |
| `Shift+Left/Right` | Move between visible panes |
| `Ctrl+Shift+Left/Right` | Move between workspaces |
| `Ctrl+Shift+Up` | Toggle the focused pane full screen |
| `Esc` | Return a focused pane to the current workspace overview |
| `Ctrl+P` | Open the command palette |
| `Ctrl+S` | Save the active project or editor |
| `Up/Down` | Move through the focused list or Inspector sections |
| `Enter` | Open or close the selected Inspector section |

From an all-pane overview, `Esc` does nothing. It never opens the CLI. A
printable key focuses the CLI only from Main overview. There are no Option or
Alt shortcuts because macOS terminal layouts can deliver those chords as text.

## Network observations

goLAN keeps only facts that remain useful without becoming another Wireshark:

- new device identities and strong MAC/IP/VLAN associations;
- DHCP, ARP, and related addressing discoveries;
- DNS query names and types;
- plaintext HTTP method, host, query-free path, and response status;
- EAPOL and MACsec access events;
- categorical risky-authentication signals such as NTLM or cleartext login;
- notable rule outcomes such as block, redirect, edit, or unsupported action.

Routine TCP, UDP, and ICMP packets do not become rows. HTTPS/TLS does not
produce an application observation because goLAN cannot read its encrypted
contents. Risk observations are categorical by default. When a detector can
unambiguously extract a plaintext secret, Settings shows a default-on `Redact
observed secrets` control: on renders `observed [REDACTED]`; off reveals the
bounded value in the current live Network Inspector. These values stay in
transient memory and never enter saved Network sessions, Canvas, projects,
journals, bundles, config diffs, or Main Output. Opaque hashes, challenges,
encrypted values, card data, and raw detector detail are not decoded into the
UI.

Use `network filter ...`, `network search ...`, and
`network session list|show ...` to review the inventory. `show captures
[session-id]` prints the full paths of captures saved during a session.

## Rules and Canvas

Rules are typed and ordered. Every rule reports `LIVE`, `SHADOW`, or
`UNSUPPORTED` honestly for each live data plane. Supported frame edits remain
length-preserving and repair applicable checksums. Rule previews use only the
bounded in-memory sample collected by a live session; there is no file picker
or offline replay path.

`canvas build|rebuild [network-session-id]` derives deterministic topology from
sanitized Network observations. Canvas, Doctor, and Health report through Main
Output and do not add workspaces.

## Runtime modes

| Mode | Behavior |
| --- | --- |
| Listen | Passive observation, automatic capture, and shadow rule evaluation |
| Fast bridge | Reversible macOS kernel bridge with compatible filter rules |
| Controlled bridge | Bounded userspace allow/block, shaping, and safe frame edits |
| Takeover | Reversible authenticated bridge identity with endpoint PF filtering |
| Edge Observe | Single-adapter passive observation |
| Edge Route | DHCPv4, routed NAT, stateful filtering, and explicit port forwards |

Stop and shutdown restore only state owned by the live session. Incomplete
restoration remains visible and retryable.

## Projects and evidence

Projects default to `~/.config/goLAN/projects/` and contain versioned metadata,
configs, policies, immutable sanitized Network sessions, automatically saved
captures, decision journals, exports, and staging state. Project
metadata and observation files are atomically saved and fingerprint-verified.

Portable full bundles may contain captures and detailed observations. Metadata
and sanitized bundles omit those artifacts. goLAN does not offer capture import
or external-reference workflows in the Workbench.

## Theme

The Workbench uses an explicit dark blue-black canvas, layered slate surfaces,
cyan focus states, restrained violet primary actions, and labeled semantic
status colors. Every cell, including empty rows and gutters, receives an
explicit background so terminal black does not leak through.

## Build and verify

```bash
go build -trimpath ./...
go test -shuffle=on -count=1 ./...
go test -race -shuffle=on -count=1 ./...
go vet ./...
```

Routine tests do not require root or mutate real network state. Privileged
macOS validation is separately gated; see
[`docs/MACOS_HARDWARE_VALIDATION.md`](docs/MACOS_HARDWARE_VALIDATION.md).
