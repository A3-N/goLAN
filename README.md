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

At the Workbench chooser, `Quick Live Session (Manual)` opens the projectless
Main CLI immediately with nothing selected, staged, or started. The separate
guided Quick Live path asks for a mode and adapters before staging a reviewable
Start command.

## Examples

The root README stays focused on the product and interface. Task-focused
command flows live under [`examples/`](examples/README.md):

| Goal | Guide |
| --- | --- |
| Manually test en11 with en0 Wi-Fi upstream | [One device to a Mac](examples/1tomac.md) |
| Manually test en11-to-en12 inline operation | [One device through a Mac to a switch](examples/2tomac.md) |
| Observe without forwarding | [Passive listen](examples/passive-listen.md) |
| Give one host DHCP and routed internet access | [Edge route](examples/edge-route.md) |
| Forward transparently between a host and switch | [Bridge](examples/bridge.md) |
| Use authenticated-identity forwarding | [NAT](examples/nat.md) |
| Review the stable device inventory | [Network review](examples/network-review.md) |
| Baseline, explain, verify, and act on observations | [Network intelligence](examples/network-intelligence.md) |
| Manage rules, projects, recovery, or Canvas | [All examples](examples/README.md) |

Run `help` in Main or press `F1` for the complete command reference.

## UI tour

The top bar has three direct destinations:

- `F2 Main` — operational Output above the only CLI.
- `F3 Network` — a device inventory and guided Inspector.
- `F4 Rules` — ordered rules and a compatibility/diagnostic Inspector.

Network is not a packet timeline. Each directly observed Layer 2 device gets
one row with its MAC, associated IPs and VLANs, useful protocols, alert count,
and last-seen time. `#` is a stable session-local discovery number: the newest
device has the highest number at the top, and later activity updates that row
without moving it. Repeated facts update counts instead of adding traffic rows.
The Inspector uses collapsible Addressing, DNS, HTTP, Access, Risk, and Action
sections so only one detail branch needs attention at a time. Its compact
`O Overview`, `E Explain`, `A Access`, `F Fate`, and `R Rule` actions keep
deeper analysis attached to the selected device.

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
- infrastructure actors and changes, including gateways, DHCP/DNS servers,
  IPv6 routers, LLDP switches, STP roots, and authenticators;
- DNS query names and types;
- useful mDNS and SSDP service identities without arbitrary TXT content;
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

### Network CLI

Device selectors accept the visible discovery number, exact MAC, associated
IP, or exact observed hostname. These are the canonical commands; there are no
command aliases.

```text
# Inventory and focused analysis
network show
network filter <all|addressing|dns|http|access|risks|actions>
network search <term|clear>
network reset
network identity <device>
network infrastructure
network services
network explain <device>
network access <device>
network fate <device>

# Saved sessions and Network Time Machine
network session list
network session show <session-id>
network baseline show
network baseline set <session-id>
network baseline clear
network compare baseline
network compare session <session-id>

# Checksummed portable fingerprints
network passport save <destination.golanpass>
network passport verify <path.golanpass>
network passport compare <path.golanpass>

# Reviewable, bounded probes: plan first, run once second
network probe plan gateway <ip>
network probe plan dns <hostname>
network probe plan route <ip>
network probe plan device <ip> <tcp-port>
network probe plan dhcp <adapter>
network probe run

# Turn retained evidence into a review-only typed rule draft
network rule draft <device>
```

`network explain` labels link-through-application evidence as PASS, WARN,
FAIL, or SKIP and never guesses encrypted content. `network fate` is a
payload-free outcome aggregate, not a packet timeline. Passport files exclude
captures, raw observations, paths, packet outcomes, and secrets. Probe plans
have a fixed three-second deadline; the macOS DHCP probe reads the existing
lease and does not solicit or renew one. Rule drafts do not commit or enforce
themselves. `show captures [session-id]` prints captures saved by goLAN.

## Rules and Canvas

Rules are typed and ordered. Every rule reports `LIVE`, `SHADOW`, or
`UNSUPPORTED` honestly for each live data plane. Supported frame edits remain
length-preserving and repair applicable checksums. Rule previews use only the
bounded in-memory sample collected by a live session; there is no file picker
or offline replay path.

`canvas build [network-session-id]` derives deterministic topology from
sanitized Network observations. Canvas, Doctor, and Health report through Main
Output and do not add workspaces.

## Runtime modes

| Mode | Behavior |
| --- | --- |
| Listen | Passive observation, automatic capture, and shadow rule evaluation |
| Fast bridge | Reversible macOS kernel bridge with compatible filter rules |
| Controlled bridge | Bounded userspace allow/block, shaping, and safe frame edits |
| NAT | Reversible authenticated bridge identity with endpoint PF filtering |
| Edge Observe | Single-adapter passive observation |
| Edge Route | DHCPv4, host-safe routed NAT, stateful filtering, optional VPN egress, and explicit port forwards |

Stop and shutdown restore only state owned by the live session. Incomplete
restoration remains visible and retryable.

Edge Route changes only traffic sourced by its one downstream client. The Mac
keeps its own connectivity and routing on its existing non-downstream
interfaces. VPN egress can force that client through an already-connected IPv4
point-to-point tunnel without moving the Mac's own traffic onto the tunnel; it
stops fail-closed if the tunnel goes away. macOS scoped DNS is discovered with
`scutil`; a port-53 loopback resolver is safely exposed through a downstream
DNS relay instead of advertising `127.0.0.1` to the client. See
[Edge route](examples/edge-route.md) for the staged commands and limitations.

Use `cleanup` to stop all live work owned by the current Workbench, retry scoped
PF and interface restoration, restore every staged adapter to its recorded
pre-goLAN service and administrative state, and clear the staged live setup
without quitting. It does not delete saved configurations, policies, projects,
captures, or observations.

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
