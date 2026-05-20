# goLAN NAC Flow

This document tracks the intended runtime flow for goLAN as a Layer 2-first NAC bridge.
The rule is simple: Layer 2 forwarding is allowed once the connecting device MAC is known.
Layer 3 details are optional intelligence and must not block passthrough.

Generic lab reference:
- Device-side adapter: `<device-side-iface>`.
- Switch-side adapter: `<switch-side-iface>`.
- The downstream device or supplicant is connected behind `<device-side-iface>`.
- The Mac is inline between that device and the switch.
- Optional RADIUS server visibility should be treated as environment-specific; use placeholders such as `<radius-ip>` in docs and saved notes.
- When a control-plane service is hosted on the inline Mac, passive capture should watch the bridge and both selected member interfaces because packets may surface on a member interface rather than only on the bridge.

## Port Roles

- LAN 1 / `ifaceA`: device-side port. This is where the connecting device is learned.
- LAN 2 / `ifaceB`: switch-side port. This is kept down until the target MAC is known and spoofing/bridge rules are prepared.
- `bridgeN`: macOS kernel bridge used for transparent frame passthrough.

## Phase 0: Host Safety

CHECK:
- Running as root.
- Two different interfaces selected.
- Interface restore state captured before lockdown.

STOP:
- Bridge creation fails.
- Same interface selected for both ports.

GO:
- Both selected adapters are locked down.
- IPv4 is stripped from adapters.
- Network services are disabled for the run and restored on teardown when their original state was known.
- Original IPv4 and IPv6 forwarding sysctl values are captured for restoration.
- Passive pcap capture starts on the device-side adapter before switch-side link-up.

## Phase 1: Layer 2 Identity

CHECK:
- Sniff on device-side port.
- Ignore local adapter MAC.
- Accept the first valid unicast source MAC from any Layer 2 evidence:
  - Ethernet data frame
  - ARP
  - IPv4
  - DHCP
  - EAPOL / 802.1X
  - VLAN-tagged traffic

STOP:
- Context cancelled before any target MAC is observed.
- Bridge member attach or bridge bring-up fails.

GO:
- Target MAC is known.
- Bridge MAC and switch-side adapter MAC are spoofed when possible.
- Bridge members are attached.
- Source-MAC safety rules are installed for local adapter identities.
- STP/LLDP/CDP leak suppression is installed and verified.
- Switch-side adapter is powered up.
- Passive pcap capture and network observers are started on every available capture point.
- EAPOL passthrough is armed immediately because 802.1X uses link-local control frames that the OS bridge may not forward natively.
- Bridge is marked ready even if IP, DHCP, gateway, DNS, or VLAN are unknown.

Important invariant:
- `MAC known` is the Layer 2 readiness gate.
- `IP known` is not a readiness gate.
- `802.1X observed` means normal frames are kernel-bridged while goLAN forwards and observes EAPOL passthrough; it does not mean goLAN is waiting before forwarding.

## Phase 2: Passive Enrichment

CHECK:
- Continue sniffing after Layer 2 readiness.
- Update target metadata without blocking forwarding:
  - IPv4 source address
  - DHCP lease address
  - DHCP subnet mask
  - DHCP router option
  - ARP gateway candidates
  - EAPOL presence
  - authenticator MAC
  - VLAN IDs

STOP:
- Do not stop Layer 2 forwarding if these fields are missing.

GO:
- NAT mode becomes available only after target IP and gateway evidence exist.
- Manual 802.1X action modes remain operator-controlled; transparent EAPOL passthrough is already active after MAC lock.

## Phase 3: Transparent L2 Passthrough

CHECK:
- Kernel bridge forwards normal frames.
- Observer maps hosts, DNS, and VLANs from bridge traffic.

STOP:
- Do not inject host traffic as part of recon.
- Do not wait for DHCP.
- Do not require gateway discovery.

GO:
- Non-IP and static-IP devices remain bridged.
- IPv4 details are learned when they naturally appear.

## Phase 4: 802.1X / EAPOL

CHECK:
- Default posture is passive-auth-first: let the real supplicant and switch complete 802.1X normally.
- Forward normal frames through the kernel bridge.
- Forward EAPOL through the automatic passthrough pump, using the learned supplicant MAC and learned authenticator direction.
- Capture untagged and VLAN-tagged EAPOL.
- Pin relay direction:
  - device to switch must source from target MAC.
  - switch to device must source from the learned authenticator MAC once known.
- Track EAP method, success/failure, logoff, reauth, and MKA/MACsec.
- If relay mode is manually used, inject EAPOL-Start only after relay capture goroutines are active.

STOP:
- Drop frames that do not match the learned supplicant/authenticator direction.
- Transparent passthrough forwards EAPOL-Logoff; manual relay modes may suppress it only when explicitly used to preserve an authorized state.
- If native bridge EAPOL suppression fails, warn that duplicate native forwarding may occur.
- Do not actively interfere with authentication while the passive topology/intelligence pages are being used.
- Do not auto-start intrusive auth actions such as EAPOL-Start injection or MACsec downgrade just because EAPOL was observed.
- MACsec downgrade defaults off and must be operator-enabled before manual relay uses it.

GO:
- EAP-Success means the switch port appears authorized.
- DHCP offer/ACK to the target, ARP from the network to the target, or IPv4 from the network to the target is data-plane proof that the port is open.
- RADIUS Access-Accept means policy accepted the auth, but it is not final data-plane proof until EAP-Success or traffic reaches the target.
- RADIUS Access-Request only means an auth attempt reached RADIUS; it does not mean the port opened.
- EAPOL passthrough owns the EAPOL path when bridge EAPOL suppression succeeds.
- Normal non-EAPOL frames continue through the kernel bridge.
- VLAN-tagged EAPOL-Start is used only for explicit operator-triggered start injection when a VLAN context is known.

## Phase 4.5: Passive Topology And Intelligence Pages

CHECK:
- Dashboard page 2 combines passive intelligence and protocol state without duplicating identity/topology fields:
  - cleartext credential exposure findings associated with service IP/port and protocol
  - recent IP conversations by endpoint, protocol, port, VLAN, age, and packet count
  - Layer 2 detail for target MAC, VLANs, switchport evidence, LLDP/CDP, EAPOL, and adapter observations
  - Layer 3 detail for target IP evidence, gateway/router, DNS servers, netmask, DHCP lease summary, observed LAN, and WAN visibility
  - internal/LAN DNS host map entries that link observed names to private response IPs; public DNS results, unresolved queries, and link-local IPs are suppressed
- Dashboard page 3 renders a selectable network layout:
  - goLAN and the switch are first-class selectable nodes
  - observed MAC/IP hosts, DNS names, DHCP lease/router/server/DNS options, RADIUS NAS/server facts, external IPs, and service endpoints are linked into the switch view
  - recent conversations render as directed protocol edges so SNMP, DNS, DHCP, RADIUS, and other traffic show who talks to whom
  - PC IP means the downstream supplicant/connected-device IP; MitM/NAT anchor IP means goLAN's operator-side access identity
  - IP-only, MAC-only, and MAC+IP sightings for the same endpoint are merged into one selectable node so one host does not appear twice as `ip:x.x.x.x` and `mac:xx:xx:xx:xx:xx:xx`
  - if one IP has multiple infrastructure roles, keep it as one node and show the combined roles, for example `gateway/router + DHCP server + DNS server`
  - infrastructure roles must include evidence tags: DHCP option 3 for router, DHCP option 6 for DNS, DNS packet/port-53 conversations for DNS, RADIUS/NAS fields for AAA, and LLDP/CDP for network devices
  - node labels prefer role/identity guesses such as Windows, Unix/Linux, Apple/Bonjour, network device, printer, DHCP server, DNS server, RADIUS server, or gateway/router
  - protocol names such as LDAP, SMB, SNMP, SSH, Kerberos, mDNS, LLMNR, LLDP, and CDP are supporting tags/evidence rather than the main host identity when an OS or device family is more accurate
  - endpoint identity should combine passive host signals from OUI/vendor, ARP behavior, DHCP options 12/15/55/60/61/119, TCP SYN fingerprints, HTTP Host/User-Agent/Server, TLS SNI, SSH banners, SSDP/UPnP, WS-Discovery, LLMNR, NetBIOS, DNS private answers, LLDP, and CDP
  - each passive signal is evidence, not ground truth; roles are promoted only when multiple characteristics or high-confidence protocol fields support the label
  - cleartext credential findings are correlated back onto matching service edges and the captured value is shown in the middle of that port connection line
  - once a protocol/service edge is observed, keep it in the bounded live map and render service rows in a stable order instead of letting newest packets reshuffle the visible topology
  - L selects LAN/internal conversations and W selects WAN/internet conversations; the modes are mutually exclusive to keep the map readable
  - LAN mode suppresses public/WAN IP nodes and all 169.254.0.0/16 link-local artifacts. WAN mode shows public IP nodes without dimming them.
  - Enter opens a node detail page with MAC, IPs, DNS names, inbound edges, and outbound edges
- Dashboard body content must fit between the header and footer. Pages 2 and 3 can clip and scroll inside that budget instead of growing beyond the terminal height.
- Packet captures are written under `~/.config/goLAN/pcaps/<timestamp>/` by default. The app does not persist or resume UI graph state; the network map is rebuilt live from bounded observer state on each run.

STOP:
- Do not assume RADIUS is visible just because a server exists. In a normal access-port topology, switch-to-RADIUS traffic is usually outside the inline bridge path.
- Do not assume a RADIUS server hosted on the inline Mac is reachable by the switch. The switch's RADIUS source interface and VLAN must have a valid route back to that server.
- Do not treat a VLAN ID in the map as usable reachability. It only means tagged traffic or policy metadata was observed on the inline path.
- Cleartext findings are shown in the map and may also appear in terminal scrollback. Treat screenshots, recordings, logs, and saved terminal output as sensitive lab artifacts.
- Do not emit hashcat-ready NTLM/Kerberos material unless a separate explicit export workflow is added.

GO:
- Watch all passive capture points (`bridgeN`, `<device-side-iface>`, `<switch-side-iface>`) when a control-plane service is bridged through the Mac because packets may surface on a member interface rather than only on the bridge interface.
- If RADIUS Access-Requests are visible but no Access-Accept/Reject/Challenge returns to the switch, treat it as a RADIUS reachability or return-path problem, not as successful authentication.
- If RADIUS packets traverse any watched capture point, parse RADIUS Access-Accept/Reject/Challenge, NAS, calling station, called station, filter, reply message, and Tunnel-Private-Group-ID.
- Do not display RADIUS CHAP or raw EAP-Message payloads as cleartext credentials.
- Flag cleartext HTTP, FTP, SMTP, IMAP, POP3, LDAP simple bind, IRC, and SNMP community exposure when it appears naturally on the bridged path.
- Use DHCP option 3 router and option 6 DNS servers as infrastructure facts for the graph. DNS server evidence can also come from inspected DNS packets and DNS conversations where the server side is identified by packet decoding and port direction. Use option 60 vendor class plus option 55 parameter request list as soft client fingerprints, for example MSFT/NetBIOS requests for Windows-like clients, dhcpcd/BusyBox/systemd for Unix-like clients, Android DHCP clients for Android/Linux, and PXEClient for boot workflows.
- Use LLDP and CDP advertisements as high-confidence Layer 2 infrastructure signals when present: system name, platform, management address, port, capabilities, native VLAN, and version can identify switches, routers, APs, phones, and managed network devices.
- Use Windows name-resolution signals as supporting evidence: NetBIOS, LLMNR, WS-Discovery, SMB, MSRPC, WinRM, RDP, and Kerberos+LDAP together are stronger Windows/AD indicators than LDAP alone.
- Use Unix-like signals as supporting evidence: SSH, syslog, rpcbind, NFS, dhcpcd/BusyBox/systemd DHCP identifiers, and Linux/BSD host strings.
- Use print-service signals as supporting evidence: JetDirect/9100, IPP, LPD, AirPrint/mDNS names, WSD print discovery, and printer vendor names.
- Use the topology map as the main lab truth source before building real-world takeover logic.

## Phase 5: NAT / Operator Access

CHECK:
- Target IP is known.
- Gateway candidate is known.
- A target subnet mask is observed before using a same-subnet operator anchor. DHCP option 1 is preferred.
- pf rules load successfully.

STOP:
- Do not mark NAT active if target IP is missing.
- Do not mark NAT active if pf rule loading fails.
- Remove the hidden anchor IP if NAT setup fails.
- Do not assign the target/PC IP to goLAN for normal NAT. That creates duplicate-IP/ARP ownership conflict while the downstream device is still bridged. Reusing that IP is an explicit takeover mode, not passive bridge + operator NAT.
- Do not invent a LAN range from only a MAC address or a static IPv4 source. Without a real subnet mask, use the off-subnet NAT anchor and keep learning passively.

GO:
- If a real subnet mask is known, choose an unused-looking operator IP from the learned subnet while avoiding the target, gateway, DHCP/RADIUS endpoints, observed hosts, and recent conversation endpoints.
- If the subnet mask is unknown or no passive candidate is available, add the hidden orthogonal IP to the bridge as a fallback.
- IPv4 forwarding is enabled only for NAT/operator-access mode.
- pf anchor is loaded.
- A route for the learned target subnet is installed through the bridge so operator traffic selects the NAT path.
- NAT state is marked active only after pf succeeds.

Note:
- NAT is an operator-access feature, not a bridge-readiness feature.
- The target device's Layer 2 passthrough should keep working without NAT.
- There is no reliable Ethernet packet that asks "what IPv4 address belongs to this MAC". ARP maps IP to MAC, so active discovery requires probing candidate IPs from a known range; passive ARP/DHCP/IPv4 evidence remains the default.

## Phase 6: Teardown

CHECK:
- Cancel bridge context.
- Cancel EAPOL relay.
- Cancel passive EAPOL listener.
- Flush NAT pf anchor.
- Destroy bridge.
- Restore IP forwarding.
- Restore IPv6 forwarding.
- Restore L2 host services.
- Restore captured network service state.

STOP:
- Report teardown errors, but continue best-effort restoration.

GO:
- No stale bridge or pf state should remain after normal shutdown.

## Current Watch Items

- macOS bridge packet-filter syntax differs by release. EAPOL suppression is best-effort and logs a warning when unsupported.
- Confirm that bridge EAPOL suppression does not block pcap-injected passthrough frames on the selected macOS release and adapter driver.
- ARP can reveal a gateway candidate, but DHCP router option is stronger evidence.
- MACsec downgrade remains a user-controlled behavior and should be treated as an active modification, not passive inspection.
- Pcap files are written under the active timestamped pcap directory. Use `--nuke` to purge saved pcaps from the goLAN config tree.
- NAT depends on macOS route selection. Confirm with `route -n get <host>` and bridge pcap/tcpdump when scans do not appear on the wire.
- Cleartext exposure detection is packet-scoped for now. Full stream reassembly is needed for split HTTP headers/forms or fragmented line-protocol authentication.

## Hardening Backlog

Items inspired by slimjim and the current goLAN review:

1. Confirm macOS bridge source-MAC rules on each adapter model and OS version; unsupported rule syntax must remain a visible degraded state.
2. Add true rotating pcap rings instead of capped per-interface pcap files.
3. Keep Layer 2 passthrough and NAT/operator access visually distinct in the UI so NAT is never confused with bridge readiness.
4. Add full protocol-specific extraction for NTLM, Kerberos AS-REQ etype 23, and MSSQL only if the project grows an explicit export workflow for hash material.
5. Add TCP stream reassembly for passive application-protocol parsers.
6. Update or replace `SCENARIOS.md`; it still contains historical probe/relay/NAT sequencing and should not be used as the canonical flow.
