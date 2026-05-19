# goLAN NAC Flow

This document tracks the intended runtime flow for goLAN as a Layer 2-first NAC bridge.
The rule is simple: Layer 2 forwarding is allowed once the connecting device MAC is known.
Layer 3 details are optional intelligence and must not block passthrough.

Current lab reference:
- Device-side adapter: `en12`
- Switch-side adapter: `en11`
- The PC with 802.1X credentials is connected behind `en12`.
- The Mac is inline between that PC and the switch.
- RADIUS server to watch for when visible: `192.168.1.157`
- In this lab, the RADIUS server is bridged on the Mac, so passive capture should watch `bridgeN`, `en12`, and `en11`.

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
- Network services are disabled for the session and restored on teardown when their original state was known.
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
- Transparent passthrough forwards EAPOL-Logoff; manual relay modes may suppress it only when explicitly used to preserve an authorized session.
- If native bridge EAPOL suppression fails, warn that duplicate native forwarding may occur.
- Do not actively interfere with authentication while the passive auth map is being used.
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

## Phase 4.5: Passive Topology Map

CHECK:
- Dashboard page 2 renders a human topology view rather than raw protocol boxes:
  - where goLAN sits: PC/supplicant -> device-side interface -> inline bridge -> switch-side interface -> switch/network
  - current target identity from MAC lock plus any DHCP/static-IP evidence
  - switchport state with the evidence that moved it forward
  - visible VLAN tags and assigned VLAN hints when passively observed
  - gateway, DHCP, and RADIUS visibility
  - cleartext credential exposure findings associated with service IP/port and protocol
  - recent IP conversations by endpoint, protocol, port, VLAN, age, and packet count
  - control-plane state for EAPOL, DHCP, and RADIUS
  - observed hosts and recent control-plane events

STOP:
- Do not assume RADIUS is visible just because a server exists. In a normal access-port topology, switch-to-RADIUS traffic is usually outside the inline bridge path.
- Do not assume a RADIUS server hosted on the inline Mac is reachable by the switch. The switch's RADIUS source interface and VLAN must have a valid route back to that server.
- Do not treat a VLAN ID in the map as usable reachability. It only means tagged traffic or policy metadata was observed on the inline path.
- Cleartext findings are shown in the map and may also appear in terminal scrollback. Treat screenshots, recordings, logs, and saved terminal output as sensitive lab artifacts.
- Do not emit hashcat-ready NTLM/Kerberos material unless a separate explicit export workflow is added.

GO:
- In the lab, watch all passive capture points (`bridgeN`, `en12`, `en11`) because the RADIUS server is bridged on the Mac and packets may surface on a member interface rather than only on the bridge interface.
- If RADIUS Access-Requests are visible but no Access-Accept/Reject/Challenge returns to the switch, treat it as a RADIUS reachability or return-path problem, not as successful authentication.
- If `192.168.1.157` RADIUS packets traverse any watched capture point, parse RADIUS Access-Accept/Reject/Challenge, NAS, calling station, called station, filter, reply message, and Tunnel-Private-Group-ID.
- Never display password, CHAP, or raw EAP-Message payloads as credentials.
- Flag cleartext HTTP, FTP, SMTP, IMAP, POP3, LDAP simple bind, IRC, and SNMP community exposure when it appears naturally on the bridged path.
- Use the topology map as the main lab truth source before building real-world takeover logic.

## Phase 5: NAT / Operator Access

CHECK:
- Target IP is known.
- Gateway candidate is known.
- pf rules load successfully.

STOP:
- Do not mark NAT active if target IP is missing.
- Do not mark NAT active if pf rule loading fails.
- Remove the hidden anchor IP if NAT setup fails.

GO:
- Hidden orthogonal IP is added to the bridge.
- IPv4 forwarding is enabled only for NAT/operator-access mode.
- pf anchor is loaded.
- A route for the learned target subnet is installed through the bridge so operator traffic selects the NAT path.
- NAT state is marked active only after pf succeeds.

Note:
- NAT is an operator-access feature, not a bridge-readiness feature.
- The target device's Layer 2 passthrough should keep working without NAT.

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
- Pcap files are written under `/tmp/golan-pcaps`; rotate/delete them outside the tool as needed for long lab sessions.
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
