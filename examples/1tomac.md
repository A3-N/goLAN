# One device to a Mac: en11 downstream, en0 Wi-Fi upstream

Use this playbook to exercise goLAN without a project when one wired test
device is attached to `en11` and the Mac reaches the LAN or internet over
Wi-Fi `en0`.

```text
Test device -- cable -- en11 [goLAN Mac] en0 -- Wi-Fi / LAN / Internet
```

This covers projectless startup, passive Listen, Edge Observe, Edge Route,
DHCP, NAT, port forwarding, policy changes, useful Network observations,
automatic capture saving, and cleanup. Bridge and authenticated-identity NAT
are intentionally absent: bridging a client onto macOS Wi-Fi is not this
topology's reliable forwarding path. Use Edge Route here and use the
[two-adapter playbook](2tomac.md) for Bridge and NAT.

## Safety and test traffic

Use an authorized test device and network. Role assignment isolates `en11`,
so the attached device can lose its existing connection. The packet script
sends one copy of each selected frame and defaults to a dry run. It uses the
documentation-only `192.0.2.0/24` range and locally administered MAC addresses;
those frames test parsing, not connectivity.

The STP and IPv6 router-advertisement fixtures are excluded unless
`--include-control-plane` is explicit. The RA has hop limit 1 so compliant
receivers reject it. Even so, use those two fixtures only on an isolated link:
managed switch ports can react to any BPDU or RA.

Run the injector on the attached test device, not on the goLAN Mac. Edge opens
`en11` for packets arriving from the wire; packets transmitted locally by the
Mac can be excluded by that capture direction.

## 1. Start a blank manual Workbench

On the goLAN Mac:

```bash
make build
sudo ./golan
```

Choose `Quick Live Session (Manual)`. It opens Main's projectless CLI with no
adapter, command, policy, or live runtime selected. Confirm that baseline:

```text
show adapters
show config
show health
doctor
```

Expected:

- `show adapters` includes `en11` and `en0`;
- `show config` reports `staged: none`;
- Listen, Edge, Bridge, and NAT are off;
- no adapter is marked selected and no project is required.

If `en11` or `en0` is missing, stop here and fix the macOS adapter or cable.

## 2. Prepare the attached test device

Copy `1tomac_packets.py` and `golan_packet_lab.py` from this directory to the
same directory on the attached device. Create a small virtual environment so
the system Python stays untouched:

```bash
python3 -m venv .golan-packet-venv
.golan-packet-venv/bin/pip install scapy
.golan-packet-venv/bin/python 1tomac_packets.py --interface <device-cable-interface>
```

The last command is a dry run. It lists every selected frame and sends
nothing. Replace `<device-cable-interface>` with the attached device's own
wired interface; it is not `en11` unless that is coincidentally its local
name.

The four bounded groups are:

| Group | Expected goLAN evidence |
| --- | --- |
| `discovery` | ARP, synthetic DHCP options, VLAN 37, LLDP, plus optional STP root and IPv6 RA/prefix |
| `access` | EAPOL types 0–5, EAP request/response/success/failure, every EAP method goLAN labels, weak-EAP risks, MKA, and MACsec EtherType `0x88e5` |
| `applications` | DNS A/AAAA/PTR queries, one mDNS service, one SSDP service, HTTP GET, and HTTP 204 |
| `risks` | HTTP Basic/form, NTLM, FTP, SMTP, POP3, IMAP, IRC, LDAP, Kerberos RC4, SNMP v1/v2c, and MSSQL categorical warnings |

Plaintext test values are fake and appear as `[REDACTED]` with the default
setting. Routine TCP/UDP packets and HTTPS contents should not become Network
rows.

## 3. Passive Listen

In goLAN Main, activate the policy first:

```text
policy use observe-everything
```

Rules opens so the revision is immediately reviewable. Press `F2` to return
to Main, then:

```text
set adapter en11 host
start listen
```

Adapter isolation is asynchronous. If Start says isolation is pending, wait
for its completion message and enter `start listen` again. Continue only when
the output reports Listen active and a PCAP path.

On the attached device, send the safe default set:

```bash
sudo .golan-packet-venv/bin/python 1tomac_packets.py --interface <device-cable-interface> --send
```

Optionally, on an isolated direct link only:

```bash
sudo .golan-packet-venv/bin/python 1tomac_packets.py --interface <device-cable-interface> --group discovery --include-control-plane --send
```

Review without turning Main Output into a packet stream:

```text
network show
network filter addressing
network infrastructure
network filter dns
network services
network filter http
network filter access
network access 1
network filter risks
network identity 1
network explain 1
show health
```

`F3` opens the same Network inventory visually. The default generator usually
creates a synthetic client identity ending in `:11` and a peer/server identity
ending in `:22`; use the visible device number instead of assuming `1` if the
order differs.

Expected acceptance rules:

- repeated facts update counts instead of making packet rows;
- DNS retains names and types, not complete messages;
- mDNS and SSDP appear in `network services` without TXT data or URL queries;
- HTTP retains method, host, query-free path, and response status;
- EAPOL Start, Logoff, Key, type 4, MKA, and EAP are readable Access events;
- MD5, LEAP, and MSCHAPv2 additionally produce categorical Risk warnings;
- MACsec produces an Access warning; it is not decrypted;
- all extracted fake plaintext values remain transient and redacted by default.

Finish and verify capture finalization:

```text
stop listen
show captures
cleanup
show config
show health
```

Expected: a finalized capture is listed, then cleanup restores the exact
pre-goLAN `en11` state and returns to `staged: none`. In a manual projectless
session the PCAP remains an external saved output, but there is no project
session index or baseline.

## 4. Edge Observe

Edge Observe gives the same physical `en11` traffic explicit downstream
semantics but still provides no DHCP and no forwarding.

```text
policy use observe-everything
```

Press `F2`, then:

```text
set adapter en11 host
set edge mode observe
start edge observe
```

Retry Start after isolation completes if prompted. Send one group from the
attached device:

```bash
sudo .golan-packet-venv/bin/python 1tomac_packets.py --interface <device-cable-interface> --group applications --send
```

Expected: DNS, service, and HTTP observations appear; the test device does not
receive a goLAN DHCP lease and cannot reach `en0` through goLAN. Then:

```text
stop edge
show captures
cleanup
```

## 5. Edge Route: DHCP and internet forwarding

Activate the policy first:

```text
policy use open-internet
```

Press `F2`, then stage the downstream cable and explicit Wi-Fi upstream:

```text
set adapter en11 host
set edge mode route
set edge upstream en0
start edge route
```

Retry Start after adapter isolation if requested. When output reports
`edge route active`, set the attached device's wired interface to
DHCP/automatic and renew it.

```text
show edge
show health
```

Expected: goLAN selects a conflict-free `10.77.x.0/24`, owns `.1` as gateway,
and leases `.2` to the single client. `show health` identifies `en11` as
downstream and `en0` as upstream. The routing rules match the client subnet,
not host-originated traffic, so the Mac should retain its own Wi-Fi internet
connection throughout the run. On the client, verify in this order:

1. its lease, mask, gateway, and DNS are present;
2. it can reach the reported `.1` gateway;
3. a DNS lookup through the supplied resolver succeeds;
4. `curl http://example.com/` succeeds;
5. `curl https://example.com/` succeeds as forwarded encrypted traffic.

Then review:

```text
network filter addressing
network filter dns
network filter http
network fate 1
network explain 1
```

DNS and plaintext HTTP should be readable. HTTPS should contribute forwarding
or fate evidence only; no HTTPS URL or content row is expected.

### Live policy change

Apply the stricter built-in policy while Edge remains active:

```text
policy use web-only
```

Rules opens with the live compatibility result. Return to Main with `F2` and
run `show rules`. DNS and TCP ports 80/443 should still work from the
client; unrelated outbound traffic should be blocked and become an Action or
Packet Fate result. Restore broad access with:

```text
policy use open-internet
```

Press `F2` again before continuing in Main.

### Client-only VPN egress

For a separate run, connect the Mac's VPN first and replace `utun4`, the
destination, and DNS server below with values from that VPN:

```text
stop edge
cleanup
set adapter en11 host
set edge egress vpn utun4
set edge vpn-destination 10.20.0.0/16
set edge dns 10.20.0.53
policy use open-internet
doctor
start edge route
```

The client can reach only the staged VPN destinations, through the tunnel;
the Mac keeps following its own existing routes. The `all` VPN destination
routes all client IPv4 traffic through the VPN. If the tunnel disappears,
goLAN stops Edge fail-closed instead of letting the client fall back to Wi-Fi.
The VPN must expose an up IPv4 point-to-point interface and permit forwarded,
NATed traffic. See the [Edge route guide](edge-route.md) for the full behavior.
If `scutil --dns` reports a resolver such as `127.0.0.1`, stage that address:
goLAN advertises its downstream `.1` gateway and relays UDP/TCP DNS on the Mac
instead of incorrectly giving the client a loopback address. Use
`set edge dns clear` for automatic scoped-resolver discovery.

### Inbound port-forward test

Port forwards must be staged before Edge starts. For a separate run, clean up
and use:

```text
policy use open-internet
```

Press `F2`, then:

```text
set adapter en11 host
set edge mode route
set edge upstream en0
set edge port-forward tcp 8443 8080
set edge port-forward list
start edge route
```

After the client receives `.2`, start an authorized test server on it:

```bash
python3 -m http.server 8080 --bind 0.0.0.0
```

From a second host reachable through the `en0` LAN, request
`http://<goLAN-Mac-en0-address>:8443/`. Expected: the client server receives
the request on 8080 and goLAN retains the readable HTTP and forwarding result.
This test depends on the Wi-Fi/LAN allowing peer-to-peer inbound traffic.

## 6. Final recovery check

Stop the owned runtime before restoring the staged adapter:

```text
stop edge
show captures
cleanup
show adapters
show config
show health
doctor
```

`[WARN]` cleanup is safe to retry with `cleanup`; successfully restored steps
are not replayed. A successful finish has no active runtime, no cleanup owner,
and no staged adapter. The Mac's original `en11` service/admin state and `en0`
Wi-Fi connection should match the pre-test state.
