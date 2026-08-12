# One device through a Mac to a switch: en11 host, en12 switch

Use this playbook when the Mac is physically inline between an authorized test
device and an isolated switch or lab LAN.

```text
Test device -- en11 [goLAN Mac] en12 -- Test switch / lab LAN
```

This covers projectless startup, two-sided Listen, Fast Bridge, Controlled
Bridge, forwarding, policies, EAPOL controls, MACsec/MKA observation,
authenticated-identity NAT, capture saving, and exact restoration.

## Safety and equipment

Do not use a production switch or a port where a brief forwarding interruption
is unacceptable. Staging either adapter isolates it. The generator sends
documentation-range addresses and synthetic MACs for parser tests; supply the
real receiver MAC/IP when testing actual end-to-end delivery.

Run the packet script on an external host attached to `en11` or `en12`, never
on the goLAN Mac itself. Controlled Bridge captures only frames arriving from
the wire. For forwarding checks, run `tcpdump` or Wireshark on a second test
host across the bridge.

STP and IPv6 RA fixtures require `--include-control-plane` and belong only on
an isolated lab link. A managed access port may intentionally disable itself
when it sees a BPDU even though the synthetic root has an unattractive
priority and the RA has invalid hop limit 1.

## 1. Start the manual CLI and preflight

On the goLAN Mac:

```bash
make build
sudo ./golan
```

Choose `Quick Live Session (Manual)`, then run:

```text
show adapters
show config
show health
doctor
```

Expected: `en11` and `en12` are present, no role is staged, no project is
attached, and all runtimes are off.

On the external packet-sending host, keep `2tomac_packets.py` and
`golan_packet_lab.py` together:

```bash
python3 -m venv .golan-packet-venv
.golan-packet-venv/bin/pip install scapy
.golan-packet-venv/bin/python 2tomac_packets.py --interface <sender-interface>
```

The dry run lists the bounded fixtures. Groups and expected observations are
the same as in [the one-device playbook](1tomac.md#2-prepare-the-attached-test-device):
`discovery`, `access`, `applications`, and `risks`.

## 2. Two-sided Listen: capture without forwarding

Activate the policy, review it in Rules, and press `F2` to return to Main:

```text
policy use observe-everything
```

Then stage both roles, waiting for each isolation operation to complete:

```text
set adapter en11 host
set adapter en12 switch
start listen
```

Retry `start listen` after isolation if prompted. Send Applications from the
host side:

```bash
sudo .golan-packet-venv/bin/python 2tomac_packets.py --interface <sender-interface> --group applications --send
```

Expected: goLAN observes and saves the frames arriving on that side, but
nothing is forwarded to the receiver across the Mac. Confirm with a receiver
capture, then review:

```text
network show
network filter dns
network services
network filter http
show health
stop listen
show captures
cleanup
```

## 3. Fast Bridge: kernel forwarding

```text
policy use observe-everything
```

Press `F2`, then:

```text
set adapter en11 host
set adapter en12 switch
start bridge fast
```

Retry Start after isolation if needed. Confirm:

```text
show bridge
show health
show rules
```

An ordinary host attached to `en11` should now obtain DHCP from the switch-side
LAN and pass normal traffic in both directions. That is the strongest
forwarding test because it exercises real replies, checksums, neighbor
discovery, and state rather than only synthetic one-way frames.

For a deterministic L2 check, find the receiver's real MAC and IP, start a
receiver capture, and run from the host side:

```bash
sudo .golan-packet-venv/bin/python 2tomac_packets.py \
  --interface <sender-interface> \
  --group applications \
  --peer-mac <receiver-mac> \
  --peer-ip <receiver-ip> \
  --send
```

Expected: the receiver sees the synthetic DNS, mDNS, SSDP, and HTTP frames;
goLAN shows readable summaries rather than one row per packet. Fast Bridge
shows rule compatibility honestly: supported kernel actions are LIVE and
others remain SHADOW or UNSUPPORTED rather than pretending enforcement.

```text
network filter all
network fate 1
show bridge
stop bridge
show captures
cleanup
```

## 4. Controlled Bridge: bounded userspace enforcement

```text
policy use controlled-bridge
```

Press `F2`, then:

```text
set adapter en11 host
set adapter en12 switch
set bridge queue-depth 256
set bridge overload fail-open
start bridge controlled
```

Use `fail-closed` instead only when dropping on overload is the intended lab
behavior. Retry Start after isolation if requested. Send the safe full set:

```bash
sudo .golan-packet-venv/bin/python 2tomac_packets.py --interface <sender-interface> --send
```

Review each retained branch:

```text
network filter addressing
network infrastructure
network filter dns
network services
network filter http
network filter access
network access 1
network filter risks
network fate 1
show bridge
show health
```

Expected packet-script contract:

- EAPOL numeric types `0`, `1`, `2`, `3`, `4`, and `5` are observed;
- EAP codes request, response, success, and failure are observed;
- Identity, Notification, NAK, MD5-Challenge, OTP, Generic Token Card, LEAP,
  and MSCHAPv2 are labeled;
- MD5, LEAP, and MSCHAPv2 create weak-authentication Risk rows;
- MACsec EtherType `0x88e5`, VLAN 37, DHCP options, ARP, LLDP, DNS, mDNS,
  SSDP, HTTP, and every listed categorical risk are visible;
- fake plaintext values stay redacted by default and never enter saved
  Network sessions.

### Policy enforcement check

The `block-internet` and `web-only` presets use Edge/NAT's `outbound`
direction, so they are not substitutes for an inline `host-to-switch` rule.
Draft an exact rule from the observed synthetic client instead:

```text
network rule draft 02:47:4f:4c:41:11
```

Rules opens a review-only block draft scoped to the source MAC and the
strongest current evidence. Review its conditions and LIVE compatibility, then
press `Ctrl+S` to commit it. Press `F2`, resend the matching group, and compare
the receiver capture plus:

```text
network filter actions
network fate 02:47:4f:4c:41:11
show rules
```

Expected: matching frames do not reach the opposite side and gain a blocked
Action/Fate result. Use `policy use controlled-bridge` afterward to return to
the allow policy, then press `F2` before entering more Main commands.

## 5. EAPOL relay and MACsec controls

The defaults keep a supplicant session alive by dropping host-to-switch
EAPOL-Logoff and suppress MACsec negotiation by dropping EAPOL-MKA type 5.
Start a receiver capture for EtherTypes `0x888e` and `0x88e5`, then send only
the access group from the `en11` host side:

```bash
sudo .golan-packet-venv/bin/python 2tomac_packets.py --interface <sender-interface> --group access --send
```

Expected in goLAN: every access fixture is observed on ingress. Expected on
the `en12` receiver with the defaults enabled: normal EAP/EAPOL exchange can
pass, while host Logoff and MKA are suppressed. `show bridge` prints both
control states.

After goLAN has learned the synthetic supplicant MAC from an EAPOL frame, test
the explicit action:

```text
send eapol start
```

Expected: an EAPOL-Start using the learned host identity appears toward
`en12`. A clear `host mac is not known` error means no acceptable host-side
EAPOL frame was learned; resend the access group from the correct side.

Now disable both controls and resend:

```text
disable eapol drop-logoff
disable eapol macsec-downgrade
show bridge
```

```bash
sudo .golan-packet-venv/bin/python 2tomac_packets.py --interface <sender-interface> --group access --send
```

Expected: Logoff and EAPOL-MKA are now eligible to cross. Re-enable the safe
defaults before the next run:

```text
enable eapol drop-logoff
enable eapol macsec-downgrade
```

## 6. Optional isolated control-plane observations

Only on an expendable isolated switch/link:

```bash
sudo .golan-packet-venv/bin/python 2tomac_packets.py \
  --interface <sender-interface> \
  --group discovery \
  --include-control-plane \
  --send
```

Expected:

```text
network infrastructure
network filter addressing
```

The inventory should include the LLDP system `golan-lab-switch`, the synthetic
STP root, IPv6 router `fe80::474f`, and prefix `2001:db8:37::/64`. These are
observations, not claims that the fixtures became the real infrastructure.

## 7. Authenticated-identity NAT

NAT is an optional Fast Bridge transition, not Edge Route. It moves the
learned/authenticated host identity onto the bridge endpoint, detaches the host
member, and obtains or applies that identity's IPv4 configuration. Use only on
a lab switch where the identity transition is expected.

Start a clean Fast Bridge. Activate the policy and press `F2`:

```text
policy use observe-everything
```

```text
set adapter en11 host
set adapter en12 switch
start bridge fast
```

Then send at least one host-side EAPOL frame using the attached device's real
MAC:

```bash
sudo .golan-packet-venv/bin/python 2tomac_packets.py \
  --interface <sender-interface> \
  --group access \
  --source-mac <attached-device-real-mac> \
  --send
```

Then:

```text
start nat
show nat
show bridge
show health
network filter access
```

With the default `auto` bridge settings, expected success is `nat state: on`,
the learned device MAC on the bridge endpoint, a DHCP-derived address on the
switch-side LAN, and owned PF/L2 restoration flags. A switch authentication or
DHCP rejection is a valid environmental failure and should be reported
explicitly rather than partially hidden.

Stop in dependency order:

```text
stop nat
show nat
stop bridge
show captures
cleanup
```

## 8. Final restoration checklist

```text
show adapters
show config
show health
doctor
```

Expected: no runtime, NAT, bridge, listener, PF owner, pending cleanup, or
staged role remains; `en11` and `en12` match their exact pre-goLAN service,
admin, MAC, and address state. If cleanup reports `[WARN]`, run `cleanup`
again. Completed restoration steps are retained and are not replayed.
