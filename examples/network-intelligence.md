# Network intelligence

This workflow turns two short live observations into a readable change report,
then follows one device from evidence to a reviewed rule. It does not import or
replay a PCAP.

## 1. Save a known-good observation

Start a passive session, let the initial DHCP, ARP, DNS, mDNS, LLDP, STP, and
access exchanges settle, then stop it. goLAN saves the sanitized Network
session and its automatic capture separately.

```text
start listen
network show
stop listen
network session list
network baseline set <known-good-session-id>
project save
```

Expected shape:

```text
network sessions: 1
  listen-... mode=listen devices=14 observations=38 started=...
network baseline: listen-... (PROJECT*)
project: saved /Users/me/.config/goLAN/projects/Lab.golan
```

## 2. Observe the current network and compare it

```text
start listen
network compare baseline
network infrastructure
network services
```

A change report prioritizes control-plane drift before ordinary inventory
changes:

```text
network compare: baseline=listen-... current=listen-... changes=3
  [FAIL] CRITICAL gateway changed · 02:00:00:00:00:fe
    before=192.0.2.1 via 02:00:00:00:00:01 after=192.0.2.254 via 02:00:00:00:00:fe
  [WARN] CHANGED  IP addresses changed · 02:00:00:00:00:20
    before=192.0.2.20 after=192.0.2.87
  [PASS] NEW      new device observed · 02:00:00:00:00:44
```

Infrastructure Watch can also expose competing DHCP servers, gateways, IPv6
routers, STP roots, and duplicate IP ownership. The service map shows bounded
mDNS and SSDP identities attached to the advertising MAC; it omits arbitrary
TXT records and query-bearing URLs.

## 3. Explain one device

Use the visible discovery number, MAC, IP, or hostname:

```text
network identity 7
network explain 7
network access 7
network fate 7
```

Expected shape:

```text
network identity: printer.local confidence=HIGH score=95 mac=02:00:00:00:00:44
network explain: first proven failure: Access — latest 802.1X result is failure
  [PASS] Link         device observed on en7 · 02:00:00:00:00:44
  [FAIL] Access       latest 802.1X result is failure · 2 attempt(s)
  [PASS] Addressing   192.0.2.87 · DHCP
  [PASS] Neighbor     neighbor resolution evidence observed
  [PASS] Gateway      192.0.2.254 · DHCP or directly observed addressing
  [PASS] DNS          DNS configuration or query evidence observed
  [WARN] Transport    4 packet outcome(s) not directly proven
  [SKIP] Application  no readable application evidence; encrypted payloads are not interpreted
```

In the Network Inspector, the same focused views are available as `O Overview`,
`E Explain`, `A Access`, and `F Fate`. Packet Fate reports only bounded flow
outcomes and confidence; it is not packet history.

## 4. Exchange a safe fingerprint

```text
network passport save /Users/me/Desktop/lab.golanpass
network passport verify /Users/me/Desktop/lab.golanpass
network passport compare /Users/me/Desktop/lab.golanpass
```

The checksum covers the whole passport document. A passport carries device,
infrastructure, service, access-result, and identity-confidence fingerprints.
It excludes captures, raw observations, paths, packet outcomes, and secrets.
Saving refuses to replace an existing destination.

## 5. Run a bounded diagnostic

Planning is inert and running is a separate confirmation step:

```text
network probe plan gateway 192.0.2.254
network probe run

network probe plan dns printer.local
network probe run

network probe plan route 198.51.100.20
network probe run

network probe plan device 192.0.2.87 443
network probe run

network probe plan dhcp en7
network probe run
```

Each plan runs once with a three-second deadline. Gateway uses one macOS ICMP
echo. DNS uses the system resolver. Route selects a local kernel path without
sending application data. Device opens and closes one exact TCP endpoint. DHCP
reads the existing macOS lease without solicitation or renewal.

## 6. Draft a rule from evidence

```text
network rule draft 7
```

goLAN opens Rules with a typed block draft scoped to the observed source MAC,
VLAN when known, and the strongest useful protocol evidence. Nothing is
committed or enforced. Review every condition, press `T` for a bounded live
sample preview when available, and press `Ctrl+S` only when the rule scope is
correct.
