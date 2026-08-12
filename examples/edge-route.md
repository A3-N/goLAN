# Edge route

Give one directly connected host a DHCPv4 lease and route/NAT its traffic
through the Mac's LAN, internet adapter, or an already-connected VPN tunnel.
The Mac keeps its own internet connection while the client is routed.

```text
Client host -- en11 [goLAN Mac] en0 -- LAN / Internet
```

```text
show adapters
set adapter en11 host
set edge mode route
set edge upstream auto
policy use open-internet
```

`auto` follows the Mac's current IPv4 default route. Use a concrete adapter,
such as `set edge upstream en0`, when you deliberately want that interface.
The upstream must not be `en11`.

The PF rules are scoped to the client subnet and downstream interface. They do
not install a new default route for the Mac or apply a host-wide IPv4/IPv6
block, so the Mac continues using its existing Wi-Fi and routing table.

## Route the client through a VPN

Connect the VPN on the Mac first, then find its IPv4 point-to-point interface
(commonly an interface such as `utun4`). goLAN validates that the named tunnel
is present, up, point-to-point, and has a usable IPv4 peer/next-hop. It also
uses the tunnel MTU to clamp downstream TCP MSS. It does not connect,
disconnect, or reconfigure the VPN.

For access only to private VPN destinations:

```text
set adapter en11 host
set edge egress vpn utun4
set edge vpn-destination 10.20.0.0/16
set edge dns 10.20.0.53
policy use open-internet
start edge route
```

Repeat `set edge vpn-destination <cidr>` for additional reachable networks.
The supplied DNS server must be IPv4 and inside one of those destinations.
The exception is a Mac-local resolver such as `127.0.0.1`: goLAN binds a DNS
relay to the downstream `.1` gateway, advertises `.1` instead of loopback, and
forwards both UDP and TCP DNS to the local resolver.

To let goLAN select the IPv4 resolver scoped by macOS to `utun4`, clear the
explicit setting before start:

```text
set edge dns clear
```

This reads `scutil --dns`, not `/etc/resolv.conf`. Automatic VPN DNS fails with
a direct error if macOS has no IPv4 resolver scoped to the selected tunnel.
Run `doctor` after staging to check the live point-to-point interface, resolver,
and exact PF anchor syntax without changing PF.
Use `set edge vpn-destination list` and `set edge dns list` to review the
staged values.

To route all of the client's IPv4 traffic through the VPN instead:

```text
set edge vpn-destination all
set edge dns 10.20.0.53
```

`all` replaces the destination list and cannot be combined with other
prefixes. VPN egress applies NAT and PF `route-to` only to the downstream
client. The Mac's own traffic keeps following the Mac's existing routes.
Traffic outside a restricted destination list is blocked, and a final source
subnet guard prevents fallback to Wi-Fi. goLAN checks the tunnel once per
second; if it disappears, Edge stops and cleans up fail-closed.

The client may use goLAN's DHCP service and optional DNS relay but is blocked
from other IPv4 and IPv6 services hosted by the Mac. `show health` reports the
DNS address advertised by DHCP, the real resolver upstreams, whether the relay
is active, and the derived egress MTU.

VPN products differ. A tunnel provider can reject forwarded or NATed traffic
even when the interface is otherwise healthy, so this requires a VPN that
allows routed client traffic. This first implementation supports IPv4
point-to-point tunnels, not layer-2/TAP tunnels or IPv6 VPN forwarding.
Encrypted DNS-only Network Extensions that expose no classic IPv4 DNS server
or port-53 loopback proxy cannot be reused as a raw downstream DNS server.

Return to ordinary system egress with:

```text
set edge egress system auto
```

Switching to system egress clears the staged VPN destination list.

Stage an optional inbound mapping before starting:

```text
set edge port-forward tcp 8443 443
set edge port-forward list
```

This maps upstream TCP port `8443` to TCP port `443` on the single DHCP client.

Start the router, then set the client interface to DHCP/automatic addressing:

```text
start edge route
```

If the start reports adapter isolation is pending, wait for it to finish and
run `start edge route` again.

Once `edge route active` appears, connect or renew DHCP on the client attached
to `en11`. `show health` reports the selected subnet and lease: goLAN uses `.1`
as the client gateway and gives the single client `.2`. The exact
`10.77.x.0/24` is selected to avoid the Mac's currently occupied IPv4 networks.

```text
show edge
show health
network filter addressing
network filter dns
network filter http
```

```text
stop edge
show captures
```

`stop edge` restores Edge-owned DHCP, alias, forwarding, and PF state but keeps
`en11` staged and isolated for another run. To stop everything, restore
`en11` to its exact pre-goLAN network-service and administrative state, and
clear the staged live configuration in one step:

```text
cleanup
show adapters
show health
```

If cleanup reports `[WARN]`, run `cleanup` again. Successful restoration steps
are not replayed. Cleanup preserves saved configs, policies, projects, and
captured evidence.

Edge route is IPv4-only and intentionally provides one deterministic client
lease. It is not a general multi-client router. VPN destination, DNS, egress,
and tunnel settings are saved with reusable goLAN configurations, while
`cleanup` resets the current staged live setup to system/auto defaults.
