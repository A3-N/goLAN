# Edge route

Give one directly connected host a DHCPv4 lease and route/NAT its traffic
through the Mac's LAN or internet adapter.

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
lease. It is not a general multi-client router.
