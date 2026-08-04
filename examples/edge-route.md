# Edge route

Give one directly connected host a DHCPv4 lease and route/NAT its traffic
through the Mac's LAN or internet adapter.

```text
Client host -- en7 [goLAN Mac] en0 -- LAN / Internet
```

```text
show adapters
set adapter en7 host
set edge mode route
set edge upstream en0
policy use open-internet
```

Use `set edge upstream auto` instead of `en0` to follow the current default
route.

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

Edge route is IPv4-only and intentionally provides one deterministic client
lease. It is not a general multi-client router.
