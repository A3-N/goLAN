# Bridge

Forward transparently between a host-facing adapter and a switch-facing
adapter. The upstream network remains responsible for DHCP.

```text
Host -- en7 [goLAN Mac] en8 -- Switch / LAN
```

## Fast bridge

Use the macOS kernel forwarding path. Unsupported rule actions remain visible
as shadow behavior.

Stage the two adapters one at a time, waiting for each isolation operation to
finish before entering the next command.

```text
show adapters
set adapter en7 host
set adapter en8 switch
policy use observe-everything
start bridge fast
```

If the start reports adapter isolation is pending, wait for it to finish and
run `start bridge fast` again.

```text
show bridge
show health
network filter all
```

```text
stop bridge
show captures
```

## Controlled bridge

Use bounded userspace forwarding for supported live rule actions.
As with the fast bridge, wait for each adapter isolation before staging the
next adapter.

```text
set adapter en7 host
set adapter en8 switch
set bridge queue-depth 256
set bridge overload fail-open
policy use controlled-bridge
start bridge controlled
```

Use `fail-closed` instead when overload must drop rather than forward.
If adapter isolation is still pending, wait and repeat `start bridge
controlled`.

```text
show bridge
show health
stop bridge
```

Optional EAPOL controls can be staged before either bridge starts:

```text
enable eapol drop-logoff
enable eapol macsec-downgrade
```
