# Edge observe

Passively observe one host connected to a dedicated Mac adapter. This mode
does not provide DHCP, NAT, or forwarding.

```text
show adapters
set adapter en7 host
set edge mode observe
policy use observe-everything
start edge observe
```

If the start reports adapter isolation is pending, wait for it to finish and
run `start edge observe` again.

```text
network filter addressing
network filter dns
network filter http
show health
```

```text
stop edge
show captures
```
