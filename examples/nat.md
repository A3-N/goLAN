# NAT

Start a fast bridge, then enable the reversible authenticated-identity
forwarding path. Wait for each adapter isolation operation before entering the
next adapter command.

```text
show adapters
set adapter en7 host
set adapter en8 switch
policy use observe-everything
start bridge fast
```

If the bridge start reports adapter isolation is pending, wait and repeat
`start bridge fast`.

Wait until `show bridge` reports the fast bridge active, then start NAT:

```text
start nat
```

```text
show nat
show bridge
show health
network filter access
```

Stop NAT before stopping its bridge:

```text
stop nat
stop bridge
show captures
```
