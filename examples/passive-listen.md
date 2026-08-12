# Passive listen

Observe a selected adapter without forwarding traffic.

```text
show adapters
set adapter en7 host
policy use observe-everything
start listen
```

If the start reports adapter isolation is pending, wait for it to finish and
run `start listen` again.

Review the live inventory:

```text
show health
network show
network filter all
```

Stop cleanly and locate the automatic capture:

```text
stop listen
show captures
```
