# Rules and policies

Start with a built-in policy and inspect its runtime compatibility.

```text
policy use observe-everything
show rules
```

Other useful starting points:

```text
policy use open-internet
policy use web-only
policy use block-internet
policy use controlled-bridge
policy use high-latency
policy use packet-loss
```

Press `F4`, then use `r` to create a rule. `T` previews the draft against the
bounded live sample and `Ctrl+S` commits it.

```text
disable rule <rule-id>
enable rule <rule-id>
delete rule <rule-id>
```

Every change creates an immutable revision:

```text
policy history
policy compare <to-revision>
policy compare <from-revision> <to-revision>
policy rollback <revision>
```
