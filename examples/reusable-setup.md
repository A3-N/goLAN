# Reusable setup

Stage adapter settings directly:

```text
show adapters
set adapter en7 host
conf en7
set label Lab client
set ip 192.0.2.10
set cidr 24
set gateway 192.0.2.1
set dns 1.1.1.1,9.9.9.9
set mtu 1500
set dhcp manual
set notes Authorized lab setup
show config
```

Run `settings` for the guided transaction instead. `Ctrl+S` validates and
saves the draft.

Without an active project, `Ctrl+S` opens the setup-save flow. Reuse it later:

```text
load
load office-lab
show config
```

Loading a setup only stages it; networking still requires an explicit
`start ...` command.
