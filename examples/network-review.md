# Network review

Press `F3` to work with the device inventory. `#` is the stable discovery
number: the newest discovered device has the highest number at the top, and
later traffic does not reorder existing rows.

```text
network show
network filter all
network filter addressing
network filter dns
network filter http
network filter access
network filter risks
network filter actions
```

```text
network search printer
network search 192.0.2.25
network search clear
network reset
```

Review a saved, sanitized Network session:

```text
network session list
network session show <session-id>
show captures <session-id>
```

Use `Up`/`Down` to select a device and `Enter` to open one Inspector section.
Use `O` for Overview, `E` for Connection Explainer, `A` for Access Story, `F`
for Packet Fate, and `R` for a review-only rule draft. The full packet evidence
remains in the automatic capture. See [Network intelligence](network-intelligence.md)
for baselines, Infrastructure Watch, service mapping, passports, and guided
probes.
