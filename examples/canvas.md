# Canvas

Build a sanitized topology from the current Network inventory:

```text
network show
canvas build
canvas auto-layout
canvas snapshot /Users/alex/Labs/current.canvas
```

Build from a saved Network session instead:

```text
network session list
canvas build <network-session-id>
canvas snapshot /Users/alex/Labs/saved-session.canvas
```

Remove generated topology while retaining manual Canvas content:

```text
canvas reset-generated confirm
```

Canvas uses observations already held by goLAN and never imports a PCAP.
