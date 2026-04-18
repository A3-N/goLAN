# goLAN

Software Layer 2 network bridge for macOS — a virtual female-to-female RJ45 adapter.

Built with Go, [Bubbletea](https://github.com/charmbracelet/bubbletea), and [Lipgloss](https://github.com/charmbracelet/lipgloss).

## What it does

Turns your Mac into a transparent Ethernet pass-through. Connect two Ethernet ports to your Mac, and goLAN bridges them at the kernel level — traffic flows between the ports as if they were directly connected with a physical coupler.

```
┌──────────┐          ┌──────────┐          ┌──────────┐
│  Switch   │──ethernet──│  Your Mac │──ethernet──│  Device   │
│           │          │  (goLAN)  │          │           │
└──────────┘          └──────────┘          └──────────┘
```

## Requirements

- macOS (uses `ifconfig bridge` under the hood)
- Two Ethernet interfaces (USB/Thunderbolt adapters work)
- Go 1.21+ to build
- Root privileges (`sudo`) to create the bridge

## Install

```bash
git clone https://github.com/mcrn/goLAN.git
cd goLAN
make build
```

## Usage

```bash
# Run the TUI (requires sudo)
sudo ./bin/golan

# Or use make
make run
```

### Cleanup

If gaLAN crashes or you need to remove stale bridges:

```bash
sudo ./bin/golan --cleanup
```

## Features

- **Interface Discovery** — Auto-detects Ethernet ports, filters out Wi-Fi/loopback
- **Visual Bridge Diagram** — See both interfaces and the bridge connection
- **Real-time Traffic Stats** — RX/TX bytes, packets, throughput
- **Sparkline Graphs** — Unicode throughput history visualization
- **Clean Teardown** — Bridge destroyed on quit, IP forwarding restored
- **Stale Bridge Cleanup** — `--cleanup` flag for crash recovery

## How it works

1. Select your two Ethernet interfaces (switch-side and device-side)
2. goLAN creates a macOS kernel bridge (`ifconfig bridge create`)
3. Both interfaces are added as bridge members
4. IP forwarding is enabled via `sysctl`
5. Traffic flows through at Layer 2 — completely transparent
6. On quit, the bridge is destroyed and settings are restored

## License

See [LICENSE](LICENSE) for details.
