# goLAN

Software Layer 2 network bridge for macOS; virtual female-to-female RJ45 adapter.

# WIP 2 802.1X

> [!IMPORTANT]
> Requires root privileges to run.

Built with Go, [Bubbletea](https://github.com/charmbracelet/bubbletea), and [Lipgloss](https://github.com/charmbracelet/lipgloss).

## Install

```bash
git clone https://github.com/mcrn/goLAN.git
cd goLAN
make install
# or 
go build -o .
```

## Packet Captures

goLAN writes passive captures under a timestamped directory:

`~/.config/goLAN/pcaps/<timestamp>/`

On exit it prints generated `.pcap` files. `--nuke` purges saved goLAN pcaps from the config directory.

# Example usage

[Guide of non 802.1x Setup](EXAMPLE.md)

[802.1X Scenario Walkthrough](SCENARIOS.md)

[Layer 2-first NAC Flow](NAC_FLOW.md)

## License

See [LICENSE](LICENSE) for details.
