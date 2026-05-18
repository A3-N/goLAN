# goLAN

Software Layer 2 network bridge for macOS; virtual female-to-female RJ45 adapter.

# WIP 802.1X / NAC Layer 2 bridging

> [!IMPORTANT]
> Requires root privileges to run.

goLAN now operates as an unnumbered Layer 2 bridge. It passively learns the
target device MAC from the device-side adapter, keeps the switch-side adapter
down until that MAC is learned, and does not request DHCP, assign a bridge IP,
enable PF/NAT, or turn on IP forwarding. A narrow raw relay handles L2 control
frames such as EAPOL and LLDP that kernel bridges may otherwise suppress.

For the intended layout, connect the printer to the Device Port first and keep
the Switch Port cable unplugged until goLAN reports the L2 bridge active.

Built with Go, [Bubbletea](https://github.com/charmbracelet/bubbletea), and [Lipgloss](https://github.com/charmbracelet/lipgloss).

![alt text](img/G3.png)

## Install

```bash
git clone https://github.com/mcrn/goLAN.git
cd goLAN
make install
# or 
go build -o .
```

# Example usage

[Guide of non 802.1x Setup](EXAMPLE.md)

## License

See [LICENSE](LICENSE) for details.
