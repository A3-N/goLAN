# goLAN examples

These are task-focused Workbench flows. Run `sudo golan` first for live
networking, replace example adapter names with values from `show adapters`, and
enter the remaining commands in Main.

| Goal | Guide |
| --- | --- |
| Manually test one device through en11 with en0 Wi-Fi upstream | [One device to a Mac](1tomac.md) |
| Manually test en11-to-en12 inline forwarding and packet recognition | [One device through a Mac to a switch](2tomac.md) |
| Observe traffic without forwarding it | [Passive listen](passive-listen.md) |
| Observe one directly connected host | [Edge observe](edge-observe.md) |
| Give one host DHCP and route it to a LAN or the web | [Edge route](edge-route.md) |
| Forward transparently between a host and switch | [Bridge](bridge.md) |
| Forward using the authenticated endpoint identity | [NAT](nat.md) |
| Review devices and useful observations | [Network review](network-review.md) |
| Baseline, explain, verify, and act on observations | [Network intelligence](network-intelligence.md) |
| Create and switch packet policies | [Rules and policies](rules-and-policies.md) |
| Save and reuse staged adapter settings | [Reusable setup](reusable-setup.md) |
| Create, save, and exchange project evidence | [Projects and bundles](projects-and-bundles.md) |
| Resolve interrupted goLAN artifacts | [Recovery](recovery.md) |
| Build a topology Canvas from observations | [Canvas](canvas.md) |

Main's CLI does not expand `~`; use absolute macOS paths without spaces in
direct path commands. Run `help` or press `F1` for the complete command manual.
