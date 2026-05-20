# Generic Non-802.1X Setup

This guide uses documentation-only placeholders. Do not replace them with real home-lab IPs, MACs, SSIDs, router screenshots, or adapter serials in committed files.

## Network Topology

You need two Ethernet interfaces or external adapters:

```text
Target device <--- device cable ---> goLAN <--- switch cable ---> switch/router
```

Suggested flow:

1. Connect the target device to the goLAN device-side adapter.
2. Keep the switch-side cable unplugged until goLAN has selected and locked down both adapters.
3. Start goLAN and choose the physical adapter connected to the target as LAN 1 / device-side.
4. Choose the physical adapter connected to the switch/router as LAN 2 / switch-side.
5. After goLAN reports that bridge setup is active, connect the switch-side cable.

## Example Target Values

Use documentation ranges and locally administered placeholder MACs in examples:

```text
MAC: 02:00:00:00:00:10
IPv4: 192.0.2.10
Gateway: 192.0.2.1
```

## Notes

- The real target MAC should be learned passively from Layer 2 traffic.
- IP, DHCP, gateway, DNS, VLAN, and service identity are enrichment signals; they must not block bridge readiness.
- Screenshots and photos from a lab environment can contain sensitive router names, hostnames, MACs, IPs, SSIDs, serial numbers, and cleartext findings. Keep those artifacts outside git.
