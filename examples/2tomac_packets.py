#!/usr/bin/env python3
"""Inject the device-to-Mac-to-switch goLAN observation fixtures."""

from golan_packet_lab import main

if __name__ == "__main__":
    main(
        "device -> en11 / goLAN Mac / en12 -> switch",
        "Run this on a host physically attached on either side; use its cable-facing interface, not en11 or en12 on the goLAN Mac.",
    )
