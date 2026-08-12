#!/usr/bin/env python3
"""Inject the one-device-to-Mac goLAN observation fixtures."""

from golan_packet_lab import main

if __name__ == "__main__":
    main(
        "device -> en11 / en0 Wi-Fi -> network",
        "Run this on the attached device and select its cable-facing interface, not en11 on the goLAN Mac.",
    )
