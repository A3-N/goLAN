"""Bounded synthetic Ethernet traffic for the goLAN manual test guides.

This module is shared by 1tomac_packets.py and 2tomac_packets.py.  It defaults
to a dry run and requires both root and an explicit --send flag before it puts
one copy of each selected frame on an interface.
"""

from __future__ import annotations

import argparse
import os
import struct
import sys
from dataclasses import dataclass
from ipaddress import AddressValueError, IPv4Address
from typing import Any


@dataclass(frozen=True)
class PacketCase:
    name: str
    group: str
    expected: str
    packet: Any
    control_plane: bool = False


def _scapy() -> Any:
    try:
        import scapy.all as scapy  # type: ignore[import-not-found]
    except ModuleNotFoundError:
        raise SystemExit(
            "Scapy is required. Install it on the packet-sending test host with: "
            "python3 -m pip install --user scapy"
        ) from None
    return scapy


def _mac_bytes(value: str) -> bytes:
    parts = value.split(":")
    if len(parts) != 6:
        raise argparse.ArgumentTypeError("MAC addresses must contain six octets")
    try:
        raw = bytes(int(part, 16) for part in parts)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(
            "MAC addresses must use hexadecimal octets"
        ) from exc
    if raw[0] & 1 or raw == bytes(6):
        raise argparse.ArgumentTypeError(
            "source and peer MAC addresses must be non-zero unicast addresses"
        )
    return raw


def _ipv4(value: str) -> str:
    try:
        return str(IPv4Address(value))
    except AddressValueError as exc:
        raise argparse.ArgumentTypeError("addresses must be valid IPv4 values") from exc


def _eapol(packet_type: int, body: bytes = b"") -> bytes:
    return bytes((2, packet_type)) + struct.pack("!H", len(body)) + body


def _eap(
    code: int, identifier: int, method: int | None = None, data: bytes = b""
) -> bytes:
    body = b"" if method is None else bytes((method,)) + data
    return bytes((code, identifier)) + struct.pack("!H", 4 + len(body)) + body


def _lldp_tlv(kind: int, value: bytes) -> bytes:
    return struct.pack("!H", (kind << 9) | len(value)) + value


def build_cases(
    source_mac: str, peer_mac: str, source_ip: str, peer_ip: str
) -> list[PacketCase]:
    s = _scapy()
    Ether, ARP, IP, IPv6 = s.Ether, s.ARP, s.IP, s.IPv6
    TCP, UDP, Raw = s.TCP, s.UDP, s.Raw
    BOOTP, DHCP = s.BOOTP, s.DHCP
    DNS, DNSQR, DNSRR, DNSRRSRV = s.DNS, s.DNSQR, s.DNSRR, s.DNSRRSRV
    RA, Prefix = s.ICMPv6ND_RA, s.ICMPv6NDOptPrefixInfo

    broadcast = "ff:ff:ff:ff:ff:ff"
    pae = "01:80:c2:00:00:03"
    cases: list[PacketCase] = []

    def add(
        name: str,
        group: str,
        expected: str,
        packet: Any,
        *,
        control_plane: bool = False,
    ) -> None:
        cases.append(PacketCase(name, group, expected, packet, control_plane))

    add(
        "arp-who-has",
        "discovery",
        f"device {source_mac}; address {source_ip}; ARP request for {peer_ip}",
        Ether(src=source_mac, dst=broadcast)
        / ARP(
            op=1,
            hwsrc=source_mac,
            psrc=source_ip,
            hwdst="00:00:00:00:00:00",
            pdst=peer_ip,
        ),
    )

    dhcp_options = [
        ("message-type", "request"),
        ("server_id", "192.0.2.2"),
        ("hostname", "golan-lab-client"),
        ("subnet_mask", "255.255.255.0"),
        ("router", "192.0.2.1"),
        ("name_server", "192.0.2.53"),
        "end",
    ]
    add(
        "dhcp-options",
        "discovery",
        "DHCP Request; hostname, server, /24, gateway, and DNS observations",
        Ether(src=source_mac, dst=broadcast)
        / IP(src=source_ip, dst="255.255.255.255")
        / UDP(sport=68, dport=67)
        / BOOTP(
            op=1,
            xid=0x474F4C41,
            ciaddr=source_ip,
            yiaddr="192.0.2.21",
            chaddr=_mac_bytes(source_mac),
        )
        / DHCP(options=dhcp_options),
    )

    add(
        "vlan-37",
        "discovery",
        "VLAN 37 and IPv4 source/destination observations",
        Ether(src=source_mac, dst=peer_mac)
        / s.Dot1Q(vlan=37)
        / IP(src=source_ip, dst=peer_ip)
        / UDP(sport=40037, dport=40037)
        / Raw(b"golan-vlan-test"),
    )

    lldp = b"".join(
        (
            _lldp_tlv(1, b"\x04" + _mac_bytes(source_mac)),
            _lldp_tlv(2, b"\x05golan-test-port"),
            _lldp_tlv(3, struct.pack("!H", 120)),
            _lldp_tlv(5, b"golan-lab-switch"),
            _lldp_tlv(0, b""),
        )
    )
    add(
        "lldp-switch",
        "discovery",
        "LLDP chassis, port, and system name golan-lab-switch",
        Ether(src=source_mac, dst="01:80:c2:00:00:0e", type=0x88CC) / Raw(lldp),
    )

    bpdu = bytearray(35)
    bpdu[2], bpdu[3] = 0, 0
    bpdu[5:7] = struct.pack("!H", 0xF000)
    bpdu[7:13] = _mac_bytes(peer_mac)
    llc_bpdu = b"\x42\x42\x03" + bytes(bpdu)
    add(
        "stp-root",
        "discovery",
        f"STP root f000/{peer_mac}",
        Ether(src=source_mac, dst="01:80:c2:00:00:00", type=len(llc_bpdu))
        / Raw(llc_bpdu),
        control_plane=True,
    )

    add(
        "ipv6-router-advertisement-invalid-hop-limit",
        "discovery",
        "IPv6 router and 2001:db8:37::/64 prefix; receivers reject hop-limit 1",
        Ether(src=source_mac, dst="33:33:00:00:00:01")
        / IPv6(src="fe80::474f", dst="ff02::1", hlim=1)
        / RA()
        / Prefix(prefixlen=64, prefix="2001:db8:37::"),
        control_plane=True,
    )

    eap_methods = (
        (1, "identity"),
        (2, "notification"),
        (3, "nak"),
        (4, "md5-challenge"),
        (5, "otp"),
        (6, "generic-token-card"),
        (17, "leap"),
        (26, "mschapv2"),
    )
    identifier = 1
    for method, label in eap_methods:
        eap = _eap(1, identifier, method, b"golan-lab")
        add(
            f"eap-request-{label}",
            "access",
            f"EAPOL EAP; EAP code request; EAP method {label}",
            Ether(src=source_mac, dst=pae, type=0x888E) / Raw(_eapol(0, eap)),
        )
        identifier += 1
    for code, label in ((2, "response"), (3, "success"), (4, "failure")):
        method = 1 if code == 2 else None
        eap = _eap(code, identifier, method, b"golan-lab" if method else b"")
        add(
            f"eap-{label}",
            "access",
            f"EAPOL EAP; EAP code {label}"
            + ("; EAP method identity" if method else ""),
            Ether(src=source_mac, dst=pae, type=0x888E) / Raw(_eapol(0, eap)),
        )
        identifier += 1

    key_body = bytes((2,)) + bytes(94)
    for packet_type, label, body in (
        (1, "start", b""),
        (2, "logoff", b""),
        (3, "key", key_body),
        (4, "type-4-asf-alert", b"golan-asf-test"),
        (5, "mka", b"golan-mka-test"),
    ):
        add(
            "eapol-" + label,
            "access",
            "EAPOL " + label,
            Ether(src=source_mac, dst=pae, type=0x888E)
            / Raw(_eapol(packet_type, body)),
        )

    add(
        "macsec-ethernet",
        "access",
        "MACsec EtherType 0x88e5 and MACsec access warning",
        Ether(src=source_mac, dst=peer_mac, type=0x88E5)
        / Raw(b"\x20\x00golan-macsec-test"),
    )

    for qtype in ("A", "AAAA", "PTR"):
        qname = "golan-lab.example." if qtype != "PTR" else "20.2.0.192.in-addr.arpa."
        add(
            "dns-query-" + qtype.lower(),
            "applications",
            f"DNS {qtype} {qname.rstrip('.')}",
            Ether(src=source_mac, dst=peer_mac)
            / IP(src=source_ip, dst=peer_ip)
            / UDP(sport=53000 + len(cases), dport=53)
            / DNS(id=0x474F, rd=1, qd=DNSQR(qname=qname, qtype=qtype)),
        )

    mdns_answers = (
        DNSRR(
            rrname="_golan._tcp.local.",
            type="PTR",
            ttl=120,
            rdata="demo._golan._tcp.local.",
        )
        / DNSRRSRV(
            rrname="demo._golan._tcp.local.",
            type="SRV",
            ttl=120,
            priority=0,
            weight=0,
            port=8080,
            target="golan-device.local.",
        )
        / DNSRR(rrname="golan-device.local.", type="A", ttl=120, rdata=source_ip)
    )
    add(
        "mdns-service",
        "applications",
        "mDNS _golan._tcp service, target golan-device.local, port 8080",
        Ether(src=source_mac, dst="01:00:5e:00:00:fb")
        / IP(src=source_ip, dst="224.0.0.251", ttl=255)
        / UDP(sport=5353, dport=5353)
        / DNS(id=0, qr=1, aa=1, ancount=3, an=mdns_answers),
    )

    ssdp = (
        b"HTTP/1.1 200 OK\r\n"
        b"ST: urn:golan:device:test:1\r\n"
        b"Server: goLAN-packet-lab/1\r\n"
        b"Location: http://192.0.2.20/device.xml\r\n\r\n"
    )
    add(
        "ssdp-service",
        "applications",
        "SSDP service type, server, and query-free location",
        Ether(src=source_mac, dst=peer_mac)
        / IP(src=source_ip, dst=peer_ip, ttl=2)
        / UDP(sport=1900, dport=49152)
        / Raw(ssdp),
    )

    def tcp_packet(dport: int, payload: bytes, sport: int) -> Any:
        return (
            Ether(src=source_mac, dst=peer_mac)
            / IP(src=source_ip, dst=peer_ip)
            / TCP(sport=sport, dport=dport, flags="PA", seq=1, ack=1)
            / Raw(payload)
        )

    add(
        "http-request",
        "applications",
        "HTTP GET golan-lab.example/status",
        tcp_packet(
            80,
            b"GET /status HTTP/1.1\r\nHost: golan-lab.example\r\nConnection: close\r\n\r\n",
            41080,
        ),
    )
    add(
        "http-response",
        "applications",
        "HTTP response 204",
        tcp_packet(
            41081, b"HTTP/1.1 204 No Content\r\nServer: goLAN-packet-lab\r\n\r\n", 80
        ),
    )

    risk_packets: tuple[tuple[str, str, int, bytes, int], ...] = (
        (
            "http-basic",
            "HTTP Basic authentication [REDACTED]",
            80,
            b"GET /private HTTP/1.1\r\nHost: golan-lab.example\r\nAuthorization: Basic bGFiOnRlc3Q=\r\n\r\n",
            42001,
        ),
        (
            "http-form",
            "HTTP plaintext form authentication [REDACTED]",
            80,
            b"POST /login HTTP/1.1\r\nHost: golan-lab.example\r\nContent-Length: 27\r\n\r\nuser=lab&password=test-only",
            42002,
        ),
        ("ntlm", "NTLM authentication", 80, b"NTLMSSP\x00\x03golan-test", 42003),
        (
            "ftp",
            "FTP plaintext authentication [REDACTED]",
            21,
            b"USER lab\r\nPASS test-only\r\n",
            42004,
        ),
        (
            "smtp",
            "SMTP plaintext authentication [REDACTED]",
            25,
            b"AUTH PLAIN AGxhYgB0ZXN0LW9ubHk=\r\n",
            42005,
        ),
        (
            "pop3",
            "POP3 plaintext authentication [REDACTED]",
            110,
            b"USER lab\r\nPASS test-only\r\n",
            42006,
        ),
        (
            "imap",
            "IMAP plaintext authentication [REDACTED]",
            143,
            b'a1 LOGIN lab "test-only"\r\n',
            42007,
        ),
        (
            "irc",
            "IRC plaintext authentication [REDACTED]",
            6667,
            b"PASS test-only\r\nUSER lab 0 * :lab\r\n",
            42008,
        ),
        (
            "ldap",
            "LDAP simple bind [REDACTED]",
            389,
            bytes.fromhex("3012020101600d02010304036c61628003") + b"pwd",
            42009,
        ),
        (
            "kerberos",
            "KERBEROS RC4 pre-authentication",
            88,
            b"golan-test\x17rc4",
            42010,
        ),
        (
            "snmp-v1",
            "SNMP v1 community authentication [REDACTED]",
            161,
            bytes.fromhex("300b02010004067075626c6963"),
            42011,
        ),
        (
            "snmp-v2c",
            "SNMP v2c community authentication [REDACTED]",
            161,
            bytes.fromhex("300b02010104067075626c6963"),
            42012,
        ),
        (
            "mssql",
            "MSSQL login exchange",
            1433,
            b"\x12\x01\x00\x08\x00\x00\x00\x00",
            42013,
        ),
    )
    for name, expected, dport, payload, sport in risk_packets:
        transport = (
            UDP(sport=sport, dport=dport)
            if name in {"kerberos", "snmp-v1", "snmp-v2c"}
            else TCP(sport=sport, dport=dport, flags="PA", seq=1, ack=1)
        )
        add(
            "risk-" + name,
            "risks",
            expected,
            Ether(src=source_mac, dst=peer_mac)
            / IP(src=source_ip, dst=peer_ip)
            / transport
            / Raw(payload),
        )

    return cases


def run(topology: str, guidance: str) -> int:
    parser = argparse.ArgumentParser(
        description=f"Send bounded goLAN observation fixtures for the {topology} manual test."
    )
    parser.add_argument(
        "--interface",
        required=True,
        help="interface on the external packet-sending test host",
    )
    parser.add_argument(
        "--group",
        choices=("all", "discovery", "access", "applications", "risks"),
        default="all",
        help="one bounded fixture group (default: all)",
    )
    parser.add_argument(
        "--source-mac", default="02:47:4f:4c:41:11", help="synthetic unicast source MAC"
    )
    parser.add_argument(
        "--peer-mac", default="02:47:4f:4c:41:22", help="synthetic unicast peer MAC"
    )
    parser.add_argument(
        "--source-ip",
        default="192.0.2.20",
        type=_ipv4,
        help="synthetic TEST-NET source IPv4 address",
    )
    parser.add_argument(
        "--peer-ip",
        default="192.0.2.1",
        type=_ipv4,
        help="synthetic TEST-NET peer IPv4 address",
    )
    parser.add_argument(
        "--send",
        action="store_true",
        help="actually inject exactly one copy of each selected frame",
    )
    parser.add_argument(
        "--include-control-plane",
        action="store_true",
        help="include the bounded STP and intentionally invalid IPv6 RA fixtures on an isolated lab link",
    )
    args = parser.parse_args()

    _mac_bytes(args.source_mac)
    _mac_bytes(args.peer_mac)
    cases = build_cases(
        args.source_mac.lower(), args.peer_mac.lower(), args.source_ip, args.peer_ip
    )
    selected = [
        case
        for case in cases
        if (args.group == "all" or case.group == args.group)
        and (args.include_control_plane or not case.control_plane)
    ]

    print(f"topology: {topology}")
    print(f"interface: {args.interface}")
    print(guidance)
    print(f"frames: {len(selected)} group={args.group}")
    omitted = [
        case.name
        for case in cases
        if case.control_plane
        and (args.group == "all" or case.group == args.group)
        and not args.include_control_plane
    ]
    if omitted:
        print(
            "control-plane fixtures omitted: "
            + ", ".join(omitted)
            + " (use --include-control-plane only on an isolated lab link)"
        )
    for case in selected:
        print(f"  {case.name:<45} -> {case.expected}")

    if not args.send:
        print(
            "dry run: no packets sent; repeat with --send after goLAN reports the runtime active"
        )
        return 0
    if os.geteuid() != 0:
        raise SystemExit("packet injection requires root; rerun with sudo and --send")

    s = _scapy()
    interfaces = set(s.get_if_list())
    if args.interface not in interfaces:
        raise SystemExit(
            f"interface {args.interface!r} was not found on this test host; available: "
            + ", ".join(sorted(interfaces))
        )
    for case in selected:
        s.sendp(case.packet, iface=args.interface, count=1, inter=0, verbose=False)
        print("sent: " + case.name)
    print(f"complete: sent {len(selected)} bounded synthetic frames")
    return 0


def main(topology: str, guidance: str) -> None:
    try:
        raise SystemExit(run(topology, guidance))
    except argparse.ArgumentTypeError as exc:
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(2) from None
