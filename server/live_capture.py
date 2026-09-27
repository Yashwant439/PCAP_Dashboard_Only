"""Bounded, metadata-only live packet capture using Scapy."""

from __future__ import annotations

import hashlib
import os
import time
from collections.abc import Iterable
from typing import Any

from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.ipsec import AH, ESP


def _pseudonymize(value: str) -> str:
    salt = os.environ.get("VPN_ANALYZER_PSEUDONYM_SALT", "local-only")
    return hashlib.sha256(f"{salt}:{value}".encode("utf-8")).hexdigest()[:24]


def _protocol(packet: Any) -> str:
    if ESP in packet:
        return "ESP"
    if AH in packet:
        return "AH"
    if UDP in packet:
        udp = packet[UDP]
        if udp.sport in (500, 4500) or udp.dport in (500, 4500):
            payload = bytes(udp.payload)
            if udp.sport == 4500 or udp.dport == 4500:
                if payload.startswith(b"\x00\x00\x00\x00"):
                    return "IKE"
                if len(payload) >= 8:
                    return "ESP"
            return "IKE"
        return "UDP"
    if TCP in packet:
        return "TCP"
    if ICMP in packet:
        return "ICMP"
    return "OTHER"


def packet_metadata(packet: Any, timestamp: float | None = None) -> dict[str, Any]:
    """Extract approved metadata without retaining or returning raw payloads."""
    source = destination = "unknown"
    if IP in packet:
        source, destination = packet[IP].src, packet[IP].dst
    elif IPv6 in packet:
        source, destination = packet[IPv6].src, packet[IPv6].dst

    protocol = _protocol(packet)
    result: dict[str, Any] = {
        "timestamp": timestamp if timestamp is not None else time.time(),
        "length": len(bytes(packet)),
        "protocol": protocol,
        "source_ip_hash": _pseudonymize(source),
        "destination_ip_hash": _pseudonymize(destination),
        "flow_id": _pseudonymize(f"{source}|{destination}|{protocol}"),
    }

    if ESP in packet or AH in packet:
        security = packet[ESP] if ESP in packet else packet[AH]
        result["spi"] = f"0x{int(security.spi):08x}"
        result["sequence_observed"] = int(security.seq)
    elif protocol == "ESP" and UDP in packet:
        payload = bytes(packet[UDP].payload)
        if payload.startswith(b"\x00\x00\x00\x00"):
            payload = payload[4:]
        result["spi"] = f"0x{int.from_bytes(payload[:4], 'big'):08x}"
        result["sequence_observed"] = int.from_bytes(payload[4:8], "big")

    if UDP in packet:
        result["source_port"] = int(packet[UDP].sport)
        result["destination_port"] = int(packet[UDP].dport)
    elif TCP in packet:
        result["source_port"] = int(packet[TCP].sport)
        result["destination_port"] = int(packet[TCP].dport)

    return result


def capture_live(
    interface: str | None = None,
    count: int = 0,
    timeout_seconds: int = 10,
) -> list[dict[str, Any]]:
    """Capture a bounded metadata window; count=0 means timeout-bounded only."""
    if count < 0 or timeout_seconds <= 0:
        raise ValueError("count must be non-negative and timeout_seconds must be positive")
    from scapy.sendrecv import sniff

    packets = sniff(
        iface=interface or None,
        count=count,
        timeout=timeout_seconds,
        store=True,
    )
    start = time.time()
    return [
        packet_metadata(packet, start + index * 0.000001)
        for index, packet in enumerate(packets)
    ]


def capture_from_packets(packets: Iterable[Any]) -> list[dict[str, Any]]:
    """Deterministic test seam for metadata extraction."""
    start = time.time()
    return [packet_metadata(packet, start + index * 0.000001) for index, packet in enumerate(packets)]
