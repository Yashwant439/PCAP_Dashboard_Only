#!/usr/bin/env python3
"""Local Scapy-backed PCAP analyzer for the browser dashboard."""

from __future__ import annotations

import json
import math
import statistics
from collections import Counter
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from io import BytesIO
from typing import Any

import os
import sys
from pathlib import Path

_SERVER_DIR = Path(__file__).resolve().parent
_PROJECT_ROOT = _SERVER_DIR.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from scapy.all import AH, ESP, ICMP, IP, IPv6, TCP, UDP, rdpcap

HOST = os.environ.get("VPN_ANALYZER_SCAPY_HOST", "127.0.0.1")
PORT = 8765


def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    size = len(data)
    return round(-sum((n / size) * math.log2(n / size) for n in counts.values()), 3)


def hex_bytes(value: bytes) -> str:
    return value.hex()


NOTIFY_NAMES = {
    16384: "INITIAL_CONTACT",
    16385: "SET_WINDOW_SIZE",
    16386: "ADDITIONAL_TS_POSSIBLE",
    16387: "IPCOMP_SUPPORTED",
    16388: "NAT_DETECTION_SOURCE_IP",
    16389: "NAT_DETECTION_DESTINATION_IP",
    16390: "COOKIE",
    16391: "USE_TRANSPORT_MODE",
    16392: "HTTP_CERT_LOOKUP_SUPPORTED",
    16400: "ESP_TFC_PADDING_NOT_SUPPORTED",
    16406: "MOBIKE_SUPPORTED",
    16430: "FRAGMENTATION_SUPPORTED",
    16431: "SIGNATURE_HASH_ALGORITHMS",
}

IKE_V1_PAYLOAD_NAMES = {
    1: "SA", 2: "Proposal", 4: "KE", 5: "ID", 6: "CERT",
    7: "CERTREQ", 8: "HASH", 9: "SIG", 10: "NONCE",
    11: "NOTIFY", 12: "DELETE", 13: "VENDOR",
}

IKE_V1_EXCHANGE_NAMES = {
    2: "Main Mode", 4: "Aggressive Mode", 5: "Informational", 32: "Quick Mode",
}


def parse_traffic_selectors(body: bytes, label: str) -> list[str]:
    if len(body) < 4:
        return []
    count = body[0]
    offset = 4
    selectors: list[str] = []
    for index in range(count):
        if offset + 8 > len(body):
            break
        selector_type = body[offset]
        protocol = body[offset + 1]
        length = int.from_bytes(body[offset + 2:offset + 4], "big")
        if length < 8 or offset + length > len(body):
            break
        start_port = int.from_bytes(body[offset + 4:offset + 6], "big")
        end_port = int.from_bytes(body[offset + 6:offset + 8], "big")
        address_size = 4 if selector_type == 7 else 16 if selector_type == 8 else 0
        if address_size == 0 or length < 8 + address_size * 2:
            selectors.append(f"{label}[{index}] type={selector_type} protocol={protocol} length={length}")
            offset += length
            continue
        start = body[offset + 8:offset + 8 + address_size]
        end = body[offset + 8 + address_size:offset + 8 + address_size * 2]
        if address_size == 4:
            start_text = ".".join(str(value) for value in start)
            end_text = ".".join(str(value) for value in end)
        else:
            start_text = ":".join(start[i:i + 2].hex() for i in range(0, 16, 2))
            end_text = ":".join(end[i:i + 2].hex() for i in range(0, 16, 2))
        protocol_text = "ANY" if protocol == 0 else str(protocol)
        selectors.append(f"{label}[{index}] {start_text}-{end_text} proto={protocol_text} ports={start_port}-{end_port}")
        offset += length
    return selectors


def parse_ike(payload: bytes) -> dict[str, Any]:
    result: dict[str, Any] = {"valid": False, "proposals": [], "payloads": [], "notifications": [], "vendorIds": [], "trafficSelectors": [], "messageId": 0, "flags": []}
    if len(payload) < 28:
        return result

    version = payload[17]
    major = version >> 4
    if major not in (1, 2):
        return result

    message_length = int.from_bytes(payload[24:28], "big")
    if message_length < 28 or message_length > len(payload):
        return result

    result.update(
        valid=True,
        ikeVersion=f"IKEv{major}",
        exchangeType=payload[18],
        initiatorSpi="0x" + payload[:8].hex(),
        responderSpi="0x" + payload[8:16].hex(),
        messageId=int.from_bytes(payload[20:24], "big"),
        flags=[name for bit, name in ((0x20, "Response"), (0x10, "Version"), (0x08, "Initiator")) if payload[19] & bit],
    )

    payload_type = payload[16]
    offset = 28
    names = {
        33: "SA", 34: "KE", 35: "IDi", 36: "IDr", 37: "CERT",
        38: "CERTREQ", 39: "AUTH", 40: "NONCE", 41: "NOTIFY",
        42: "DELETE", 43: "VENDOR", 44: "TSi", 45: "TSr",
        46: "ENCRYPTED", 47: "CONFIGURATION", 48: "EAP",
    }
    while payload_type and offset + 4 <= message_length and len(result["payloads"]) < 100:
        next_type = payload[offset]
        length = int.from_bytes(payload[offset + 2:offset + 4], "big")
        if length < 4 or offset + length > message_length:
            break
        payload_names = IKE_V1_PAYLOAD_NAMES if major == 1 else names
        result["payloads"].append(payload_names.get(payload_type, f"Payload-{payload_type}"))
        if payload_type == 33 and major == 2:
            result["proposals"].extend(parse_sa(payload[offset + 4:offset + length]))
        elif ((major == 2 and payload_type == 41) or (major == 1 and payload_type == 11)) and length >= 8:
            notify_type = int.from_bytes(payload[offset + 6:offset + 8], "big")
            result["notifications"].append(NOTIFY_NAMES.get(notify_type, f"Notify-{notify_type}"))
            if notify_type in (16388, 16389):
                result.setdefault("natDetection", []).append(f"Notify-{notify_type}")
            if notify_type == 16430:
                result.setdefault("fragmentation", []).append("Supported")
        elif (major == 2 and payload_type == 43) or (major == 1 and payload_type == 13):
            result["vendorIds"].append("0x" + payload[offset + 4:offset + length].hex())
        elif payload_type in (44, 45):
            result["trafficSelectors"].extend(parse_traffic_selectors(payload[offset + 4:offset + length], names[payload_type]))
        payload_type = next_type
        offset += length
    return result


def parse_sa(body: bytes) -> list[dict[str, Any]]:
    proposals: list[dict[str, Any]] = []
    offset = 0
    while offset + 8 <= len(body):
        length = int.from_bytes(body[offset + 2:offset + 4], "big")
        if length < 8 or offset + length > len(body):
            break
        proposal_end = offset + length
        spi_size = body[offset + 6]
        transform_count = body[offset + 7]
        cursor = offset + 8
        spi = "0x" + body[cursor:cursor + spi_size].hex() if spi_size else ""
        cursor += spi_size
        transforms: list[dict[str, Any]] = []
        for _ in range(transform_count):
            if cursor + 8 > proposal_end:
                break
            transform_length = int.from_bytes(body[cursor + 2:cursor + 4], "big")
            if transform_length < 8 or cursor + transform_length > proposal_end:
                break
            # IKEv2 Transform: type is byte 4; byte 5 is reserved.
            transform_type = body[cursor + 4]
            transform_id = int.from_bytes(body[cursor + 6:cursor + 8], "big")
            attributes: dict[str, int] = {}
            attribute_offset = cursor + 8
            while attribute_offset + 4 <= cursor + transform_length:
                raw_type = int.from_bytes(body[attribute_offset:attribute_offset + 2], "big")
                raw_value = int.from_bytes(body[attribute_offset + 2:attribute_offset + 4], "big")
                attribute_type = raw_type & 0x7fff
                if raw_type & 0x8000:
                    attributes[str(attribute_type)] = raw_value
                    attribute_offset += 4
                else:
                    size = raw_value
                    if attribute_offset + 4 + size > cursor + transform_length:
                        break
                    if size <= 4:
                        attributes[str(attribute_type)] = int.from_bytes(
                            body[attribute_offset + 4:attribute_offset + 4 + size], "big"
                        )
                    attribute_offset += 4 + size
            transforms.append({
                "type": transform_type,
                "id": transform_id,
                "attributes": attributes,
                "rawBytes": hex_bytes(body[cursor:cursor + transform_length]),
                "attributeRawBytes": {},
            })
            cursor += transform_length
        proposals.append({
            "number": body[offset + 4],
            "protocolId": body[offset + 5],
            "spi": spi,
            "transforms": transforms,
        })
        offset = proposal_end
    return proposals


def transform_name(transform_type: int, transform_id: int) -> str:
    encryption = {
        1: "DES-IV64", 2: "DES", 3: "3DES", 10: "NULL", 11: "AES-CBC-OLD",
        12: "AES-CBC", 13: "AES-CTR", 14: "AES-CCM-8", 15: "AES-CCM-12",
        16: "AES-CCM-16", 18: "AES-GCM-8", 19: "AES-GCM-12", 20: "AES-GCM-16",
        28: "CHACHA20-POLY1305",
    }
    prf = {1: "PRF-HMAC-MD5", 2: "PRF-HMAC-SHA1", 4: "AES128-XCBC", 5: "PRF-HMAC-SHA2-256", 6: "PRF-HMAC-SHA2-384", 7: "PRF-HMAC-SHA2-512"}
    integrity = {1: "AUTH-HMAC-MD5-96", 2: "AUTH-HMAC-SHA1-96", 5: "AUTH-AES-XCBC-96", 12: "AUTH-HMAC-SHA2-256-128", 13: "AUTH-HMAC-SHA2-384-192", 14: "AUTH-HMAC-SHA2-512-256"}
    dh = {1: "DH Group 1 (MODP 768-bit)", 2: "DH Group 2 (MODP 1024-bit)", 5: "DH Group 5 (MODP 1536-bit)", 14: "DH Group 14 (MODP 2048-bit)", 19: "DH Group 19 (ECP 256-bit)", 20: "DH Group 20 (ECP 384-bit)", 21: "DH Group 21 (ECP 521-bit)", 31: "DH Group 31 (Curve25519)"}
    if transform_type == 1:
        return encryption.get(transform_id, f"Unknown Encryption {transform_id}")
    if transform_type == 2:
        return prf.get(transform_id, f"Unknown PRF {transform_id}")
    if transform_type == 3:
        return integrity.get(transform_id, f"Unknown Integrity {transform_id}")
    if transform_type == 4:
        return dh.get(transform_id, f"Unknown DH Group {transform_id}")
    if transform_type == 5:
        return "Extended Sequence Numbers" if transform_id == 1 else "No Extended Sequence Numbers"
    return f"Unknown Transform Type {transform_type} ID {transform_id}"


def analyze(data: bytes, filename: str) -> dict[str, Any]:
    packets = rdpcap(BytesIO(data))
    if not packets:
        raise ValueError("No packets found in capture file")
    first_time = float(packets[0].time)
    parsed_packets: list[dict[str, Any]] = []
    proposals: list[dict[str, Any]] = []
    evidence: list[dict[str, Any]] = []
    esp_lengths: list[int] = []
    esp_times: list[float] = []
    esp_bytes = bytearray()
    ip_versions: set[str] = set()
    ike_version = None
    initiator_spi = "Not observed in capture"
    responder_spi = "Not observed in capture"
    encryption = None
    key_bits = 0
    integrity = None
    dh_group = None
    dh_number = 0
    dh_bits = 0
    ike_packets = 0
    esp_packets = 0
    ah_packets = 0
    udp_packets = 0
    tcp_packets = 0
    icmp_packets = 0
    ike_exchanges: set[str] = set()
    ike_payloads: set[str] = set()
    ike_message_ids: set[int] = set()
    ike_notifications: set[str] = set()
    ike_flags: set[str] = set()
    ike_vendor_ids: set[str] = set()
    nat_detection: set[str] = set()
    fragmentation: set[str] = set()
    traffic_selectors: set[str] = set()
    esp_spis: set[str] = set()
    ah_spis: set[str] = set()
    ah_sequences: list[int] = []
    esp_flow_directions: set[str] = set()
    esp_sequences: list[int] = []
    esp_sequence_set: set[int] = set()
    esp_duplicate_sequences: set[int] = set()
    esp_out_of_order = False
    last_esp_sequence: int | None = None
    nat_traversal = False
    link_types: set[str] = set()
    first_ip = None
    up = down = 0

    for index, packet in enumerate(packets, 1):
        timestamp = (float(packet.time) - first_time) * 1000
        src = dst = "Unknown"
        protocol = "OTHER"
        info = ", ".join(layer.__name__ for layer in packet.layers())
        spi = None
        seq = None
        source_port = dest_port = None
        raw = bytes(packet)
        if packet.firstlayer() is not None:
            link_types.add(packet.firstlayer().__class__.__name__)

        if IP in packet:
            ip = packet[IP]
            src, dst = ip.src, ip.dst
            ip_versions.add("IPv4")
        elif IPv6 in packet:
            ip = packet[IPv6]
            src, dst = ip.src, ip.dst
            ip_versions.add("IPv6")

        if first_ip is None and src != "Unknown":
            first_ip = src
        if first_ip:
            if src == first_ip:
                up += len(packet)
            elif dst == first_ip:
                down += len(packet)

        if UDP in packet:
            udp_packets += 1
            udp = packet[UDP]
            source_port, dest_port = int(udp.sport), int(udp.dport)
            if source_port in (500, 4500) or dest_port in (500, 4500):
                protocol = "IKE"
                ike_packets += 1
                nat_traversal = nat_traversal or source_port == 4500 or dest_port == 4500
                payload = bytes(udp.payload)
                is_nat_t = source_port == 4500 or dest_port == 4500
                has_non_esp_marker = is_nat_t and payload.startswith(b"\x00\x00\x00\x00")
                if has_non_esp_marker:
                    payload = payload[4:]
                ike = parse_ike(payload)
                if ike.get("valid"):
                    ike_version = ike.get("ikeVersion")
                    ike_exchanges.add(str(ike.get("exchangeType")))
                    ike_payloads.update(ike.get("payloads", []))
                    ike_message_ids.add(int(ike.get("messageId", 0)))
                    ike_notifications.update(ike.get("notifications", []))
                    ike_flags.update(ike.get("flags", []))
                    ike_vendor_ids.update(ike.get("vendorIds", []))
                    nat_detection.update(ike.get("natDetection", []))
                    fragmentation.update(ike.get("fragmentation", []))
                    traffic_selectors.update(ike.get("trafficSelectors", []))
                    initiator_spi = ike.get("initiatorSpi", initiator_spi)
                    if ike.get("responderSpi") != "0x0000000000000000":
                        responder_spi = ike.get("responderSpi", responder_spi)
                    for proposal in ike.get("proposals", []):
                        proposal["packetNumber"] = index
                        for transform in proposal["transforms"]:
                            transform["name"] = transform_name(transform["type"], transform["id"])
                            transform["packetNumber"] = index
                            evidence.append({"value": transform["name"], "confidence": "exact", "source": "Scapy IKEv2 SA Proposal", "packetNumber": index, "rawBytes": transform["rawBytes"], "fieldPath": f"IKE.SA.Proposal[{proposal['number']}]"})
                            if transform["type"] == 1:
                                encryption = transform["name"]
                                key_bits = transform["attributes"].get("14", 0) or ({18: 128, 19: 192, 20: 256}.get(transform["id"], 0))
                            elif transform["type"] == 3:
                                integrity = transform["name"]
                            elif transform["type"] == 4:
                                dh_group, dh_number = transform["name"], transform["id"]
                                dh_bits = {
                                    1: 768, 2: 1024, 5: 1536, 14: 2048,
                                    15: 3072, 16: 4096, 17: 6144, 18: 8192,
                                    19: 256, 20: 384, 21: 521, 31: 255,
                                }.get(dh_number, 0)
                        proposals.append(proposal)
                    exchange_type = int(ike.get("exchangeType", 0))
                    exchange_name = (
                        IKE_V1_EXCHANGE_NAMES.get(exchange_type, f"IKEv1 Exchange {exchange_type}")
                        if ike_version == "IKEv1"
                        else f"exchange {exchange_type}"
                    )
                    info = f"{ike_version} {exchange_name} | {len(ike.get('proposals', []))} SA proposal(s)"
                else:
                    if is_nat_t and len(payload) >= 8:
                        protocol = "ESP"
                        ike_packets -= 1
                        esp_packets += 1
                        spi = f"0x{int.from_bytes(payload[:4], 'big'):08x}"
                        seq = int.from_bytes(payload[4:8], "big")
                        esp_spis.add(spi)
                        if seq in esp_sequence_set:
                            esp_duplicate_sequences.add(seq)
                        if last_esp_sequence is not None and seq < last_esp_sequence:
                            esp_out_of_order = True
                        last_esp_sequence = seq
                        esp_sequence_set.add(seq)
                        esp_sequences.append(seq)
                        esp_lengths.append(len(packet))
                        esp_times.append(timestamp)
                        esp_bytes.extend(payload)
                        info = f"ESP-in-UDP Encrypted Datagram | SPI {spi} | Seq {seq}"
                    else:
                        info = "IKE/ISAKMP UDP datagram"
            else:
                protocol = "UDP"
                info = f"UDP {source_port} -> {dest_port}"
        elif ESP in packet or (IP in packet and packet[IP].proto == 50) or (IPv6 in packet and packet[IPv6].nh == 50):
            protocol = "ESP"
            esp_packets += 1
            esp = packet[ESP] if ESP in packet else None
            if esp:
                spi, seq = f"0x{int(esp.spi):08x}", int(esp.seq)
                esp_spis.add(spi)
                esp_flow_directions.add(f"{src} -> {dst}")
                if seq in esp_sequence_set:
                    esp_duplicate_sequences.add(seq)
                if last_esp_sequence is not None and seq < last_esp_sequence:
                    esp_out_of_order = True
                last_esp_sequence = seq
                esp_sequence_set.add(seq)
                esp_sequences.append(seq)
                info = f"ESP Encrypted Datagram | SPI {spi} | Seq {seq}"
            esp_lengths.append(len(packet))
            esp_times.append(timestamp)
            esp_bytes.extend(raw[-max(0, len(raw) - 8):])
        elif AH in packet:
            protocol = "AH"
            ah_packets += 1
            ah = packet[AH]
            spi = f"0x{int(ah.spi):08x}"
            seq = int(ah.seq)
            ah_spis.add(spi)
            ah_sequences.append(seq)
            info = f"AH Authentication Header | SPI {spi} | Seq {seq}"
        elif TCP in packet:
            protocol = "OTHER"
            tcp_packets += 1
            info = f"TCP {source_port or packet[TCP].sport} -> {dest_port or packet[TCP].dport}"
        elif ICMP in packet:
            protocol = "ICMP"
            icmp_packets += 1
            info = f"ICMP type {packet[ICMP].type} code {packet[ICMP].code}"
        elif UDP in packet:
            protocol = "UDP"
            info = f"UDP {source_port} -> {dest_port}"

        parsed_packets.append({"id": index, "timestamp": max(0, round(timestamp, 3)), "sourceIp": src, "destIp": dst, "protocol": protocol, "length": len(packet), "info": info, "spi": spi, "seq": seq, "rawPreview": raw[:32].hex(), "sourcePort": source_port, "destPort": dest_port, "ipVersion": next(iter(ip_versions), None), "debug": packet.show(dump=True)[:4000]})

    iats = [b - a for a, b in zip(esp_times, esp_times[1:]) if 0 <= b - a < 5]
    total = sum(esp_lengths)
    mean = statistics.mean(esp_lengths) if esp_lengths else 0
    std = statistics.pstdev(esp_lengths) if len(esp_lengths) > 1 else 0
    symmetry = min(up, down) / max(up, down) if max(up, down) else 0
    sequence_range = "Not observed"
    if esp_sequences:
        sequence_range = f"{min(esp_sequences)} - {max(esp_sequences)}"
    observations = {
        "totalPackets": len(parsed_packets), "ikePackets": ike_packets,
        "espPackets": esp_packets, "ahPackets": ah_packets,
        "udpPackets": udp_packets, "tcpPackets": tcp_packets,
        "icmpPackets": icmp_packets, "ikeExchanges": sorted(ike_exchanges),
        "ikePayloads": sorted(ike_payloads), "ikeMessageIds": sorted(ike_message_ids),
        "ikeFlags": sorted(ike_flags), "ikeVendorIds": sorted(ike_vendor_ids),
        "ikeNotifications": sorted(ike_notifications),
        "natDetection": "Detected" if nat_detection else "Not detected",
        "fragmentation": "Supported" if fragmentation else "Not observed",
        "trafficSelectors": sorted(traffic_selectors),
        "natTraversal": "Detected" if nat_traversal else "Not detected",
        "espSpis": sorted(esp_spis), "ahSpis": sorted(ah_spis),
        "ahSequenceRange": f"{min(ah_sequences)} - {max(ah_sequences)}" if ah_sequences else "Not observed",
        "espFlowDirections": sorted(esp_flow_directions),
        "captureDurationMs": round((float(packets[-1].time) - first_time) * 1000, 3),
        "espSequenceRange": sequence_range,
        "espDuplicateSequences": sorted(esp_duplicate_sequences),
        "espOutOfOrder": "Observed" if esp_out_of_order else "Not observed",
        "espExtendedSequenceNumbers": "Not determined",
        "linkTypes": sorted(link_types),
        "captureNotes": [
            "IKE_AUTH encrypted payload contents were not decoded without session keys."
            if "ENCRYPTED" in ike_payloads else "",
            "Replay window configuration is not carried in ESP packets."
            if esp_packets else "",
        ],
    }
    observations["captureNotes"] = [note for note in observations["captureNotes"] if note]
    sa = {"ikeVersion": ike_version or "Not observed in capture", "operationalMode": "Not determined from capture", "ipVersion": next(iter(ip_versions), "Not observed in capture"), "encryptionAlgorithm": encryption or "Not observed in capture", "encryptionKeyBits": key_bits, "authIntegrityAlgorithm": integrity or "Not observed in capture", "dhGroup": dh_group or "Not observed in capture", "dhGroupNumber": dh_number, "dhBits": dh_bits, "pfsEnabled": None, "keyLifetimeSeconds": None, "replayProtection": None, "replayWindowSize": None, "initiatorSpi": initiator_spi, "responderSpi": responder_spi, "proposals": proposals, "evidence": evidence or [{"value": None, "confidence": "unavailable", "source": "PCAP capture", "fieldPath": "IKE.SA"}], "observations": observations}

    ml_predictions = None
    ml_security_findings = []
    ml_warning = None
    try:
        from backend.app.feature_extraction import extract_features_from_bytes, validate_ml_features
        from backend.app.ml_inference import run_inference
        from backend.app.ml_assessment import assess_ml_results

        raw_ml_feats = extract_features_from_bytes(data, filename)
        validated_ml_feats = validate_ml_features(raw_ml_feats)
        ml_predictions = run_inference(validated_ml_feats)
        ml_security_findings = assess_ml_results(ml_predictions, raw_ml_feats)
    except Exception as exc:
        ml_warning = f"ML inference unavailable: {exc}"

    return {
        "scenarioName": filename.rsplit(".", 1)[0],
        "packets": parsed_packets,
        "sa": sa,
        "features": {
            "packetCount": len(esp_lengths),
            "totalBytes": total,
            "meanPacketLength": round(mean),
            "stdPacketLength": round(std),
            "minPacketLength": min(esp_lengths, default=0),
            "maxPacketLength": max(esp_lengths, default=0),
            "meanInterArrivalTimeMs": round(statistics.mean(iats), 1) if iats else 0,
            "burstRatio": 0.9 if iats and statistics.mean(iats) < 10 else 0.6 if iats and statistics.mean(iats) < 40 else 0.25 if iats else 0,
            "flowSymmetry": round(symmetry, 2),
            "calculatedEntropy": entropy(bytes(esp_bytes)),
            "flowDurationMs": round((float(packets[-1].time) - first_time) * 1000, 3)
        },
        "fileSizeBytes": len(data),
        "evidence": evidence,
        "mlPredictions": ml_predictions,
        "mlSecurityFindings": ml_security_findings,
        "mlWarning": ml_warning,
    }


class Handler(BaseHTTPRequestHandler):
    def do_OPTIONS(self) -> None:
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, X-Filename")
        self.end_headers()

    def do_POST(self) -> None:
        if self.path != "/analyze":
            self.send_error(404)
            return
        try:
            size = int(self.headers.get("Content-Length", "0"))
            result = analyze(self.rfile.read(size), self.headers.get("X-Filename", "capture.pcap"))
            body = json.dumps(result).encode()
            self.send_response(200)
        except Exception as exc:
            body = json.dumps({"error": str(exc)}).encode()
            self.send_response(400)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:
        print(f"[scapy] {format % args}")


if __name__ == "__main__":
    print(f"Scapy analyzer listening on http://{HOST}:{PORT}")
    ThreadingHTTPServer((HOST, PORT), Handler).serve_forever()
