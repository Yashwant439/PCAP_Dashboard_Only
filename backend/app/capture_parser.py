import ipaddress
import struct
from dataclasses import dataclass
from typing import Iterable

from .models import (
    CaptureAnalysis,
    IKEMessage,
    IKEProposal,
    IKETransform,
    ParsedPacket,
    ParserIssue,
    ProtocolSummary,
    TrafficSelector,
)
from .sa_correlator import correlate_security_associations
from .security_analysis import assess_security


class CaptureParseError(ValueError):
    pass


@dataclass(frozen=True)
class LinkPacket:
    payload: bytes
    network_type: int | None
    source_mac: str | None = None
    destination_mac: str | None = None


def _mac(value: bytes) -> str:
    return ":".join(f"{byte:02x}" for byte in value)


def _read_uint(data: bytes, offset: int, size: int, byte_order: str) -> int:
    if offset < 0 or offset + size > len(data):
        raise CaptureParseError(f"read exceeds capture boundary at offset {offset}")
    return int.from_bytes(data[offset:offset + size], byte_order)


def _format_ip(data: bytes) -> str:
    return str(ipaddress.ip_address(data))


def _ethernet(frame: bytes) -> LinkPacket:
    if len(frame) < 14:
        raise CaptureParseError("Ethernet frame is shorter than 14 bytes")
    network_type = int.from_bytes(frame[12:14], "big")
    offset = 14
    while network_type in {0x8100, 0x88A8, 0x9100}:
        if len(frame) < offset + 4:
            raise CaptureParseError("truncated VLAN header")
        network_type = int.from_bytes(frame[offset + 2:offset + 4], "big")
        offset += 4
    return LinkPacket(
        payload=frame[offset:],
        network_type=network_type,
        source_mac=_mac(frame[6:12]),
        destination_mac=_mac(frame[0:6]),
    )


def _link_payload(frame: bytes, link_type: int) -> LinkPacket:
    if link_type == 1:
        return _ethernet(frame)
    if link_type == 113:
        if len(frame) < 16:
            raise CaptureParseError("Linux cooked frame is shorter than 16 bytes")
        return LinkPacket(payload=frame[16:], network_type=int.from_bytes(frame[14:16], "big"))
    if link_type == 0:
        if len(frame) < 4:
            raise CaptureParseError("loopback frame is shorter than 4 bytes")
        family = int.from_bytes(frame[:4], "little")
        network_type = 0x0800 if family in {2, 24, 28, 30} else 0x86DD if family in {10, 23, 26, 28} else None
        return LinkPacket(payload=frame[4:], network_type=network_type)
    raise CaptureParseError(f"unsupported link type {link_type}")


def _ipv6_next_header(payload: bytes, next_header: int, offset: int) -> tuple[int, int]:
    extension_headers = {0, 43, 44, 50, 51, 60}
    while next_header in extension_headers and next_header not in {50, 51}:
        if next_header == 44:
            if offset + 8 > len(payload):
                raise CaptureParseError("truncated IPv6 fragment header")
            next_header = payload[offset]
            offset += 8
            continue
        if offset + 2 > len(payload):
            raise CaptureParseError("truncated IPv6 extension header")
        header_length = (payload[offset + 1] + 1) * 8
        if offset + header_length > len(payload):
            raise CaptureParseError("IPv6 extension header exceeds packet boundary")
        next_header = payload[offset]
        offset += header_length
    return next_header, offset


def _protocol_name(protocol: int) -> str:
    return {1: "ICMP", 6: "TCP", 17: "UDP", 50: "ESP", 51: "AH"}.get(protocol, f"IP-{protocol}")


def _transform_name(transform_type: int, transform_id: int) -> str | None:
    names = {
        1: {3: "3DES", 12: "AES-CBC", 13: "AES-CTR", 18: "AES-GCM-8", 19: "AES-GCM-12", 20: "AES-GCM-16", 28: "ChaCha20-Poly1305"},
        2: {2: "PRF-HMAC-MD5", 3: "PRF-HMAC-SHA1", 5: "PRF-HMAC-SHA2-256", 6: "PRF-HMAC-SHA2-384", 7: "PRF-HMAC-SHA2-512"},
        3: {0: "NONE", 2: "HMAC-MD5-96", 3: "HMAC-SHA1-96", 12: "HMAC-SHA2-256-128", 13: "HMAC-SHA2-384-192", 14: "HMAC-SHA2-512-256"},
        4: {1: "DH Group 1", 2: "DH Group 2", 5: "DH Group 5", 14: "DH Group 14", 19: "DH Group 19", 20: "DH Group 20", 21: "DH Group 21"},
        5: {0: "No ESN", 1: "ESN"},
    }
    return names.get(transform_type, {}).get(transform_id)


def _parse_transform(data: bytes, packet_number: int) -> IKETransform | None:
    if len(data) < 8:
        return None
    transform_length = int.from_bytes(data[2:4], "big")
    if transform_length < 8 or transform_length > len(data):
        return None
    transform_type = data[4]
    transform_id = int.from_bytes(data[6:8], "big")
    attributes: dict[int, int | str] = {}
    offset = 8
    while offset + 4 <= transform_length:
        attribute_type = int.from_bytes(data[offset:offset + 2], "big")
        attribute_value = int.from_bytes(data[offset + 2:offset + 4], "big")
        is_tv = bool(attribute_type & 0x8000)
        attribute_number = attribute_type & 0x7FFF
        offset += 4
        if is_tv:
            attributes[attribute_number] = attribute_value
            continue
        if offset + attribute_value > transform_length:
            break
        raw_value = data[offset:offset + attribute_value]
        attributes[attribute_number] = int.from_bytes(raw_value, "big") if len(raw_value) <= 8 else raw_value.hex()
        offset += attribute_value
    return IKETransform(
        transform_type=transform_type,
        transform_id=transform_id,
        name=_transform_name(transform_type, transform_id),
        attributes=attributes,
        packet=packet_number,
    )


def _parse_proposals(data: bytes, packet_number: int) -> list[IKEProposal]:
    proposals: list[IKEProposal] = []
    offset = 0
    while offset + 8 <= len(data):
        proposal_length = int.from_bytes(data[offset + 2:offset + 4], "big")
        if proposal_length < 8 or offset + proposal_length > len(data):
            break
        proposal_number = data[offset + 4]
        protocol_id = data[offset + 5]
        spi_size = data[offset + 6]
        transform_count = data[offset + 7]
        spi_start = offset + 8
        transform_offset = spi_start + spi_size
        if transform_offset > offset + proposal_length:
            break
        proposal = IKEProposal(
            proposal_number=proposal_number,
            protocol_id=protocol_id,
            spi=data[spi_start:transform_offset].hex() or None,
            packet=packet_number,
        )
        for _ in range(transform_count):
            transform = _parse_transform(data[transform_offset:offset + proposal_length], packet_number)
            if transform is None:
                break
            proposal.transforms.append(transform)
            transform_length = int.from_bytes(data[transform_offset + 2:transform_offset + 4], "big")
            transform_offset += transform_length
        proposals.append(proposal)
        offset += proposal_length
    return proposals


def _parse_traffic_selectors(data: bytes, packet_number: int) -> list[TrafficSelector]:
    if len(data) < 8:
        return []
    count = int.from_bytes(data[:4], "big")
    offset = 8
    selectors: list[TrafficSelector] = []
    for _ in range(count):
        if offset + 8 > len(data):
            break
        selector_type = data[offset]
        ip_protocol = data[offset + 1]
        selector_length = int.from_bytes(data[offset + 2:offset + 4], "big")
        if selector_length < 8 or offset + selector_length > len(data):
            break
        start_port = int.from_bytes(data[offset + 4:offset + 6], "big")
        end_port = int.from_bytes(data[offset + 6:offset + 8], "big")
        address_length = 4 if selector_type == 7 else 16 if selector_type == 8 else 0
        if address_length == 0 or selector_length < 8 + address_length * 2:
            offset += selector_length
            continue
        start_address = _format_ip(data[offset + 8:offset + 8 + address_length])
        end_address = _format_ip(data[offset + 8 + address_length:offset + 8 + address_length * 2])
        selectors.append(
            TrafficSelector(
                selector_type=selector_type,
                ip_protocol=ip_protocol,
                start_port=start_port,
                end_port=end_port,
                start_address=start_address,
                end_address=end_address,
                packet=packet_number,
            )
        )
        offset += selector_length
    return selectors


def _parse_ike_message(data: bytes, packet_number: int) -> IKEMessage | None:
    if len(data) < 28:
        return None
    message_length = int.from_bytes(data[24:28], "big")
    if message_length < 28:
        return None
    bounded = data[:min(message_length, len(data))]
    next_payload = data[16]
    payload_offset = 28
    payload_types: list[int] = []
    proposals: list[IKEProposal] = []
    traffic_selectors_i: list[TrafficSelector] = []
    traffic_selectors_r: list[TrafficSelector] = []
    fragment_number: int | None = None
    fragment_total: int | None = None
    while next_payload and payload_offset + 4 <= len(bounded):
        payload_type = next_payload
        next_payload = bounded[payload_offset]
        payload_length = int.from_bytes(bounded[payload_offset + 2:payload_offset + 4], "big")
        if payload_length < 4 or payload_offset + payload_length > len(bounded):
            break
        payload_types.append(payload_type)
        payload_body = bounded[payload_offset + 4:payload_offset + payload_length]
        if payload_type == 33:
            proposals.extend(_parse_proposals(payload_body, packet_number))
        elif payload_type == 44:
            traffic_selectors_i = _parse_traffic_selectors(payload_body, packet_number)
        elif payload_type == 45:
            traffic_selectors_r = _parse_traffic_selectors(payload_body, packet_number)
        elif payload_type == 132 and len(payload_body) >= 4:
            fragment_number = int.from_bytes(payload_body[:2], "big") or None
            fragment_total = int.from_bytes(payload_body[2:4], "big") or None
        payload_offset += payload_length
    return IKEMessage(
        initiator_spi=f"0x{data[:8].hex()}",
        responder_spi=f"0x{data[8:16].hex()}",
        version=f"IKEv{data[17] >> 4}",
        next_payload=data[16],
        exchange_type=data[18],
        flags=data[19],
        message_id=int.from_bytes(data[20:24], "big"),
        length=message_length,
        payload_types=payload_types,
        proposals=proposals,
        traffic_selectors_i=traffic_selectors_i,
        traffic_selectors_r=traffic_selectors_r,
        encrypted_payload=46 in payload_types or 53 in payload_types or 132 in payload_types,
        fragmented=132 in payload_types,
        fragment_number=fragment_number,
        fragment_total=fragment_total,
        packet=packet_number,
    )


def _decode_network_packet(packet_number: int, timestamp: float, frame: bytes, link_type: int) -> ParsedPacket:
    link = _link_payload(frame, link_type)
    payload = link.payload
    source_ip: str | None = None
    destination_ip: str | None = None
    protocol_number: int | None = None
    transport_offset = 0
    ip_version: str | None = None

    if link.network_type == 0x0800:
        if len(payload) < 20:
            raise CaptureParseError("IPv4 packet is shorter than 20 bytes")
        version = payload[0] >> 4
        ihl = (payload[0] & 0x0F) * 4
        if version != 4 or ihl < 20 or len(payload) < ihl:
            raise CaptureParseError("invalid IPv4 header")
        ip_version = "IPv4"
        source_ip = _format_ip(payload[12:16])
        destination_ip = _format_ip(payload[16:20])
        protocol_number = payload[9]
        transport_offset = ihl
    elif link.network_type == 0x86DD:
        if len(payload) < 40 or payload[0] >> 4 != 6:
            raise CaptureParseError("invalid IPv6 header")
        ip_version = "IPv6"
        source_ip = _format_ip(payload[8:24])
        destination_ip = _format_ip(payload[24:40])
        protocol_number, transport_offset = _ipv6_next_header(payload, payload[6], 40)
    else:
        return ParsedPacket(
            number=packet_number,
            timestamp=timestamp,
            length=len(frame),
            protocol="UNKNOWN",
            source_ip=None,
            destination_ip=None,
            ip_version=None,
            info=f"Unsupported network type 0x{link.network_type:04x}" if link.network_type else "Unknown network type",
            raw_preview=frame[:32].hex(" "),
        )

    protocol = _protocol_name(protocol_number)
    source_port: int | None = None
    destination_port: int | None = None
    spi: str | None = None
    sequence: int | None = None
    ike_version: str | None = None
    exchange_type: int | None = None
    nat_t = False
    ike_message: IKEMessage | None = None
    info = f"{protocol} packet"

    if protocol_number == 17:
        if len(payload) < transport_offset + 8:
            raise CaptureParseError("truncated UDP header")
        source_port = int.from_bytes(payload[transport_offset:transport_offset + 2], "big")
        destination_port = int.from_bytes(payload[transport_offset + 2:transport_offset + 4], "big")
        udp_payload_offset = transport_offset + 8
        udp_payload = payload[udp_payload_offset:]
        if source_port in {500, 4500} or destination_port in {500, 4500}:
            nat_t = source_port == 4500 or destination_port == 4500
            if nat_t and len(udp_payload) >= 4 and udp_payload[:4] == b"\x00\x00\x00\x00":
                udp_payload_offset += 4
                udp_payload = udp_payload[4:]

            if len(udp_payload) >= 28:
                ike_message = _parse_ike_message(udp_payload, packet_number)
                if ike_message is not None:
                    ike_version = ike_message.version
                    exchange_type = ike_message.exchange_type
                    protocol = "IKE"
                    info = f"{ike_version or 'IKE'} exchange {exchange_type if exchange_type is not None else 'unknown'}"
                    if nat_t:
                        info = f"NAT-T {info}"
            elif nat_t and len(udp_payload) >= 8:
                protocol = "ESP"
                spi = f"0x{int.from_bytes(udp_payload[:4], 'big'):08x}"
                sequence = int.from_bytes(udp_payload[4:8], "big")
                info = f"UDP-encapsulated ESP (SPI {spi}, Seq {sequence})"
        if protocol == "UDP":
            info = f"UDP {source_port} → {destination_port}"
    elif protocol_number in {50, 51}:
        if len(payload) < transport_offset + 8:
            raise CaptureParseError(f"truncated {protocol} header")
        spi = f"0x{int.from_bytes(payload[transport_offset:transport_offset + 4], 'big'):08x}"
        sequence = int.from_bytes(payload[transport_offset + 4:transport_offset + 8], "big")
        info = f"{protocol} (SPI {spi}, Seq {sequence})"

    return ParsedPacket(
        number=packet_number,
        timestamp=timestamp,
        length=len(frame),
        protocol=protocol,
        source_ip=source_ip,
        destination_ip=destination_ip,
        ip_version=ip_version,
        source_port=source_port,
        destination_port=destination_port,
        spi=spi,
        sequence=sequence,
        ike_version=ike_version,
        exchange_type=exchange_type,
        nat_t=nat_t,
        info=info,
        raw_preview=frame[:32].hex(" "),
        ike=ike_message,
    )


def _classic_packets(data: bytes) -> tuple[str, int, Iterable[tuple[float, bytes]]]:
    if len(data) < 24:
        raise CaptureParseError("classic PCAP header is truncated")
    magic = data[:4]
    formats = {
        b"\xa1\xb2\xc3\xd4": ("big", "PCAP"),
        b"\xd4\xc3\xb2\xa1": ("little", "PCAP"),
        b"\xa1\xb2\x3c\x4d": ("big", "PCAP-NSEC"),
        b"\x4d\x3c\xb2\xa1": ("little", "PCAP-NSEC"),
    }
    if magic not in formats:
        raise CaptureParseError("unsupported classic PCAP magic number")
    byte_order, capture_format = formats[magic]
    link_type = _read_uint(data, 20, 4, byte_order)

    def records() -> Iterable[tuple[float, bytes]]:
        offset = 24
        while offset < len(data):
            if offset + 16 > len(data):
                raise CaptureParseError(f"truncated packet header at offset {offset}")
            seconds = _read_uint(data, offset, 4, byte_order)
            fraction = _read_uint(data, offset + 4, 4, byte_order)
            captured_length = _read_uint(data, offset + 8, 4, byte_order)
            offset += 16
            if offset + captured_length > len(data):
                raise CaptureParseError(f"packet at offset {offset} exceeds capture boundary")
            packet = data[offset:offset + captured_length]
            offset += captured_length
            divisor = 1_000_000_000 if capture_format == "PCAP-NSEC" else 1_000_000
            yield seconds + fraction / divisor, packet

    return capture_format, link_type, records()


def _pcapng_packets(data: bytes) -> tuple[str, int, Iterable[tuple[float, bytes]]]:
    if len(data) < 28 or data[:4] != b"\x0a\x0d\x0d\x0a":
        raise CaptureParseError("PCAPNG section header is truncated or missing")
    byte_order = "little" if data[8:12] == b"\x4d\x3c\x2b\x1a" else "big" if data[8:12] == b"\x1a\x2b\x3c\x4d" else None
    if byte_order is None:
        raise CaptureParseError("unsupported PCAPNG byte-order magic")
    interfaces: dict[int, int] = {}
    interface_tsresol: dict[int, float] = {}
    records: list[tuple[float, bytes]] = []
    offset = 0
    current_time_sec = 0.0
    while offset + 12 <= len(data):
        block_type = _read_uint(data, offset, 4, byte_order)
        block_length = _read_uint(data, offset + 4, 4, byte_order)
        if block_length < 12 or offset + block_length > len(data):
            raise CaptureParseError(f"invalid PCAPNG block at offset {offset}")
        block = data[offset:offset + block_length]
        if block_type == 0x0A0D0D0A and block_length >= 28:
            new_bo = "little" if block[8:12] == b"\x4d\x3c\x2b\x1a" else "big" if block[8:12] == b"\x1a\x2b\x3c\x4d" else None
            if new_bo:
                byte_order = new_bo
        elif block_type == 1 and block_length >= 20:
            interface_id = len(interfaces)
            interfaces[interface_id] = _read_uint(block, 8, 2, byte_order)
            tsresol = 1_000_000.0
            opt_offset = 16
            while opt_offset + 4 <= block_length - 4:
                opt_code = _read_uint(block, opt_offset, 2, byte_order)
                opt_len = _read_uint(block, opt_offset + 2, 2, byte_order)
                opt_val_offset = opt_offset + 4
                if opt_code == 0:
                    break
                if opt_val_offset + opt_len > block_length - 4:
                    break
                if opt_code == 9 and opt_len >= 1:
                    raw_res = block[opt_val_offset]
                    if raw_res & 0x80:
                        tsresol = float(2 ** (raw_res & 0x7F))
                    else:
                        tsresol = float(10 ** raw_res)
                pad = (4 - (opt_len % 4)) % 4
                opt_offset = opt_val_offset + opt_len + pad
            interface_tsresol[interface_id] = tsresol
        elif block_type == 6 and block_length >= 32:
            interface_id = _read_uint(block, 8, 4, byte_order)
            if interface_id not in interfaces and interfaces:
                interface_id = next(iter(interfaces.keys()))
            elif interface_id not in interfaces:
                interfaces[0] = 1
                interface_tsresol[0] = 1_000_000.0
            divisor = interface_tsresol.get(interface_id, 1_000_000.0)
            timestamp = (_read_uint(block, 12, 4, byte_order) << 32) | _read_uint(block, 16, 4, byte_order)
            captured_length = _read_uint(block, 20, 4, byte_order)
            packet_end = 28 + captured_length
            if packet_end > len(block) - 4:
                raise CaptureParseError(f"enhanced packet at offset {offset} exceeds block boundary")
            current_time_sec = timestamp / divisor if divisor > 0 else timestamp / 1_000_000.0
            records.append((current_time_sec, block[28:packet_end]))
        elif block_type == 3 and block_length >= 16:
            orig_len = _read_uint(block, 8, 4, byte_order)
            cap_len = min(orig_len, block_length - 16)
            packet_end = 12 + cap_len
            if packet_end > len(block) - 4:
                packet_end = len(block) - 4
            records.append((current_time_sec, block[12:packet_end]))
        elif block_type == 2 and block_length >= 32:
            interface_id = _read_uint(block, 8, 2, byte_order)
            divisor = interface_tsresol.get(interface_id, 1_000_000.0)
            timestamp = (_read_uint(block, 12, 4, byte_order) << 32) | _read_uint(block, 16, 4, byte_order)
            captured_length = _read_uint(block, 20, 4, byte_order)
            packet_end = 28 + captured_length
            if packet_end > len(block) - 4:
                raise CaptureParseError(f"packet at offset {offset} exceeds block boundary")
            current_time_sec = timestamp / divisor if divisor > 0 else timestamp / 1_000_000.0
            records.append((current_time_sec, block[28:packet_end]))
        offset += block_length

    if not interfaces:
        if records:
            link_type = 1
        else:
            raise CaptureParseError("PCAPNG contains no interface description block")
    else:
        link_type = next(iter(interfaces.values()))
    return "PCAPNG", link_type, records


def parse_capture(data: bytes) -> CaptureAnalysis:
    if data[:4] == b"\x0a\x0d\x0d\x0a":
        capture_format, link_type, records = _pcapng_packets(data)
    else:
        capture_format, link_type, records = _classic_packets(data)

    packets: list[ParsedPacket] = []
    issues: list[ParserIssue] = []
    for number, (timestamp, frame) in enumerate(records, start=1):
        try:
            packets.append(_decode_network_packet(number, timestamp, frame, link_type))
        except CaptureParseError as error:
            issues.append(ParserIssue(packet=number, detail=str(error)))

    counts: dict[str, int] = {}
    for packet in packets:
        counts[packet.protocol] = counts.get(packet.protocol, 0) + 1
    ike_sas, child_sas, esp_flows, events, limitations = correlate_security_associations(packets)
    security = assess_security(packets, ike_sas, child_sas, esp_flows)
    security.limitations = list(dict.fromkeys([*security.limitations, *limitations]))
    return CaptureAnalysis(
        format=capture_format,
        link_type=link_type,
        packet_count=len(packets),
        packets=packets,
        protocol_summary=ProtocolSummary(counts=counts),
        issues=issues,
        ike_sas=ike_sas,
        child_sas=child_sas,
        esp_flows=esp_flows,
        events=events,
        security=security,
        limitations=limitations,
    )