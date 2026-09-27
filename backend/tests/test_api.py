from fastapi.testclient import TestClient

from backend.app.main import app
from backend.app.models import ChildSA, IKEMessage, IKEProposal, IKETransform, ParsedPacket
from backend.app.capture_parser import _parse_ike_message
from backend.app.sa_correlator import _extract_lifetime_seconds, correlate_security_associations
from backend.app.security_analysis import assess_security


client = TestClient(app)


def _pcap_packet(frame: bytes) -> bytes:
    return _pcap_packets([frame])


def _pcap_packets(frames: list[bytes]) -> bytes:
    global_header = (
        b"\xd4\xc3\xb2\xa1"
        + (2).to_bytes(2, "little")
        + (4).to_bytes(2, "little")
        + (0).to_bytes(4, "little", signed=True)
        + (0).to_bytes(4, "little")
        + (65535).to_bytes(4, "little")
        + (1).to_bytes(4, "little")
    )
    records = b"".join(
        (index + 1).to_bytes(4, "little")
        + (0).to_bytes(4, "little")
        + len(frame).to_bytes(4, "little")
        + len(frame).to_bytes(4, "little")
        + frame
        for index, frame in enumerate(frames)
    )
    return global_header + records


def _ethernet_ipv4_esp_frame(spi: bytes = bytes.fromhex("01020304"), sequence: int = 7) -> bytes:
    ethernet = bytes.fromhex("00112233445566778899aabb0800")
    ipv4 = bytes.fromhex("4500001c00000000403200000a0000010a000002")
    esp = spi + sequence.to_bytes(4, "big")
    return ethernet + ipv4 + esp


def _pcapng_packet(frame: bytes) -> bytes:
    section_header = (
        b"\x0a\x0d\x0d\x0a"
        + (28).to_bytes(4, "little")
        + b"\x4d\x3c\x2b\x1a"
        + (1).to_bytes(2, "little")
        + (0).to_bytes(2, "little")
        + (0xFFFFFFFFFFFFFFFF).to_bytes(8, "little")
        + (28).to_bytes(4, "little")
    )
    interface = (
        (1).to_bytes(4, "little")
        + (20).to_bytes(4, "little")
        + (1).to_bytes(2, "little")
        + (0).to_bytes(2, "little")
        + (65535).to_bytes(4, "little")
        + (20).to_bytes(4, "little")
    )
    padding = b"\x00" * ((4 - len(frame) % 4) % 4)
    block_length = 32 + len(frame) + len(padding)
    enhanced_packet = (
        (6).to_bytes(4, "little")
        + block_length.to_bytes(4, "little")
        + (0).to_bytes(4, "little")
        + (0).to_bytes(4, "little")
        + (1).to_bytes(4, "little")
        + len(frame).to_bytes(4, "little")
        + len(frame).to_bytes(4, "little")
        + frame
        + padding
        + block_length.to_bytes(4, "little")
    )
    return section_header + interface + enhanced_packet


def _pcapng_standard_packet(frame: bytes) -> bytes:
    section_header = (
        b"\x0a\x0d\x0d\x0a"
        + (28).to_bytes(4, "little")
        + b"\x4d\x3c\x2b\x1a"
        + (1).to_bytes(2, "little")
        + (0).to_bytes(2, "little")
        + (0xFFFFFFFFFFFFFFFF).to_bytes(8, "little")
        + (28).to_bytes(4, "little")
    )
    interface = (
        (1).to_bytes(4, "little")
        + (20).to_bytes(4, "little")
        + (1).to_bytes(2, "little")
        + (0).to_bytes(2, "little")
        + (65535).to_bytes(4, "little")
        + (20).to_bytes(4, "little")
    )
    padding = b"\x00" * ((4 - len(frame) % 4) % 4)
    block_length = 16 + len(frame) + len(padding)
    packet_block = (
        (3).to_bytes(4, "little")
        + block_length.to_bytes(4, "little")
        + len(frame).to_bytes(4, "little")
        + frame
        + padding
        + block_length.to_bytes(4, "little")
    )
    return section_header + interface + packet_block


def _ethernet_ipv6_udp_frame() -> bytes:
    ethernet = bytes.fromhex("00112233445566778899aabb86dd")
    source = bytes.fromhex("20010db8000000000000000000000001")
    destination = bytes.fromhex("20010db8000000000000000000000002")
    ipv6 = bytes.fromhex("60000000000c1140") + source + destination
    udp = (500).to_bytes(2, "big") + (500).to_bytes(2, "big") + (12).to_bytes(2, "big") + b"\x00\x00"
    ike_header = b"\x01" * 16 + bytes([0, 0, 0, 0x20, 34, 0, 0, 0, 0, 0, 0, 28])
    return ethernet + ipv6 + udp + ike_header


def _ethernet_ipv4_nat_t_ike_frame() -> bytes:
    ethernet = bytes.fromhex("00112233445566778899aabb0800")
    ike_header = (
        bytes.fromhex("0102030405060708")
        + bytes.fromhex("1112131415161718")
        + bytes([33, 0x20, 34, 8])
        + (0).to_bytes(4, "big")
        + (28 + 28).to_bytes(4, "big")
    )
    ike = ike_header + b"\x00" * 28
    ipv4 = bytes([0x45, 0x00, 0x00, 20 + 8 + 4 + len(ike), 0x00, 0x00, 0x00, 0x00, 64, 17, 0x00, 0x00, 10, 0, 0, 1, 10, 0, 0, 2])
    udp = (4500).to_bytes(2, "big") + (4500).to_bytes(2, "big") + (8 + 4 + len(ike)).to_bytes(2, "big") + b"\x00\x00"
    return ethernet + ipv4 + udp + b"\x00\x00\x00\x00" + ike


def _ethernet_ipv4_ike_sa_frame(protocol_id: int = 1, proposal_spi: bytes = b"", include_selectors: bool = False) -> bytes:
    ethernet = bytes.fromhex("00112233445566778899aabb0800")
    transforms = b"".join(
        bytes([3 if index < 3 else 0, 0, 0, 8, transform_type, 0])
        + transform_id.to_bytes(2, "big")
        for index, (transform_type, transform_id) in enumerate(((1, 20), (2, 5), (3, 0), (4, 19)))
    )
    proposal_body = bytes([0, 0]) + (40 + len(proposal_spi)).to_bytes(2, "big") + bytes([1, protocol_id, len(proposal_spi), 4]) + proposal_spi + transforms
    selector_body = (
        (1).to_bytes(4, "big")
        + b"\x00\x00\x00\x00"
        + bytes([7, 0])
        + (16).to_bytes(2, "big")
        + b"\x00\x00\x00\x00"
        + bytes([10, 0, 0, 0, 10, 0, 0, 255])
    )
    selector_i = bytes([45 if include_selectors else 0, 0]) + (4 + len(selector_body)).to_bytes(2, "big") + selector_body
    selector_r = bytes([0, 0]) + (4 + len(selector_body)).to_bytes(2, "big") + selector_body
    sa_next = 44 if include_selectors else 0
    sa_payload = bytes([sa_next, 0]) + (44 + len(proposal_spi)).to_bytes(2, "big") + proposal_body
    ike_payload = sa_payload + (selector_i + selector_r if include_selectors else b"")
    ike_header = (
        bytes.fromhex("0102030405060708")
        + bytes.fromhex("1112131415161718")
        + bytes([33, 0x20, 34, 8])
        + (0).to_bytes(4, "big")
        + (28 + len(ike_payload)).to_bytes(4, "big")
    )
    ike = ike_header + ike_payload
    ipv4 = bytes([0x45, 0, 0, 20 + 8 + len(ike), 0, 0, 0, 0, 64, 17, 0, 0, 10, 0, 0, 1, 10, 0, 0, 2])
    udp = (500).to_bytes(2, "big") + (500).to_bytes(2, "big") + (8 + len(ike)).to_bytes(2, "big") + b"\x00\x00"
    return ethernet + ipv4 + udp + ike


def test_health() -> None:
    response = client.get("/api/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_upload_and_queue_capture() -> None:
    response = client.post(
        "/api/captures",
        files={"file": ("sample.pcap", b"pcap-foundation-test", "application/vnd.tcpdump.pcap")},
    )
    assert response.status_code == 201
    capture = response.json()
    assert capture["format"] == "PCAP"
    assert len(capture["sha256"]) == 64

    job_response = client.post(f"/api/captures/{capture['capture_id']}/analyze")
    assert job_response.status_code == 202
    assert job_response.json()["status"] == "PENDING"


def test_analysis_job_completes_for_valid_capture() -> None:
    response = client.post(
        "/api/captures",
        files={"file": ("job.pcap", _pcap_packet(_ethernet_ipv4_esp_frame()), "application/vnd.tcpdump.pcap")},
    )
    capture_id = response.json()["capture_id"]

    job_response = client.post(f"/api/captures/{capture_id}/analyze")
    job_id = job_response.json()["job_id"]
    completed_job = client.get(f"/api/analyze/{job_id}").json()
    capture = client.get(f"/api/captures/{capture_id}").json()

    assert completed_job["status"] == "COMPLETED"
    assert completed_job["progress"] == 100
    assert capture["analysis_status"] == "COMPLETED"
    assert capture["packet_count"] == 1


def test_empty_upload_is_rejected() -> None:
    response = client.post("/api/captures", files={"file": ("empty.pcap", b"", "application/octet-stream")})
    assert response.status_code == 400


def test_analysis_extracts_ipv4_esp_fields() -> None:
    response = client.post(
        "/api/captures",
        files={"file": ("esp.pcap", _pcap_packet(_ethernet_ipv4_esp_frame()), "application/vnd.tcpdump.pcap")},
    )
    assert response.status_code == 201
    capture_id = response.json()["capture_id"]

    analysis = client.get(f"/api/captures/{capture_id}/analysis")
    assert analysis.status_code == 200
    packet = analysis.json()["packets"][0]
    assert packet["protocol"] == "ESP"
    assert packet["source_ip"] == "10.0.0.1"
    assert packet["destination_ip"] == "10.0.0.2"
    assert packet["spi"] == "0x01020304"
    assert packet["sequence"] == 7


def test_analysis_parses_pcapng() -> None:
    response = client.post(
        "/api/captures",
        files={"file": ("esp.pcapng", _pcapng_packet(_ethernet_ipv4_esp_frame()), "application/pcapng")},
    )
    capture_id = response.json()["capture_id"]
    analysis = client.get(f"/api/captures/{capture_id}/analysis")
    assert analysis.status_code == 200
    assert analysis.json()["format"] == "PCAPNG"
    assert analysis.json()["protocol_summary"]["counts"]["ESP"] == 1


def test_analysis_parses_pcapng_standard_packet_block() -> None:
    response = client.post(
        "/api/captures",
        files={"file": ("esp-standard.pcapng", _pcapng_standard_packet(_ethernet_ipv4_esp_frame()), "application/pcapng")},
    )
    capture_id = response.json()["capture_id"]
    analysis = client.get(f"/api/captures/{capture_id}/analysis")
    assert analysis.status_code == 200
    assert analysis.json()["packet_count"] == 1
    assert analysis.json()["protocol_summary"]["counts"]["ESP"] == 1


def test_analysis_parses_ipv6_endpoints_and_ike() -> None:
    response = client.post(
        "/api/captures",
        files={"file": ("ipv6.pcap", _pcap_packet(_ethernet_ipv6_udp_frame()), "application/vnd.tcpdump.pcap")},
    )
    capture_id = response.json()["capture_id"]
    analysis = client.get(f"/api/captures/{capture_id}/analysis")
    assert analysis.status_code == 200
    packet = analysis.json()["packets"][0]
    assert packet["protocol"] == "IKE"
    assert packet["ip_version"] == "IPv6"
    assert packet["source_ip"] == "2001:db8::1"
    assert packet["destination_ip"] == "2001:db8::2"


def test_analysis_surfaces_encrypted_ike_limitation_in_security_assessment() -> None:
    packet = ParsedPacket(
        number=1,
        timestamp=1.0,
        length=120,
        protocol="IKE",
        source_ip="10.0.0.1",
        destination_ip="10.0.0.2",
        ip_version="IPv4",
        info="Encrypted IKE packet",
        raw_preview="",
        ike=IKEMessage(
            initiator_spi="0x1111111111111111",
            responder_spi="0x2222222222222222",
            version="IKEv2",
            next_payload=53,
            exchange_type=37,
            flags=0x08,
            message_id=1,
            length=120,
            payload_types=[53],
            encrypted_payload=True,
            packet=1,
        ),
    )

    analysis = assess_security([packet], [], [], [])

    assert any("Encrypted IKE payloads" in limitation for limitation in analysis.limitations)


def test_parser_records_ike_fragment_metadata() -> None:
    fragment_payload = bytes([0, 0]) + (8).to_bytes(2, "big") + (2).to_bytes(2, "big") + (3).to_bytes(2, "big")
    ike_header = (
        bytes.fromhex("0102030405060708")
        + bytes.fromhex("1112131415161718")
        + bytes([132, 0x20, 37, 8])
        + (0).to_bytes(4, "big")
        + (28 + len(fragment_payload)).to_bytes(4, "big")
    )

    message = _parse_ike_message(ike_header + fragment_payload, 1)

    assert message is not None
    assert message.fragmented is True
    assert message.fragment_number == 2
    assert message.fragment_total == 3
    assert message.encrypted_payload is True


def test_analysis_marks_nat_t_ike_on_udp_4500() -> None:
    response = client.post(
        "/api/captures",
        files={"file": ("nat-t-ike.pcap", _pcap_packet(_ethernet_ipv4_nat_t_ike_frame()), "application/vnd.tcpdump.pcap")},
    )
    capture_id = response.json()["capture_id"]
    result = client.get(f"/api/captures/{capture_id}/analysis").json()
    packet = result["packets"][0]
    assert packet["protocol"] == "IKE"
    assert packet["source_port"] == 4500
    assert packet["destination_port"] == 4500
    assert packet["nat_t"] is True


def test_analysis_decodes_ike_sa_proposal_transforms() -> None:
    response = client.post(
        "/api/captures",
        files={"file": ("ike.pcap", _pcap_packet(_ethernet_ipv4_ike_sa_frame()), "application/vnd.tcpdump.pcap")},
    )
    capture_id = response.json()["capture_id"]
    analysis = client.get(f"/api/captures/{capture_id}/analysis")
    assert analysis.status_code == 200
    ike = analysis.json()["packets"][0]["ike"]
    assert ike["version"] == "IKEv2"
    assert ike["exchange_type"] == 34
    assert ike["payload_types"] == [33]
    assert [transform["transform_id"] for transform in ike["proposals"][0]["transforms"]] == [20, 5, 0, 19]
    assert [transform["name"] for transform in ike["proposals"][0]["transforms"]] == [
        "AES-GCM-16",
        "PRF-HMAC-SHA2-256",
        "NONE",
        "DH Group 19",
    ]


def test_analysis_correlates_child_sa_spi_with_esp_flow() -> None:
    spi = bytes.fromhex("01020304")
    capture = _pcap_packets([_ethernet_ipv4_ike_sa_frame(protocol_id=3, proposal_spi=spi), _ethernet_ipv4_esp_frame(spi)])
    response = client.post(
        "/api/captures",
        files={"file": ("correlated.pcap", capture, "application/vnd.tcpdump.pcap")},
    )
    capture_id = response.json()["capture_id"]
    analysis = client.get(f"/api/captures/{capture_id}/analysis")
    assert analysis.status_code == 200
    result = analysis.json()
    assert result["child_sas"][0]["spi"] == "0x1020304"
    assert result["child_sas"][0]["esp_packet_numbers"] == [2]
    assert result["esp_flows"][0]["status"] == "DERIVED"
    assert result["esp_flows"][0]["child_sa_index"] == 0


def test_analysis_tracks_selectors_lifecycle_and_direction() -> None:
    spi = bytes.fromhex("01020304")
    capture = _pcap_packets([
        _ethernet_ipv4_ike_sa_frame(protocol_id=3, proposal_spi=spi, include_selectors=True),
        _ethernet_ipv4_esp_frame(spi),
    ])
    response = client.post(
        "/api/captures",
        files={"file": ("selectors.pcap", capture, "application/vnd.tcpdump.pcap")},
    )
    capture_id = response.json()["capture_id"]
    result = client.get(f"/api/captures/{capture_id}/analysis").json()
    child = result["child_sas"][0]
    assert result["events"][0]["name"] == "IKE_SA_INIT"
    assert child["lifecycle"] == "OBSERVED"
    assert child["traffic_selectors_i"][0]["start_address"] == "10.0.0.0"
    assert child["traffic_selectors_i"][0]["end_address"] == "10.0.0.255"
    assert child["direction"] == "INITIATOR_TO_RESPONDER"
    assert result["esp_flows"][0]["direction"] == "INITIATOR_TO_RESPONDER"


def test_analysis_extracts_negotiated_child_sa_pfs_and_lifetime() -> None:
    spi = bytes.fromhex("01020304")
    capture = _pcap_packets([
        _ethernet_ipv4_ike_sa_frame(protocol_id=3, proposal_spi=spi),
        _ethernet_ipv4_esp_frame(spi),
    ])
    response = client.post(
        "/api/captures",
        files={"file": ("negotiated.pcap", capture, "application/vnd.tcpdump.pcap")},
    )
    capture_id = response.json()["capture_id"]
    result = client.get(f"/api/captures/{capture_id}/analysis").json()
    child = result["child_sas"][0]
    assert child["pfs"] is True
    assert child["lifetime_seconds"] is None
    assert "AES-GCM-16" in child["selected_transforms"]
    assert "DH Group 19" in child["selected_transforms"]

    lifetime = _extract_lifetime_seconds([
        IKETransform(transform_type=1, transform_id=20, attributes={1: 3600}, packet=1)
    ])
    assert lifetime == 3600


def test_child_sa_rekey_lifecycle_and_esn_are_recorded() -> None:
    first = ParsedPacket(
        number=1,
        timestamp=1.0,
        length=120,
        protocol="IKE",
        source_ip="10.0.0.1",
        destination_ip="10.0.0.2",
        ip_version="IPv4",
        info="IKE packet",
        raw_preview="",
        ike=IKEMessage(
            initiator_spi="0x1111111111111111",
            responder_spi="0x2222222222222222",
            version="IKEv2",
            next_payload=33,
            exchange_type=36,
            flags=0x08,
            message_id=1,
            length=100,
            payload_types=[33],
            proposals=[
                IKEProposal(
                    proposal_number=1,
                    protocol_id=3,
                    spi="0x01020304",
                    packet=1,
                    transforms=[
                        IKETransform(transform_type=1, transform_id=20, name="AES-GCM-16", packet=1),
                    ],
                )
            ],
            packet=1,
        ),
    )
    second = ParsedPacket(
        number=2,
        timestamp=2.0,
        length=120,
        protocol="IKE",
        source_ip="10.0.0.1",
        destination_ip="10.0.0.2",
        ip_version="IPv4",
        info="IKE packet",
        raw_preview="",
        ike=IKEMessage(
            initiator_spi="0x1111111111111111",
            responder_spi="0x2222222222222222",
            version="IKEv2",
            next_payload=33,
            exchange_type=36,
            flags=0x20,
            message_id=2,
            length=100,
            payload_types=[33],
            proposals=[
                IKEProposal(
                    proposal_number=1,
                    protocol_id=3,
                    spi="0x01020305",
                    packet=2,
                    transforms=[
                        IKETransform(transform_type=1, transform_id=20, name="AES-GCM-16", packet=2),
                        IKETransform(transform_type=5, transform_id=1, name="ESN", packet=2),
                    ],
                )
            ],
            packet=2,
        ),
    )

    _, child_sas, _, _, _ = correlate_security_associations([first, second])
    assert len(child_sas) == 2
    assert child_sas[0].lifecycle == "CREATED"
    assert child_sas[1].lifecycle == "REKEYED"
    assert child_sas[0].proposal_role == "OFFERED"
    assert child_sas[1].proposal_role == "UNKNOWN"
    assert child_sas[1].esn is True

    matching_second = second.model_copy(
        update={"ike": second.ike.model_copy(update={"message_id": 1})}
    )
    _, matched_children, _, _, _ = correlate_security_associations([first, matching_second])
    assert len(matched_children) == 1
    assert matched_children[0].proposal_role == "SELECTED"
    assert matched_children[0].initiator_spi == "0x1020304"
    assert matched_children[0].responder_spi == "0x1020305"
    assert matched_children[0].esn is True

    second_offer = first.ike.proposals[0].model_copy(
        update={"proposal_number": 2, "spi": "0x01020306"}
    )
    second_selection = second.ike.proposals[0].model_copy(
        update={"proposal_number": 2, "spi": "0x01020307"}
    )
    multiple_first = first.model_copy(
        update={
            "ike": first.ike.model_copy(
                update={"proposals": [first.ike.proposals[0], second_offer]}
            )
        }
    )
    multiple_second = second.model_copy(
        update={
            "ike": second.ike.model_copy(
                update={
                    "message_id": 1,
                    "proposals": [second.ike.proposals[0], second_selection],
                }
            )
        }
    )
    _, multiple_children, _, _, _ = correlate_security_associations([multiple_first, multiple_second])
    assert len(multiple_children) == 2
    assert [(child.initiator_spi, child.responder_spi) for child in multiple_children] == [
        ("0x1020304", "0x1020305"),
        ("0x1020306", "0x1020307"),
    ]


def test_security_analysis_reports_duplicate_esp_sequence() -> None:
    spi = bytes.fromhex("01020304")
    capture = _pcap_packets([_ethernet_ipv4_esp_frame(spi, 7), _ethernet_ipv4_esp_frame(spi, 7)])
    response = client.post(
        "/api/captures",
        files={"file": ("replay.pcap", capture, "application/vnd.tcpdump.pcap")},
    )
    capture_id = response.json()["capture_id"]
    result = client.get(f"/api/captures/{capture_id}/analysis").json()
    sequence = result["security"]["sequence_analysis"][0]
    assert sequence["duplicate_sequences"] == [7]
    assert any(finding["id"] == "IPSEC-REPLAY-001" for finding in result["security"]["findings"])


def test_security_analysis_accepts_esp_sequence_rollover() -> None:
    capture = _pcap_packets([
        _ethernet_ipv4_esp_frame(sequence=0xFFFFFFFF),
        _ethernet_ipv4_esp_frame(sequence=0),
    ])
    response = client.post(
        "/api/captures",
        files={"file": ("rollover.pcap", capture, "application/vnd.tcpdump.pcap")},
    )
    capture_id = response.json()["capture_id"]
    sequence = client.get(f"/api/captures/{capture_id}/analysis").json()["security"]["sequence_analysis"][0]

    assert sequence["out_of_order"] is False
    assert sequence["gaps"] == []


def test_security_analysis_merges_repeated_weak_transform_findings() -> None:
    child = ChildSA(
        spi="0x01020304",
        protocol="ESP",
        proposal_packet=1,
        ike_sa_key="ike-sa",
        transforms=[
            IKETransform(transform_type=1, transform_id=3, name="3DES", packet=1),
            IKETransform(transform_type=1, transform_id=3, name="3DES", packet=2),
        ],
        status="OBSERVED",
    )

    assessment = assess_security([], [], [child], [])

    weak_cipher_findings = [finding for finding in assessment.findings if finding.id == "IPSEC-CRYPTO-001"]
    assert len(weak_cipher_findings) == 1
    assert assessment.risk_score == 35
    assert [item.packet for item in weak_cipher_findings[0].evidence] == [1, 2]


def test_security_analysis_reports_missing_pfs_only_for_selected_child_sa() -> None:
    child = ChildSA(
        spi="0x01020304",
        protocol="ESP",
        proposal_packet=1,
        ike_sa_key="ike-sa",
        transforms=[IKETransform(transform_type=1, transform_id=20, name="AES-GCM-16", packet=1)],
        pfs=False,
        proposal_role="SELECTED",
        status="OBSERVED",
    )

    assessment = assess_security([], [], [child], [])

    assert any(finding.id == "IPSEC-PFS-001" for finding in assessment.findings)


def test_api_root_endpoints() -> None:
    for path in ["/api", "/api/"]:
        res = client.get(path)
        assert res.status_code == 200
        assert res.json()["status"] == "ok"


def test_upload_alias_and_trailing_slashes() -> None:
    for path in ["/api/upload", "/api/upload/", "/api/captures/"]:
        response = client.post(
            path,
            files={"file": ("sample.pcap", b"pcap-foundation-test", "application/vnd.tcpdump.pcap")},
        )
        assert response.status_code == 201
        assert response.json()["filename"] == "sample.pcap"

