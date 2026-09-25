from collections import defaultdict

from .models import (
    ChildSA,
    ESPFlow,
    EvidenceItem,
    EvidenceStatus,
    IKESecurityAssociation,
    IKEEvent,
    ParsedPacket,
)


def _normalize_spi(spi: str | None) -> str | None:
    if not spi:
        return None
    value = spi.lower().removeprefix("0x")
    return f"0x{value.lstrip('0') or '0'}"


def _selected_transforms(transforms: list) -> list[str]:
    selected: list[str] = []
    for transform in transforms:
        if transform.name and transform.name not in selected:
            selected.append(transform.name)
    return selected


def _has_pfs(transforms: list) -> bool:
    for transform in transforms:
        if transform.transform_type == 4 and transform.transform_id != 0:
            return True
    return False


def _extract_lifetime_seconds(transforms: list) -> int | None:
    lifetime_candidates: list[int] = []
    for transform in transforms:
        for attribute_type, value in transform.attributes.items():
            if not isinstance(value, int):
                continue
            if attribute_type == 1 and 0 < value <= 86_400 * 365 * 10:
                lifetime_candidates.append(value)
    return max(lifetime_candidates) if lifetime_candidates else None


def _detect_esn(transforms: list) -> bool:
    return any(transform.transform_type == 5 and transform.transform_id == 1 for transform in transforms)


def _proposal_role(exchange_type: int, flags: int, matching_request: bool) -> str:
    if exchange_type not in {35, 36}:
        return "UNKNOWN"
    if flags & 0x08:
        return "OFFERED"
    if flags & 0x20 and matching_request:
        return "SELECTED"
    return "UNKNOWN"


def correlate_security_associations(
    packets: list[ParsedPacket],
) -> tuple[list[IKESecurityAssociation], list[ChildSA], list[ESPFlow], list[IKEEvent], list[str]]:
    ike_sas_by_key: dict[str, IKESecurityAssociation] = {}
    children: list[ChildSA] = []
    child_by_spi: dict[str, int] = {}
    limitations: list[str] = []
    events: list[IKEEvent] = []
    prior_children_by_key: dict[str, set[str]] = defaultdict(set)
    pending_child_requests: dict[tuple[str, int], dict[int, int]] = {}

    for packet in packets:
        if packet.ike is None:
            continue
        ike = packet.ike
        key = f"{ike.initiator_spi}/{ike.responder_spi}"
        association = ike_sas_by_key.setdefault(
            key,
            IKESecurityAssociation(
                key=key,
                initiator_spi=ike.initiator_spi,
                responder_spi=ike.responder_spi,
                version=ike.version,
                initiator_endpoint=packet.source_ip,
                responder_endpoint=packet.destination_ip,
            ),
        )
        if packet.number not in association.message_packets:
            association.message_packets.append(packet.number)
        message_key = (key, ike.message_id)
        pending_for_message = pending_child_requests.get(message_key, {})
        request_child_indexes: dict[int, int] = {}
        for proposal in ike.proposals:
            if proposal.protocol_id != 3:
                continue
            spi = _normalize_spi(proposal.spi)
            prior_for_key = prior_children_by_key.get(key, set())
            pending_child_index = pending_for_message.get(proposal.proposal_number)
            has_matching_request = pending_child_index is not None
            proposal_role = _proposal_role(ike.exchange_type, ike.flags, has_matching_request)
            if proposal_role == "SELECTED" and pending_child_index is not None:
                child = children[pending_child_index]
                child.responder_spi = spi
                child.transforms = proposal.transforms
                child.selected_transforms = _selected_transforms(proposal.transforms)
                child.pfs = _has_pfs(proposal.transforms)
                child.lifetime_seconds = _extract_lifetime_seconds(proposal.transforms)
                child.esn = _detect_esn(proposal.transforms)
                child.proposal_role = "SELECTED"
                child.evidence.append(EvidenceItem(packet=proposal.packet, field="IKE.SA.SelectedProposal"))
                if spi is not None:
                    child_by_spi[spi] = pending_child_index
                continue
            if ike.exchange_type in {35, 36}:
                child_lifecycle = "REKEYED" if prior_for_key else "CREATED"
            else:
                child_lifecycle = "OBSERVED"
            child = ChildSA(
                spi=spi,
                initiator_spi=spi if ike.flags & 0x08 else None,
                responder_spi=spi if ike.flags & 0x20 else None,
                protocol="ESP",
                proposal_packet=proposal.packet,
                ike_sa_key=key,
                transforms=proposal.transforms,
                offered_transforms=proposal.transforms if proposal_role == "OFFERED" else [],
                selected_transforms=_selected_transforms(proposal.transforms),
                pfs=_has_pfs(proposal.transforms),
                lifetime_seconds=_extract_lifetime_seconds(proposal.transforms),
                esn=_detect_esn(proposal.transforms),
                proposal_role=proposal_role,
                traffic_selectors_i=ike.traffic_selectors_i,
                traffic_selectors_r=ike.traffic_selectors_r,
                lifecycle=child_lifecycle,
                status=EvidenceStatus.OBSERVED,
                evidence=[EvidenceItem(packet=proposal.packet, field="IKE.SA.Proposal")],
            )
            if spi is None:
                child.status = EvidenceStatus.INSUFFICIENT_DATA
                child.reason = "ESP proposal was observed without a usable SPI."
            else:
                child_by_spi[spi] = len(children)
                prior_children_by_key[key].add(spi)
            children.append(child)
            association.child_sa_indexes.append(len(children) - 1)
            if proposal_role == "OFFERED":
                request_child_indexes[proposal.proposal_number] = len(children) - 1
        if ike.exchange_type in {35, 36} and ike.flags & 0x08 and any(
            proposal.protocol_id == 3 for proposal in ike.proposals
        ):
            if request_child_indexes:
                pending_child_requests[message_key] = request_child_indexes
        elif ike.exchange_type in {35, 36} and ike.flags & 0x20:
            pending_child_requests.pop(message_key, None)
        event_names = {34: "IKE_SA_INIT", 35: "IKE_AUTH", 36: "CREATE_CHILD_SA", 37: "INFORMATIONAL"}
        events.append(
            IKEEvent(
                packet=packet.number,
                exchange_type=ike.exchange_type,
                name=event_names.get(ike.exchange_type, f"EXCHANGE_{ike.exchange_type}"),
                ike_sa_key=key,
            )
        )

    esp_packets: dict[str, list[ParsedPacket]] = defaultdict(list)
    for packet in packets:
        if packet.protocol == "ESP" and packet.spi:
            esp_packets[_normalize_spi(packet.spi) or packet.spi].append(packet)

    flows: list[ESPFlow] = []
    for spi, flow_packets in esp_packets.items():
        child_index = child_by_spi.get(spi)
        association = None
        if child_index is not None:
            association = ike_sas_by_key.get(children[child_index].ike_sa_key)
        direction = "UNKNOWN"
        if association and flow_packets:
            source_ip = flow_packets[0].source_ip
            if source_ip == association.initiator_endpoint:
                direction = "INITIATOR_TO_RESPONDER"
            elif source_ip == association.responder_endpoint:
                direction = "RESPONDER_TO_INITIATOR"
        if child_index is None:
            flows.append(
                ESPFlow(
                    spi=spi,
                    packet_numbers=[packet.number for packet in flow_packets],
                    source_ips=sorted({packet.source_ip for packet in flow_packets if packet.source_ip}),
                    destination_ips=sorted({packet.destination_ip for packet in flow_packets if packet.destination_ip}),
                    status=EvidenceStatus.NOT_OBSERVABLE,
                    direction=direction,
                    reason="ESP traffic was observed, but no matching ESP proposal SPI was visible in the captured IKE payloads.",
                )
            )
            continue
        children[child_index].esp_packet_numbers.extend(packet.number for packet in flow_packets)
        children[child_index].direction = direction
        children[child_index].evidence.extend(
            EvidenceItem(packet=packet.number, field="ESP.SPI") for packet in flow_packets
        )
        flows.append(
            ESPFlow(
                spi=spi,
                packet_numbers=[packet.number for packet in flow_packets],
                source_ips=sorted({packet.source_ip for packet in flow_packets if packet.source_ip}),
                destination_ips=sorted({packet.destination_ip for packet in flow_packets if packet.destination_ip}),
                status=EvidenceStatus.DERIVED,
                child_sa_index=child_index,
                direction=direction,
            )
        )

    if esp_packets and not children:
        limitations.append("ESP traffic is present, but no visible ESP proposal was available for CHILD_SA reconstruction.")
    if any(packet.ike and packet.ike.encrypted_payload for packet in packets):
        limitations.append("Encrypted IKE payloads were detected; fields inside SK/SKF payloads are not observable without session keys.")
    return list(ike_sas_by_key.values()), children, flows, events, limitations