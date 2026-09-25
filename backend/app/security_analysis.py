from collections import defaultdict

from .models import (
    ChildSA,
    ESPFlow,
    ESPSequenceAnalysis,
    EvidenceItem,
    EvidenceStatus,
    IKESecurityAssociation,
    ParsedPacket,
    SecurityAssessment,
    SecurityFinding,
)


def _normalize_spi(spi: str) -> str:
    value = spi.lower().removeprefix("0x")
    return f"0x{value.lstrip('0') or '0'}"


def _sequence_analysis(packets: list[ParsedPacket]) -> list[ESPSequenceAnalysis]:
    grouped: dict[str, list[ParsedPacket]] = defaultdict(list)
    for packet in packets:
        if packet.protocol == "ESP" and packet.spi and packet.sequence is not None:
            grouped[_normalize_spi(packet.spi)].append(packet)

    analyses: list[ESPSequenceAnalysis] = []
    for spi, flow_packets in grouped.items():
        sequences = [packet.sequence for packet in flow_packets if packet.sequence is not None]
        duplicates: list[int] = []
        seen: set[int] = set()
        gaps: list[int] = []
        out_of_order = False
        max_forward_jump = 0
        for previous, current in zip(sequences, sequences[1:]):
            if current in seen or current == previous:
                duplicates.append(current)
                seen.add(previous)
                continue
            forward_delta = (current - previous) & 0xFFFFFFFF
            if forward_delta >= 0x80000000:
                out_of_order = True
            elif forward_delta > 1:
                gaps.append(forward_delta - 1)
                max_forward_jump = max(max_forward_jump, forward_delta)
            seen.add(previous)
        if sequences:
            seen.add(sequences[-1])
        anomalies = bool(duplicates or out_of_order)
        evidence = [
            EvidenceItem(packet=packet.number, field="ESP.Sequence")
            for packet in flow_packets
        ]
        analyses.append(
            ESPSequenceAnalysis(
                spi=spi,
                packet_numbers=[packet.number for packet in flow_packets],
                sequences=sequences,
                duplicate_sequences=duplicates,
                gaps=gaps,
                out_of_order=out_of_order,
                max_forward_jump=max_forward_jump,
                status=EvidenceStatus.OBSERVED,
                evidence=evidence,
                reason="Duplicate or out-of-order sequence behavior observed." if anomalies else "No duplicate or out-of-order sequence behavior observed in captured packets.",
            )
        )
    return analyses


def _finding(
    finding_id: str,
    title: str,
    category: str,
    severity: str,
    penalty: int,
    confidence: float,
    evidence: list[EvidenceItem],
    impact: str,
    recommendation: str,
) -> SecurityFinding:
    return SecurityFinding(
        id=finding_id,
        title=title,
        category=category,
        severity=severity,
        penalty=penalty,
        status=EvidenceStatus.OBSERVED,
        confidence=confidence,
        evidence=evidence,
        impact=impact,
        recommendation=recommendation,
    )


def _merge_findings(findings: list[SecurityFinding]) -> list[SecurityFinding]:
    merged: dict[str, SecurityFinding] = {}
    for finding in findings:
        existing = merged.get(finding.id)
        if existing is None:
            merged[finding.id] = finding
            continue
        known_evidence = {(item.packet, item.field, item.payload, item.detail) for item in existing.evidence}
        existing.evidence.extend(
            item for item in finding.evidence
            if (item.packet, item.field, item.payload, item.detail) not in known_evidence
        )
        existing.confidence = max(existing.confidence, finding.confidence)
    return list(merged.values())


def assess_security(
    packets: list[ParsedPacket],
    ike_sas: list[IKESecurityAssociation],
    child_sas: list[ChildSA],
    esp_flows: list[ESPFlow],
) -> SecurityAssessment:
    findings: list[SecurityFinding] = []
    limitations: list[str] = []
    sequence_analysis = _sequence_analysis(packets)

    if not ike_sas:
        limitations.append("No IKE Security Association was observed in this capture.")
    if not child_sas and esp_flows:
        limitations.append("ESP was observed without an observable CHILD_SA proposal; negotiated cryptography is not scored.")
    if any(packet.ike and packet.ike.encrypted_payload for packet in packets):
        limitations.append("Encrypted IKE payloads were detected; fields inside SK/SKF payloads are not observable without session keys.")
    if any(packet.ike and packet.ike.fragmented for packet in packets):
        limitations.append("IKE fragmentation was observed; fragment contents cannot be reassembled or decoded without the negotiated session keys.")

    for association in ike_sas:
        if association.version == "IKEv1":
            findings.append(
                _finding(
                    "IPSEC-PROTOCOL-001",
                    "Legacy IKEv1 observed",
                    "Protocol",
                    "MEDIUM",
                    15,
                    0.99,
                    [EvidenceItem(packet=packet, field="IKE.Version") for packet in association.message_packets],
                    "IKEv1 has weaker protocol design and legacy negotiation modes.",
                    "Prefer IKEv2 where deployment compatibility permits.",
                )
            )

    for child in child_sas:
        if child.proposal_role == "SELECTED" and child.pfs is False:
            findings.append(
                _finding(
                    "IPSEC-PFS-001",
                    "Selected CHILD_SA has no PFS transform",
                    "Forward Secrecy",
                    "HIGH",
                    20,
                    0.99,
                    [EvidenceItem(packet=transform.packet, field="IKE.SA.SelectedProposal") for transform in child.transforms],
                    "The selected CHILD_SA proposal does not show a distinct Diffie-Hellman exchange for key derivation.",
                    "Enable PFS for CHILD_SA rekeys with an approved DH or ECDH group.",
                )
            )
        for transform in child.transforms:
            name = (transform.name or "").upper()
            evidence = [EvidenceItem(packet=transform.packet, field="IKE.SA.Transform")]
            if name in {"3DES", "DES"}:
                findings.append(
                    _finding(
                        "IPSEC-CRYPTO-001",
                        "Legacy block cipher observed",
                        "Cryptography",
                        "CRITICAL",
                        35,
                        0.99,
                        evidence,
                        "3DES/DES provides obsolete cryptographic protection and has a small block size.",
                        "Migrate to an approved AEAD construction such as AES-GCM.",
                    )
                )
            elif "MD5" in name or "SHA1" in name:
                findings.append(
                    _finding(
                        "IPSEC-CRYPTO-002",
                        "Legacy integrity or PRF algorithm observed",
                        "Cryptography",
                        "HIGH",
                        20,
                        0.99,
                        evidence,
                        "MD5 and SHA-1 are deprecated for modern security deployments.",
                        "Use SHA-2 based integrity and PRF algorithms or an approved AEAD suite.",
                    )
                )
            elif name in {"DH GROUP 1", "DH GROUP 2", "DH GROUP 5"}:
                findings.append(
                    _finding(
                        "IPSEC-CRYPTO-003",
                        "Weak Diffie-Hellman group observed",
                        "Key Exchange",
                        "HIGH",
                        25,
                        0.99,
                        evidence,
                        "Legacy MODP groups provide inadequate modern security strength.",
                        "Use an approved modern MODP or ECDH group.",
                    )
                )

    for analysis in sequence_analysis:
        if analysis.duplicate_sequences or analysis.out_of_order:
            findings.append(
                _finding(
                    "IPSEC-REPLAY-001",
                    "Replay-like ESP sequence behavior observed",
                    "Replay Protection",
                    "HIGH",
                    20,
                    0.98,
                    analysis.evidence,
                    "Duplicate or out-of-order sequence numbers can indicate replay, capture loss, or reordering.",
                    "Validate anti-replay configuration and investigate the affected flow and capture conditions.",
                )
            )

    findings = _merge_findings(findings)
    observed_categories = sum(
        [
            bool(ike_sas),
            bool(child_sas and any(child.transforms for child in child_sas)),
            bool(child_sas and any(child.traffic_selectors_i or child.traffic_selectors_r for child in child_sas)),
            bool(esp_flows),
            bool(sequence_analysis),
        ]
    )
    evidence_coverage = observed_categories / 5
    risk_score = min(100, sum(finding.penalty for finding in findings))
    confidence = evidence_coverage if findings or observed_categories else 0.0
    return SecurityAssessment(
        risk_score=risk_score,
        confidence=confidence,
        evidence_coverage=evidence_coverage,
        findings=findings,
        sequence_analysis=sequence_analysis,
        limitations=limitations,
    )
