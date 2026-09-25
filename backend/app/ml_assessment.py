"""
ML-based Security Assessment Engine
======================================

Produces structured security findings from ML predictions and observed
features.  All findings are clearly tagged with their basis:
  - "ml_inferred"  — derived from ML model output
  - "observed"     — derived directly from extracted packet features
  - "derived"      — calculated from observed features

Rules are conservative: findings are only produced when the evidence
actually supports them.  If a property cannot be assessed, the finding
is omitted rather than fabricated.

Confidence thresholds (configurable):
    HIGH   >= 0.80
    MEDIUM >= 0.55
    LOW    <  0.55
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

# ---------------------------------------------------------------------------
# Configurable confidence thresholds
# ---------------------------------------------------------------------------

CONFIDENCE_HIGH = 0.80
CONFIDENCE_MEDIUM = 0.55


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------


@dataclass
class MLSecurityFinding:
    id: str
    title: str
    category: str
    severity: str            # "info" | "low" | "medium" | "high" | "critical"
    basis: str               # "ml_inferred" | "observed" | "derived"
    confidence: float        # 0.0 – 1.0
    message: str
    detail: str
    recommendation: str


def _confidence_label(confidence: float) -> str:
    if confidence >= CONFIDENCE_HIGH:
        return "HIGH"
    if confidence >= CONFIDENCE_MEDIUM:
        return "MEDIUM"
    return "LOW"


# ---------------------------------------------------------------------------
# Assessment helpers
# ---------------------------------------------------------------------------


def _assess_encryption(
    prediction: str,
    confidence: float,
    findings: list[MLSecurityFinding],
) -> None:
    label = _confidence_label(confidence)

    if prediction == "AES256":
        findings.append(
            MLSecurityFinding(
                id="enc-aes256",
                title="Encryption: AES-256 (ML prediction)",
                category="cryptographic_configuration",
                severity="info",
                basis="ml_inferred",
                confidence=confidence,
                message=f"ML model predicts AES-256 encryption ({label} confidence: {confidence*100:.1f}%).",
                detail="AES-256 is recommended by NSA CNSA Suite and NIST SP 800-77 Rev. 1.",
                recommendation="No action required if confirmed.",
            )
        )
    elif prediction == "AES128":
        severity = "low" if confidence >= CONFIDENCE_MEDIUM else "info"
        findings.append(
            MLSecurityFinding(
                id="enc-aes128",
                title="Encryption: AES-128 (ML prediction)",
                category="cryptographic_configuration",
                severity=severity,
                basis="ml_inferred",
                confidence=confidence,
                message=f"ML model predicts AES-128 encryption ({label} confidence: {confidence*100:.1f}%).",
                detail=(
                    "AES-128 provides 128-bit security level. CNSA Suite 2.0 recommends AES-256 "
                    "for TOP SECRET data. AES-128 remains acceptable for most deployments."
                ),
                recommendation="Consider upgrading to AES-256 for highest-assurance deployments.",
            )
        )


def _assess_hash(
    prediction: str,
    confidence: float,
    findings: list[MLSecurityFinding],
) -> None:
    label = _confidence_label(confidence)

    if prediction == "SHA256":
        findings.append(
            MLSecurityFinding(
                id="hash-sha256",
                title="Integrity: SHA-256 (ML prediction)",
                category="cryptographic_configuration",
                severity="info",
                basis="ml_inferred",
                confidence=confidence,
                message=f"ML model predicts SHA-256 integrity algorithm ({label} confidence: {confidence*100:.1f}%).",
                detail="SHA-256 is acceptable under RFC 8221. SHA-384 or SHA-512 preferred for CNSA Suite.",
                recommendation="Consider SHA-384 for highest-assurance environments.",
            )
        )
    elif prediction == "SHA384":
        findings.append(
            MLSecurityFinding(
                id="hash-sha384",
                title="Integrity: SHA-384 (ML prediction)",
                category="cryptographic_configuration",
                severity="info",
                basis="ml_inferred",
                confidence=confidence,
                message=f"ML model predicts SHA-384 integrity algorithm ({label} confidence: {confidence*100:.1f}%).",
                detail="SHA-384 meets NSA CNSA Suite requirements.",
                recommendation="No action required.",
            )
        )


def _assess_dh_group(
    prediction: str,
    confidence: float,
    findings: list[MLSecurityFinding],
) -> None:
    label = _confidence_label(confidence)

    if prediction == "DH14":
        severity = "medium" if confidence >= CONFIDENCE_MEDIUM else "low"
        findings.append(
            MLSecurityFinding(
                id="dh-group14",
                title="Key Exchange: DH Group 14 / MODP-2048 (ML prediction)",
                category="dh_configuration",
                severity=severity,
                basis="ml_inferred",
                confidence=confidence,
                message=f"ML model predicts DH Group 14 (MODP-2048) ({label} confidence: {confidence*100:.1f}%).",
                detail=(
                    "DH Group 14 (MODP-2048) provides 112-bit security. "
                    "CNSA Suite 2.0 requires a minimum of DH Group 15 (MODP-3072) or ECDH P-384."
                ),
                recommendation="Upgrade to DH Group 15 (MODP-3072) or DH Group 19/20 (ECDH).",
            )
        )
    elif prediction == "DH15":
        findings.append(
            MLSecurityFinding(
                id="dh-group15",
                title="Key Exchange: DH Group 15 / MODP-3072 (ML prediction)",
                category="dh_configuration",
                severity="info",
                basis="ml_inferred",
                confidence=confidence,
                message=f"ML model predicts DH Group 15 (MODP-3072) ({label} confidence: {confidence*100:.1f}%).",
                detail="DH Group 15 (MODP-3072) meets NSA CNSA Suite minimum requirements.",
                recommendation="No action required.",
            )
        )


def _assess_pfs(
    prediction: str,
    confidence: float,
    findings: list[MLSecurityFinding],
) -> None:
    label = _confidence_label(confidence)

    if prediction == "NOPFS":
        severity = "high" if confidence >= CONFIDENCE_HIGH else "medium"
        findings.append(
            MLSecurityFinding(
                id="pfs-disabled",
                title="Perfect Forward Secrecy: Disabled (ML prediction)",
                category="pfs_configuration",
                severity=severity,
                basis="ml_inferred",
                confidence=confidence,
                message=f"ML model predicts PFS is not in use ({label} confidence: {confidence*100:.1f}%).",
                detail=(
                    "Without PFS, compromise of the long-term IKE SA keys could allow "
                    "decryption of all past ESP sessions. PFS is required by many compliance frameworks."
                ),
                recommendation=(
                    "Enable PFS using CREATE_CHILD_SA with a new DH exchange "
                    "(DH Group 14 minimum, Group 15+ recommended)."
                ),
            )
        )
    elif prediction in {"PFS14", "PFS15"}:
        dh_label = "DH Group 14" if prediction == "PFS14" else "DH Group 15"
        findings.append(
            MLSecurityFinding(
                id=f"pfs-{prediction.lower()}",
                title=f"Perfect Forward Secrecy: {dh_label} (ML prediction)",
                category="pfs_configuration",
                severity="info",
                basis="ml_inferred",
                confidence=confidence,
                message=f"ML model predicts PFS is enabled using {dh_label} ({label} confidence: {confidence*100:.1f}%).",
                detail="PFS ensures that compromise of long-term keys does not expose past session data.",
                recommendation="No action required." if prediction == "PFS15" else
                    "Consider upgrading to DH Group 15+ for highest-assurance PFS.",
            )
        )


def _assess_observed_features(
    observed: dict[str, Any],
    findings: list[MLSecurityFinding],
) -> None:
    """Produce findings from directly observed/extracted PCAP features."""

    packet_count = observed.get("packet_count", 0)
    ike_packet_count = observed.get("ike_packet_count", 0)
    esp_packet_count = observed.get("esp_packet_count", 0)
    capture_duration = observed.get("capture_duration_seconds", 0)

    # IKE activity
    if ike_packet_count > 0:
        findings.append(
            MLSecurityFinding(
                id="obs-ike-detected",
                title="IKE Handshake Traffic Observed",
                category="protocol_visibility",
                severity="info",
                basis="observed",
                confidence=1.0,
                message=f"{ike_packet_count} IKE packet(s) observed in capture.",
                detail=(
                    "IKE handshake metadata (exchange type, SPIs, payload types) is visible "
                    "in plaintext. Only the payload content within encrypted exchanges is protected."
                ),
                recommendation=(
                    "IKE control-plane visibility is expected. "
                    "Ensure IKE_AUTH payloads use encryption (payload type 46)."
                ),
            )
        )

    # ESP activity
    if esp_packet_count > 0:
        findings.append(
            MLSecurityFinding(
                id="obs-esp-detected",
                title="ESP Data Tunnel Active",
                category="protocol_visibility",
                severity="info",
                basis="observed",
                confidence=1.0,
                message=f"{esp_packet_count} ESP packet(s) observed — encrypted data tunnel confirmed active.",
                detail=(
                    "ESP (Encapsulating Security Payload) packets provide confidentiality and "
                    "integrity for the data plane. Inner packet headers are encrypted."
                ),
                recommendation="Verify ESP replay window size is configured appropriately.",
            )
        )

    # Very small capture
    if packet_count < 10 and packet_count > 0:
        findings.append(
            MLSecurityFinding(
                id="obs-small-capture",
                title="Small Capture — Limited Analysis Confidence",
                category="metadata",
                severity="low",
                basis="observed",
                confidence=1.0,
                message=f"Only {packet_count} packets captured. ML predictions may be less reliable.",
                detail=(
                    "The feature extraction quality and ML prediction accuracy improve "
                    "with larger captures containing complete IKE exchanges and ESP flows."
                ),
                recommendation="Capture a more complete session for higher-confidence analysis.",
            )
        )

    # No IKE packets
    if ike_packet_count == 0 and packet_count > 0:
        findings.append(
            MLSecurityFinding(
                id="obs-no-ike",
                title="No IKE Exchange Packets Detected",
                category="protocol_visibility",
                severity="low",
                basis="observed",
                confidence=1.0,
                message="No IKE handshake packets were found in this capture.",
                detail=(
                    "The capture may contain only ESP data-plane traffic (mid-session), "
                    "or the IKE exchange occurred outside the capture window."
                ),
                recommendation=(
                    "Capture the full session including the IKE_SA_INIT and IKE_AUTH exchanges "
                    "for complete cryptographic analysis."
                ),
            )
        )


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------


def assess_ml_results(
    ml_predictions: dict[str, Any],
    observed_features: dict[str, Any],
) -> list[dict[str, Any]]:
    """
    Produce a list of security finding dicts from ML predictions and
    observed packet features.

    Parameters
    ----------
    ml_predictions : dict
        Output of ml_inference.run_inference()
    observed_features : dict
        Full feature dict from feature_extraction.extract_features_from_bytes()

    Returns
    -------
    list of dicts, each conforming to:
        {
            "id": str,
            "title": str,
            "category": str,
            "severity": str,
            "basis": str,
            "confidence": float,
            "confidence_label": str,
            "message": str,
            "detail": str,
            "recommendation": str,
        }
    """
    findings: list[MLSecurityFinding] = []

    # ML-inferred findings
    for target, result in ml_predictions.items():
        prediction = result.get("prediction", "")
        confidence = result.get("confidence") or 0.0

        if target == "encryption":
            _assess_encryption(prediction, confidence, findings)
        elif target == "hash":
            _assess_hash(prediction, confidence, findings)
        elif target == "dh_group":
            _assess_dh_group(prediction, confidence, findings)
        elif target == "pfs_group":
            _assess_pfs(prediction, confidence, findings)

    # Observed-feature findings
    _assess_observed_features(observed_features, findings)

    return [
        {
            "id": f.id,
            "title": f.title,
            "category": f.category,
            "severity": f.severity,
            "basis": f.basis,
            "confidence": f.confidence,
            "confidence_label": _confidence_label(f.confidence),
            "message": f.message,
            "detail": f.detail,
            "recommendation": f.recommendation,
        }
        for f in findings
    ]
