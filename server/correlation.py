"""Evidence-preserving PCAP and gateway telemetry correlation."""

from __future__ import annotations

from typing import Any


def _normalize_spi(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip().lower()
    if not text:
        return None
    raw = text[2:] if text.startswith("0x") else text
    try:
        int(raw, 16)
        return "0x" + (raw.lstrip("0") or "0")
    except ValueError:
        return text


def correlate_spi(
    pcap_spis: list[str],
    telemetry_records: list[dict[str, Any]],
) -> dict[str, Any]:
    """Correlate only exact normalized SPI identifiers.

    No source/destination or timing guess is used as confirmation. Records
    without a matching SPI remain unknown and are returned separately.
    """
    pcap = {_normalize_spi(spi) for spi in pcap_spis}
    pcap.discard(None)
    matches: list[dict[str, Any]] = []
    unmatched_telemetry: list[dict[str, Any]] = []
    matched_ids: set[str] = set()

    for record in telemetry_records:
        candidate_values = [
            record.get("spi"), record.get("inbound_spi"),
            record.get("outbound_spi"), record.get("child_sa_spi"),
            record.get("spi_in"), record.get("spi_out"),
        ]
        candidate_ids = {_normalize_spi(value) for value in candidate_values}
        candidate_ids.discard(None)
        intersection = sorted(pcap.intersection(candidate_ids))
        if intersection:
            matched_ids.update(intersection)
            matches.append({
                "correlation_status": "CONFIRMED",
                "matched_spis": intersection,
                "telemetry": record,
            })
        else:
            unmatched_telemetry.append({
                "correlation_status": "UNKNOWN",
                "telemetry": record,
                "evidence": "No exact PCAP SPI match was available.",
            })

    return {
        "correlation_status": "CONFIRMED" if matches else "UNKNOWN",
        "matched": matches,
        "unmatchedTelemetry": unmatched_telemetry,
        "unmatchedPcapSpis": sorted(pcap - matched_ids),
    }
