"""Default-deny metadata sanitizer for optional cloud transmission."""

from __future__ import annotations

import math
from typing import Any


PACKET_FIELDS = frozenset({
    "timestamp", "direction", "length", "protocol", "spi", "flow_id",
    "iat", "source_ip_hash", "destination_ip_hash", "sequence_observed",
    "source_port", "destination_port",
})
TELEMETRY_FIELDS = frozenset({
    "name", "uniqueid", "state", "version", "local_ts", "remote_ts",
    "initiator_spi", "responder_spi", "inbound_spi", "outbound_spi",
    "spi", "child_sa_spi", "protocol", "reqid", "local_host", "remote_host",
    "established", "encr", "integ", "prf", "dh", "mode", "rekey_time",
    "life_time", "reauth_time", "esn", "esn_in", "esn_out",
    "replay_protection", "replay_window_in", "replay_window_out",
    "xfrm_spi_in", "xfrm_spi_out",
    "bytes_in", "bytes_out", "packets_in", "packets_out",
})
FEATURE_FIELDS = frozenset({
    "packet_count", "total_bytes", "flow_duration", "packets_per_second",
    "bytes_per_second", "avg_packet_size", "std_packet_size",
    "min_packet_size", "max_packet_size", "median_packet_size", "avg_iat",
    "std_iat", "min_iat", "max_iat", "median_iat", "forward_packets",
    "reverse_packets", "forward_bytes", "reverse_bytes", "direction_ratio",
    "burst_count", "avg_burst_size", "max_burst_size", "active_time",
    "idle_time", "packet_size_entropy",
})


def _safe_scalar(value: Any) -> str | int | float | bool | None:
    if value is None or isinstance(value, (str, bool, int)):
        return value
    if isinstance(value, float) and math.isfinite(value):
        return value
    return None


def sanitize_packet_metadata(packet: dict[str, Any]) -> dict[str, Any]:
    """Return only explicitly approved packet metadata; payloads are dropped."""
    return {
        key: _safe_scalar(packet[key])
        for key in PACKET_FIELDS
        if key in packet and _safe_scalar(packet[key]) is not None
    }


def sanitize_telemetry(record: dict[str, Any]) -> dict[str, Any]:
    """Return recognized SA metadata and never keys, credentials, or payloads."""
    return {
        key: _safe_scalar(record[key])
        for key in TELEMETRY_FIELDS
        if key in record and _safe_scalar(record[key]) is not None
    }


def sanitize_analysis_payload(payload: dict[str, Any]) -> dict[str, Any]:
    packets = payload.get("packets", [])
    telemetry = payload.get("telemetry", payload.get("records", []))
    raw_features = payload.get("features", {})
    safe_features = {
        key: _safe_scalar(raw_features[key])
        for key in FEATURE_FIELDS
        if isinstance(raw_features, dict)
        and key in raw_features
        and _safe_scalar(raw_features[key]) is not None
    }
    gateway_id = payload.get("gateway_id") or payload.get("gatewayId")
    agent_version = payload.get("agent_version") or payload.get("agentVersion")
    collected_at = payload.get("collected_at") or payload.get("collectedAt")
    adapter = payload.get("adapter")
    source = payload.get("source")
    status = payload.get("status")
    error = payload.get("error")
    evidence = payload.get("evidence") or []
    packet_list = [sanitize_packet_metadata(item) for item in packets if isinstance(item, dict)]
    telemetry_records = [sanitize_telemetry(item) for item in telemetry if isinstance(item, dict)]

    if not telemetry_records and isinstance(payload.get("records"), list):
        telemetry_records = [sanitize_telemetry(item) for item in payload.get("records", []) if isinstance(item, dict)]

    return {
        "analysis_id": _safe_scalar(payload.get("analysis_id") or payload.get("analysisId")),
        "gateway_id": _safe_scalar(gateway_id),
        "agent_version": _safe_scalar(agent_version),
        "collected_at": _safe_scalar(collected_at),
        "adapter": _safe_scalar(adapter),
        "source": _safe_scalar(source),
        "status": _safe_scalar(status),
        "error": _safe_scalar(error),
        "evidence": [str(item) for item in evidence if item is not None],
        "packets": packet_list,
        "telemetry": telemetry_records,
        "features": safe_features,
    }
