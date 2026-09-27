"""API gateway for offline PCAP analysis and gateway agent management.

This server manages gateway enrollment, authenticated telemetry ingestion,
exact SPI correlation, and agent distribution. It enforces request size limits,
sanitizes telemetry, never persists raw secrets or packet payloads, and never
exposes internal gateway interfaces or command execution to browsers.
"""

from __future__ import annotations

import io
import hmac
import json
import os
import tarfile
import threading
import time
import urllib.parse
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from ai_reporting import (
    GroqReportError,
    build_gateway_ai_context,
    build_pcap_ai_context,
    generate_groq_pcap_narrative,
    generate_groq_narrative,
    load_project_env,
)
from correlation import correlate_spi
from sanitizer import sanitize_analysis_payload
from scapy_analyzer import analyze
from repository import AnalysisRepository
from testbed_control import render_swanctl_config, validate_testbed_settings

load_project_env()

HOST = os.environ.get("VPN_ANALYZER_API_HOST", "0.0.0.0")
PORT = int(os.environ.get("VPN_ANALYZER_API_PORT", "8770"))
MAX_BODY_BYTES = 100 * 1024 * 1024
MAX_PCAP_REPORT_CONTEXT_BYTES = 64 * 1024
AGENT_TOKEN = os.environ.get("VPN_ANALYZER_AGENT_TOKEN")
REPOSITORY = AnalysisRepository(os.environ.get("VPN_ANALYZER_DATABASE", "data/analyzer.sqlite3"))
AI_REPORT_COOLDOWN_SECONDS = 15
_AI_REPORT_LAST_REQUEST: dict[str, float] = {}
_AI_REPORT_RATE_LOCK = threading.Lock()
TESTBED_CONTROL_TOKEN = os.environ.get("VPN_ANALYZER_TESTBED_TOKEN", "")
TESTBED_JOBS: dict[str, dict[str, Any]] = {}
TESTBED_JOBS_LOCK = threading.Lock()


def json_response(
    handler: BaseHTTPRequestHandler,
    status: int,
    value: dict[str, Any] | list[Any],
) -> None:
    body = json.dumps(value).encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json")
    origin = handler.headers.get("Origin", "*")
    handler.send_header("Access-Control-Allow-Origin", origin if origin else "*")
    handler.send_header(
        "Access-Control-Allow-Headers",
        "Content-Type, Authorization, X-Filename, X-Gateway-Id, X-Testbed-Token",
    )
    handler.send_header("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
    handler.send_header("Content-Length", str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)


def text_response(
    handler: BaseHTTPRequestHandler,
    status: int,
    text: str,
    content_type: str = "text/plain",
) -> None:
    body = text.encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", content_type)
    origin = handler.headers.get("Origin", "*")
    handler.send_header("Access-Control-Allow-Origin", origin if origin else "*")
    handler.send_header("Content-Length", str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)


def binary_response(
    handler: BaseHTTPRequestHandler,
    status: int,
    data: bytes,
    content_type: str,
    filename: str | None = None,
) -> None:
    handler.send_response(status)
    handler.send_header("Content-Type", content_type)
    if filename:
        handler.send_header("Content-Disposition", f'attachment; filename="{filename}"')
    origin = handler.headers.get("Origin", "*")
    handler.send_header("Access-Control-Allow-Origin", origin if origin else "*")
    handler.send_header("Content-Length", str(len(data)))
    handler.end_headers()
    handler.wfile.write(data)


def _gateway_field_evidence(value: Any, field: str, valid: bool = True) -> dict[str, Any]:
    if not valid or value is None or (isinstance(value, str) and not value.strip()):
        return {
            "value": None,
            "source": "GATEWAY_TELEMETRY",
            "status": "NOT_DETERMINABLE",
            "evidence": f"The gateway did not provide a valid {field} value.",
        }
    return {
        "value": value,
        "source": "GATEWAY_TELEMETRY",
        "status": "CONFIRMED",
        "evidence": f"Explicit {field} value reported for this active Child SA.",
    }


def _valid_esp_spi(value: Any) -> str | None:
    if isinstance(value, int):
        spi = value
        return f"0x{spi:x}" if 0 < spi <= 0xFFFFFFFF else None
    if not isinstance(value, str):
        return None
    text = str(value).strip().lower()
    raw = text[2:] if text.startswith("0x") else text
    if not raw or len(raw) > 8:
        return None
    try:
        spi = int(raw, 16)
    except ValueError:
        return None
    return f"0x{spi:x}" if spi else None


GATEWAY_SCORE_WEIGHTS = {
    "IKE_VERSION": 8,
    "IKE_ENCRYPTION": 12,
    "IKE_INTEGRITY": 10,
    "DH_GROUP": 10,
    "CHILD_SA_ENCRYPTION": 12,
    "CHILD_SA_INTEGRITY": 10,
    "CHILD_SA_DH_GROUP": 14,
    "CHILD_SA_REPLAY_WINDOW": 14,
    "CHILD_SA_LIFETIME": 10,
}


def _gateway_score(findings: list[dict[str, Any]]) -> dict[str, Any]:
    """Score verified controls only; missing evidence earns no points, not a failure."""
    quality_by_severity = {
        "PASS": 1.0,
        "LOW": 0.75,
        "MEDIUM": 0.5,
        "HIGH": 0.25,
        "CRITICAL": 0.0,
    }
    points = 0.0
    assessed_weight = 0
    factors = []

    for category, weight in GATEWAY_SCORE_WEIGHTS.items():
        matches = [item for item in findings if item.get("category") == category]
        if not matches:
            factors.append({"category": category, "weight": weight, "status": "NOT_DETERMINABLE", "points": 0})
            continue

        quality = min(
            quality_by_severity.get(str(item.get("severity", "")).upper(), 0.0)
            for item in matches
        )
        factor_points = weight * quality
        points += factor_points
        assessed_weight += weight
        factors.append({
            "category": category,
            "weight": weight,
            "status": "ASSESSED",
            "worstSeverity": min(matches, key=lambda item: quality_by_severity.get(str(item.get("severity", "")).upper(), 0.0)).get("severity"),
            "points": round(factor_points, 2),
        })

    coverage = round(assessed_weight)
    score_value = round(points)
    status = "COMPLETE" if coverage == 100 else "PARTIAL" if coverage else "INSUFFICIENT"
    rating = "Hardened" if score_value >= 90 else "Secure" if score_value >= 75 else "Moderate" if score_value >= 55 else "Weak" if score_value >= 35 else "Critical"
    return {
        "value": score_value,
        "max": 100,
        "rating": rating,
        "status": status,
        "evidenceCoveragePercent": coverage,
        "assessedWeight": assessed_weight,
        "totalWeight": 100,
        "method": "Weighted verified-control score. Unknown controls earn no points but are not classified as failures; evidence coverage is shown separately.",
        "factors": factors,
    }


def _configuration_recommendations(
    ike_records: list[dict[str, Any]],
    child_records: list[dict[str, Any]],
) -> list[dict[str, str]]:
    def values(records: list[dict[str, Any]], key: str) -> str:
        found = sorted({str(record[key]) for record in records if record.get(key) not in (None, "")})
        return ", ".join(found) if found else "Not determinable"

    inbound_windows = sorted({str(record["replay_window_in"]) for record in child_records if isinstance(record.get("replay_window_in"), int)})
    current_replay = f"Inbound window: {', '.join(inbound_windows)} packets" if inbound_windows else "Not determinable"
    rekey_values = sorted({str(record["rekey_time"]) for record in child_records if isinstance(record.get("rekey_time"), int)})
    expiry_values = sorted({str(record["life_time"]) for record in child_records if isinstance(record.get("life_time"), int)})
    current_timers = (
        f"Rekey countdown: {', '.join(rekey_values)} s; expiry countdown: {', '.join(expiry_values)} s; configured limits unknown"
        if rekey_values or expiry_values else "Not determinable"
    )

    return [
        {"id": "IKE_VERSION", "setting": "IKE version", "current": values(ike_records, "version"), "recommended": "IKEv2 (RFC 7296)", "basis": "Use the current IKE protocol; confirm peer compatibility."},
        {"id": "IKE_ENCRYPTION", "setting": "IKE encryption", "current": values(ike_records, "encr"), "recommended": "AES-256-GCM or another approved AEAD suite", "basis": "Prefer authenticated encryption where both peers support the same proposal."},
        {"id": "IKE_INTEGRITY", "setting": "IKE integrity / PRF", "current": values(ike_records, "integ") + " / " + values(ike_records, "prf"), "recommended": "Approved SHA-2 PRF/integrity, or AEAD where applicable", "basis": "Do not treat missing telemetry as proof that integrity is absent."},
        {"id": "DH_GROUP", "setting": "IKE key exchange", "current": values(ike_records, "dh"), "recommended": "A currently approved strong group, such as ECP-384 or MODP-3072+", "basis": "Select a group supported by both peers and the deployment policy."},
        {"id": "CHILD_SA_ENCRYPTION", "setting": "ESP encryption", "current": values(child_records, "encr"), "recommended": "AES-256-GCM (AEAD), subject to peer compatibility", "basis": "AEAD combines confidentiality and integrity protection."},
        {"id": "CHILD_SA_INTEGRITY", "setting": "ESP integrity", "current": values(child_records, "integ"), "recommended": "AEAD-integrated integrity or an approved HMAC-SHA-2 transform", "basis": "The correct separate integrity transform depends on the negotiated cipher."},
        {"id": "CHILD_SA_DH_GROUP", "setting": "Child-SA PFS", "current": values(child_records, "dh"), "recommended": "Require a fresh approved Child-SA DH exchange at rekey", "basis": "Verify the active Child SA, not only its configured proposal."},
        {"id": "CHILD_SA_REPLAY_WINDOW", "setting": "Inbound anti-replay", "current": current_replay, "recommended": "Enable anti-replay with a window of at least 64 packets; use ESN when throughput requires it and both peers support it", "basis": "The reported window is a runtime inbound value matched by SPI."},
        {"id": "CHILD_SA_LIFETIME", "setting": "Child-SA lifetime policy", "current": current_timers, "recommended": "Review policy-defined rekey and hard lifetime limits; do not use remaining-time countdowns as configured limits", "basis": "Runtime countdown telemetry does not reveal the configured lifetime policy."},
    ]


def _normalized_algorithm(value: Any) -> str:
    if not isinstance(value, str):
        return ""
    return "".join(character for character in value.upper() if character.isalnum())


def _known_gateway_encryption(value: Any) -> bool:
    normalized = _normalized_algorithm(value)
    return normalized.startswith((
        "AES128", "AES192", "AES256", "AESGCM", "AESCBC", "AESCTR",
        "CHACHA20POLY1305",
    ))


def _gateway_encryption_prefers_aead(value: Any) -> bool:
    return _normalized_algorithm(value).startswith("AESCBC")


def _weak_gateway_encryption(value: Any) -> bool:
    normalized = _normalized_algorithm(value)
    return normalized.startswith(("DES", "3DES", "NULL"))


def _known_gateway_integrity(value: Any) -> bool:
    normalized = _normalized_algorithm(value)
    return normalized.startswith((
        "SHA256", "SHA2256", "SHA384", "SHA2384", "SHA512", "SHA2512",
        "HMACSHA256", "HMACSHA2256", "HMACSHA384", "HMACSHA2384",
        "HMACSHA512", "HMACSHA2512", "AUTHHMACSHA", "AESXCBC", "AESGMAC", "AEAD",
    ))


def _weak_gateway_integrity(value: Any) -> bool:
    normalized = _normalized_algorithm(value)
    return normalized.startswith(("MD5", "HMACMD5", "SHA1", "HMACSHA1", "SHA96", "HMACSHA96"))


def _known_gateway_dh_group(value: Any) -> bool:
    normalized = _normalized_algorithm(value)
    return normalized.startswith((
        "MODP2048", "MODP3072", "MODP4096", "MODP6144", "MODP8192",
        "DH14", "DH15", "DH16", "DH17", "DH18", "DH19", "DH20", "DH21",
        "DHGROUP14", "DHGROUP15", "DHGROUP16", "DHGROUP17", "DHGROUP18",
        "DHGROUP19", "DHGROUP20", "DHGROUP21", "ECP256", "ECP384", "ECP521",
        "GROUP19", "GROUP20", "GROUP21", "CURVE25519", "CURVE448",
    ))


def _weak_gateway_dh_group(value: Any) -> bool:
    normalized = _normalized_algorithm(value)
    return normalized in {
        "MODP768", "MODP1024", "MODP1536", "DH1", "DH2", "DH5",
    }


def _build_child_sa_evidence(
    child_records: list[dict[str, Any]],
    fresh: bool,
    collected_at: str | None,
) -> list[dict[str, Any]]:
    evidence_records = []
    for record in child_records:
        spi_values = [
            _valid_esp_spi(record.get(key))
            for key in ("inbound_spi", "outbound_spi", "spi", "child_sa_spi")
        ]
        observed_spis = sorted(set(value for value in spi_values if value))
        current_spis = observed_spis if fresh else []
        spi_valid = bool(current_spis)
        fields: dict[str, Any] = {}

        mode = record.get("mode")
        mode_valid = isinstance(mode, str) and mode.strip().upper() in {"TUNNEL", "TRANSPORT"}
        fields["mode"] = _gateway_field_evidence(mode.upper() if mode_valid else None, "mode", mode_valid and spi_valid)

        for field in ("state", "encr", "integ", "local_ts", "remote_ts"):
            value = record.get(field)
            valid = isinstance(value, (str, int, float)) and bool(str(value).strip())
            if field == "state":
                valid = valid and str(value).strip().upper() in {
                    "ACTIVE", "ESTABLISHED", "INSTALLED", "REKEYING", "DELETING",
                }
            elif field == "encr":
                valid = valid and (_known_gateway_encryption(value) or _weak_gateway_encryption(value))
            elif field == "integ":
                valid = valid and (_known_gateway_integrity(value) or _weak_gateway_integrity(value))
            fields[field] = _gateway_field_evidence(value if valid else None, field, valid and spi_valid)

        dh_group = record.get("dh")
        dh_valid = _known_gateway_dh_group(dh_group) or _weak_gateway_dh_group(dh_group)
        fields["dh_group"] = _gateway_field_evidence(dh_group if dh_valid else None, "Child-SA DH group", dh_valid and spi_valid)
        fields["pfs"] = _gateway_field_evidence(True, "Child-SA PFS", dh_valid and spi_valid)

        esn = record.get("esn")
        esn_valid = isinstance(esn, bool)
        fields["esn"] = _gateway_field_evidence(esn if esn_valid else None, "Extended Sequence Numbers", esn_valid and spi_valid)

        for direction in ("in", "out"):
            spi_field = "inbound_spi" if direction == "in" else "outbound_spi"
            child_spi = _valid_esp_spi(record.get(spi_field))
            xfrm_spi = _valid_esp_spi(record.get(f"xfrm_spi_{direction}"))
            xfrm_match = bool(fresh and child_spi and xfrm_spi and child_spi == xfrm_spi)
            window = record.get(f"replay_window_{direction}")
            window_valid = isinstance(window, int) and not isinstance(window, bool) and window >= 0
            fields[f"replay_window_{direction}"] = _gateway_field_evidence(
                window if window_valid else None,
                f"{direction}bound XFRM replay window",
                window_valid and xfrm_match,
            )

            esn_direction = record.get(f"esn_{direction}")
            if isinstance(esn_direction, bool):
                esn_match = xfrm_match
            elif esn_valid:
                esn_direction = esn
                esn_match = spi_valid
            else:
                esn_direction = None
                esn_match = False
            fields[f"esn_{direction}"] = _gateway_field_evidence(
                esn_direction if isinstance(esn_direction, bool) else None,
                f"{direction}bound Extended Sequence Numbers",
                isinstance(esn_direction, bool) and esn_match,
            )

        for field in ("rekey_time", "life_time"):
            value = record.get(field)
            try:
                seconds = int(value)
                valid = seconds >= 0 and str(value).strip() == str(seconds)
            except (TypeError, ValueError):
                seconds = None
                valid = False
            fields[field] = _gateway_field_evidence(seconds, field, valid and spi_valid)

        replay_protection = record.get("replay_protection")
        inbound_window_valid = (
            isinstance(record.get("replay_window_in"), int)
            and not isinstance(record.get("replay_window_in"), bool)
            and record["replay_window_in"] >= 0
            and fresh
            and _valid_esp_spi(record.get("inbound_spi")) is not None
            and _valid_esp_spi(record.get("inbound_spi")) == _valid_esp_spi(record.get("xfrm_spi_in"))
        )
        if not isinstance(replay_protection, bool) and inbound_window_valid:
            replay_protection = record["replay_window_in"] > 0
        fields["replay_protection"] = _gateway_field_evidence(
            replay_protection if isinstance(replay_protection, bool) else None,
            "inbound replay protection",
            isinstance(replay_protection, bool) and inbound_window_valid and spi_valid,
        )

        evidence_records.append({
            "spi": current_spis[0] if len(current_spis) == 1 else None,
            "observed_spis": observed_spis,
            "collected_at": collected_at,
            "sa_identity_status": "CONFIRMED" if spi_valid else "NOT_DETERMINABLE",
            "fields": fields,
        })
    return evidence_records


def _extract_bearer_token(auth_header: str | None) -> str | None:
    if not auth_header:
        return None
    parts = auth_header.strip().split(" ", 1)
    if len(parts) == 2 and parts[0].lower() == "bearer":
        return parts[1].strip()
    return None


class ApiHandler(BaseHTTPRequestHandler):
    def do_OPTIONS(self) -> None:
        self.send_response(204)
        origin = self.headers.get("Origin", "*")
        self.send_header("Access-Control-Allow-Origin", origin if origin else "*")
        self.send_header(
            "Access-Control-Allow-Headers",
            "Content-Type, Authorization, X-Filename, X-Gateway-Id, X-Testbed-Token",
        )
        self.send_header("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_POST(self) -> None:
        content_length = int(self.headers.get("Content-Length", "0"))
        path = self.path.split("?")[0].rstrip("/")
        if content_length > MAX_BODY_BYTES:
            json_response(self, 413, {"error": "INVALID_CONTENT_LENGTH"})
            return
        if path == "/api/reports/pcap-narrative" and content_length > MAX_PCAP_REPORT_CONTEXT_BYTES:
            json_response(self, 413, {"error": "REPORT_CONTEXT_TOO_LARGE"})
            return

        body = self.rfile.read(content_length) if content_length > 0 else b""

        # 1. PCAP Analysis
        if path == "/api/analyze/pcap":
            self._analyze_pcap(body)
            return

        if path == "/api/reports/pcap-narrative":
            self._generate_pcap_report_narrative(body)
            return

        # 2. Gateway Registration
        if path == "/api/gateways":
            self._create_gateway(body)
            return

        # 3. Gateway Enrollment
        if path == "/api/gateways/enroll":
            self._enroll_gateway(body)
            return

        # 4. Gateway Actions
        if path.startswith("/api/gateways/"):
            parts = path[len("/api/gateways/"):].split("/")
            if len(parts) >= 2 and parts[1] == "testbed":
                if len(parts) == 2:
                    self._queue_testbed_apply(parts[0], body)
                    return
                if len(parts) == 3 and parts[2] == "next":
                    self._agent_next_testbed_job(parts[0])
                    return
                if len(parts) == 4 and parts[3] == "result":
                    self._agent_testbed_result(parts[0], parts[2], body)
                    return
            if len(parts) == 2:
                gateway_id, action = parts
                if action == "heartbeat":
                    self._gateway_heartbeat(gateway_id, body)
                    return
                elif action == "telemetry":
                    self._gateway_telemetry(gateway_id, body)
                    return
                elif action == "token":
                    self._gateway_regenerate_token(gateway_id)
                    return
                elif action == "revoke":
                    self._gateway_revoke(gateway_id)
                    return
                elif action == "ai-report":
                    self._generate_gateway_ai_report(gateway_id)
                    return

        # 5. Analysis Correlation
        if path.startswith("/api/analysis/") and path.endswith("/correlate"):
            analysis_id = path[len("/api/analysis/"):-len("/correlate")].strip("/")
            self._correlate_analysis(analysis_id, body)
            return

        # 6. Legacy Telemetry Ingestion
        if path == "/api/agent/telemetry":
            self._ingest_metadata(body)
            return
        if path.startswith("/api/analysis/") and path.endswith("/telemetry"):
            analysis_id = path[len("/api/analysis/"):-len("/telemetry")]
            self._ingest_analysis_telemetry(analysis_id, body)
            return

        json_response(self, 404, {"error": "NOT_FOUND"})

    def do_GET(self) -> None:
        parsed_url = urllib.parse.urlparse(self.path)
        path = parsed_url.path.rstrip("/")
        query = urllib.parse.parse_qs(parsed_url.query)

        # 1. Gateway List
        if path == "/api/gateways":
            gateways = REPOSITORY.list_gateways()
            json_response(self, 200, gateways)
            return

        # 2. Gateway Details
        if path.startswith("/api/gateways/"):
            parts = path[len("/api/gateways/"):].split("/")
            if len(parts) == 1:
                gateway_id = parts[0]
                gateway = REPOSITORY.get_gateway(gateway_id, include_history=True)
                if gateway is None:
                    json_response(self, 404, {"error": "GATEWAY_NOT_FOUND"})
                    return
                json_response(self, 200, gateway)
                return
            elif len(parts) == 2 and parts[1] == "telemetry":
                gateway_id = parts[0]
                telemetry = REPOSITORY.get_latest_gateway_telemetry(gateway_id)
                json_response(self, 200, telemetry or {})
                return
            elif len(parts) == 2 and parts[1] == "report":
                self._serve_gateway_report(parts[0])
                return
            elif len(parts) == 3 and parts[1] == "testbed":
                self._testbed_job_status(parts[0], parts[2])
                return

        # 3. Agent Installer & Package
        if path == "/api/agent/install.sh":
            self._serve_install_script()
            return
        if path in ("/api/agent/download", "/api/agent/bundle.tar.gz"):
            self._serve_agent_bundle()
            return

        # 4. Analysis Endpoints
        if path.startswith("/api/analysis/"):
            prefix = "/api/analysis/"
            if path.endswith("/telemetry"):
                analysis_id = path[len(prefix):-len("/telemetry")]
                if not analysis_id or len(analysis_id) > 80:
                    json_response(self, 400, {"error": "INVALID_ANALYSIS_ID"})
                    return
                gateway_id = query.get("gateway_id", [None])[0]
                if gateway_id:
                    result = REPOSITORY.correlate_analysis_with_gateway(analysis_id, gateway_id)
                else:
                    result = self._build_telemetry_summary(analysis_id)
                if result is None:
                    json_response(self, 404, {"error": "ANALYSIS_NOT_FOUND"})
                    return
                json_response(self, 200, result)
                return

            analysis_id = path[len(prefix):].split("/")[0]
            if not analysis_id or len(analysis_id) > 80:
                json_response(self, 400, {"error": "INVALID_ANALYSIS_ID"})
                return
            result = REPOSITORY.get_analysis(analysis_id)
            if result is None:
                json_response(self, 404, {"error": "ANALYSIS_NOT_FOUND"})
                return
            json_response(self, 200, result)
            return

        json_response(self, 404, {"error": "NOT_FOUND"})

    def do_DELETE(self) -> None:
        path = self.path.split("?")[0].rstrip("/")
        if path.startswith("/api/gateways/"):
            gateway_id = path[len("/api/gateways/"):].strip("/")
            if not gateway_id or "/" in gateway_id:
                json_response(self, 400, {"error": "INVALID_GATEWAY_ID"})
                return
            removed = REPOSITORY.remove_gateway(gateway_id)
            if not removed:
                json_response(self, 404, {"error": "GATEWAY_NOT_FOUND"})
                return
            json_response(self, 200, {"status": "REMOVED", "gateway_id": gateway_id})
            return
        json_response(self, 404, {"error": "NOT_FOUND"})

    # ================= Helper Handlers =================

    def _analyze_pcap(self, body: bytes) -> None:
        try:
            filename = self.headers.get("X-Filename", "capture.pcap")
            result = analyze(body, filename)
        except Exception as exc:
            json_response(self, 400, {"error": "PCAP_ANALYSIS_FAILED", "detail": str(exc)})
            return
        analysis_id = REPOSITORY.save_analysis(result)
        result["analysisId"] = analysis_id

        # If gateway context was provided on upload, correlate server-side immediately
        gateway_id = self.headers.get("X-Gateway-Id")
        if gateway_id:
            summary = REPOSITORY.correlate_analysis_with_gateway(analysis_id, gateway_id)
            if summary:
                result["gatewayTelemetry"] = summary
                result["correlation"] = summary.get("correlation")

        json_response(self, 200, result)

    def _create_gateway(self, body: bytes) -> None:
        try:
            payload = json.loads(body.decode("utf-8")) if body else {}
        except (UnicodeDecodeError, json.JSONDecodeError):
            json_response(self, 400, {"error": "INVALID_JSON"})
            return
        if not isinstance(payload, dict):
            json_response(self, 400, {"error": "JSON_OBJECT_REQUIRED"})
            return

        display_name = payload.get("display_name") or payload.get("displayName")
        if not display_name or not isinstance(display_name, str) or not display_name.strip():
            json_response(self, 400, {"error": "DISPLAY_NAME_REQUIRED"})
            return

        gateway_type = payload.get("gateway_type") or payload.get("gatewayType") or "STRONGSWAN"
        try:
            gateway, raw_token, expires_at = REPOSITORY.create_gateway(
                display_name=display_name.strip(),
                gateway_type=str(gateway_type).strip(),
            )
        except Exception as exc:
            json_response(self, 500, {"error": "GATEWAY_CREATION_FAILED", "detail": str(exc)})
            return

        host = self.headers.get("Host", f"127.0.0.1:{PORT}")
        server_url = f"http://{host}"

        json_response(
            self,
            201,
            {
                "gateway_id": gateway["gateway_id"],
                "display_name": gateway["display_name"],
                "gateway_type": gateway["gateway_type"],
                "status": gateway["status"],
                "created_at": gateway["created_at"],
                "enrollment_token": raw_token,
                "expires_at": expires_at,
                "server_url": server_url,
            },
        )

    def _enroll_gateway(self, body: bytes) -> None:
        try:
            payload = json.loads(body.decode("utf-8")) if body else {}
        except (UnicodeDecodeError, json.JSONDecodeError):
            json_response(self, 400, {"error": "INVALID_JSON"})
            return
        if not isinstance(payload, dict):
            json_response(self, 400, {"error": "JSON_OBJECT_REQUIRED"})
            return

        token = payload.get("token") or payload.get("enrollment_token")
        if not token or not isinstance(token, str):
            json_response(self, 400, {"error": "TOKEN_REQUIRED"})
            return

        agent_version = str(payload.get("agent_version") or "1.0.0")
        adapter = str(payload.get("adapter") or "STRONGSWAN")

        result = REPOSITORY.enroll_gateway(
            enrollment_token=token.strip(),
            agent_version=agent_version,
            adapter=adapter,
        )

        if "error" in result:
            status_code = 401 if "INVALID" in result["error"] or "REVOKED" in result["error"] else 400
            json_response(self, status_code, result)
            return

        json_response(self, 200, result)

    def _gateway_heartbeat(self, gateway_id: str, body: bytes) -> None:
        token = _extract_bearer_token(self.headers.get("Authorization"))
        if not token:
            json_response(self, 401, {"error": "UNAUTHORIZED", "detail": "Bearer token required"})
            return

        gateway = REPOSITORY.authenticate_agent(gateway_id, token)
        if gateway is None:
            json_response(self, 401, {"error": "UNAUTHORIZED", "detail": "Invalid or revoked credentials"})
            return

        REPOSITORY.record_heartbeat(gateway_id)
        json_response(self, 200, {"status": "OK", "gateway_id": gateway_id})

    def _gateway_telemetry(self, gateway_id: str, body: bytes) -> None:
        token = _extract_bearer_token(self.headers.get("Authorization"))
        if not token:
            json_response(self, 401, {"error": "UNAUTHORIZED", "detail": "Bearer token required"})
            return

        gateway = REPOSITORY.authenticate_agent(gateway_id, token)
        if gateway is None:
            json_response(self, 401, {"error": "UNAUTHORIZED", "detail": "Invalid or revoked credentials"})
            return

        try:
            payload = json.loads(body.decode("utf-8")) if body else {}
        except (UnicodeDecodeError, json.JSONDecodeError):
            json_response(self, 400, {"error": "INVALID_JSON"})
            return
        if not isinstance(payload, dict):
            json_response(self, 400, {"error": "JSON_OBJECT_REQUIRED"})
            return

        sanitized = sanitize_analysis_payload({**payload, "gateway_id": gateway_id})
        REPOSITORY.record_gateway_telemetry(
            gateway_id=gateway_id,
            payload=sanitized,
            analysis_id=sanitized.get("analysis_id"),
        )

        json_response(self, 200, {"status": "ACCEPTED", "gateway_id": gateway_id})

    def _gateway_regenerate_token(self, gateway_id: str) -> None:
        try:
            raw_token, expires_at = REPOSITORY.create_enrollment_token(gateway_id)
            json_response(
                self,
                200,
                {
                    "gateway_id": gateway_id,
                    "enrollment_token": raw_token,
                    "expires_at": expires_at,
                },
            )
        except ValueError as exc:
            json_response(self, 404 if "NOT_FOUND" in str(exc) else 400, {"error": str(exc)})
        except Exception as exc:
            json_response(self, 500, {"error": "FAILED_TO_GENERATE_TOKEN", "detail": str(exc)})

    def _gateway_revoke(self, gateway_id: str) -> None:
        success = REPOSITORY.revoke_gateway(gateway_id)
        if not success:
            json_response(self, 404, {"error": "GATEWAY_NOT_FOUND"})
            return
        json_response(self, 200, {"status": "REVOKED", "gateway_id": gateway_id})

    def _testbed_control_authorized(self) -> bool:
        provided = self.headers.get("X-Testbed-Token", "")
        expected = os.environ.get("VPN_ANALYZER_TESTBED_TOKEN", "") or TESTBED_CONTROL_TOKEN
        return bool(expected and provided and hmac.compare_digest(provided, expected))

    def _testbed_control_configured(self) -> bool:
        return bool(os.environ.get("VPN_ANALYZER_TESTBED_TOKEN", "") or TESTBED_CONTROL_TOKEN)

    def _queue_testbed_apply(self, gateway_id: str, body: bytes) -> None:
        if not self._testbed_control_authorized():
            json_response(self, 503 if not self._testbed_control_configured() else 401, {
                "error": "TESTBED_CONTROL_TOKEN_NOT_CONFIGURED" if not self._testbed_control_configured() else "UNAUTHORIZED",
            })
            return

        try:
            value = json.loads(body.decode("utf-8")) if body else {}
        except (UnicodeDecodeError, json.JSONDecodeError):
            json_response(self, 400, {"error": "INVALID_JSON"})
            return
        if not isinstance(value, dict) or value.get("confirmed") is not True:
            json_response(self, 400, {"error": "EXPLICIT_CONFIRMATION_REQUIRED"})
            return
        try:
            settings = validate_testbed_settings(value.get("settings"))
        except ValueError as exc:
            json_response(self, 400, {"error": str(exc)})
            return

        gateway = REPOSITORY.get_gateway(gateway_id, include_history=False)
        if gateway is None:
            json_response(self, 404, {"error": "GATEWAY_NOT_FOUND"})
            return
        if gateway.get("status") != "CONNECTED":
            json_response(self, 409, {"error": "GATEWAY_NOT_CONNECTED"})
            return
        if gateway.get("gateway_type") not in {"STRONGSWAN", "STRONGSWAN_VICI"}:
            json_response(self, 400, {"error": "UNSUPPORTED_GATEWAY_TYPE"})
            return

        with TESTBED_JOBS_LOCK:
            active = any(
                job.get("gateway_id") == gateway_id and job.get("status") in {"PENDING", "RUNNING"}
                for job in TESTBED_JOBS.values()
            )
            if active:
                json_response(self, 409, {"error": "TESTBED_JOB_ALREADY_ACTIVE"})
                return
            job_id = uuid.uuid4().hex
            suffix = job_id[:10]
            job = {
                "job_id": job_id,
                "gateway_id": gateway_id,
                "connection_name": f"lab_testbed_{suffix}",
                "child_name": f"lab_child_{suffix}",
                "settings": settings,
                "status": "PENDING",
                "message": "Waiting for the opted-in gateway agent.",
                "created_at": time.time(),
            }
            TESTBED_JOBS[job_id] = job

        json_response(self, 202, {
            "jobId": job_id,
            "status": job["status"],
            "message": job["message"],
            "connectionName": job["connection_name"],
            "childName": job["child_name"],
        })

    def _agent_next_testbed_job(self, gateway_id: str) -> None:
        token = _extract_bearer_token(self.headers.get("Authorization"))
        if not token or REPOSITORY.authenticate_agent(gateway_id, token) is None:
            json_response(self, 401, {"error": "UNAUTHORIZED"})
            return
        with TESTBED_JOBS_LOCK:
            job = next((
                item for item in TESTBED_JOBS.values()
                if item["gateway_id"] == gateway_id and item["status"] == "PENDING"
            ), None)
            if job is None:
                json_response(self, 200, {"job": None})
                return
            job["status"] = "RUNNING"
            job["message"] = "Agent is applying the validated temporary connection."
            response = {
                "jobId": job["job_id"],
                "connectionName": job["connection_name"],
                "childName": job["child_name"],
                "settings": job["settings"],
            }
        json_response(self, 200, {"job": response})

    def _agent_testbed_result(self, gateway_id: str, job_id: str, body: bytes) -> None:
        token = _extract_bearer_token(self.headers.get("Authorization"))
        if not token or REPOSITORY.authenticate_agent(gateway_id, token) is None:
            json_response(self, 401, {"error": "UNAUTHORIZED"})
            return
        try:
            value = json.loads(body.decode("utf-8")) if body else {}
        except (UnicodeDecodeError, json.JSONDecodeError):
            json_response(self, 400, {"error": "INVALID_JSON"})
            return
        if not isinstance(value, dict) or value.get("status") not in {"SUCCEEDED", "FAILED"}:
            json_response(self, 400, {"error": "INVALID_TESTBED_RESULT"})
            return
        message = value.get("message")
        if not isinstance(message, str) or len(message) > 240:
            json_response(self, 400, {"error": "INVALID_TESTBED_RESULT"})
            return
        with TESTBED_JOBS_LOCK:
            job = TESTBED_JOBS.get(job_id)
            if job is None or job["gateway_id"] != gateway_id or job["status"] != "RUNNING":
                json_response(self, 404, {"error": "TESTBED_JOB_NOT_FOUND"})
                return
            job["status"] = value["status"]
            job["message"] = message
            job["finished_at"] = time.time()
        json_response(self, 200, {"jobId": job_id, "status": value["status"]})

    def _testbed_job_status(self, gateway_id: str, job_id: str) -> None:
        if not self._testbed_control_authorized():
            json_response(self, 503 if not self._testbed_control_configured() else 401, {
                "error": "TESTBED_CONTROL_TOKEN_NOT_CONFIGURED" if not self._testbed_control_configured() else "UNAUTHORIZED",
            })
            return
        with TESTBED_JOBS_LOCK:
            job = TESTBED_JOBS.get(job_id)
            if job is None or job["gateway_id"] != gateway_id:
                json_response(self, 404, {"error": "TESTBED_JOB_NOT_FOUND"})
                return
            response = {"jobId": job_id, "status": job["status"], "message": job["message"]}
        json_response(self, 200, response)

    def _correlate_analysis(self, analysis_id: str, body: bytes) -> None:
        try:
            payload = json.loads(body.decode("utf-8")) if body else {}
        except (UnicodeDecodeError, json.JSONDecodeError):
            json_response(self, 400, {"error": "INVALID_JSON"})
            return
        if not isinstance(payload, dict):
            json_response(self, 400, {"error": "JSON_OBJECT_REQUIRED"})
            return

        gateway_id = payload.get("gateway_id")
        if not gateway_id or not isinstance(gateway_id, str):
            json_response(self, 400, {"error": "GATEWAY_ID_REQUIRED"})
            return

        summary = REPOSITORY.correlate_analysis_with_gateway(analysis_id, gateway_id.strip())
        if summary is None:
            json_response(self, 404, {"error": "ANALYSIS_NOT_FOUND"})
            return
        json_response(self, 200, summary)

    def _serve_install_script(self) -> None:
        host = self.headers.get("Host", f"127.0.0.1:{PORT}")
        server_url = f"http://{host}"
        script = f"""#!/usr/bin/env bash
set -e

SERVER_URL="${{SERVER_URL:-"{server_url}"}}"
INSTALL_DIR="/opt/vpn-analyzer-agent"
BIN_DIR="/usr/local/bin"

if [ "$(id -u)" -ne 0 ]; then
  INSTALL_DIR="$HOME/.vpn-analyzer-agent"
  BIN_DIR="$HOME/.local/bin"
fi

echo "[*] Installing VPN Analyzer Gateway Agent..."
mkdir -p "$INSTALL_DIR"
mkdir -p "$BIN_DIR"

if command -v curl >/dev/null 2>&1; then
  curl -sSL "$SERVER_URL/api/agent/download" | tar -xz -C "$INSTALL_DIR"
elif command -v wget >/dev/null 2>&1; then
  wget -qO- "$SERVER_URL/api/agent/download" | tar -xz -C "$INSTALL_DIR"
else
  echo "[!] Error: curl or wget is required to install the agent."
  exit 1
fi

WRAPPER="$BIN_DIR/vpn-analyzer-agent"
cat << 'EOF' > "$WRAPPER"
#!/usr/bin/env bash
AGENT_DIR="$(dirname "$(realpath "$0")")"
if [ ! -f "$AGENT_DIR/vpn_analyzer_agent.py" ]; then
  AGENT_DIR="/opt/vpn-analyzer-agent"
  if [ ! -f "$AGENT_DIR/vpn_analyzer_agent.py" ]; then
    AGENT_DIR="$HOME/.vpn-analyzer-agent"
  fi
fi
exec python3 "$AGENT_DIR/vpn_analyzer_agent.py" "$@"
EOF

chmod +x "$WRAPPER"
chmod +x "$INSTALL_DIR/vpn_analyzer_agent.py"

echo "[✓] VPN Analyzer Gateway Agent installed successfully!"
echo "[✓] Binary location: $WRAPPER"
echo ""
echo "Next step: Enroll your gateway by running:"
echo "  vpn-analyzer-agent enroll --server $SERVER_URL --token <ONE_TIME_TOKEN>"
"""
        text_response(self, 200, script, content_type="text/x-shellscript")

    def _serve_agent_bundle(self) -> None:
        buf = io.BytesIO()
        base_dir = Path(__file__).resolve().parent
        files_to_pack = [
            ("vpn_analyzer_agent.py", base_dir / "vpn_analyzer_agent.py"),
            ("telemetry.py", base_dir / "telemetry.py"),
            ("sanitizer.py", base_dir / "sanitizer.py"),
            ("testbed_control.py", base_dir / "testbed_control.py"),
            ("correlation.py", base_dir / "correlation.py"),
            ("agent_config.example.json", base_dir / "agent_config.example.json"),
        ]

        with tarfile.open(fileobj=buf, mode="w:gz") as tar:
            for arcname, filepath in files_to_pack:
                if filepath.exists():
                    tar.add(str(filepath), arcname=arcname)

        binary_response(
            self,
            200,
            buf.getvalue(),
            content_type="application/gzip",
            filename="vpn-analyzer-agent.tar.gz",
        )

    def _serve_gateway_report(self, gateway_id: str) -> None:
        report = self._build_gateway_report_payload(gateway_id)
        if report is None:
            json_response(self, 404, {"error": "GATEWAY_NOT_FOUND"})
            return
        json_response(self, 200, report)

    def _build_gateway_report_payload(self, gateway_id: str) -> dict[str, Any] | None:
        """Build a report from the latest stored gateway snapshot."""
        import time as _time
        gateway = REPOSITORY.get_gateway(gateway_id, include_history=False)
        if gateway is None:
            return None

        telemetry = REPOSITORY.get_latest_gateway_telemetry(gateway_id)
        records = telemetry.get("records", []) if telemetry else []
        evidence = telemetry.get("evidence", []) if telemetry else []
        adapter = (telemetry.get("adapter") or gateway.get("telemetry_adapter") or "STRONGSWAN") if telemetry else "STRONGSWAN"
        collected_at = telemetry.get("collectedAt") if telemetry else None
        received_at = telemetry.get("receivedAt") if telemetry else None
        telem_status = (telemetry.get("status") or "NOT_DETERMINABLE") if telemetry else "NOT_DETERMINABLE"
        telemetry_fresh = gateway.get("status") == "CONNECTED" and telem_status == "CONFIRMED"

        ike_records = [r for r in records if isinstance(r, dict) and (r.get("version") or r.get("initiator_spi") or r.get("responder_spi") or r.get("prf"))]
        child_records = [r for r in records if isinstance(r, dict) and (r.get("protocol") == "ESP" or r.get("inbound_spi") or r.get("outbound_spi"))]

        # Gateway-only security assessment
        findings = []
        limitations = []

        if not telemetry or not records:
            limitations.append("No telemetry received from the gateway yet. Assessment is incomplete.")
        elif not telemetry_fresh:
            limitations.append("Gateway telemetry is stale or unconfirmed; current security findings are not determinable.")
        else:
            # IKE assessment
            for ike in ike_records:
                version = ike.get("version")
                if version == 2 or str(version) == "2":
                    findings.append({"category": "IKE_VERSION", "severity": "Pass", "value": "IKEv2", "detail": "The active IKE SA reports IKEv2."})
                elif version == 1 or str(version) == "1":
                    findings.append({"category": "IKE_VERSION", "severity": "High", "value": "IKEv1", "detail": "The active IKE SA reports legacy IKEv1; migrate to IKEv2 where peer compatibility permits."})
                else:
                    limitations.append("IKE version could not be determined from available telemetry.")

                encr = ike.get("encr", "")
                if _weak_gateway_encryption(encr):
                    findings.append({"category": "IKE_ENCRYPTION", "severity": "Critical", "value": encr, "detail": "Weak or null IKE encryption algorithm detected."})
                elif _gateway_encryption_prefers_aead(encr):
                    findings.append({"category": "IKE_ENCRYPTION", "severity": "Low", "value": encr, "detail": "AES-CBC is a recognized cipher; prefer AEAD where peers support it. This is a hardening recommendation, not evidence that this implementation is vulnerable."})
                elif _known_gateway_encryption(encr):
                    findings.append({"category": "IKE_ENCRYPTION", "severity": "Pass", "value": encr, "detail": "IKE encryption algorithm is acceptable."})
                else:
                    limitations.append("IKE encryption algorithm could not be determined from available telemetry.")

                integ = ike.get("integ", "")
                if _weak_gateway_integrity(integ):
                    findings.append({"category": "IKE_INTEGRITY", "severity": "High", "value": integ, "detail": "Weak IKE integrity/PRF algorithm detected."})
                elif _known_gateway_integrity(integ):
                    findings.append({"category": "IKE_INTEGRITY", "severity": "Pass", "value": integ, "detail": "IKE integrity algorithm is acceptable."})
                else:
                    limitations.append("IKE integrity algorithm could not be determined from available telemetry.")

                dh = ike.get("dh", "")
                if _weak_gateway_dh_group(dh):
                    findings.append({"category": "DH_GROUP", "severity": "High", "value": dh, "detail": "Weak Diffie-Hellman group; susceptible to downgrade attacks."})
                elif _known_gateway_dh_group(dh):
                    findings.append({"category": "DH_GROUP", "severity": "Pass", "value": dh, "detail": "Diffie-Hellman group is acceptable."})
                else:
                    limitations.append("Diffie-Hellman group could not be determined from available telemetry.")

            # Child SA assessment
            for child in child_records:
                c_encr = child.get("encr", "")
                if _weak_gateway_encryption(c_encr):
                    findings.append({"category": "CHILD_SA_ENCRYPTION", "severity": "Critical", "value": c_encr, "detail": "Weak or null Child-SA encryption detected."})
                elif _gateway_encryption_prefers_aead(c_encr):
                    findings.append({"category": "CHILD_SA_ENCRYPTION", "severity": "Low", "value": c_encr, "detail": "AES-CBC is a recognized cipher; prefer AEAD where peers support it. This is a hardening recommendation, not evidence that this implementation is vulnerable."})
                elif _known_gateway_encryption(c_encr):
                    findings.append({"category": "CHILD_SA_ENCRYPTION", "severity": "Pass", "value": c_encr, "detail": "Child-SA encryption algorithm is acceptable."})
                else:
                    limitations.append("Child-SA encryption could not be determined from available telemetry.")

                c_integ = child.get("integ", "")
                if _weak_gateway_integrity(c_integ):
                    findings.append({"category": "CHILD_SA_INTEGRITY", "severity": "High", "value": c_integ, "detail": "Weak Child-SA integrity algorithm detected."})
                elif _known_gateway_integrity(c_integ):
                    findings.append({"category": "CHILD_SA_INTEGRITY", "severity": "Pass", "value": c_integ, "detail": "Child-SA integrity algorithm is acceptable."})
                else:
                    limitations.append("Child-SA integrity could not be determined from available telemetry.")

                child_dh = child.get("dh", "")
                if _weak_gateway_dh_group(child_dh):
                    findings.append({"category": "CHILD_SA_DH_GROUP", "severity": "High", "value": child_dh, "detail": "Weak Child-SA key-exchange group detected."})
                elif _known_gateway_dh_group(child_dh):
                    findings.append({"category": "CHILD_SA_DH_GROUP", "severity": "Pass", "value": child_dh, "detail": "Child-SA key-exchange group is recognized."})
                else:
                    limitations.append("Child-SA key-exchange group could not be determined from available telemetry.")

                inbound_window = child.get("replay_window_in")
                inbound_spi = _valid_esp_spi(child.get("inbound_spi"))
                xfrm_inbound_spi = _valid_esp_spi(child.get("xfrm_spi_in"))
                replay_state_matched = bool(
                    telemetry_fresh and inbound_spi and xfrm_inbound_spi and inbound_spi == xfrm_inbound_spi
                )
                if replay_state_matched and isinstance(inbound_window, int) and not isinstance(inbound_window, bool) and inbound_window >= 0:
                    if inbound_window == 0:
                        findings.append({"category": "CHILD_SA_REPLAY_WINDOW", "severity": "High", "value": "0 packets", "detail": "Inbound ESP anti-replay window is disabled."})
                    elif inbound_window < 64:
                        findings.append({"category": "CHILD_SA_REPLAY_WINDOW", "severity": "Medium", "value": f"{inbound_window} packets", "detail": "Inbound anti-replay is enabled, but the window is below the project's 64-packet recommendation."})
                    else:
                        findings.append({"category": "CHILD_SA_REPLAY_WINDOW", "severity": "Pass", "value": f"{inbound_window} packets", "detail": "Inbound ESP anti-replay window meets the project's 64-packet recommendation."})
                elif not replay_state_matched:
                    limitations.append("Inbound replay-window evidence was not matched to the active Child-SA SPI.")
                else:
                    limitations.append("Inbound replay-window size could not be determined from SPI-matched XFRM state.")

            if not ike_records and not child_records:
                limitations.append("Gateway is connected but no active Security Associations were reported. No cryptographic assessment is possible without active SAs.")

        if not any(
            _known_gateway_dh_group(child.get("dh")) or _weak_gateway_dh_group(child.get("dh"))
            for child in child_records
        ):
            limitations.append("PFS could not be determined because no supported Child-SA DH group was reported.")
        if not any(isinstance(child.get("esn_in"), bool) for child in child_records):
            limitations.append("Inbound ESN status could not be determined from SPI-matched gateway or XFRM metadata.")
        limitations.append("This report reflects the gateway state at the moment the report was generated, not at any arbitrary historical point.")
        if not telemetry:
            limitations.append("Gateway has not submitted telemetry yet. Connect the agent and allow at least one telemetry cycle before generating a report.")

        score = _gateway_score(findings)
        configuration_recommendations = _configuration_recommendations(ike_records, child_records)
        severity_counts = {
            severity: sum(1 for item in findings if item.get("severity") == severity)
            for severity in ("Critical", "High", "Medium", "Low", "Pass")
        }

        report_generated_at = _time.strftime("%Y-%m-%d %H:%M:%S", _time.gmtime())

        report = {
            "reportType": "GATEWAY_SECURITY_REPORT",
            "reportGeneratedAt": report_generated_at,
            "gateway": {
                "gateway_id": gateway["gateway_id"],
                "display_name": gateway["display_name"],
                "gateway_type": gateway["gateway_type"],
                "status": gateway["status"],
                "enrolled_at": gateway.get("enrolled_at"),
                "last_seen_at": gateway.get("last_seen_at"),
                "agent_version": gateway.get("agent_version"),
                "telemetry_adapter": adapter,
                "active_ike_sa_count": gateway.get("active_ike_sa_count", 0),
                "active_child_sa_count": gateway.get("active_child_sa_count", 0),
            },
            "telemetry": {
                "status": telem_status,
                "adapter": adapter,
                "collectedAt": collected_at,
                "receivedAt": received_at,
                "ikeRecords": ike_records,
                "childRecords": child_records,
                "evidence": evidence,
            },
            "securityAssessment": {
                "findings": findings,
                "source": "GATEWAY_TELEMETRY",
                "score": score,
                "configurationRecommendations": configuration_recommendations,
                "charts": {
                    "securityScore": score["value"],
                    "evidenceCoveragePercent": score["evidenceCoveragePercent"],
                    "findingSeverityCounts": severity_counts,
                },
                "childSaEvidence": _build_child_sa_evidence(
                    child_records,
                    fresh=telemetry_fresh,
                    collected_at=collected_at,
                ),
                "limitations": limitations,
            },
        }
        return report

    def _generate_gateway_ai_report(self, gateway_id: str) -> None:
        report = self._build_gateway_report_payload(gateway_id)
        if report is None:
            json_response(self, 404, {"error": "GATEWAY_NOT_FOUND"})
            return
        if not os.environ.get("GROQ_API_KEY", "").strip():
            json_response(self, 503, {"error": "GROQ_API_KEY_NOT_CONFIGURED"})
            return

        client_ip = self.client_address[0] if self.client_address else "unknown"
        now = time.monotonic()
        with _AI_REPORT_RATE_LOCK:
            last_request = _AI_REPORT_LAST_REQUEST.get(client_ip, 0)
            if now - last_request < AI_REPORT_COOLDOWN_SECONDS:
                json_response(self, 429, {"error": "AI_REPORT_RATE_LIMITED"})
                return
            _AI_REPORT_LAST_REQUEST[client_ip] = now

        try:
            narrative = generate_groq_narrative(build_gateway_ai_context(report))
        except GroqReportError as exc:
            json_response(self, exc.status, {"error": exc.code})
            return

        json_response(self, 200, {
            "source": "GROQ_LLM",
            "model": os.environ.get("GROQ_MODEL", "qwen/qwen3.8-27b"),
            "reportGeneratedAt": report["reportGeneratedAt"],
            "score": report["securityAssessment"]["score"],
            "findings": report["securityAssessment"]["findings"],
            "limitations": report["securityAssessment"]["limitations"],
            "configurationRecommendations": report["securityAssessment"]["configurationRecommendations"],
            "charts": report["securityAssessment"]["charts"],
            "narrative": narrative,
        })

    def _generate_pcap_report_narrative(self, body: bytes) -> None:
        if not os.environ.get("GROQ_API_KEY", "").strip():
            json_response(self, 503, {"error": "GROQ_API_KEY_NOT_CONFIGURED"})
            return

        try:
            report_context = json.loads(body.decode("utf-8"))
            context = build_pcap_ai_context(report_context)
        except (UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError):
            json_response(self, 400, {"error": "INVALID_REPORT_CONTEXT"})
            return

        client_ip = self.client_address[0] if self.client_address else "unknown"
        now = time.monotonic()
        with _AI_REPORT_RATE_LOCK:
            last_request = _AI_REPORT_LAST_REQUEST.get(client_ip, 0)
            if now - last_request < AI_REPORT_COOLDOWN_SECONDS:
                json_response(self, 429, {"error": "AI_REPORT_RATE_LIMITED"})
                return
            _AI_REPORT_LAST_REQUEST[client_ip] = now

        try:
            narrative = generate_groq_pcap_narrative(context)
        except GroqReportError as exc:
            json_response(self, exc.status, {"error": exc.code})
            return

        json_response(self, 200, {
            "source": "GROQ_LLM",
            "model": os.environ.get("GROQ_MODEL", "qwen/qwen3.8-27b"),
            "narrative": narrative,
        })

    def _build_telemetry_summary(self, analysis_id: str) -> dict[str, Any] | None:
        session = REPOSITORY.get_analysis(analysis_id)
        if session is None:
            return None

        telemetry = []
        correlation = {
            "correlation_status": "UNKNOWN",
            "matched": [],
            "unmatchedTelemetry": [],
            "unmatchedPcapSpis": [],
        }

        for item in session.get("telemetry", []):
            record = item.get("record", {}) if isinstance(item, dict) else {}
            if not isinstance(record, dict):
                continue
            telemetry.append({
                "gatewayId": record.get("gateway_id") or record.get("gatewayId"),
                "adapter": record.get("adapter") or "STRONGSWAN",
                "source": record.get("source") or "GATEWAY_TELEMETRY",
                "status": record.get("status") or "NOT_DETERMINABLE",
                "collectedAt": record.get("collected_at") or record.get("collectedAt"),
                "records": record.get("records") or [record],
                "evidence": record.get("evidence") or [],
                "error": record.get("error"),
            })
            entry_correlation = item.get("correlation") if isinstance(item, dict) else None
            if isinstance(entry_correlation, dict):
                if isinstance(entry_correlation.get("matched"), list):
                    correlation["matched"].extend(entry_correlation["matched"])
                if isinstance(entry_correlation.get("unmatchedTelemetry"), list):
                    correlation["unmatchedTelemetry"].extend(entry_correlation["unmatchedTelemetry"])
                if isinstance(entry_correlation.get("unmatchedPcapSpis"), list):
                    correlation["unmatchedPcapSpis"].extend(entry_correlation["unmatchedPcapSpis"])
                if entry_correlation.get("correlation_status") == "CONFIRMED":
                    correlation["correlation_status"] = "CONFIRMED"

        pcap_spis = []
        for packet in session.get("packets", []):
            if isinstance(packet, dict) and packet.get("spi"):
                pcap_spis.append(packet.get("spi"))

        if not correlation["matched"] and not correlation["unmatchedTelemetry"] and session.get("telemetry"):
            correlation["unmatchedPcapSpis"] = list(dict.fromkeys(pcap_spis))

        return {
            "analysisId": analysis_id,
            "gatewayId": telemetry[0].get("gatewayId") if telemetry else None,
            "telemetry": telemetry,
            "correlation": correlation,
            "pcapSpis": list(dict.fromkeys(pcap_spis)),
        }

    def _ingest_metadata(self, body: bytes) -> None:
        if not AGENT_TOKEN:
            json_response(self, 503, {"error": "AGENT_AUTH_NOT_CONFIGURED"})
            return
        authorization = self.headers.get("Authorization", "")
        if authorization != f"Bearer {AGENT_TOKEN}":
            json_response(self, 401, {"error": "UNAUTHORIZED"})
            return
        try:
            value = json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            json_response(self, 400, {"error": "INVALID_JSON"})
            return
        if not isinstance(value, dict):
            json_response(self, 400, {"error": "JSON_OBJECT_REQUIRED"})
            return
        sanitized = sanitize_analysis_payload(value)
        pcap_spis = [
            packet.get("spi") for packet in sanitized["packets"]
            if packet.get("spi")
        ]
        telemetry = sanitized["telemetry"]
        correlation = correlate_spi(pcap_spis, telemetry)
        analysis_id = sanitized.get("analysis_id")
        if isinstance(analysis_id, str) and analysis_id:
            REPOSITORY.save_telemetry(analysis_id, telemetry, correlation)
        json_response(self, 200, {
            "status": "ACCEPTED",
            "sanitized": sanitized,
            "correlation": correlation,
        })

    def _ingest_analysis_telemetry(self, analysis_id: str, body: bytes) -> None:
        if not analysis_id or len(analysis_id) > 80:
            json_response(self, 400, {"error": "INVALID_ANALYSIS_ID"})
            return
        if not AGENT_TOKEN:
            json_response(self, 503, {"error": "AGENT_AUTH_NOT_CONFIGURED"})
            return
        authorization = self.headers.get("Authorization", "")
        if authorization != f"Bearer {AGENT_TOKEN}":
            json_response(self, 401, {"error": "UNAUTHORIZED"})
            return
        try:
            value = json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            json_response(self, 400, {"error": "INVALID_JSON"})
            return
        if not isinstance(value, dict):
            json_response(self, 400, {"error": "JSON_OBJECT_REQUIRED"})
            return
        sanitized = sanitize_analysis_payload({**value, "analysis_id": analysis_id})
        pcap_spis = [
            packet.get("spi") for packet in sanitized["packets"]
            if packet.get("spi")
        ]
        telemetry = sanitized["telemetry"]
        if not telemetry and sanitized.get("records"):
            telemetry = sanitized["records"]
        correlation = correlate_spi(pcap_spis, telemetry)
        REPOSITORY.save_telemetry(analysis_id, telemetry, correlation)
        json_response(self, 200, {
            "status": "ACCEPTED",
            "analysisId": analysis_id,
            "sanitized": sanitized,
            "correlation": correlation,
        })

    def log_message(self, format: str, *args: object) -> None:
        print(f"[api] {format % args}")


if __name__ == "__main__":
    print(f"Local analyzer API listening on http://{HOST}:{PORT}")
    ThreadingHTTPServer((HOST, PORT), ApiHandler).serve_forever()
