"""SQLite persistence for sanitized analysis metadata and gateway onboarding."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import time
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from correlation import correlate_spi

FRESHNESS_CONNECTED_SECONDS = int(os.environ.get("GATEWAY_FRESHNESS_SECONDS", "60"))
FRESHNESS_STALE_SECONDS = int(os.environ.get("GATEWAY_STALE_SECONDS", "180"))


def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _utc_now_str() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def _parse_db_time(timestamp_str: str | None) -> float | None:
    if not timestamp_str:
        return None
    for fmt in (
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d %H:%M:%S.%f",
        "%Y-%m-%dT%H:%M:%SZ",
        "%Y-%m-%dT%H:%M:%S.%fZ",
        "%Y-%m-%dT%H:%M:%S",
    ):
        try:
            dt = datetime.strptime(timestamp_str, fmt).replace(tzinfo=timezone.utc)
            return dt.timestamp()
        except ValueError:
            continue
    return None


def compute_gateway_status(gateway_row: dict[str, Any] | sqlite3.Row) -> str:
    if gateway_row["revoked_at"] is not None:
        return "REVOKED"
    if gateway_row["enrolled_at"] is None or gateway_row["last_seen_at"] is None:
        return "NEVER_CONNECTED"
    ts = _parse_db_time(gateway_row["last_seen_at"])
    if ts is None:
        return "NEVER_CONNECTED"
    age = time.time() - ts
    if age < 0 or age <= FRESHNESS_CONNECTED_SECONDS:
        return "CONNECTED"
    if age <= FRESHNESS_STALE_SECONDS:
        return "STALE"
    return "OFFLINE"


class AnalysisRepository:
    def __init__(self, path: str | Path = "data/analyzer.sqlite3") -> None:
        self.path = Path(path)
        self._memory_connection: sqlite3.Connection | None = None
        if str(path) == ":memory:":
            self._memory_connection = sqlite3.connect(":memory:")
            self._memory_connection.row_factory = sqlite3.Row
        elif self.path != Path(":memory:"):
            self.path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        if self._memory_connection is not None:
            return self._memory_connection
        connection = sqlite3.connect(self.path)
        connection.row_factory = sqlite3.Row
        return connection

    def close(self) -> None:
        if self._memory_connection is not None:
            self._memory_connection.close()
            self._memory_connection = None

    @contextmanager
    def _connection(self):
        if self._memory_connection is not None:
            with self._memory_connection:
                yield self._memory_connection
            return
        connection = self._connect()
        try:
            with connection:
                yield connection
        finally:
            connection.close()

    def _initialize(self) -> None:
        with self._connection() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS analysis_sessions (
                    id TEXT PRIMARY KEY,
                    scenario_name TEXT NOT NULL,
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    sa_json TEXT NOT NULL,
                    features_json TEXT NOT NULL,
                    observations_json TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS packet_evidence (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    analysis_id TEXT NOT NULL REFERENCES analysis_sessions(id),
                    packet_id INTEGER NOT NULL,
                    timestamp REAL NOT NULL,
                    protocol TEXT NOT NULL,
                    length INTEGER NOT NULL,
                    source_ip_hash TEXT,
                    destination_ip_hash TEXT,
                    spi TEXT,
                    sequence_observed INTEGER
                );
                CREATE TABLE IF NOT EXISTS gateway_telemetry (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    analysis_id TEXT NOT NULL REFERENCES analysis_sessions(id),
                    record_json TEXT NOT NULL,
                    correlation_json TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS gateways (
                    gateway_id TEXT PRIMARY KEY,
                    display_name TEXT NOT NULL,
                    gateway_type TEXT NOT NULL DEFAULT 'STRONGSWAN',
                    status TEXT NOT NULL DEFAULT 'NEVER_CONNECTED',
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    enrolled_at TEXT,
                    last_seen_at TEXT,
                    revoked_at TEXT,
                    agent_version TEXT,
                    telemetry_adapter TEXT,
                    auth_token_hash TEXT,
                    active_ike_sa_count INTEGER DEFAULT 0,
                    active_child_sa_count INTEGER DEFAULT 0,
                    last_error TEXT
                );
                CREATE TABLE IF NOT EXISTS gateway_enrollment_tokens (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    gateway_id TEXT NOT NULL REFERENCES gateways(gateway_id),
                    token_hash TEXT NOT NULL UNIQUE,
                    expires_at REAL NOT NULL,
                    used_at REAL,
                    created_at REAL NOT NULL,
                    revoked_at REAL
                );
                CREATE TABLE IF NOT EXISTS gateway_telemetry_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    gateway_id TEXT NOT NULL REFERENCES gateways(gateway_id),
                    analysis_id TEXT,
                    collected_at TEXT NOT NULL,
                    received_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    source TEXT NOT NULL,
                    adapter TEXT NOT NULL,
                    status TEXT NOT NULL,
                    error TEXT,
                    records_json TEXT NOT NULL,
                    evidence_json TEXT NOT NULL
                );
                """
            )

    def save_analysis(self, result: dict[str, Any]) -> str:
        analysis_id = str(uuid.uuid4())
        sa = result.get("sa", {})
        features = result.get("features", {})
        observations = sa.get("observations", {})
        with self._connection() as connection:
            connection.execute(
                "INSERT INTO analysis_sessions (id, scenario_name, sa_json, features_json, observations_json) VALUES (?, ?, ?, ?, ?)",
                (
                    analysis_id,
                    str(result.get("scenarioName", "capture")),
                    json.dumps(_without_packet_payload(sa)),
                    json.dumps(features),
                    json.dumps(observations),
                ),
            )
            for packet in result.get("packets", []):
                connection.execute(
                    """INSERT INTO packet_evidence
                    (analysis_id, packet_id, timestamp, protocol, length, source_ip_hash,
                     destination_ip_hash, spi, sequence_observed)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        analysis_id,
                        int(packet.get("id", 0)),
                        float(packet.get("timestamp", 0)),
                        str(packet.get("protocol", "UNKNOWN")),
                        int(packet.get("length", 0)),
                        packet.get("source_ip_hash"),
                        packet.get("destination_ip_hash"),
                        packet.get("spi"),
                        packet.get("seq"),
                    ),
                )
        return analysis_id

    def save_telemetry(
        self,
        analysis_id: str,
        records: list[dict[str, Any]],
        correlation: dict[str, Any],
    ) -> None:
        with self._connection() as connection:
            for record in records:
                connection.execute(
                    "INSERT INTO gateway_telemetry (analysis_id, record_json, correlation_json) VALUES (?, ?, ?)",
                    (analysis_id, json.dumps(record), json.dumps(correlation)),
                )

    def get_analysis(self, analysis_id: str) -> dict[str, Any] | None:
        with self._connection() as connection:
            session = connection.execute(
                "SELECT * FROM analysis_sessions WHERE id = ?", (analysis_id,)
            ).fetchone()
            if session is None:
                return None
            packets = connection.execute(
                """SELECT packet_id AS id, timestamp, protocol, length, source_ip_hash,
                          destination_ip_hash, spi, sequence_observed
                   FROM packet_evidence WHERE analysis_id = ? ORDER BY packet_id""",
                (analysis_id,),
            ).fetchall()
            telemetry = connection.execute(
                "SELECT record_json, correlation_json FROM gateway_telemetry WHERE analysis_id = ?",
                (analysis_id,),
            ).fetchall()
        return {
            "analysisId": session["id"],
            "scenarioName": session["scenario_name"],
            "createdAt": session["created_at"],
            "sa": json.loads(session["sa_json"]),
            "features": json.loads(session["features_json"]),
            "observations": json.loads(session["observations_json"]),
            "packets": [dict(packet) for packet in packets],
            "telemetry": [
                {
                    "record": json.loads(row["record_json"]),
                    "correlation": json.loads(row["correlation_json"]),
                }
                for row in telemetry
            ],
        }

    # ================= Gateway Management =================

    def create_gateway(
        self,
        display_name: str,
        gateway_type: str = "STRONGSWAN",
        validity_seconds: int = 3600,
    ) -> tuple[dict[str, Any], str, float]:
        gateway_id = f"gw-{secrets.token_hex(6)}"
        created_at = _utc_now_str()
        with self._connection() as connection:
            connection.execute(
                """INSERT INTO gateways
                (gateway_id, display_name, gateway_type, status, created_at)
                VALUES (?, ?, ?, 'NEVER_CONNECTED', ?)""",
                (gateway_id, display_name.strip(), gateway_type.strip(), created_at),
            )
        raw_token, expires_at = self.create_enrollment_token(gateway_id, validity_seconds)
        gateway = self.get_gateway(gateway_id)
        if gateway is None:
            raise RuntimeError("Failed to retrieve created gateway")
        return gateway, raw_token, expires_at

    def create_enrollment_token(
        self, gateway_id: str, validity_seconds: int = 3600
    ) -> tuple[str, float]:
        with self._connection() as connection:
            gw = connection.execute(
                "SELECT * FROM gateways WHERE gateway_id = ?", (gateway_id,)
            ).fetchone()
            if gw is None:
                raise ValueError("GATEWAY_NOT_FOUND")
            if gw["revoked_at"] is not None:
                raise ValueError("GATEWAY_REVOKED")

            raw_token = f"gw_enroll_{secrets.token_urlsafe(32)}"
            token_hash = _hash_token(raw_token)
            now = time.time()
            expires_at = now + validity_seconds

            # Revoke existing unused enrollment tokens for this gateway
            connection.execute(
                "UPDATE gateway_enrollment_tokens SET revoked_at = ? WHERE gateway_id = ? AND used_at IS NULL AND revoked_at IS NULL",
                (now, gateway_id),
            )

            connection.execute(
                """INSERT INTO gateway_enrollment_tokens
                (gateway_id, token_hash, expires_at, created_at)
                VALUES (?, ?, ?, ?)""",
                (gateway_id, token_hash, expires_at, now),
            )
        return raw_token, expires_at

    def enroll_gateway(
        self,
        enrollment_token: str,
        agent_version: str = "1.0.0",
        adapter: str = "STRONGSWAN",
    ) -> dict[str, Any]:
        token_hash = _hash_token(enrollment_token.strip())
        now = time.time()
        now_str = _utc_now_str()

        with self._connection() as connection:
            token_row = connection.execute(
                "SELECT * FROM gateway_enrollment_tokens WHERE token_hash = ?",
                (token_hash,),
            ).fetchone()

            if token_row is None:
                return {"error": "INVALID_ENROLLMENT_TOKEN"}
            if token_row["revoked_at"] is not None:
                return {"error": "ENROLLMENT_TOKEN_REVOKED"}
            if token_row["used_at"] is not None:
                return {"error": "ENROLLMENT_TOKEN_ALREADY_USED"}
            if now > token_row["expires_at"]:
                return {"error": "ENROLLMENT_TOKEN_EXPIRED"}

            gateway_id = token_row["gateway_id"]
            gw = connection.execute(
                "SELECT * FROM gateways WHERE gateway_id = ?", (gateway_id,)
            ).fetchone()
            if gw is None:
                return {"error": "GATEWAY_NOT_FOUND"}
            if gw["revoked_at"] is not None:
                return {"error": "GATEWAY_REVOKED"}

            # Mark token used
            connection.execute(
                "UPDATE gateway_enrollment_tokens SET used_at = ? WHERE id = ?",
                (now, token_row["id"]),
            )

            # Generate separate runtime agent token
            raw_agent_token = f"gw_agent_{secrets.token_urlsafe(32)}"
            agent_token_hash = _hash_token(raw_agent_token)

            connection.execute(
                """UPDATE gateways
                SET enrolled_at = ?, last_seen_at = ?, auth_token_hash = ?,
                    agent_version = ?, telemetry_adapter = ?, status = 'CONNECTED'
                WHERE gateway_id = ?""",
                (now_str, now_str, agent_token_hash, agent_version, adapter, gateway_id),
            )

        return {
            "status": "ENROLLED",
            "gateway_id": gateway_id,
            "agent_token": raw_agent_token,
        }

    def authenticate_agent(
        self, gateway_id: str, raw_agent_token: str
    ) -> dict[str, Any] | None:
        if not raw_agent_token or not gateway_id:
            return None
        token_hash = _hash_token(raw_agent_token.strip())
        with self._connection() as connection:
            gw = connection.execute(
                "SELECT * FROM gateways WHERE gateway_id = ?", (gateway_id,)
            ).fetchone()
            if gw is None or gw["revoked_at"] is not None:
                return None
            stored_hash = gw["auth_token_hash"]
            if not stored_hash or not hmac.compare_digest(token_hash, stored_hash):
                return None
            return dict(gw)

    def record_heartbeat(self, gateway_id: str) -> bool:
        now_str = _utc_now_str()
        with self._connection() as connection:
            cursor = connection.execute(
                "UPDATE gateways SET last_seen_at = ? WHERE gateway_id = ? AND revoked_at IS NULL",
                (now_str, gateway_id),
            )
            return cursor.rowcount > 0

    def record_gateway_telemetry(
        self,
        gateway_id: str,
        payload: dict[str, Any],
        analysis_id: str | None = None,
    ) -> None:
        now_str = _utc_now_str()
        records = payload.get("telemetry") or payload.get("records") or []
        evidence = payload.get("evidence") or []
        source = payload.get("source") or "GATEWAY_TELEMETRY"
        adapter = payload.get("adapter") or "STRONGSWAN"
        status = payload.get("status") or "NOT_DETERMINABLE"
        error = payload.get("error")
        collected_at = payload.get("collected_at") or now_str

        # Calculate active IKE SAs and Child SAs from records
        active_ike = 0
        active_child = 0
        for rec in records:
            if not isinstance(rec, dict):
                continue
            if rec.get("protocol") == "ESP" or rec.get("inbound_spi") or rec.get("outbound_spi"):
                active_child += 1
            elif rec.get("version") or rec.get("initiator_spi") or rec.get("responder_spi"):
                active_ike += 1

        with self._connection() as connection:
            connection.execute(
                """UPDATE gateways
                SET last_seen_at = ?,
                    telemetry_adapter = ?,
                    active_ike_sa_count = ?,
                    active_child_sa_count = ?,
                    last_error = ?
                WHERE gateway_id = ?""",
                (now_str, adapter, active_ike, active_child, error, gateway_id),
            )
            connection.execute(
                """INSERT INTO gateway_telemetry_history
                (gateway_id, analysis_id, collected_at, source, adapter, status, error, records_json, evidence_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    gateway_id,
                    analysis_id,
                    collected_at,
                    source,
                    adapter,
                    status,
                    error,
                    json.dumps(records),
                    json.dumps(evidence),
                ),
            )

    def get_latest_gateway_telemetry(self, gateway_id: str) -> dict[str, Any] | None:
        with self._connection() as connection:
            row = connection.execute(
                """SELECT * FROM gateway_telemetry_history
                   WHERE gateway_id = ?
                   ORDER BY id DESC LIMIT 1""",
                (gateway_id,),
            ).fetchone()
            if row is None:
                return None
            return {
                "id": row["id"],
                "gatewayId": row["gateway_id"],
                "analysisId": row["analysis_id"],
                "collectedAt": row["collected_at"],
                "receivedAt": row["received_at"],
                "source": row["source"],
                "adapter": row["adapter"],
                "status": row["status"],
                "error": row["error"],
                "records": json.loads(row["records_json"]),
                "evidence": json.loads(row["evidence_json"]),
            }

    def get_gateway(
        self, gateway_id: str, include_history: bool = False
    ) -> dict[str, Any] | None:
        with self._connection() as connection:
            gw = connection.execute(
                "SELECT * FROM gateways WHERE gateway_id = ?", (gateway_id,)
            ).fetchone()
            if gw is None:
                return None

            status = compute_gateway_status(gw)
            result = {
                "gateway_id": gw["gateway_id"],
                "display_name": gw["display_name"],
                "gateway_type": gw["gateway_type"],
                "status": status,
                "created_at": gw["created_at"],
                "enrolled_at": gw["enrolled_at"],
                "last_seen_at": gw["last_seen_at"],
                "revoked_at": gw["revoked_at"],
                "agent_version": gw["agent_version"],
                "telemetry_adapter": gw["telemetry_adapter"],
                "active_ike_sa_count": gw["active_ike_sa_count"],
                "active_child_sa_count": gw["active_child_sa_count"],
                "last_error": gw["last_error"],
            }

            latest = self.get_latest_gateway_telemetry(gateway_id)
            result["latest_telemetry"] = latest

            if include_history:
                rows = connection.execute(
                    """SELECT * FROM gateway_telemetry_history
                       WHERE gateway_id = ?
                       ORDER BY id DESC LIMIT 20""",
                    (gateway_id,),
                ).fetchall()
                result["history"] = [
                    {
                        "id": r["id"],
                        "collectedAt": r["collected_at"],
                        "receivedAt": r["received_at"],
                        "status": r["status"],
                        "error": r["error"],
                        "recordsCount": len(json.loads(r["records_json"])),
                    }
                    for r in rows
                ]
            return result

    def list_gateways(self) -> list[dict[str, Any]]:
        with self._connection() as connection:
            rows = connection.execute(
                "SELECT * FROM gateways ORDER BY created_at DESC"
            ).fetchall()
            gateways = []
            for row in rows:
                status = compute_gateway_status(row)
                gateways.append(
                    {
                        "gateway_id": row["gateway_id"],
                        "display_name": row["display_name"],
                        "gateway_type": row["gateway_type"],
                        "status": status,
                        "created_at": row["created_at"],
                        "enrolled_at": row["enrolled_at"],
                        "last_seen_at": row["last_seen_at"],
                        "revoked_at": row["revoked_at"],
                        "agent_version": row["agent_version"],
                        "telemetry_adapter": row["telemetry_adapter"],
                        "active_ike_sa_count": row["active_ike_sa_count"],
                        "active_child_sa_count": row["active_child_sa_count"],
                        "last_error": row["last_error"],
                    }
                )
            return gateways

    def revoke_gateway(self, gateway_id: str) -> bool:
        now = time.time()
        now_str = _utc_now_str()
        with self._connection() as connection:
            cursor = connection.execute(
                """UPDATE gateways
                SET revoked_at = ?, auth_token_hash = NULL, status = 'REVOKED'
                WHERE gateway_id = ? AND revoked_at IS NULL""",
                (now_str, gateway_id),
            )
            connection.execute(
                "UPDATE gateway_enrollment_tokens SET revoked_at = ? WHERE gateway_id = ? AND revoked_at IS NULL",
                (now, gateway_id),
            )
            return cursor.rowcount > 0

    def remove_gateway(self, gateway_id: str) -> bool:
        with self._connection() as connection:
            connection.execute(
                "DELETE FROM gateway_telemetry_history WHERE gateway_id = ?",
                (gateway_id,),
            )
            connection.execute(
                "DELETE FROM gateway_enrollment_tokens WHERE gateway_id = ?",
                (gateway_id,),
            )
            cursor = connection.execute(
                "DELETE FROM gateways WHERE gateway_id = ?", (gateway_id,)
            )
            return cursor.rowcount > 0

    def correlate_analysis_with_gateway(
        self, analysis_id: str, gateway_id: str
    ) -> dict[str, Any] | None:
        session = self.get_analysis(analysis_id)
        if session is None:
            return None

        pcap_spis = []
        for packet in session.get("packets", []):
            if isinstance(packet, dict) and packet.get("spi"):
                pcap_spis.append(packet.get("spi"))
        obs_spis = session.get("observations", {}).get("espSpis", [])
        if isinstance(obs_spis, list):
            pcap_spis.extend(obs_spis)
        pcap_spis = list(dict.fromkeys(pcap_spis))

        telemetry = self.get_latest_gateway_telemetry(gateway_id)
        if telemetry is None:
            correlation = {
                "correlation_status": "UNKNOWN",
                "matched": [],
                "unmatchedTelemetry": [],
                "unmatchedPcapSpis": pcap_spis,
            }
            summary = {
                "analysisId": analysis_id,
                "gatewayId": gateway_id,
                "gatewayStatus": "NOT_DETERMINABLE",
                "correlationStatus": "UNKNOWN",
                "source": "GATEWAY_TELEMETRY",
                "adapter": "STRONGSWAN",
                "collectedAt": None,
                "matchedSpis": [],
                "unmatchedPcapSpis": pcap_spis,
                "evidence": ["No telemetry available for selected gateway."],
                "telemetry": [],
                "correlation": correlation,
            }
            return summary

        records = telemetry.get("records", [])
        correlation = correlate_spi(pcap_spis, records)
        self.save_telemetry(analysis_id, records, correlation)

        matched_spis = []
        for m in correlation.get("matched", []):
            matched_spis.extend(m.get("matched_spis", []))
        matched_spis = list(dict.fromkeys(matched_spis))

        return {
            "analysisId": analysis_id,
            "gatewayId": gateway_id,
            "gatewayStatus": telemetry.get("status") or "CONFIRMED",
            "correlationStatus": correlation.get("correlation_status") or "UNKNOWN",
            "source": telemetry.get("source") or "GATEWAY_TELEMETRY",
            "adapter": telemetry.get("adapter") or "STRONGSWAN",
            "collectedAt": telemetry.get("collectedAt"),
            "matchedSpis": matched_spis,
            "unmatchedPcapSpis": correlation.get("unmatchedPcapSpis") or [],
            "evidence": telemetry.get("evidence") or [],
            "telemetry": [telemetry],
            "correlation": correlation,
        }


def _without_packet_payload(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            key: _without_packet_payload(item)
            for key, item in value.items()
            if key not in {"rawPreview", "debug", "payload", "rawPayload"}
        }
    if isinstance(value, list):
        return [_without_packet_payload(item) for item in value]
    return value
