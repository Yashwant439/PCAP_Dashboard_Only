"""Authorized VPN gateway telemetry adapters.

Only read-only SA metadata is collected. PSKs, private keys, and session keys
are never requested or parsed.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import importlib
from dataclasses import dataclass
from typing import Any, Sequence


@dataclass(frozen=True)
class TelemetryResult:
    source: str
    status: str
    records: list[dict[str, Any]]
    evidence: list[str]
    error: str | None = None


class GatewayAdapter:
    name = "UNKNOWN"

    def collect(self) -> TelemetryResult:
        raise NotImplementedError


class StrongSwanAdapter(GatewayAdapter):
    """Read authorized metadata using the read-only swanctl command."""

    name = "STRONGSWAN"

    def __init__(
        self,
        command: Sequence[str] = ("swanctl", "--list-sas", "--raw"),
        timeout_seconds: float = 10,
    ) -> None:
        self.command = tuple(command)
        self.timeout_seconds = timeout_seconds

    def collect(self) -> TelemetryResult:
        executable = shutil.which(self.command[0])
        if executable is None:
            return TelemetryResult(
                source="GATEWAY_TELEMETRY",
                status="NOT_DETERMINABLE",
                records=[],
                evidence=["swanctl is not installed or is not available on PATH."],
                error="STRONGSWAN_CONTROL_TOOL_UNAVAILABLE",
            )

        try:
            completed = subprocess.run(
                (executable, *self.command[1:]),
                capture_output=True,
                text=True,
                timeout=self.timeout_seconds,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            return TelemetryResult(
                source="GATEWAY_TELEMETRY",
                status="NOT_DETERMINABLE",
                records=[],
                evidence=[f"StrongSwan telemetry command failed: {type(exc).__name__}."],
                error="STRONGSWAN_CONTROL_QUERY_FAILED",
            )

        if completed.returncode != 0:
            return TelemetryResult(
                source="GATEWAY_TELEMETRY",
                status="NOT_DETERMINABLE",
                records=[],
                evidence=["StrongSwan rejected the read-only SA query."],
                error="STRONGSWAN_CONTROL_QUERY_REJECTED",
            )

        records = parse_swanctl_records(completed.stdout)
        if not records:
            return TelemetryResult(
                source="GATEWAY_TELEMETRY",
                status="NOT_DETERMINABLE",
                records=[],
                evidence=["The gateway returned no parseable SA metadata."],
                error="STRONGSWAN_NO_PARSEABLE_SA",
            )

        xfrm_states, xfrm_error = collect_xfrm_state_metadata()
        merge_xfrm_state_metadata(records, xfrm_states)
        evidence = ["Read-only swanctl SA telemetry was parsed from the gateway."]
        if xfrm_states:
            evidence.append("Read-only Linux XFRM replay and ESN metadata was SPI-correlated; raw state output was discarded.")
        elif xfrm_error:
            evidence.append(f"Linux XFRM metadata unavailable: {xfrm_error}.")

        return TelemetryResult(
            source="GATEWAY_TELEMETRY",
            status="CONFIRMED",
            records=records,
            evidence=evidence,
        )


class ViciAdapter(GatewayAdapter):
    """Optional read-only StrongSwan VICI adapter.

    The VICI Python package and socket are deployment dependencies. This
    adapter never falls back to guessed values when either is unavailable.
    """

    name = "STRONGSWAN_VICI"

    def __init__(self, client_factory: Any | None = None) -> None:
        self.client_factory = client_factory

    def collect(self) -> TelemetryResult:
        try:
            factory = self.client_factory
            if factory is None:
                module = importlib.import_module("vici")
                factory = module.Session
            session = factory()
            response = session.request("list-sas", {})
            records = parse_vici_records(response)
        except (ImportError, OSError, RuntimeError, TypeError, ValueError) as exc:
            return TelemetryResult(
                source="GATEWAY_TELEMETRY",
                status="NOT_DETERMINABLE",
                records=[],
                evidence=[f"VICI telemetry unavailable: {type(exc).__name__}."],
                error="STRONGSWAN_VICI_UNAVAILABLE",
            )

        if not records:
            return TelemetryResult(
                source="GATEWAY_TELEMETRY",
                status="NOT_DETERMINABLE",
                records=[],
                evidence=["VICI returned no parseable SA metadata."],
                error="STRONGSWAN_VICI_NO_PARSEABLE_SA",
            )
        xfrm_states, xfrm_error = collect_xfrm_state_metadata()
        merge_xfrm_state_metadata(records, xfrm_states)
        evidence = ["Read-only StrongSwan VICI SA telemetry was parsed."]
        if xfrm_states:
            evidence.append("Read-only Linux XFRM replay and ESN metadata was SPI-correlated; raw state output was discarded.")
        elif xfrm_error:
            evidence.append(f"Linux XFRM metadata unavailable: {xfrm_error}.")
        return TelemetryResult(
            source="GATEWAY_TELEMETRY",
            status="CONFIRMED",
            records=records,
            evidence=evidence,
        )


def _format_spi(value: Any) -> str | None:
    if not value:
        return None
    val_str = str(value).strip()
    if val_str.startswith("0x"):
        return val_str
    try:
        int(val_str, 16)
        return f"0x{val_str}"
    except ValueError:
        return val_str


def _format_algo(alg: Any, keysize: Any = None) -> str | None:
    if not alg:
        return None
    if keysize:
        return f"{alg}_{keysize}"
    return str(alg)


def _format_ts(val: Any) -> str | None:
    if isinstance(val, list):
        return ", ".join(str(x) for x in val)
    return str(val) if val is not None else None


def _to_int_or_str(val: Any) -> Any:
    if val is None:
        return None
    try:
        return int(val)
    except (ValueError, TypeError):
        return str(val)


def _to_esn_bool(value: Any) -> bool | None:
    if isinstance(value, bool):
        return value
    if value in (1, "1", "yes", "true", "YES", "TRUE"):
        return True
    if value in (0, "0", "no", "false", "NO", "FALSE"):
        return False
    return None


def _normalize_spi(value: Any) -> str | None:
    if not isinstance(value, (str, int)) or isinstance(value, bool):
        return None
    text = str(value).strip().lower()
    raw = text[2:] if text.startswith("0x") else text
    try:
        spi = int(raw, 16)
    except ValueError:
        return None
    if spi <= 0 or spi > 0xFFFFFFFF:
        return None
    return f"0x{spi:x}"


def parse_xfrm_state_records(output: str) -> list[dict[str, Any]]:
    """Extract only safe replay metadata; never return raw XFRM state text."""
    records: list[dict[str, Any]] = []
    current: dict[str, Any] | None = None

    def finish_record() -> None:
        if current and current.get("spi") and current.get("protocol") == "esp":
            records.append(current.copy())

    for line in output.splitlines():
        stripped = line.strip()
        state_match = re.match(
            r"^proto\s+(\S+)\s+spi\s+(0x[0-9a-fA-F]+)(?:\([^)]*\))?.*?\bmode\s+(\S+)",
            stripped,
            re.IGNORECASE,
        )
        if state_match:
            finish_record()
            current = {
                "protocol": state_match.group(1).lower(),
                "spi": _normalize_spi(state_match.group(2)),
                "mode": state_match.group(3).lower(),
            }
            continue

        if current is None:
            continue

        window_match = re.search(r"\breplay-window\s+(\d+)\b", stripped, re.IGNORECASE)
        if window_match and re.search(r"\bseq\s+0x[0-9a-fA-F]+\b", stripped, re.IGNORECASE):
            current["replay_window"] = int(window_match.group(1))

        flag_match = re.search(r"\bflag\s+(.+?)(?:\s+\(0x[0-9a-fA-F]+\))?$", stripped, re.IGNORECASE)
        if flag_match:
            flags = {flag.lower() for flag in re.split(r"[\s,]+", flag_match.group(1).strip()) if flag}
            current["esn"] = "esn" in flags

    finish_record()
    return records


def collect_xfrm_state_metadata(
    command: Sequence[str] = ("ip", "-s", "xfrm", "state"),
    timeout_seconds: float = 5,
) -> tuple[list[dict[str, Any]], str | None]:
    """Read Linux XFRM state and discard all non-allowlisted output in memory."""
    executable = shutil.which(command[0])
    if executable is None:
        return [], "IPROUTE2_UNAVAILABLE"

    try:
        completed = subprocess.run(
            (executable, *command[1:]),
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return [], "XFRM_QUERY_TIMEOUT"
    except OSError as exc:
        return [], f"XFRM_QUERY_FAILED_{type(exc).__name__}"

    if completed.returncode != 0:
        return [], "XFRM_QUERY_REJECTED"
    return parse_xfrm_state_records(completed.stdout), None


def merge_xfrm_state_metadata(
    telemetry_records: list[dict[str, Any]],
    xfrm_records: list[dict[str, Any]],
) -> None:
    """Attach directional XFRM values only when an SPI has one exact match."""
    states_by_spi: dict[str, dict[str, Any] | None] = {}
    for state in xfrm_records:
        spi = _normalize_spi(state.get("spi"))
        if spi is None:
            continue
        if spi in states_by_spi:
            states_by_spi[spi] = None
        else:
            states_by_spi[spi] = state

    for record in telemetry_records:
        if str(record.get("protocol", "")).lower() != "esp":
            continue
        for direction, spi_field in (("in", "inbound_spi"), ("out", "outbound_spi")):
            spi = _normalize_spi(record.get(spi_field))
            state = states_by_spi.get(spi) if spi else None
            if not isinstance(state, dict):
                continue
            record[f"xfrm_spi_{direction}"] = state["spi"]
            window = state.get("replay_window")
            if isinstance(window, int) and not isinstance(window, bool) and window >= 0:
                record[f"replay_window_{direction}"] = window
                if direction == "in":
                    record["replay_protection"] = window > 0
            esn = state.get("esn")
            if isinstance(esn, bool):
                record[f"esn_{direction}"] = esn


def _parse_swanctl_event_blocks(text: str) -> list[dict[str, Any]]:
    import re
    tokens = re.findall(r'\{|\}|\[|\]|[^\s\{\}\[\]=]+|=', text)
    if not tokens:
        return []

    idx = 0

    def parse_dict():
        nonlocal idx
        d: dict[str, Any] = {}
        while idx < len(tokens):
            tok = tokens[idx]
            if tok == '}':
                idx += 1
                return d
            key = tok
            idx += 1
            if idx >= len(tokens):
                break
            nxt = tokens[idx]
            if nxt == '=':
                idx += 1
                if idx < len(tokens) and tokens[idx] == '[':
                    idx += 1
                    items = []
                    while idx < len(tokens) and tokens[idx] != ']':
                        items.append(tokens[idx])
                        idx += 1
                    if idx < len(tokens) and tokens[idx] == ']':
                        idx += 1
                    d[key] = items
                elif idx < len(tokens) and tokens[idx] == '{':
                    idx += 1
                    d[key] = parse_dict()
                else:
                    d[key] = tokens[idx] if idx < len(tokens) else ''
                    idx += 1
            elif nxt == '{':
                idx += 1
                d[key] = parse_dict()
            elif nxt == '[':
                idx += 1
                items = []
                while idx < len(tokens) and tokens[idx] != ']':
                    items.append(tokens[idx])
                    idx += 1
                if idx < len(tokens) and tokens[idx] == ']':
                    idx += 1
                d[key] = items
        return d

    data = parse_dict()
    conns: dict[str, Any] = {}
    if "event" in data and isinstance(data["event"], dict):
        conns = data["event"]
    elif "list-sa" in data and isinstance(data["list-sa"], dict):
        conns = data["list-sa"]
    else:
        conns = data

    records: list[dict[str, Any]] = []
    for conn_name, ike_info in conns.items():
        if not isinstance(ike_info, dict):
            continue
        ike_rec = {
            "name": conn_name,
            "uniqueid": _to_int_or_str(ike_info.get("uniqueid")),
            "version": _to_int_or_str(ike_info.get("version")),
            "state": ike_info.get("state"),
            "local_host": ike_info.get("local-host") or ike_info.get("local_host"),
            "remote_host": ike_info.get("remote-host") or ike_info.get("remote_host"),
            "initiator_spi": _format_spi(ike_info.get("initiator-spi") or ike_info.get("initiator_spi")),
            "responder_spi": _format_spi(ike_info.get("responder-spi") or ike_info.get("responder_spi")),
            "encr": _format_algo(ike_info.get("encr-alg") or ike_info.get("encr"), ike_info.get("encr-keysize")),
            "integ": _format_algo(ike_info.get("integ-alg") or ike_info.get("integ"), ike_info.get("integ-keysize")),
            "prf": ike_info.get("prf-alg") or ike_info.get("prf"),
            "dh": ike_info.get("dh-group") or ike_info.get("dh"),
            "established": _to_int_or_str(ike_info.get("established")),
            "reauth_time": _to_int_or_str(ike_info.get("reauth-time")),
        }
        child_sas = ike_info.get("child-sas") or ike_info.get("child_sas") or {}
        if isinstance(child_sas, dict):
            for child_key, child_info in child_sas.items():
                if not isinstance(child_info, dict):
                    continue
                spi_in = _format_spi(child_info.get("spi-in") or child_info.get("inbound_spi") or child_info.get("spi_in"))
                spi_out = _format_spi(child_info.get("spi-out") or child_info.get("outbound_spi") or child_info.get("spi_out"))
                child_rec = {
                    "name": child_info.get("name", child_key),
                    "uniqueid": _to_int_or_str(child_info.get("uniqueid")),
                    "reqid": _to_int_or_str(child_info.get("reqid")),
                    "state": child_info.get("state"),
                    "mode": child_info.get("mode"),
                    "protocol": child_info.get("protocol", "ESP"),
                    "inbound_spi": spi_in,
                    "outbound_spi": spi_out,
                    "spi": spi_in or spi_out,
                    "child_sa_spi": spi_in or spi_out,
                    "encr": _format_algo(child_info.get("encr-alg") or child_info.get("encr"), child_info.get("encr-keysize")),
                    "integ": _format_algo(child_info.get("integ-alg") or child_info.get("integ"), child_info.get("integ-keysize")),
                    "dh": child_info.get("dh-group") or child_info.get("dh"),
                    "esn": _to_esn_bool(child_info.get("esn")),
                    "rekey_time": _to_int_or_str(child_info.get("rekey-time")),
                    "life_time": _to_int_or_str(child_info.get("life-time")),
                    "bytes_in": _to_int_or_str(child_info.get("bytes-in")),
                    "bytes_out": _to_int_or_str(child_info.get("bytes-out")),
                    "packets_in": _to_int_or_str(child_info.get("packets-in")),
                    "packets_out": _to_int_or_str(child_info.get("packets-out")),
                    "local_ts": _format_ts(child_info.get("local-ts")),
                    "remote_ts": _format_ts(child_info.get("remote-ts")),
                }
                child_rec = {k: v for k, v in child_rec.items() if v is not None}
                records.append(child_rec)

        ike_rec = {k: v for k, v in ike_rec.items() if v is not None}
        records.append(ike_rec)

    return records


def parse_swanctl_records(output: str) -> list[dict[str, Any]]:
    text = output.strip()
    if not text:
        return []

    try:
        decoded = json.loads(text)
    except json.JSONDecodeError:
        decoded = None

    if decoded is not None:
        return _extract_json_records(decoded)

    if "{" in text and ("=" in text or "event" in text or "reply" in text):
        records = _parse_swanctl_event_blocks(text)
        if records:
            return records

    records: list[dict[str, Any]] = []
    current: dict[str, Any] = {}
    allowed = {
        "name", "uniqueid", "state", "version", "local_host", "remote_host",
        "local_ts", "remote_ts", "initiator_spi", "responder_spi", "inbound_spi",
        "outbound_spi", "spi", "child_sa_spi", "protocol", "reqid",
        "encr", "integ", "prf", "dh", "mode", "rekey_time", "life_time",
        "reauth_time", "bytes_in", "bytes_out", "packets_in", "packets_out",
    }
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped:
            if current:
                records.append(current)
                current = {}
            continue
        if ":" not in stripped:
            continue
        key, value = (part.strip() for part in stripped.split(":", 1))
        normalized = key.lower().replace("-", "_").replace(" ", "_")
        if normalized in allowed:
            current[normalized] = value
    if current:
        records.append(current)
    return records


VICI_ALLOWED_FIELDS = {
    "name", "uniqueid", "state", "version", "local_host", "remote_host",
    "local_ts", "remote_ts", "initiator_spi", "responder_spi", "inbound_spi",
    "outbound_spi", "spi_in", "spi_out", "encr", "encr_alg", "encr_keysize",
    "integ", "integ_alg", "integ_keysize", "prf", "prf_alg", "dh", "dh_group",
    "protocol", "mode", "rekey_time", "life_time", "reauth_time", "esn", "bytes_in", "bytes_out",
    "packets_in", "packets_out",
}


def parse_vici_records(value: Any) -> list[dict[str, Any]]:
    """Flatten only recognized scalar SA metadata from a VICI response."""
    records: list[dict[str, Any]] = []

    def visit(node: Any) -> None:
        if isinstance(node, dict):
            record: dict[str, Any] = {}
            for key, item in node.items():
                normalized = str(key).lower().replace("-", "_").replace(" ", "_")
                if normalized in VICI_ALLOWED_FIELDS and isinstance(item, (str, int, float, bool)):
                    record[normalized] = item
                else:
                    visit(item)
            if record:
                if "spi_in" in record and "inbound_spi" not in record:
                    record["inbound_spi"] = _format_spi(record.pop("spi_in"))
                if "spi_out" in record and "outbound_spi" not in record:
                    record["outbound_spi"] = _format_spi(record.pop("spi_out"))
                if "encr_alg" in record:
                    record["encr"] = _format_algo(record.pop("encr_alg"), record.pop("encr_keysize", None))
                if "integ_alg" in record:
                    record["integ"] = _format_algo(record.pop("integ_alg"), record.pop("integ_keysize", None))
                if "prf_alg" in record and "prf" not in record:
                    record["prf"] = record.pop("prf_alg")
                if "dh_group" in record and "dh" not in record:
                    record["dh"] = record.pop("dh_group")
                if "esn" in record:
                    record["esn"] = _to_esn_bool(record["esn"])
                records.append(record)
        elif isinstance(node, (list, tuple)):
            for item in node:
                visit(item)

    visit(value)
    return records


def _extract_json_records(value: Any) -> list[dict[str, Any]]:
    if isinstance(value, list):
        return [item for item in value if isinstance(item, dict)]
    if isinstance(value, dict):
        for key in ("sas", "child_sas", "connections", "records"):
            nested = value.get(key)
            if isinstance(nested, (list, dict)):
                records = _extract_json_records(nested)
                if records:
                    return records
        return [value]
    return []
