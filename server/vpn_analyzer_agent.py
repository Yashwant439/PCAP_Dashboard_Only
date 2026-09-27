"""Local/cloud agent entry point and gateway runner for the VPN analyzer.

The agent sends metadata only. It never accepts or transmits PSKs, private keys,
session keys, or packet payloads.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import ssl
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from correlation import correlate_spi
from sanitizer import sanitize_analysis_payload
from telemetry import GatewayAdapter, StrongSwanAdapter, ViciAdapter
from testbed_control import render_swanctl_config, validate_testbed_settings

AGENT_VERSION = "1.3.0"
DEFAULT_CONFIG_PATH = os.environ.get("VPN_AGENT_CONFIG", "agent_config.json")


def load_config(config_path: str | Path | None = None) -> dict[str, Any]:
    path = Path(config_path or DEFAULT_CONFIG_PATH)
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        print(f"[agent] Warning: Failed to parse config {path}: {exc}", file=sys.stderr)
        return {}


def save_config(config: dict[str, Any], config_path: str | Path | None = None) -> Path:
    path = Path(config_path or DEFAULT_CONFIG_PATH)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(config, indent=2), encoding="utf-8")
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    return path


def collect_telemetry(kind: str) -> dict[str, Any]:
    adapter: GatewayAdapter
    if kind == "strongswan":
        adapter = StrongSwanAdapter()
    elif kind == "strongswan-vici":
        adapter = ViciAdapter()
    else:
        return {
            "source": "GATEWAY_TELEMETRY",
            "status": "NOT_DETERMINABLE",
            "records": [],
            "evidence": ["No gateway adapter configured."],
            "error": "ADAPTER_NOT_CONFIGURED",
        }
    result = adapter.collect()
    return {
        "source": result.source,
        "status": result.status,
        "records": result.records,
        "evidence": result.evidence,
        "error": result.error,
    }


def analyze_local(pcap_path: Path | None, gateway: str) -> dict[str, Any]:
    if pcap_path is None:
        return {
            "status": "NOT_DETERMINABLE",
            "evidence": ["No PCAP was supplied. Live capture is not enabled by this agent build."],
        }

    from scapy_analyzer import analyze

    data = pcap_path.read_bytes()
    parsed = analyze(data, pcap_path.name)
    telemetry = collect_telemetry(gateway)
    pcap_spis = parsed.get("sa", {}).get("observations", {}).get("espSpis", [])
    correlation = correlate_spi(pcap_spis, telemetry.get("records", []))
    return {
        "status": "ANALYZED",
        "analysis": parsed,
        "telemetry": telemetry,
        "correlation": correlation,
    }


def capture_local(interface: str | None, count: int, timeout: int) -> dict[str, Any]:
    from live_capture import capture_live

    packets = capture_live(interface, count, timeout)
    return {
        "status": "CAPTURED",
        "packet_count": len(packets),
        "packets": packets,
        "evidence": ["Bounded Scapy live capture; metadata only, payloads excluded."],
    }


def send_cloud(endpoint: str, token: str, payload: dict[str, Any]) -> dict[str, Any]:
    if not endpoint.lower().startswith(("http://", "https://")):
        raise ValueError("Cloud mode requires an HTTP or HTTPS endpoint")
    body = json.dumps(sanitize_analysis_payload(payload)).encode("utf-8")
    request = urllib.request.Request(
        endpoint,
        data=body,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {token}",
        },
    )
    context = ssl.create_default_context() if endpoint.lower().startswith("https://") else None
    with urllib.request.urlopen(request, context=context, timeout=15) as response:
        return {"status": response.status, "body": response.read().decode("utf-8")}


def submit_gateway_telemetry(
    server: str,
    gateway_id: str,
    token: str,
    adapter_kind: str,
    timeout: int = 10,
) -> dict[str, Any]:
    telemetry_data = collect_telemetry(adapter_kind)
    telemetry_data["gateway_id"] = gateway_id
    telemetry_data["agent_version"] = AGENT_VERSION
    telemetry_data["adapter"] = adapter_kind
    telemetry_data["collected_at"] = datetime.now(timezone.utc).isoformat()

    sanitized = sanitize_analysis_payload(telemetry_data)
    url = f"{server.rstrip('/')}/api/gateways/{urllib.parse.quote(gateway_id)}/telemetry"
    body = json.dumps(sanitized).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=body,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {token}",
        },
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


def send_gateway_heartbeat(
    server: str,
    gateway_id: str,
    token: str,
    timeout: int = 5,
) -> dict[str, Any]:
    url = f"{server.rstrip('/')}/api/gateways/{urllib.parse.quote(gateway_id)}/heartbeat"
    req = urllib.request.Request(
        url,
        data=b"{}",
        method="POST",
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {token}",
        },
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


def poll_testbed_job(server: str, gateway_id: str, token: str, timeout: int = 5) -> dict[str, Any] | None:
    url = f"{server.rstrip('/')}/api/gateways/{urllib.parse.quote(gateway_id)}/testbed/next"
    request = urllib.request.Request(
        url,
        data=b"{}",
        method="POST",
        headers={"Content-Type": "application/json", "Authorization": f"Bearer {token}"},
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        payload = json.loads(response.read().decode("utf-8"))
    job = payload.get("job")
    return job if isinstance(job, dict) else None


def apply_testbed_job(job: dict[str, Any], command_timeout: int = 35) -> dict[str, str]:
    """Apply one validated temporary StrongSwan connection; never handles secrets."""
    connection_name = job.get("connectionName")
    child_name = job.get("childName")
    try:
        config = render_swanctl_config(job.get("settings"), connection_name, child_name)
    except (TypeError, ValueError) as exc:
        return {"status": "FAILED", "message": str(exc)}

    executable = shutil.which("swanctl")
    if executable is None:
        return {"status": "FAILED", "message": "STRONGSWAN_CONTROL_TOOL_UNAVAILABLE"}

    config_path = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", suffix=".conf", delete=False) as config_file:
            config_file.write(config)
            config_path = config_file.name
        try:
            os.chmod(config_path, 0o600)
        except OSError:
            pass

        loaded = subprocess.run(
            (executable, "--load-conns", "--file", config_path),
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
        if loaded.returncode != 0:
            return {"status": "FAILED", "message": "STRONGSWAN_REJECTED_TESTBED_CONFIGURATION"}

        initiated = subprocess.run(
            (executable, "--initiate", "--child", child_name, "--ike", connection_name, "--timeout", str(command_timeout)),
            capture_output=True,
            text=True,
            timeout=command_timeout + 5,
            check=False,
        )
        if initiated.returncode != 0:
            return {
                "status": "FAILED",
                "message": "CONFIGURATION_LOADED_BUT_TUNNEL_NOT_ESTABLISHED_CHECK_PEER_ROUTE_AND_PREPROVISIONED_CREDENTIALS",
            }
        return {"status": "SUCCEEDED", "message": "CONFIGURATION_LOADED_AND_TUNNEL_INITIATION_ACCEPTED"}
    except subprocess.TimeoutExpired:
        return {"status": "FAILED", "message": "STRONGSWAN_COMMAND_TIMEOUT"}
    except OSError as exc:
        return {"status": "FAILED", "message": f"STRONGSWAN_COMMAND_FAILED_{type(exc).__name__}"}
    finally:
        if config_path:
            try:
                os.unlink(config_path)
            except OSError:
                pass


def submit_testbed_job_result(
    server: str,
    gateway_id: str,
    token: str,
    job_id: str,
    result: dict[str, str],
    timeout: int = 5,
) -> None:
    url = (
        f"{server.rstrip('/')}/api/gateways/{urllib.parse.quote(gateway_id)}"
        f"/testbed/{urllib.parse.quote(job_id)}/result"
    )
    request = urllib.request.Request(
        url,
        data=json.dumps(result).encode("utf-8"),
        method="POST",
        headers={"Content-Type": "application/json", "Authorization": f"Bearer {token}"},
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        response.read()


def enroll_agent(
    server: str,
    token: str,
    adapter: str = "strongswan",
    config_path: str | Path | None = None,
) -> dict[str, Any]:
    server_clean = server.rstrip("/")
    enroll_url = f"{server_clean}/api/gateways/enroll"
    payload = {
        "token": token,
        "agent_version": AGENT_VERSION,
        "adapter": adapter,
    }
    body = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        enroll_url,
        data=body,
        method="POST",
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        err_body = exc.read().decode("utf-8")
        try:
            err_json = json.loads(err_body)
            err_msg = err_json.get("error", err_body)
        except Exception:
            err_msg = err_body
        raise RuntimeError(f"Enrollment rejected by server ({exc.code}): {err_msg}")
    except Exception as exc:
        raise RuntimeError(f"Failed to connect to central API at {enroll_url}: {exc}")

    if "error" in data:
        raise RuntimeError(f"Enrollment failed: {data['error']}")

    gateway_id = data.get("gateway_id")
    agent_token = data.get("agent_token")
    if not gateway_id or not agent_token:
        raise RuntimeError("Server did not return gateway_id and agent_token")

    config = {
        "central_api_url": server_clean,
        "gateway_id": gateway_id,
        "agent_token": agent_token,
        "telemetry_adapter": adapter,
        "agent_version": AGENT_VERSION,
        "interval": 15,
        "timeout": 10,
    }
    saved_path = save_config(config, config_path)
    print(f"[+] Gateway enrolled successfully!")
    print(f"    Gateway ID: {gateway_id}")
    print(f"    Server:     {server_clean}")
    print(f"    Adapter:    {adapter}")
    print(f"    Config:     {saved_path.resolve()}")

    try:
        initial_res = submit_gateway_telemetry(
            server_clean, gateway_id, agent_token, adapter
        )
        print(f"[+] Initial telemetry submitted: {initial_res.get('status', 'OK')}")
    except Exception as exc:
        print(f"[!] Note: Initial telemetry submission failed ({exc}), but gateway is enrolled.")

    return data


def run_agent(
    server: str | None = None,
    gateway_id: str | None = None,
    token: str | None = None,
    adapter_kind: str | None = None,
    config_path: str | Path | None = None,
    once: bool = False,
    interval: int | None = None,
    allow_testbed_apply: bool = False,
) -> int:
    config = load_config(config_path)
    srv = server or config.get("central_api_url") or os.environ.get("VPN_ANALYZER_SERVER")
    gid = gateway_id or config.get("gateway_id") or os.environ.get("VPN_ANALYZER_GATEWAY_ID")
    tok = token or config.get("agent_token") or os.environ.get("VPN_ANALYZER_AGENT_TOKEN")
    adapter = (
        adapter_kind
        or config.get("telemetry_adapter")
        or os.environ.get("VPN_ANALYZER_ADAPTER", "strongswan")
    )
    intv = interval if interval is not None else int(config.get("interval", 15))

    if not srv or not gid or not tok:
        print(
            "[agent] Error: Gateway is not configured. Run 'enroll' first or supply --server, --gateway-id, and --token.",
            file=sys.stderr,
        )
        return 1

    print(f"[agent] Starting Gateway Agent for {gid} -> {srv} (adapter: {adapter}, interval: {intv}s)")
    if allow_testbed_apply:
        print("[agent] Testbed apply enabled: only validated settings and fixed swanctl commands are accepted.")

    while True:
        try:
            res = submit_gateway_telemetry(srv, gid, tok, adapter)
            print(f"[agent] [{datetime.now().strftime('%H:%M:%S')}] Telemetry submitted: {res.get('status', 'OK')}")
        except urllib.error.HTTPError as exc:
            if exc.code in (401, 403):
                print(
                    f"[agent] [FATAL] Authentication failed (HTTP {exc.code}). Gateway may be REVOKED or token invalid.",
                    file=sys.stderr,
                )
                return 1
            print(f"[agent] [WARN] Server returned HTTP {exc.code}: {exc.reason}", file=sys.stderr)
        except Exception as exc:
            print(f"[agent] [WARN] Telemetry submission failed: {exc}", file=sys.stderr)

        if allow_testbed_apply:
            try:
                job = poll_testbed_job(srv, gid, tok)
                if job:
                    result = apply_testbed_job(job)
                    submit_testbed_job_result(srv, gid, tok, str(job.get("jobId", "")), result)
                    print(f"[agent] Testbed job {result['status'].lower()}: {result['message']}")
            except Exception as exc:
                print(f"[agent] [WARN] Testbed job poll/apply failed: {type(exc).__name__}", file=sys.stderr)

        if once:
            break
        time.sleep(intv)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="IPsec VPN analyzer agent & gateway runner")

    # Subcommands
    subparsers = parser.add_subparsers(dest="command", help="Agent commands")

    # enroll
    enroll_parser = subparsers.add_parser("enroll", help="Enroll with central API using one-time token")
    enroll_parser.add_argument("--server", required=True, help="Central API URL (e.g. http://127.0.0.1:8770)")
    enroll_parser.add_argument("--token", required=True, help="One-time enrollment token")
    enroll_parser.add_argument("--adapter", choices=("strongswan", "strongswan-vici"), default="strongswan")
    enroll_parser.add_argument("--config", help="Path to write configuration file")

    # run
    run_parser = subparsers.add_parser("run", help="Run agent to collect and submit telemetry")
    run_parser.add_argument("--server", help="Central API URL (overrides config)")
    run_parser.add_argument("--gateway-id", help="Gateway ID (overrides config)")
    run_parser.add_argument("--token", help="Agent authentication token (overrides config)")
    run_parser.add_argument("--adapter", choices=("strongswan", "strongswan-vici"), help="Telemetry adapter")
    run_parser.add_argument("--config", help="Path to configuration file")
    run_parser.add_argument("--once", action="store_true", help="Send telemetry once and exit")
    run_parser.add_argument("--interval", type=int, help="Telemetry submission interval in seconds")
    run_parser.add_argument("--allow-testbed-apply", action="store_true", help="Allow explicitly confirmed validated testbed jobs")

    # heartbeat
    hb_parser = subparsers.add_parser("heartbeat", help="Send a heartbeat ping")
    hb_parser.add_argument("--server", help="Central API URL")
    hb_parser.add_argument("--gateway-id", help="Gateway ID")
    hb_parser.add_argument("--token", help="Agent authentication token")
    hb_parser.add_argument("--config", help="Path to configuration file")

    # status
    status_parser = subparsers.add_parser("status", help="Check local agent configuration and status")
    status_parser.add_argument("--config", help="Path to configuration file")

    # Legacy options for local analysis / pcap
    parser.add_argument("--mode", choices=("local", "cloud"), default="local")
    parser.add_argument("--pcap", type=Path)
    parser.add_argument("--live", action="store_true", help="Capture a bounded metadata-only live window")
    parser.add_argument("--interface")
    parser.add_argument("--count", type=int, default=0)
    parser.add_argument("--timeout", type=int, default=10)
    parser.add_argument("--gateway", choices=("none", "strongswan", "strongswan-vici"), default="none")
    parser.add_argument("--endpoint", help="HTTPS cloud endpoint for sanitized metadata")
    parser.add_argument("--token-env", default="VPN_ANALYZER_AGENT_TOKEN")

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    if args.command == "enroll":
        try:
            enroll_agent(args.server, args.token, args.adapter, args.config)
            return 0
        except Exception as exc:
            print(f"[agent] Error: {exc}", file=sys.stderr)
            return 1

    if args.command == "run":
        return run_agent(
            server=args.server,
            gateway_id=args.gateway_id,
            token=args.token,
            adapter_kind=args.adapter,
            config_path=args.config,
            once=args.once,
            interval=args.interval,
            allow_testbed_apply=args.allow_testbed_apply,
        )

    if args.command == "heartbeat":
        config = load_config(args.config)
        srv = args.server or config.get("central_api_url")
        gid = args.gateway_id or config.get("gateway_id")
        tok = args.token or config.get("agent_token")
        if not srv or not gid or not tok:
            print("[agent] Missing configuration for heartbeat", file=sys.stderr)
            return 1
        try:
            res = send_gateway_heartbeat(srv, gid, tok)
            print(f"[agent] Heartbeat OK: {res}")
            return 0
        except Exception as exc:
            print(f"[agent] Heartbeat failed: {exc}", file=sys.stderr)
            return 1

    if args.command == "status":
        config = load_config(args.config)
        if not config:
            print("[agent] No configuration found. Run 'enroll' first.")
            return 1
        print("=== Gateway Agent Status ===")
        print(f"Gateway ID:        {config.get('gateway_id')}")
        print(f"Central Server:    {config.get('central_api_url')}")
        print(f"Telemetry Adapter: {config.get('telemetry_adapter')}")
        print(f"Agent Version:     {config.get('agent_version', AGENT_VERSION)}")
        print(f"Interval:          {config.get('interval', 15)}s")
        return 0

    # Legacy execution
    if args.live and args.pcap:
        raise SystemExit("--live and --pcap cannot be used together")
    result = capture_local(args.interface, args.count, args.timeout) if args.live else analyze_local(args.pcap, args.gateway)
    if args.mode == "cloud":
        if not args.endpoint:
            raise SystemExit("--endpoint is required in cloud mode")
        token = os.environ.get(args.token_env)
        if not token:
            raise SystemExit(f"{args.token_env} must be set in cloud mode")
        result = send_cloud(args.endpoint, token, result)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
