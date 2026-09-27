"""Allowlisted strongSwan testbed configuration generation."""

from __future__ import annotations

import ipaddress
import re
from typing import Any

ALLOWED_IKE_VERSIONS = {"IKEv1", "IKEv2"}
ALLOWED_MODES = {"Tunnel Mode", "Transport Mode"}
ALLOWED_CIPHERS = {"AES-256-GCM", "AES-128-GCM", "AES-256-CBC", "3DES-CBC"}
ALLOWED_DH_GROUPS = {2, 5, 14, 19, 20}
ALLOWED_AUTH = {"psk", "pubkey"}
ALLOWED_TRAFFIC = {
    "VoIP / Audio Call",
    "Video Streaming",
    "Web Browsing / HTTPS",
    "Bulk Data Transfer (DB/FTP)",
}
SAFE_ID_RE = re.compile(r"^[A-Za-z0-9_.@:+-]{1,128}$")
SAFE_NAME_RE = re.compile(r"^[a-z][a-z0-9_]{2,47}$")

DH_SUFFIX = {
    2: "modp1024",
    5: "modp1536",
    14: "modp2048",
    19: "ecp256",
    20: "ecp384",
}


def validate_testbed_settings(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError("TESTBED_SETTINGS_INVALID")

    allowed_keys = {
        "ikeVersion", "mode", "cipher", "dhGroup", "pfs", "ipVersion",
        "localAddress", "remoteAddress", "localId", "remoteId", "authMethod",
        "localTs", "remoteTs", "trafficType",
    }
    if set(value) - allowed_keys:
        raise ValueError("TESTBED_SETTINGS_UNSUPPORTED_FIELD")

    ike_version = value.get("ikeVersion")
    mode = value.get("mode")
    cipher = value.get("cipher")
    dh_group = value.get("dhGroup")
    ip_version = value.get("ipVersion")
    auth_method = value.get("authMethod")
    pfs = value.get("pfs")

    if ike_version not in ALLOWED_IKE_VERSIONS:
        raise ValueError("TESTBED_IKE_VERSION_INVALID")
    if mode not in ALLOWED_MODES:
        raise ValueError("TESTBED_MODE_INVALID")
    if cipher not in ALLOWED_CIPHERS:
        raise ValueError("TESTBED_CIPHER_INVALID")
    if isinstance(dh_group, bool) or not isinstance(dh_group, int) or dh_group not in ALLOWED_DH_GROUPS:
        raise ValueError("TESTBED_DH_GROUP_INVALID")
    if ip_version not in {"IPv4", "IPv6"}:
        raise ValueError("TESTBED_IP_VERSION_INVALID")
    if auth_method not in ALLOWED_AUTH:
        raise ValueError("TESTBED_AUTH_METHOD_INVALID")
    if not isinstance(pfs, bool):
        raise ValueError("TESTBED_PFS_INVALID")

    try:
        local_address = ipaddress.ip_address(str(value.get("localAddress", "")))
        remote_address = ipaddress.ip_address(str(value.get("remoteAddress", "")))
        local_ts = ipaddress.ip_network(str(value.get("localTs", "")), strict=False)
        remote_ts = ipaddress.ip_network(str(value.get("remoteTs", "")), strict=False)
    except ValueError:
        raise ValueError("TESTBED_ADDRESS_INVALID") from None

    expected_version = 4 if ip_version == "IPv4" else 6
    if any(address.version != expected_version for address in (local_address, remote_address, local_ts, remote_ts)):
        raise ValueError("TESTBED_ADDRESS_FAMILY_MISMATCH")

    local_id = value.get("localId")
    remote_id = value.get("remoteId")
    if not isinstance(local_id, str) or not SAFE_ID_RE.fullmatch(local_id):
        raise ValueError("TESTBED_LOCAL_ID_INVALID")
    if not isinstance(remote_id, str) or not SAFE_ID_RE.fullmatch(remote_id):
        raise ValueError("TESTBED_REMOTE_ID_INVALID")

    traffic_type = value.get("trafficType")
    if traffic_type not in ALLOWED_TRAFFIC:
        raise ValueError("TESTBED_TRAFFIC_TYPE_INVALID")

    return {
        "ikeVersion": ike_version,
        "mode": mode,
        "cipher": cipher,
        "dhGroup": dh_group,
        "pfs": pfs,
        "ipVersion": ip_version,
        "localAddress": str(local_address),
        "remoteAddress": str(remote_address),
        "localId": local_id,
        "remoteId": remote_id,
        "authMethod": auth_method,
        "localTs": str(local_ts),
        "remoteTs": str(remote_ts),
        "trafficType": traffic_type,
    }


def _proposals(settings: dict[str, Any]) -> tuple[str, str]:
    dh = DH_SUFFIX[settings["dhGroup"]]
    cipher = settings["cipher"]
    if cipher == "AES-256-GCM":
        encryption = "aes256gcm16"
        prf = "prfsha384"
        integrity = ""
    elif cipher == "AES-128-GCM":
        encryption = "aes128gcm16"
        prf = "prfsha256"
        integrity = ""
    elif cipher == "AES-256-CBC":
        encryption = "aes256"
        prf = "sha256"
        integrity = "sha256"
    else:
        encryption = "3des"
        prf = "sha1"
        integrity = "sha1"

    ike_proposal = f"{encryption}-{prf}-{dh}"
    child_proposal = f"{encryption}{('-' + integrity) if integrity else ''}"
    if settings["pfs"]:
        child_proposal += f"-{dh}"
    return ike_proposal, child_proposal


def render_swanctl_config(
    value: Any,
    connection_name: str = "lab_testbed",
    child_name: str = "lab_child",
) -> str:
    settings = validate_testbed_settings(value)
    if not SAFE_NAME_RE.fullmatch(connection_name) or not SAFE_NAME_RE.fullmatch(child_name):
        raise ValueError("TESTBED_NAME_INVALID")
    ike_proposal, child_proposal = _proposals(settings)
    mode = "tunnel" if settings["mode"] == "Tunnel Mode" else "transport"
    return f"""# Generated testbed configuration. No credentials are included.
# The matching PSK/certificate must already be provisioned on both peers.
connections {{
  {connection_name} {{
    version = {2 if settings['ikeVersion'] == 'IKEv2' else 1}
    local_addrs = {settings['localAddress']}
    remote_addrs = {settings['remoteAddress']}
    proposals = {ike_proposal}
    reauth_time = 8h

    local {{
      auth = {settings['authMethod']}
      id = {settings['localId']}
    }}
    remote {{
      auth = {settings['authMethod']}
      id = {settings['remoteId']}
    }}

    children {{
      {child_name} {{
        mode = {mode}
        local_ts = {settings['localTs']}
        remote_ts = {settings['remoteTs']}
        esp_proposals = {child_proposal}
        rekey_time = 1h
      }}
    }}
  }}
}}
"""


def build_manual_commands(
    value: Any,
    config_path: str = "/etc/swanctl/conf.d/lab-testbed.conf",
) -> str:
    settings = validate_testbed_settings(value)
    if (
        not isinstance(config_path, str)
        or not re.fullmatch(r"/[A-Za-z0-9_./-]+", config_path)
        or ".." in config_path.split("/")
    ):
        raise ValueError("TESTBED_CONFIG_PATH_INVALID")
    del settings
    return (
        f"sudo install -m 0644 lab-testbed.conf {config_path}\n"
        f"sudo swanctl --load-conns --file {config_path}\n"
        "sudo swanctl --initiate --child lab_child --ike lab_testbed\n"
        "sudo swanctl --list-sas --raw"
    )
