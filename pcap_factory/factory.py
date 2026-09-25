import base64
import json
import os
import sys
import time
import getpass
import signal
import traceback
import re
from datetime import datetime

import paramiko


# ============================================================
# IPsec PCAP FACTORY
# ============================================================
#
# Purpose:
#   Automatically create labeled IPsec PCAP datasets.
#
# Dataset goals:
#
#   IKEv2
#   PSK authentication
#   Tunnel mode
#   AES-256
#   SHA-256
#   MODP-2048 / DH14
#   ESP AES-256 / SHA-256
#   Optional ESP PFS MODP-2048
#
# IMPORTANT:
#   A capture is SUCCESS only when the negotiated values
#   match the requested experiment.
#
# ============================================================


BASE_DIR = os.path.dirname(os.path.abspath(__file__))

EXPERIMENT_FILE = os.path.join(
    BASE_DIR,
    "experiments.json"
)

CAPTURE_DIR = os.path.join(
    BASE_DIR,
    "captures"
)

METADATA_DIR = os.path.join(
    BASE_DIR,
    "metadata"
)

os.makedirs(CAPTURE_DIR, exist_ok=True)
os.makedirs(METADATA_DIR, exist_ok=True)


# ============================================================
# TESTBED
# ============================================================

HOSTS = {
    "officeA": {
        "host": "192.168.56.106",
        "user": "meow2"
    },

    "officeB": {
        "host": "192.168.56.107",
        "user": "meow3"
    }
}


OFFICE_A_IP = "192.168.56.106"
OFFICE_B_IP = "192.168.56.107"

INTERFACE = "enp0s8"

VPN_CONNECTION = "office-vpn"


# ============================================================
# GLOBAL STATE
# ============================================================

office_a_global = None
office_b_global = None


# ============================================================
# SSH
# ============================================================

class SSHHost:

    def __init__(self, name, password):

        self.name = name
        self.password = password
        self.client = None

    @property
    def username(self):

        return HOSTS[self.name]["user"]

    @property
    def address(self):

        return HOSTS[self.name]["host"]

    def connect(self):

        print(
            f"Connecting to {self.name} "
            f"({self.address})..."
        )

        self.client = paramiko.SSHClient()

        self.client.set_missing_host_key_policy(
            paramiko.AutoAddPolicy()
        )

        self.client.connect(
            hostname=self.address,
            username=self.username,
            password=self.password,
            timeout=15,
            look_for_keys=False,
            allow_agent=False
        )

        print(
            f"Connected to {self.name}."
        )

    def command(self, cmd, timeout=60):

        if self.client is None:

            raise RuntimeError(
                f"{self.name}: SSH connection is not established"
            )

        stdin, stdout, stderr = self.client.exec_command(
            cmd,
            timeout=timeout
        )

        output = stdout.read().decode(
            "utf-8",
            errors="replace"
        )

        error = stderr.read().decode(
            "utf-8",
            errors="replace"
        )

        exit_code = stdout.channel.recv_exit_status()

        return exit_code, output, error

    def sudo_command(self, cmd, timeout=60):

        password_b64 = base64.b64encode(
            self.password.encode("utf-8")
        ).decode("ascii")

        command_b64 = base64.b64encode(
            cmd.encode("utf-8")
        ).decode("ascii")

        decoded_command = (
            f"echo {shell_quote(command_b64)} "
            f"| base64 -d | bash"
        )

        remote_command = (
            f"printf '%s' {shell_quote(password_b64)} "
            f"| base64 -d | "
            f"sudo -S -p '' "
            f"bash -c {shell_quote(decoded_command)}"
        )

        return self.command(
            remote_command,
            timeout=timeout
        )

    def close(self):

        if self.client is not None:

            try:
                self.client.close()
            except Exception:
                pass

            self.client = None


# ============================================================
# SHELL HELPERS
# ============================================================

def shell_quote(value):

    value = str(value)

    return (
        "'"
        + value.replace(
            "'",
            "'\\''"
        )
        + "'"
    )


def run(
    host,
    cmd,
    timeout=60,
    check=True
):

    code, output, error = host.command(
        cmd,
        timeout
    )

    if check and code != 0:

        print()
        print("[ERROR] Command failed:")
        print(cmd)

        if error:
            print(error)

        raise RuntimeError(
            f"Command failed with exit code {code}"
        )

    return output


def sudo(
    host,
    cmd,
    timeout=60,
    check=True
):

    code, output, error = host.sudo_command(
        cmd,
        timeout
    )

    if check and code != 0:

        print()
        print("[ERROR] sudo command failed:")
        print(cmd)

        if error:
            print(error)

        raise RuntimeError(
            f"sudo command failed with exit code {code}"
        )

    return output


# ============================================================
# IPsec CONFIG
# ============================================================

def build_ipsec_conf(
    local_ip,
    remote_ip,
    ike,
    esp
):

    return f"""config setup
    uniqueids=no
    strictcrlpolicy=no

conn office-vpn
    type=tunnel
    keyexchange=ikev2

    left={local_ip}
    leftid={local_ip}

    right={remote_ip}
    rightid={remote_ip}

    authby=psk

    ike={ike}!
    esp={esp}!

    ikelifetime=8h
    lifetime=1h
    rekeytime=55m

    dpdaction=restart
    dpddelay=30s

    fragmentation=no
    mobike=no

    auto=add
"""


def write_remote_file(
    host,
    remote_file,
    content
):

    encoded = base64.b64encode(
        content.encode("utf-8")
    ).decode("ascii")

    sudo(
        host,
        (
            f"echo {shell_quote(encoded)} "
            f"| base64 -d "
            f"| tee {shell_quote(remote_file)} "
            f"> /dev/null"
        )
    )


def configure_host(
    host,
    local_ip,
    remote_ip,
    ike,
    esp
):

    print(
        f"Writing IPsec configuration on "
        f"{host.name}..."
    )

    config = build_ipsec_conf(
        local_ip,
        remote_ip,
        ike,
        esp
    )

    write_remote_file(
        host,
        "/etc/ipsec.conf",
        config
    )

    verified = sudo(
        host,
        "cat /etc/ipsec.conf"
    )

    if f"ike={ike}!" not in verified:

        raise RuntimeError(
            f"{host.name}: IKE proposal was not "
            f"written correctly"
        )

    if f"esp={esp}!" not in verified:

        raise RuntimeError(
            f"{host.name}: ESP proposal was not "
            f"written correctly"
        )

    print(
        f"{host.name} configuration verified."
    )

    # Restart strongSwan so there is no ambiguity
    # about the connection currently loaded.

    sudo(
        host,
        "ipsec restart",
        timeout=30
    )

    time.sleep(3)

    sudo(
        host,
        "ipsec rereadall",
        timeout=30
    )

    sudo(
        host,
        "ipsec rereadsecrets",
        timeout=30,
        check=False
    )



def verify_loaded_config(
    host,
    expected_ike,
    expected_esp
):
    print(
        f"Checking loaded strongSwan configuration "
        f"on {host.name}..."
    )

    status = sudo(
        host,
        "ipsec statusall",
        timeout=30
    )

    print(status)

    # --------------------------------------------------------
    # Verify that the connection itself is loaded
    # --------------------------------------------------------

    if "office-vpn" not in status:
        raise RuntimeError(
            f"{host.name}: office-vpn connection "
            f"was not loaded"
        )

    # --------------------------------------------------------
    # Verify IKEv2
    # --------------------------------------------------------

    if "IKEv2" not in status:
        raise RuntimeError(
            f"{host.name}: IKEv2 connection "
            f"was not loaded"
        )

    # --------------------------------------------------------
    # IMPORTANT:
    #
    # Do NOT check AES_CBC_256 / HMAC_SHA2_256 /
    # MODP_2048 here.
    #
    # strongSwan 6.0.4 may not display the configured
    # proposal names in `ipsec statusall` before negotiation.
    #
    # The actual negotiated algorithms will be verified
    # after the CHILD_SA is established.
    # --------------------------------------------------------

    print(
        f"{host.name}: IPsec connection loaded successfully."
    )

    print(
        f"Configured IKE proposal: {expected_ike}"
    )

    print(
        f"Configured ESP proposal: {expected_esp}"
    )

    return status



# ============================================================
# VPN CONTROL
# ============================================================

def stop_vpn(host):

    print(
        f"Stopping IPsec on {host.name}..."
    )

    sudo(
        host,
        f"ipsec down {VPN_CONNECTION}",
        timeout=30,
        check=False
    )

    time.sleep(1)


def start_vpn(host):

    print(
        f"Starting IPsec on {host.name}..."
    )

    return sudo(
        host,
        f"ipsec up {VPN_CONNECTION}",
        timeout=60
    )


def get_status(host):

    return sudo(
        host,
        "ipsec statusall",
        timeout=30
    )


def wait_for_established(
    host,
    timeout=45
):

    print(
        f"Waiting for IKEv2 / CHILD_SA "
        f"on {host.name}..."
    )

    start = time.time()

    last_status = ""

    while time.time() - start < timeout:

        try:

            status = get_status(host)

            last_status = status

            upper = status.upper()

            has_established = (
                "ESTABLISHED" in upper
            )

            has_child_sa = (
                "INSTALLED" in upper
                and "TUNNEL" in upper
            )

            if (
                has_established
                and has_child_sa
            ):

                return status

        except Exception:
            pass

        time.sleep(2)

    print()
    print(
        f"Last status from {host.name}:"
    )
    print(last_status)

    raise RuntimeError(
        f"{host.name}: "
        f"IKEv2 / CHILD_SA establishment timeout"
    )


# ============================================================
# TCPDUMP
# ============================================================

def start_capture(
    host,
    remote_filename
):

    print(
        "Starting tcpdump BEFORE "
        "IKE negotiation..."
    )

    pid_file = (
        "/tmp/ipsec_factory_tcpdump.pid"
    )

    log_file = (
        "/tmp/ipsec_factory_tcpdump.log"
    )

    filter_expression = (
        "udp port 500 or "
        "udp port 4500 or "
        "ip proto 50"
    )

    sudo(
        host,
        (
            f"rm -f "
            f"{shell_quote(pid_file)} "
            f"{shell_quote(log_file)} "
            f"{shell_quote(remote_filename)}"
        ),
        check=False
    )

    command = (
        f"nohup tcpdump "
        f"-i {shell_quote(INTERFACE)} "
        f"-s 0 "
        f"-U "
        f"-w {shell_quote(remote_filename)} "
        f"{filter_expression} "
        f"> {shell_quote(log_file)} "
        f"2>&1 & "
        f"echo $! > {shell_quote(pid_file)}"
    )

    sudo(
        host,
        command
    )

    time.sleep(2)

    pid = sudo(
        host,
        f"cat {shell_quote(pid_file)}"
    ).strip()

    if not pid.isdigit():

        raise RuntimeError(
            "Could not obtain tcpdump PID"
        )

    alive = sudo(
        host,
        (
            f"kill -0 {pid} "
            f"2>/dev/null "
            f"&& echo RUNNING "
            f"|| echo STOPPED"
        ),
        check=False
    ).strip()

    if alive != "RUNNING":

        log = sudo(
            host,
            f"cat {shell_quote(log_file)}",
            check=False
        )

        raise RuntimeError(
            "tcpdump failed to start.\n"
            f"tcpdump log:\n{log}"
        )

    print(
        f"tcpdump started on {host.name}, "
        f"PID={pid}"
    )

    return {
        "pid": pid,
        "pid_file": pid_file,
        "log_file": log_file,
        "remote_file": remote_filename,
        "interface": INTERFACE,
        "filter": filter_expression
    }


def stop_capture(
    host,
    capture_info
):

    if not capture_info:
        return

    pid = capture_info["pid"]

    print(
        f"Stopping tcpdump PID {pid}..."
    )

    sudo(
        host,
        (
            f"kill -TERM {pid} "
            f"2>/dev/null || true"
        ),
        check=False
    )

    time.sleep(2)

    still_alive = sudo(
        host,
        (
            f"kill -0 {pid} "
            f"2>/dev/null "
            f"&& echo RUNNING "
            f"|| echo STOPPED"
        ),
        check=False
    ).strip()

    if still_alive == "RUNNING":

        sudo(
            host,
            (
                f"kill -KILL {pid} "
                f"2>/dev/null || true"
            ),
            check=False
        )

        time.sleep(1)

    print(
        "tcpdump stopped."
    )


def verify_pcap(
    host,
    remote_file
):

    result = sudo(
        host,
        (
            f"test -s {shell_quote(remote_file)} "
            f"&& ls -lh {shell_quote(remote_file)}"
        ),
        check=False
    )

    if not result.strip():

        log = sudo(
            host,
            "cat /tmp/ipsec_factory_tcpdump.log",
            check=False
        )

        raise RuntimeError(
            "Remote PCAP was not created.\n"
            f"tcpdump log:\n{log}"
        )

    print(
        "Remote PCAP exists:"
    )

    print(result.strip())


# ============================================================
# PCAP DOWNLOAD
# ============================================================

def download_file(
    host,
    remote_file,
    local_file
):

    print(
        "Preparing PCAP for download..."
    )

    sudo(
        host,
        (
            f"chown "
            f"{shell_quote(host.username)}:"
            f"{shell_quote(host.username)} "
            f"{shell_quote(remote_file)}"
        )
    )

    print(
        "Downloading PCAP..."
    )

    sftp = host.client.open_sftp()

    try:

        sftp.get(
            remote_file,
            local_file
        )

    finally:

        sftp.close()

    if not os.path.exists(local_file):

        raise RuntimeError(
            "PCAP download failed"
        )

    if os.path.getsize(local_file) == 0:

        raise RuntimeError(
            "Downloaded PCAP is empty"
        )

    print(
        f"Downloaded PCAP: {local_file}"
    )

    print(
        f"PCAP size: "
        f"{os.path.getsize(local_file)} bytes"
    )


def remove_remote_pcap(
    host,
    remote_file
):

    sudo(
        host,
        (
            f"rm -f "
            f"{shell_quote(remote_file)}"
        ),
        check=False
    )


# ============================================================
# TRAFFIC
# ============================================================

def generate_icmp(
    host,
    count=20
):

    print(
        f"Generating ICMP traffic "
        f"({count} packets)..."
    )

    output = run(
        host,
        (
            f"ping "
            f"-c {int(count)} "
            f"-W 2 "
            f"{OFFICE_B_IP}"
        ),
        timeout=90
    )

    print(
        output.strip()
    )


# ============================================================
# TCP
# ============================================================

def start_tcp_server(
    host,
    port
):

    script = f"""
import socket

HOST = "0.0.0.0"
PORT = {int(port)}

server = socket.socket(
    socket.AF_INET,
    socket.SOCK_STREAM
)

server.setsockopt(
    socket.SOL_SOCKET,
    socket.SO_REUSEADDR,
    1
)

server.bind(
    (HOST, PORT)
)

server.listen(20)

while True:

    conn, addr = server.accept()

    try:
        conn.recv(4096)

    except Exception:
        pass

    finally:
        conn.close()
"""

    encoded = base64.b64encode(
        script.encode("utf-8")
    ).decode("ascii")

    command = (
        f"echo {shell_quote(encoded)} "
        f"| base64 -d "
        f"> /tmp/ipsec_tcp_server.py && "
        f"nohup python3 "
        f"/tmp/ipsec_tcp_server.py "
        f"> /tmp/ipsec_tcp_server.log "
        f"2>&1 & "
        f"echo $!"
    )

    output = run(
        host,
        command
    )

    pid = (
        output.strip()
        .splitlines()[-1]
    )

    time.sleep(2)

    check = run(
        host,
        (
            f"ss -lnt | "
            f"grep -E ':{int(port)}[[:space:]]'"
        )
    )

    if not check.strip():

        log = run(
            host,
            "cat /tmp/ipsec_tcp_server.log",
            check=False
        )

        raise RuntimeError(
            "TCP server failed to start.\n"
            f"{log}"
        )

    print(
        f"TCP server listening on "
        f"{host.address}:{port}"
    )

    return pid


def stop_tcp_server(
    host,
    pid
):

    run(
        host,
        f"kill {pid} 2>/dev/null || true",
        check=False
    )

    run(
        host,
        "rm -f /tmp/ipsec_tcp_server.py",
        check=False
    )


def generate_tcp(
    office_a,
    office_b,
    port=8080,
    count=30
):

    print(
        f"Generating TCP traffic "
        f"({count} messages)..."
    )

    server_pid = start_tcp_server(
        office_b,
        port
    )

    try:

        script = f"""
import socket
import sys

target = "{OFFICE_B_IP}"
port = {int(port)}
count = {int(count)}

success = 0

for i in range(1, count + 1):

    try:

        s = socket.socket(
            socket.AF_INET,
            socket.SOCK_STREAM
        )

        s.settimeout(3)

        s.connect(
            (target, port)
        )

        message = (
            f"IPSEC_TCP_PACKET_{{i}}"
        ).encode()

        s.sendall(message)

        s.close()

        success += 1

    except Exception as e:

        print(
            f"TCP packet {{i}} failed: {{e}}"
        )

print(
    f"TCP_SUCCESS={{success}}/{{count}}"
)

if success == 0:
    sys.exit(1)
"""

        encoded = base64.b64encode(
            script.encode("utf-8")
        ).decode("ascii")

        output = run(
            office_a,
            (
                f"echo {shell_quote(encoded)} "
                f"| base64 -d "
                f"| python3"
            ),
            timeout=120
        )

        print(
            output.strip()
        )

    finally:

        stop_tcp_server(
            office_b,
            server_pid
        )


# ============================================================
# UDP
# ============================================================

def start_udp_server(
    host,
    port
):

    script = f"""
import socket

HOST = "0.0.0.0"
PORT = {int(port)}

server = socket.socket(
    socket.AF_INET,
    socket.SOCK_DGRAM
)

server.setsockopt(
    socket.SOL_SOCKET,
    socket.SO_REUSEADDR,
    1
)

server.bind(
    (HOST, PORT)
)

while True:

    try:
        server.recvfrom(65535)

    except Exception:
        pass
"""

    encoded = base64.b64encode(
        script.encode("utf-8")
    ).decode("ascii")

    command = (
        f"echo {shell_quote(encoded)} "
        f"| base64 -d "
        f"> /tmp/ipsec_udp_server.py && "
        f"nohup python3 "
        f"/tmp/ipsec_udp_server.py "
        f"> /tmp/ipsec_udp_server.log "
        f"2>&1 & "
        f"echo $!"
    )

    output = run(
        host,
        command
    )

    pid = (
        output.strip()
        .splitlines()[-1]
    )

    time.sleep(2)

    check = run(
        host,
        (
            f"ss -lun | "
            f"grep -E ':{int(port)}[[:space:]]'"
        )
    )

    if not check.strip():

        log = run(
            host,
            "cat /tmp/ipsec_udp_server.log",
            check=False
        )

        raise RuntimeError(
            "UDP server failed to start.\n"
            f"{log}"
        )

    print(
        f"UDP server listening on "
        f"{host.address}:{port}"
    )

    return pid


def stop_udp_server(
    host,
    pid
):

    run(
        host,
        f"kill {pid} 2>/dev/null || true",
        check=False
    )

    run(
        host,
        "rm -f /tmp/ipsec_udp_server.py",
        check=False
    )


def generate_udp(
    office_a,
    office_b,
    port=9090,
    count=30
):

    print(
        f"Generating UDP traffic "
        f"({count} messages)..."
    )

    server_pid = start_udp_server(
        office_b,
        port
    )

    try:

        script = f"""
import socket
import sys

target = "{OFFICE_B_IP}"
port = {int(port)}
count = {int(count)}

sock = socket.socket(
    socket.AF_INET,
    socket.SOCK_DGRAM
)

sock.settimeout(3)

success = 0

for i in range(1, count + 1):

    try:

        message = (
            f"IPSEC_UDP_PACKET_{{i}}"
        ).encode()

        sock.sendto(
            message,
            (target, port)
        )

        success += 1

    except Exception as e:

        print(
            f"UDP packet {{i}} failed: {{e}}"
        )

sock.close()

print(
    f"UDP_SUCCESS={{success}}/{{count}}"
)

if success == 0:
    sys.exit(1)
"""

        encoded = base64.b64encode(
            script.encode("utf-8")
        ).decode("ascii")

        output = run(
            office_a,
            (
                f"echo {shell_quote(encoded)} "
                f"| base64 -d "
                f"| python3"
            ),
            timeout=120
        )

        print(
            output.strip()
        )

    finally:

        stop_udp_server(
            office_b,
            server_pid
        )


def generate_traffic(
    experiment,
    office_a,
    office_b,
    settings
):

    traffic_type = (
        experiment["traffic"]
        .lower()
    )

    traffic_settings = settings.get(
        "traffic",
        {}
    )

    if traffic_type == "icmp":

        icmp_settings = traffic_settings.get(
            "icmp",
            {}
        )

        generate_icmp(
            office_a,
            count=icmp_settings.get(
                "count",
                20
            )
        )

    elif traffic_type == "tcp":

        tcp_settings = traffic_settings.get(
            "tcp",
            {}
        )

        generate_tcp(
            office_a,
            office_b,
            port=tcp_settings.get(
                "port",
                8080
            ),
            count=tcp_settings.get(
                "count",
                30
            )
        )

    elif traffic_type == "udp":

        udp_settings = traffic_settings.get(
            "udp",
            {}
        )

        generate_udp(
            office_a,
            office_b,
            port=udp_settings.get(
                "port",
                9090
            ),
            count=udp_settings.get(
                "count",
                30
            )
        )

    else:

        raise ValueError(
            f"Unsupported traffic type: "
            f"{traffic_type}"
        )


# ============================================================
# PROPOSAL PARSING
# ============================================================

def clean_proposal(value):

    if not value:
        return None

    value = value.strip()

    value = value.rstrip(",")

    value = value.rstrip(".")

    return value


def parse_ike_proposal(text):

    """
    Supports:

        IKE proposal: AES_CBC_256/...
        selected proposal: IKE:AES_CBC_256/...
    """

    for line in text.splitlines():

        if "selected proposal: IKE:" in line:

            proposal = line.split(
                "selected proposal: IKE:",
                1
            )[1].strip()

            return clean_proposal(
                proposal
            )

        if "IKE proposal:" in line:

            proposal = line.split(
                "IKE proposal:",
                1
            )[1].strip()

            return clean_proposal(
                proposal
            )

    return None


def parse_esp_proposal(text):

    """
    Supports:

        ESP proposal: AES_CBC_256/...
        selected proposal: ESP:AES_CBC_256/...
    """

    for line in text.splitlines():

        if "selected proposal: ESP:" in line:

            proposal = line.split(
                "selected proposal: ESP:",
                1
            )[1].strip()

            return clean_proposal(
                proposal
            )

        if "ESP proposal:" in line:

            proposal = line.split(
                "ESP proposal:",
                1
            )[1].strip()

            return clean_proposal(
                proposal
            )

    return None


def parse_ike_spis(text):

    for line in text.splitlines():

        if "IKEv2 SPIs:" in line:

            return line.split(
                "IKEv2 SPIs:",
                1
            )[1].strip()

    return None


def parse_esp_spis(text):

    for line in text.splitlines():

        if "ESP SPIs:" in line:

            value = line.split(
                "ESP SPIs:",
                1
            )[1].strip()

            parts = value.split()

            inbound = None
            outbound = None

            for part in parts:

                if "_i" in part:

                    inbound = part.replace(
                        "_i",
                        ""
                    )

                if "_o" in part:

                    outbound = part.replace(
                        "_o",
                        ""
                    )

            return {
                "inbound": inbound,
                "outbound": outbound,
                "raw": value
            }

    return None


def parse_prf(
    ike_proposal
):

    if not ike_proposal:
        return None

    parts = ike_proposal.split("/")

    for part in parts:

        part = part.strip()

        if part.upper().startswith(
            "PRF_"
        ):

            return part

    return None


def parse_dh_from_ike(
    ike_proposal
):

    if not ike_proposal:
        return None

    parts = ike_proposal.split("/")

    for part in parts:

        p = part.strip().upper()

        if (
            p.startswith("MODP_")
            or p.startswith("ECP_")
            or p.startswith("CURVE_")
            or p.startswith("X25519")
            or p.startswith("X448")
        ):

            return p

    return None


def parse_pfs_group(text):
    """
    Extract the CHILD_SA PFS/DH group only from explicit ESP
    proposal evidence.

    IMPORTANT:
        Do NOT search the entire text for MODP_2048 because IKE
        proposals also contain MODP_2048. That would incorrectly
        label IKE DH as ESP PFS.

    Accepted evidence examples:
        ESP:AES_CBC-256/HMAC_SHA2_256_128/MODP_2048
        ESP:AES_CBC_256/HMAC_SHA2_256_128/MODP_2048

    Returns:
        MODP_2048 / MODP_3072 / MODP_4096 / ECP_256 /
        ECP_384 / ECP_521 / CURVE_25519 / X25519 / X448
        or None when the CHILD_SA PFS group is not exposed.
    """

    if not text:
        return None

    # Only inspect lines that explicitly describe an ESP proposal.
    # This prevents IKE DH from being mistaken for CHILD_SA PFS.
    for line in text.splitlines():
        upper = line.upper()

        if "ESP:" not in upper:
            continue

        compact = upper.replace("-", "_")

        match = re.search(
            r"/(MODP_\d+|ECP_\d+|CURVE_\d+|X25519|X448)(?:[/\s,]|$)",
            compact
        )

        if match:
            return match.group(1)

    return None


def normalize_pfs_group(value):

    if not value:
        return None

    value = value.strip().upper()

    aliases = {
        "MODP2048": "MODP_2048",
        "MODP_2048": "MODP_2048",
        "DH14": "MODP_2048",
        "MODP14": "MODP_2048",
        "MODP3072": "MODP_3072",
        "MODP_3072": "MODP_3072",
        "DH15": "MODP_3072",
        "MODP4096": "MODP_4096",
        "MODP_4096": "MODP_4096",
        "DH16": "MODP_4096",
        "ECP256": "ECP_256",
        "ECP_256": "ECP_256",
        "ECP384": "ECP_384",
        "ECP_384": "ECP_384",
        "ECP521": "ECP_521",
        "ECP_521": "ECP_521",
        "CURVE25519": "CURVE_25519",
        "CURVE_25519": "CURVE_25519",
        "X25519": "X25519",
        "X448": "X448"
    }

    return aliases.get(value, value)


def parse_child_sa_state(
    status
):

    for line in status.splitlines():

        upper = line.upper()

        if "INSTALLED" in upper:

            mode = None

            if "TUNNEL" in upper:

                mode = "TUNNEL"

            elif "TRANSPORT" in upper:

                mode = "TRANSPORT"

            return {
                "installed": True,
                "mode": mode,
                "raw": line.strip()
            }

    return {
        "installed": False,
        "mode": None,
        "raw": None
    }


# ============================================================
# NORMALIZATION
# ============================================================

def normalize_requested_ike(
    proposal
):

    parts = proposal.lower().split("-")

    if len(parts) < 3:

        raise ValueError(
            f"Invalid IKE proposal: {proposal}"
        )

    return {
        "encryption": parts[0],
        "integrity": parts[1],
        "dh": "-".join(parts[2:])
    }


def normalize_requested_esp(
    proposal
):

    parts = proposal.lower().split("-")

    if len(parts) < 2:

        raise ValueError(
            f"Invalid ESP proposal: {proposal}"
        )

    return {
        "encryption": parts[0],
        "integrity": parts[1],
        "pfs_group": (
            "-".join(parts[2:])
            if len(parts) >= 3
            else None
        )
    }


def normalize_ike_negotiated(
    proposal
):

    if not proposal:
        return None

    p = proposal.upper()

    result = {
        "encryption": None,
        "integrity": None,
        "prf": None,
        "dh": None
    }

    if "AES_CBC_128" in p:

        result["encryption"] = "aes128"

    elif "AES_CBC_192" in p:

        result["encryption"] = "aes192"

    elif "AES_CBC_256" in p:

        result["encryption"] = "aes256"

    elif "AES_GCM_16_128" in p:

        result["encryption"] = "aes128-gcm"

    elif "AES_GCM_16_256" in p:

        result["encryption"] = "aes256-gcm"

    # --------------------------------------------------------
    # Integrity
    # --------------------------------------------------------

    if "HMAC_SHA2_256" in p:

        result["integrity"] = "sha256"

    elif "HMAC_SHA2_384" in p:

        result["integrity"] = "sha384"

    elif "HMAC_SHA2_512" in p:

        result["integrity"] = "sha512"

    elif "HMAC_SHA1" in p:

        result["integrity"] = "sha1"

    # --------------------------------------------------------
    # PRF
    # --------------------------------------------------------

    if "PRF_HMAC_SHA2_256" in p:

        result["prf"] = "sha256"

    elif "PRF_HMAC_SHA2_384" in p:

        result["prf"] = "sha384"

    elif "PRF_HMAC_SHA2_512" in p:

        result["prf"] = "sha512"

    elif "PRF_HMAC_SHA1" in p:

        result["prf"] = "sha1"

    # --------------------------------------------------------
    # DH
    # --------------------------------------------------------

    if "MODP_2048" in p:

        result["dh"] = "modp2048"

    elif "MODP_3072" in p:

        result["dh"] = "modp3072"

    elif "MODP_4096" in p:

        result["dh"] = "modp4096"

    elif "ECP_256" in p:

        result["dh"] = "ecp256"

    elif "ECP_384" in p:

        result["dh"] = "ecp384"

    elif "ECP_521" in p:

        result["dh"] = "ecp521"

    elif (
        "CURVE_25519" in p
        or "X25519" in p
    ):

        result["dh"] = "curve25519"

    return result


def normalize_esp_negotiated(
    proposal
):

    if not proposal:
        return None

    p = proposal.upper()

    result = {
        "encryption": None,
        "integrity": None,
        "pfs_group": None
    }

    # --------------------------------------------------------
    # Encryption
    # --------------------------------------------------------

    if "AES_CBC_128" in p:

        result["encryption"] = "aes128"

    elif "AES_CBC_192" in p:

        result["encryption"] = "aes192"

    elif "AES_CBC_256" in p:

        result["encryption"] = "aes256"

    elif "AES_GCM_16_128" in p:

        result["encryption"] = "aes128-gcm"

    elif "AES_GCM_16_256" in p:

        result["encryption"] = "aes256-gcm"

    # --------------------------------------------------------
    # Integrity
    # --------------------------------------------------------

    if "HMAC_SHA2_256" in p:

        result["integrity"] = "sha256"

    elif "HMAC_SHA2_384" in p:

        result["integrity"] = "sha384"

    elif "HMAC_SHA2_512" in p:

        result["integrity"] = "sha512"

    elif "HMAC_SHA1" in p:

        result["integrity"] = "sha1"

    # --------------------------------------------------------
    # PFS
    # --------------------------------------------------------

    pfs = parse_pfs_group(
        proposal
    )

    if pfs == "MODP_2048":

        result["pfs_group"] = "modp2048"

    elif pfs == "MODP_3072":

        result["pfs_group"] = "modp3072"

    elif pfs == "MODP_4096":

        result["pfs_group"] = "modp4096"

    elif pfs == "ECP_256":

        result["pfs_group"] = "ecp256"

    elif pfs == "ECP_384":

        result["pfs_group"] = "ecp384"

    elif pfs == "ECP_521":

        result["pfs_group"] = "ecp521"

    elif pfs in (
        "CURVE_25519",
        "X25519"
    ):

        result["pfs_group"] = "curve25519"

    return result


# ============================================================
# VALIDATION
# ============================================================

def validate_ike(
    requested,
    negotiated
):

    mismatches = []

    if negotiated is None:

        return [
            (
                "IKE proposal",
                requested,
                None
            )
        ]

    for field, label in [
        ("encryption", "IKE encryption"),
        ("integrity", "IKE integrity"),
        ("dh", "IKE DH")
    ]:

        if (
            negotiated.get(field)
            != requested.get(field)
        ):

            mismatches.append(
                (
                    label,
                    requested.get(field),
                    negotiated.get(field)
                )
            )

    return mismatches


def validate_esp(
    requested,
    negotiated
):

    mismatches = []

    if negotiated is None:

        return [
            (
                "ESP proposal",
                requested,
                None
            )
        ]

    for field, label in [
        ("encryption", "ESP encryption"),
        ("integrity", "ESP integrity")
    ]:

        if (
            negotiated.get(field)
            != requested.get(field)
        ):

            mismatches.append(
                (
                    label,
                    requested.get(field),
                    negotiated.get(field)
                )
            )

    return mismatches


def validate_negotiation(
    experiment,
    status_a,
    status_b,
    start_output
):

    requested_ike = normalize_requested_ike(
        experiment["ike"]
    )

    requested_esp = normalize_requested_esp(
        experiment["esp"]
    )

    # --------------------------------------------------------
    # Parse actual selected proposals
    # --------------------------------------------------------

    combined_a = (
        start_output
        + "\n"
        + status_a
    )

    combined_b = (
        status_b
    )

    ike_raw = parse_ike_proposal(
        combined_a
    )

    esp_raw = parse_esp_proposal(
        combined_a
    )

    ike_b_raw = parse_ike_proposal(
        combined_b
    )

    esp_b_raw = parse_esp_proposal(
        combined_b
    )

    ike = normalize_ike_negotiated(
        ike_raw
    )

    esp = normalize_esp_negotiated(
        esp_raw
    )

    ike_b = normalize_ike_negotiated(
        ike_b_raw
    )

    esp_b = normalize_esp_negotiated(
        esp_b_raw
    )

    child_a = parse_child_sa_state(
        status_a
    )

    child_b = parse_child_sa_state(
        status_b
    )

    mismatches = []

    # --------------------------------------------------------
    # IKE
    # --------------------------------------------------------

    mismatches.extend(
        validate_ike(
            requested_ike,
            ike
        )
    )

    # --------------------------------------------------------
    # ESP
    # --------------------------------------------------------

    mismatches.extend(
        validate_esp(
            requested_esp,
            esp
        )
    )

    # --------------------------------------------------------
    # Office B
    # --------------------------------------------------------

    if (
        ike
        and ike_b
        and ike != ike_b
    ):

        mismatches.append(
            (
                "Office A/B IKE",
                ike,
                ike_b
            )
        )

    if (
        esp
        and esp_b
        and esp != esp_b
    ):

        mismatches.append(
            (
                "Office A/B ESP",
                esp,
                esp_b
            )
        )

    # --------------------------------------------------------
    # CHILD SA
    # --------------------------------------------------------

    if not child_a["installed"]:

        mismatches.append(
            (
                "Office A CHILD_SA",
                "INSTALLED",
                None
            )
        )

    if not child_b["installed"]:

        mismatches.append(
            (
                "Office B CHILD_SA",
                "INSTALLED",
                None
            )
        )

    if child_a["mode"] != "TUNNEL":

        mismatches.append(
            (
                "Office A mode",
                "TUNNEL",
                child_a["mode"]
            )
        )

    if child_b["mode"] != "TUNNEL":

        mismatches.append(
            (
                "Office B mode",
                "TUNNEL",
                child_b["mode"]
            )
        )

    return {
        "valid":
            len(mismatches) == 0,

        "requested": {
            "ike": requested_ike,
            "esp": requested_esp
        },

        "negotiated": {
            "ike_raw": ike_raw,
            "ike": ike,
            "esp_raw": esp_raw,
            "esp": esp
        },

        "office_b_negotiated": {
            "ike_raw": ike_b_raw,
            "ike": ike_b,
            "esp_raw": esp_b_raw,
            "esp": esp_b
        },

        "child_sa": {
            "office_a": child_a,
            "office_b": child_b
        },

        "mismatches": mismatches
    }


# ============================================================
# PFS REKEY
# ============================================================

def perform_child_rekey(
    host
):
    """
    Rekey the CHILD_SA through the VICI/swanctl interface and
    immediately collect the live SA state.

    strongSwan 6.0.4 does not provide `ipsec rekey`, so using
    `ipsec rekey ...` is invalid on this installation.

    `swanctl --rekey --child office-vpn` triggers the CHILD_SA
    rekey. `swanctl --list-sas` then exposes the negotiated ESP
    proposal, including the PFS group when PFS is negotiated.
    """

    print()
    print(
        "Performing CHILD_SA rekey to expose "
        "ESP PFS negotiation..."
    )

    rekey_output = sudo(
        host,
        f"swanctl --rekey --child {VPN_CONNECTION}",
        timeout=60
    )

    print(
        rekey_output.strip()
    )

    # Give charon time to install the replacement CHILD_SA.
    time.sleep(3)

    sas_output = sudo(
        host,
        "swanctl --list-sas",
        timeout=30
    )

    print()
    print(
        "Live SA state after CHILD_SA rekey:"
    )
    print(
        sas_output.strip()
    )

    return (
        rekey_output
        + "\n"
        + "===== swanctl --list-sas =====\n"
        + sas_output
    )


def create_metadata(
    experiment,
    repetition,
    status_a,
    status_b,
    start_output,
    rekey_output,
    capture_file,
    validation,
    capture_info
):

    requested_ike = normalize_requested_ike(
        experiment["ike"]
    )

    requested_esp = normalize_requested_esp(
        experiment["esp"]
    )

    negotiated_ike = validation[
        "negotiated"
    ]["ike_raw"]

    negotiated_esp = validation[
        "negotiated"
    ]["esp_raw"]

    normalized_ike = validation[
        "negotiated"
    ]["ike"]

    normalized_esp = validation[
        "negotiated"
    ]["esp"]

    configured_pfs = (
        requested_esp["pfs_group"]
        is not None
    )

    negotiated_pfs = None

    # PFS is verified during CHILD_SA rekey. The initial ESP
    # proposal normally ends in NO_EXT_SEQ and therefore does
    # not expose the negotiated PFS group.
    pfs_validation = validation.get(
        "pfs",
        {}
    )

    if pfs_validation.get("negotiated"):
        negotiated_pfs = pfs_validation.get(
            "negotiated_group"
        )
    elif normalized_esp:
        negotiated_pfs = normalized_esp.get(
            "pfs_group"
        )

    metadata = {

        "dataset_schema_version":
            "3.0",

        "experiment_id":
            experiment["id"],

        "repetition":
            repetition,

        "timestamp":
            datetime.now().isoformat(),

        "status":
            "SUCCESS"
            if validation["valid"]
            else "FAILED",

        "ike_version":
            "IKEv2",

        "authentication":
            "PSK",

        "mode":
            "TUNNEL",

        "requested": {

            "ike":
                experiment["ike"],

            "esp":
                experiment["esp"],

            "traffic":
                experiment["traffic"]
        },

        "ike": {

            "configured": {

                "configured_proposal":
                    experiment["ike"],

                "encryption":
                    requested_ike["encryption"],

                "integrity":
                    requested_ike["integrity"],

                "dh":
                    requested_ike["dh"]
            },

            "negotiated":
                negotiated_ike,

            "normalized_negotiated":
                normalized_ike,

            "prf":
                parse_prf(
                    negotiated_ike
                ),

            "dh":
                parse_dh_from_ike(
                    negotiated_ike
                ),

            "spis":
                parse_ike_spis(
                    start_output
                    + "\n"
                    + status_a
                )
        },

        "esp": {

            "configured": {

                "configured_proposal":
                    experiment["esp"],

                "encryption":
                    requested_esp["encryption"],

                "integrity":
                    requested_esp["integrity"],

                "pfs":
                    configured_pfs,

                "pfs_group":
                    requested_esp["pfs_group"]
            },

            "negotiated":
                negotiated_esp,

            "normalized_negotiated":
                normalized_esp,

            "child_sa": {

                "mode":
                    validation[
                        "child_sa"
                    ]["office_a"]["mode"],

                "installed":
                    validation[
                        "child_sa"
                    ]["office_a"]["installed"]
            },

            "pfs": {

                "configured":
                    configured_pfs,

                "configured_group":
                    requested_esp["pfs_group"],

                "negotiated":
                    negotiated_pfs is not None,

                "negotiated_group":
                    negotiated_pfs
            },

            "spis":
                parse_esp_spis(
                    start_output
                    + "\n"
                    + status_a
                )
        },

        "traffic": {

            "type":
                experiment["traffic"]
        },

        "ground_truth": {

            "ike_version":
                "IKEv2",

            "authentication":
                "PSK",

            "mode":
                "TUNNEL",

            "ike": {

                "encryption":
                    requested_ike["encryption"],

                "integrity":
                    requested_ike["integrity"],

                "prf":
                    parse_prf(
                        negotiated_ike
                    ),

                "dh":
                    requested_ike["dh"]
            },

            "esp": {

                "encryption":
                    requested_esp["encryption"],

                "integrity":
                    requested_esp["integrity"]
            },

            "pfs": {

                "configured":
                    configured_pfs,

                "configured_group":
                    requested_esp["pfs_group"],

                "negotiated":
                    negotiated_pfs is not None,

                "negotiated_group":
                    negotiated_pfs
            },

            "traffic_type":
                experiment["traffic"]
        },

        "validation":
            validation,

        "capture": {

            "interface":
                INTERFACE,

            "filter":
                (
                    "udp port 500 or "
                    "udp port 4500 or "
                    "ip proto 50"
                ),

            "file":
                capture_file,

            "tcpdump_pid":
                capture_info["pid"]
                if capture_info
                else None
        },

        "evidence": {

            "ike_up_output":
                start_output,

            "child_rekey_output":
                rekey_output,

            "office_a_statusall":
                status_a,

            "office_b_statusall":
                status_b
        }
    }

    return metadata


def save_metadata(
    metadata,
    path
):

    with open(
        path,
        "w",
        encoding="utf-8"
    ) as f:

        json.dump(
            metadata,
            f,
            indent=2
        )


# ============================================================
# FAILURE METADATA
# ============================================================

def save_failure_metadata(
    experiment,
    repetition,
    reason,
    status_a=None,
    status_b=None,
    validation=None,
    capture_file=None
):

    filename = (
        f"{experiment['id']}_"
        f"rep{repetition:02d}_FAILED.json"
    )

    path = os.path.join(
        METADATA_DIR,
        filename
    )

    metadata = {

        "dataset_schema_version":
            "3.0",

        "experiment_id":
            experiment["id"],

        "repetition":
            repetition,

        "timestamp":
            datetime.now().isoformat(),

        "status":
            "FAILED",

        "reason":
            str(reason),

        "requested": {

            "ike":
                experiment["ike"],

            "esp":
                experiment["esp"],

            "traffic":
                experiment["traffic"]
        },

        "validation":
            validation,

        "capture": {

            "file":
                capture_file
        },

        "evidence": {

            "office_a_statusall":
                status_a,

            "office_b_statusall":
                status_b
        }
    }

    save_metadata(
        metadata,
        path
    )

    print(
        f"Failure metadata saved: {path}"
    )


# ============================================================
# SINGLE EXPERIMENT
# ============================================================

def run_experiment(
    experiment,
    repetition,
    office_a,
    office_b,
    settings
):

    experiment_id = experiment["id"]

    filename = (
        f"{experiment_id}_"
        f"rep{repetition:02d}"
    )

    remote_pcap = (
        f"/tmp/{filename}.pcap"
    )

    local_pcap = os.path.join(
        CAPTURE_DIR,
        f"{filename}.pcap"
    )

    metadata_file = os.path.join(
        METADATA_DIR,
        f"{filename}.json"
    )

    capture_info = None

    status_a = None
    status_b = None
    validation = None

    start_output = ""
    rekey_output = ""

    print()
    print("=" * 70)
    print(
        f"EXPERIMENT: {filename}"
    )
    print("=" * 70)

    print(
        f"IKE     : {experiment['ike']}"
    )

    print(
        f"ESP     : {experiment['esp']}"
    )

    print(
        f"Traffic : {experiment['traffic']}"
    )

    try:

        # ----------------------------------------------------
        # Stop old SAs
        # ----------------------------------------------------

        print(
            "\nStopping any existing VPN..."
        )

        stop_vpn(
            office_a
        )

        stop_vpn(
            office_b
        )

        time.sleep(2)

        # ----------------------------------------------------
        # Configure A
        # ----------------------------------------------------

        print(
            "\nConfiguring Office A..."
        )

        configure_host(
            office_a,
            OFFICE_A_IP,
            OFFICE_B_IP,
            experiment["ike"],
            experiment["esp"]
        )

        # ----------------------------------------------------
        # Configure B
        # ----------------------------------------------------

        print(
            "Configuring Office B..."
        )

        configure_host(
            office_b,
            OFFICE_B_IP,
            OFFICE_A_IP,
            experiment["ike"],
            experiment["esp"]
        )

        # ----------------------------------------------------
        # Verify loaded config
        # ----------------------------------------------------

        verify_loaded_config(
            office_a,
            experiment["ike"],
            experiment["esp"]
        )

        verify_loaded_config(
            office_b,
            experiment["ike"],
            experiment["esp"]
        )

        # ----------------------------------------------------
        # Capture before IKE
        # ----------------------------------------------------

        capture_info = start_capture(
            office_a,
            remote_pcap
        )

        # ----------------------------------------------------
        # Start VPN
        # ----------------------------------------------------

        print(
            "\nStarting IKEv2 negotiation..."
        )

        start_output = start_vpn(
            office_a
        )

        print(
            start_output.strip()
        )

        # ----------------------------------------------------
        # Wait for SA
        # ----------------------------------------------------

        status_a = wait_for_established(
            office_a
        )

        status_b = wait_for_established(
            office_b
        )

        print()
        print(
            "IKEv2 / CHILD_SA established."
        )

        # ----------------------------------------------------
        # Parse initial negotiation
        # ----------------------------------------------------

        combined = (
            start_output
            + "\n"
            + status_a
        )

        negotiated_ike = parse_ike_proposal(
            combined
        )

        negotiated_esp = parse_esp_proposal(
            combined
        )

        print()
        print(
            "Actual negotiated IKE:"
        )

        print(
            negotiated_ike
        )

        print()
        print(
            "Actual negotiated ESP:"
        )

        print(
            negotiated_esp
        )

        print()
        print(
            "Actual negotiated IKE PRF:"
        )

        print(
            parse_prf(
                negotiated_ike
            )
        )

        # ----------------------------------------------------
        # Validate initial negotiation
        # ----------------------------------------------------

        validation = validate_negotiation(
            experiment,
            status_a,
            status_b,
            start_output
        )

        if not validation["valid"]:

            print()
            print(
                "!!! PROPOSAL MISMATCH !!!"
            )

            for (
                parameter,
                requested,
                actual
            ) in validation["mismatches"]:

                print(
                    f"  {parameter}: "
                    f"requested={requested}, "
                    f"actual={actual}"
                )

            raise RuntimeError(
                "Negotiated cryptographic parameters "
                "do not match the experiment."
            )

        print()
        print(
            "Initial negotiation matches "
            "requested IKE/ESP encryption "
            "and integrity."
        )

        # ----------------------------------------------------
        # PFS experiment
        # ----------------------------------------------------

        requested_esp = normalize_requested_esp(
            experiment["esp"]
        )

        if requested_esp["pfs_group"]:

            expected_pfs = normalize_pfs_group(
                requested_esp["pfs_group"]
            )

            rekey_output = perform_child_rekey(
                office_a
            )

            status_a = get_status(
                office_a
            )

            status_b = get_status(
                office_b
            )

            combined_rekey = (
                rekey_output
                + "\n"
                + status_a
                + "\n"
                + status_b
            )

            detected_pfs = normalize_pfs_group(
                parse_pfs_group(combined_rekey)
            )

            print()
            print(
                "Requested CHILD_SA PFS group:"
            )
            print(
                expected_pfs
            )

            print()
            print(
                "Detected CHILD_SA PFS group:"
            )
            print(
                detected_pfs
            )

            if detected_pfs is None:
                raise RuntimeError(
                    "PFS could not be verified: no explicit "
                    "ESP proposal containing a PFS group was "
                    "found in the post-rekey SA evidence."
                )

            if detected_pfs != expected_pfs:
                raise RuntimeError(
                    f"PFS mismatch: requested "
                    f"{expected_pfs}, detected "
                    f"{detected_pfs}"
                )

            # Preserve the verified PFS result for metadata.
            validation["negotiated"]["esp"]["pfs_group"] = (
                detected_pfs.lower()
            )
            validation["pfs"] = {
                "configured": True,
                "requested_group": expected_pfs.lower(),
                "negotiated": True,
                "negotiated_group": detected_pfs.lower()
            }

            print()
            print(
                f"PFS verified successfully: "
                f"{detected_pfs}"
            )

        else:

            print()
            print(
                "NO-PFS experiment."
            )

        # ----------------------------------------------------
        # Generate encrypted traffic
        # ----------------------------------------------------

        generate_traffic(
            experiment,
            office_a,
            office_b,
            settings
        )

        # ----------------------------------------------------
        # More traffic after PFS rekey
        # ----------------------------------------------------

        time.sleep(3)

    finally:

        if capture_info:

            try:

                stop_capture(
                    office_a,
                    capture_info
                )

            except Exception as e:

                print(
                    f"Warning while stopping "
                    f"capture: {e}"
                )

    # --------------------------------------------------------
    # Verify/download
    # --------------------------------------------------------

    verify_pcap(
        office_a,
        remote_pcap
    )

    download_file(
        office_a,
        remote_pcap,
        local_pcap
    )

    remove_remote_pcap(
        office_a,
        remote_pcap
    )

    # --------------------------------------------------------
    # Metadata
    # --------------------------------------------------------

    metadata = create_metadata(
        experiment,
        repetition,
        status_a,
        status_b,
        start_output,
        rekey_output,
        local_pcap,
        validation,
        capture_info
    )

    save_metadata(
        metadata,
        metadata_file
    )

    print()
    print("=" * 70)
    print(
        "EXPERIMENT SUCCESS"
    )
    print("=" * 70)

    print(
        f"PCAP: {local_pcap}"
    )

    print(
        f"JSON: {metadata_file}"
    )

    print("=" * 70)


# ============================================================
# CLEANUP
# ============================================================

def safe_stop_everything(
    office_a,
    office_b
):

    print()
    print(
        "Cleaning up IPsec..."
    )

    if office_a:

        try:

            stop_vpn(
                office_a
            )

        except Exception:
            pass

    if office_b:

        try:

            stop_vpn(
                office_b
            )

        except Exception:
            pass


# ============================================================
# SIGNAL
# ============================================================

def handle_interrupt(
    signum,
    frame
):

    global office_a_global
    global office_b_global

    print()
    print(
        "Factory interrupted by user."
    )

    safe_stop_everything(
        office_a_global,
        office_b_global
    )

    if office_a_global:
        office_a_global.close()

    if office_b_global:
        office_b_global.close()

    sys.exit(130)


# ============================================================
# MAIN
# ============================================================

def main():

    global office_a_global
    global office_b_global

    signal.signal(
        signal.SIGINT,
        handle_interrupt
    )

    print("=" * 70)
    print(
        "                    IPsec PCAP FACTORY"
    )
    print("=" * 70)

    # --------------------------------------------------------
    # Experiment file
    # --------------------------------------------------------

    if not os.path.exists(
        EXPERIMENT_FILE
    ):

        print(
            f"ERROR: {EXPERIMENT_FILE} not found."
        )

        sys.exit(1)

    with open(
        EXPERIMENT_FILE,
        "r",
        encoding="utf-8"
    ) as f:

        config = json.load(f)

    settings = config[
        "settings"
    ]

    experiments = config[
        "experiments"
    ]

    repetitions = int(
        settings.get(
            "repetitions",
            1
        )
    )

    print()
    print(
        f"Loaded {len(experiments)} experiments."
    )

    print(
        f"Repetitions per experiment: "
        f"{repetitions}"
    )

    total = (
        len(experiments)
        * repetitions
    )

    print(
        f"Total captures planned: "
        f"{total}"
    )

    # --------------------------------------------------------
    # Password
    # --------------------------------------------------------

    password_a = getpass.getpass(
        "\nOffice A password (meow2): "
    )

    password_b = getpass.getpass(
        "Office B password (meow3): "
    )

    # --------------------------------------------------------
    # SSH
    # --------------------------------------------------------

    office_a = SSHHost(
        "officeA",
        password_a
    )

    office_b = SSHHost(
        "officeB",
        password_b
    )

    office_a_global = office_a
    office_b_global = office_b

    successful = 0
    failed = 0

    try:

        print(
            "\nConnecting to Office A..."
        )

        office_a.connect()

        print(
            "Connecting to Office B..."
        )

        office_b.connect()

        print()
        print(
            "Connections established."
        )

        # ----------------------------------------------------
        # Matrix
        # ----------------------------------------------------

        for experiment in experiments:

            for repetition in range(
                1,
                repetitions + 1
            ):

                status_a = None
                status_b = None
                validation = None

                try:

                    run_experiment(
                        experiment,
                        repetition,
                        office_a,
                        office_b,
                        settings
                    )

                    successful += 1

                except KeyboardInterrupt:

                    raise

                except Exception as e:

                    failed += 1

                    print()
                    print(
                        "!!! EXPERIMENT FAILED !!!"
                    )

                    print(
                        f"{experiment['id']} "
                        f"rep {repetition}"
                    )

                    print(
                        f"Reason: {e}"
                    )

                    try:

                        status_a = get_status(
                            office_a
                        )

                    except Exception:

                        status_a = None

                    try:

                        status_b = get_status(
                            office_b
                        )

                    except Exception:

                        status_b = None

                    safe_stop_everything(
                        office_a,
                        office_b
                    )

                    try:

                        save_failure_metadata(
                            experiment,
                            repetition,
                            e,
                            status_a,
                            status_b,
                            validation
                        )

                    except Exception as metadata_error:

                        print(
                            "Could not save failure "
                            f"metadata: {metadata_error}"
                        )

                    continue

        # ----------------------------------------------------
        # Summary
        # ----------------------------------------------------

        print()
        print("=" * 70)
        print(
            "                       FACTORY COMPLETE"
        )
        print("=" * 70)

        print(
            f"Successful: {successful}/{total}"
        )

        print(
            f"Failed:     {failed}/{total}"
        )

        print()

        print(
            "PCAP directory:"
        )

        print(
            CAPTURE_DIR
        )

        print()

        print(
            "Metadata directory:"
        )

        print(
            METADATA_DIR
        )

    except KeyboardInterrupt:

        print()
        print(
            "Factory interrupted by user."
        )

        safe_stop_everything(
            office_a,
            office_b
        )

    except Exception as e:

        print()
        print(
            "FATAL FACTORY ERROR:"
        )

        print(
            str(e)
        )

        traceback.print_exc()

    finally:

        safe_stop_everything(
            office_a,
            office_b
        )

        try:
            office_a.close()
        except Exception:
            pass

        try:
            office_b.close()
        except Exception:
            pass

        office_a_global = None
        office_b_global = None


# ============================================================
# ENTRY
# ============================================================

if __name__ == "__main__":
    main()