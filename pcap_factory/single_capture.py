import getpass
import json
import os
import re
import time
from datetime import datetime

import paramiko


OFFICE_A = {
    "host": "192.168.56.106",
    "user": "meow2",
}

OFFICE_B = {
    "host": "192.168.56.107",
    "user": "meow3",
}

CONNECTION_NAME = "office-vpn"

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

CAPTURE_DIR = os.path.join(BASE_DIR, "captures")
METADATA_DIR = os.path.join(BASE_DIR, "metadata")

os.makedirs(CAPTURE_DIR, exist_ok=True)
os.makedirs(METADATA_DIR, exist_ok=True)


def connect(host_info, password):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    client.connect(
        hostname=host_info["host"],
        username=host_info["user"],
        password=password,
        look_for_keys=False,
        allow_agent=False,
        timeout=10,
    )

    return client


def run_command(client, command, password=None):
    stdin, stdout, stderr = client.exec_command(command)

    if password is not None:
        stdin.write(password + "\n")
        stdin.flush()

    output = stdout.read().decode(errors="replace")
    error = stderr.read().decode(errors="replace")

    return output, error


def get_status(client, password):
    output, error = run_command(
        client,
        "sudo -S -p '' ipsec statusall",
        password,
    )

    return output


def wait_for_established(client, password, timeout=30):
    print("Waiting for IPsec SA to become ESTABLISHED...")

    start = time.time()

    while time.time() - start < timeout:

        status = get_status(client, password)

        if "ESTABLISHED" in status:
            print("IPsec SA is ESTABLISHED.")
            return True

        time.sleep(1)

    print("ERROR: IPsec SA did not become ESTABLISHED.")
    return False


def main():

    print("==============================================")
    print("      IPsec PCAP Factory - Full Capture")
    print("==============================================")

    experiment_id = "exp002_full_ike_esp"

    password_a = getpass.getpass(
        "\nOffice A password (meow2): "
    )

    password_b = getpass.getpass(
        "Office B password (meow3): "
    )

    print("\nConnecting to Office A...")
    client_a = connect(OFFICE_A, password_a)

    print("Connecting to Office B...")
    client_b = connect(OFFICE_B, password_b)

    remote_pcap = f"/tmp/{experiment_id}.pcap"

    local_pcap = os.path.join(
        CAPTURE_DIR,
        f"{experiment_id}.pcap"
    )

    metadata_file = os.path.join(
        METADATA_DIR,
        f"{experiment_id}.json"
    )

    # ---------------------------------------------------------
    # 1. Capture current state
    # ---------------------------------------------------------

    print("\nCapturing current IPsec state...")

    status_before_a = get_status(
        client_a,
        password_a
    )

    status_before_b = get_status(
        client_b,
        password_b
    )

    # ---------------------------------------------------------
    # 2. Bring VPN down
    # ---------------------------------------------------------

    print("\nBringing IPsec connection DOWN...")

    run_command(
        client_a,
        f"sudo -S -p '' ipsec down {CONNECTION_NAME}",
        password_a,
    )

    time.sleep(2)

    # ---------------------------------------------------------
    # 3. Remove old PCAP
    # ---------------------------------------------------------

    run_command(
        client_a,
        f"sudo -S -p '' rm -f {remote_pcap}",
        password_a,
    )

    # ---------------------------------------------------------
    # 4. Start tcpdump
    # ---------------------------------------------------------

    print("\nStarting tcpdump BEFORE IKE negotiation...")

    capture_command = (
        f"sudo -S -p '' tcpdump "
        f"-i enp0s8 "
        f"-U "
        f"-w {remote_pcap} "
        f"'udp port 500 or udp port 4500 or ip proto 50'"
    )

    stdin, stdout, stderr = client_a.exec_command(
        capture_command
    )

    stdin.write(password_a + "\n")
    stdin.flush()

    time.sleep(3)

    print("tcpdump is running.")

    # ---------------------------------------------------------
    # 5. Bring VPN UP
    # ---------------------------------------------------------

    print("\nBringing IPsec connection UP...")

    up_output, up_error = run_command(
        client_a,
        f"sudo -S -p '' ipsec up {CONNECTION_NAME}",
        password_a,
    )

    print(up_output)

    if up_error:
        print(up_error)

    # ---------------------------------------------------------
    # 6. Wait for SA
    # ---------------------------------------------------------

    established = wait_for_established(
        client_a,
        password_a,
        timeout=30,
    )

    if not established:
        print("\nIPsec failed to establish.")

        run_command(
            client_a,
            "sudo -S -p '' pkill tcpdump",
            password_a,
        )

        client_a.close()
        client_b.close()

        return

    # ---------------------------------------------------------
    # 7. Generate traffic
    # ---------------------------------------------------------

    print("\nGenerating ICMP traffic...")

    traffic_output, traffic_error = run_command(
        client_a,
        "ping -c 30 192.168.56.107",
    )

    print(traffic_output)

    if traffic_error:
        print(traffic_error)

    # Give ESP packets time to flush.
    time.sleep(3)

    # ---------------------------------------------------------
    # 8. Stop tcpdump
    # ---------------------------------------------------------

    print("\nStopping tcpdump...")

    run_command(
        client_a,
        "sudo -S -p '' pkill tcpdump",
        password_a,
    )

    time.sleep(2)

    # ---------------------------------------------------------
    # 9. Get final IPsec state
    # ---------------------------------------------------------

    print("\nCollecting final IPsec state...")

    status_after_a = get_status(
        client_a,
        password_a
    )

    status_after_b = get_status(
        client_b,
        password_b
    )

    # ---------------------------------------------------------
    # 10. Download PCAP
    # ---------------------------------------------------------

    print("\nDownloading PCAP...")

    sftp = client_a.open_sftp()

    sftp.get(
        remote_pcap,
        local_pcap,
    )

    sftp.close()

    print(f"PCAP saved:")
    print(local_pcap)

    # ---------------------------------------------------------
    # 11. Save metadata
    # ---------------------------------------------------------

    metadata = {
        "experiment_id": experiment_id,

        "timestamp": datetime.now().isoformat(),

        "status": "SUCCESS",

        "topology": {
            "office_a": "192.168.56.106",
            "office_b": "192.168.56.107",
            "interface": "enp0s8"
        },

        "vpn": {
            "connection": CONNECTION_NAME,
            "ike_version": "IKEv2",
            "authentication": "PSK",
            "mode": "tunnel"
        },

        "configuration": {
            "ike_encryption": "AES-256-CBC",
            "ike_integrity": "SHA-384",
            "ike_prf": "HMAC-SHA2-384",
            "ike_dh": "ECP-256",

            "esp_encryption": "AES-256-CBC",
            "esp_integrity": "SHA-384",

            "pfs": True,
            "pfs_group": "ECP-256"
        },

        "traffic": {
            "type": "ICMP",
            "command": "ping -c 30 192.168.56.107"
        },

        "capture": {
            "interface": "enp0s8",
            "filter": (
                "udp port 500 or "
                "udp port 4500 or "
                "ip proto 50"
            )
        },

        "ipsec_status_before": {
            "office_a": status_before_a,
            "office_b": status_before_b
        },

        "ipsec_status_after": {
            "office_a": status_after_a,
            "office_b": status_after_b
        }
    }

    with open(
        metadata_file,
        "w",
        encoding="utf-8"
    ) as f:

        json.dump(
            metadata,
            f,
            indent=2
        )

    print(f"Metadata saved:")
    print(metadata_file)

    client_a.close()
    client_b.close()

    print("\n==============================================")
    print("FULL IKE + ESP EXPERIMENT COMPLETE")
    print("==============================================")


if __name__ == "__main__":
    main()