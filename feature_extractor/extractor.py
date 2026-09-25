import json
import os
import sys
from collections import Counter

from scapy.all import rdpcap, IP, UDP


# ============================================================
# IPsec PCAP FEATURE EXTRACTOR
# ============================================================
#
# Purpose:
#   Extract observable network/packet features from an IPsec PCAP.
#
# Important:
#   Scapy versions differ in how IKE/ISAKMP classes are exposed.
#   Therefore this extractor does NOT import ISAKMP/IKEv2 directly.
#
#   We also intentionally DO NOT recursively walk the Scapy payload
#   chain. Some Scapy payload structures can make such traversal
#   extremely slow or problematic.
#
#   IKE is identified primarily through UDP ports 500/4500 and,
#   when available, the decoded Scapy class name "ISAKMP".
#
# IKEv2 exchange types:
#   34 = IKE_SA_INIT
#   35 = IKE_AUTH
#   36 = CREATE_CHILD_SA
#   37 = INFORMATIONAL
#
# Cryptographic ground truth comes separately from the PCAP factory
# metadata. This extractor reports observable PCAP features.
# ============================================================


EXCHANGE_TYPES = {
    34: "IKE_SA_INIT",
    35: "IKE_AUTH",
    36: "CREATE_CHILD_SA",
    37: "INFORMATIONAL",
}


# ============================================================
# SAFE PACKET HELPERS
# ============================================================

def safe_len(packet):
    """Return packet length safely."""
    try:
        return len(packet)
    except Exception:
        return 0


def get_packet_timestamp(packet):
    """Return packet timestamp as float when available."""
    try:
        return float(packet.time)
    except Exception:
        return None


def get_class_name(layer):
    """Return a Scapy layer's class name safely."""
    try:
        return layer.__class__.__name__.upper()
    except Exception:
        return ""


# ============================================================
# IKE DETECTION
# ============================================================

def get_ike_layer(packet):
    """
    Return the top-level decoded ISAKMP layer without recursively
    walking the payload chain.

    Scapy currently decodes the IKE packets in this dataset as:

        UDP / ISAKMP / ISAKMP_payload / ...

    We only inspect the first decoded payload immediately after UDP.

    This avoids the previous infinite/very-slow payload traversal.
    """

    if UDP not in packet:
        return None

    udp = packet[UDP]

    # The payload directly after UDP should be ISAKMP for IKE.
    payload = getattr(udp, "payload", None)

    if payload is None:
        return None

    if get_class_name(payload) == "ISAKMP":
        return payload

    return None


def is_ike_port_packet(packet):
    """
    Identify IKE transport packets using standard IKE ports.

    IKE:
        UDP 500
        UDP 4500 (NAT-T)
    """

    if UDP not in packet:
        return False

    sport = int(packet[UDP].sport)
    dport = int(packet[UDP].dport)

    return (
        sport in (500, 4500)
        or dport in (500, 4500)
    )


def is_esp_packet(packet):
    """
    ESP = IP protocol 50.
    """

    return (
        IP in packet
        and getattr(packet[IP], "proto", None) == 50
    )


# ============================================================
# IKE CLASSIFICATION
# ============================================================

def classify_ike_packet(ike):
    """
    Classify an already-detected ISAKMP/IKE layer.

    IKEv2:
        version = 0x20

    Exchange types:
        34 = IKE_SA_INIT
        35 = IKE_AUTH
        36 = CREATE_CHILD_SA
        37 = INFORMATIONAL
    """

    if ike is None:
        return None

    version = getattr(ike, "version", None)
    exchange_type = getattr(ike, "exch_type", None)

    # IKEv2 version byte is 0x20.
    if version != 0x20:
        return "IKE_UNKNOWN"

    return EXCHANGE_TYPES.get(
        exchange_type,
        "IKE_UNKNOWN",
    )


def classify_ike_by_ports(packet):
    """
    Fallback classification for an IKE transport packet when Scapy
    does not expose the ISAKMP layer.

    We know it is an IKE transport candidate from UDP 500/4500,
    but we cannot safely determine the exchange type without
    successfully decoding the IKE header.

    Therefore return IKE_UNKNOWN rather than inventing a type.
    """

    if is_ike_port_packet(packet):
        return "IKE_UNKNOWN"

    return None


# ============================================================
# FEATURE EXTRACTION
# ============================================================

def extract_features(pcap_path):

    print("Reading PCAP...")

    packets = rdpcap(pcap_path)

    if len(packets) == 0:
        raise RuntimeError(
            "PCAP contains no packets."
        )

    packet_count = len(packets)

    # --------------------------------------------------------
    # Packet sizes
    # --------------------------------------------------------

    packet_sizes = [
        safe_len(packet)
        for packet in packets
    ]

    total_bytes = sum(packet_sizes)

    avg_packet_size = (
        total_bytes / packet_count
        if packet_count
        else 0
    )

    min_packet_size = (
        min(packet_sizes)
        if packet_sizes
        else 0
    )

    max_packet_size = (
        max(packet_sizes)
        if packet_sizes
        else 0
    )

    # --------------------------------------------------------
    # Capture duration
    # --------------------------------------------------------

    timestamps = [
        get_packet_timestamp(packet)
        for packet in packets
    ]

    timestamps = [
        timestamp
        for timestamp in timestamps
        if timestamp is not None
    ]

    if len(timestamps) >= 2:
        capture_duration = (
            max(timestamps)
            - min(timestamps)
        )
    else:
        capture_duration = 0.0

    # --------------------------------------------------------
    # Counters
    # --------------------------------------------------------

    udp_packet_count = 0
    tcp_packet_count = 0
    icmp_packet_count = 0

    udp_500_count = 0
    udp_4500_count = 0

    ike_packet_count = 0
    esp_packet_count = 0

    ike_sa_init_count = 0
    ike_auth_count = 0
    create_child_sa_count = 0
    informational_count = 0
    ike_unknown_count = 0

    ike_request_count = 0
    ike_response_count = 0

    ike_bytes = 0
    esp_bytes = 0

    unique_src_ips = set()
    unique_dst_ips = set()
    src_dst_pairs = set()

    exchange_distribution = Counter()

    # --------------------------------------------------------
    # Process packets
    # --------------------------------------------------------

    for packet in packets:

        packet_size = safe_len(packet)

        # ----------------------------------------------------
        # IP
        # ----------------------------------------------------

        if IP in packet:

            src = packet[IP].src
            dst = packet[IP].dst

            unique_src_ips.add(src)
            unique_dst_ips.add(dst)

            src_dst_pairs.add(
                (src, dst)
            )

        # ----------------------------------------------------
        # UDP
        # ----------------------------------------------------

        if UDP in packet:

            udp_packet_count += 1

            sport = int(packet[UDP].sport)
            dport = int(packet[UDP].dport)

            if sport == 500 or dport == 500:
                udp_500_count += 1

            if sport == 4500 or dport == 4500:
                udp_4500_count += 1

        # ----------------------------------------------------
        # TCP
        # ----------------------------------------------------

        if (
            IP in packet
            and packet[IP].proto == 6
        ):
            tcp_packet_count += 1

        # ----------------------------------------------------
        # ICMP
        # ----------------------------------------------------

        if (
            IP in packet
            and packet[IP].proto == 1
        ):
            icmp_packet_count += 1

        # ----------------------------------------------------
        # ESP
        # ----------------------------------------------------

        if is_esp_packet(packet):

            esp_packet_count += 1
            esp_bytes += packet_size

        # ----------------------------------------------------
        # IKE / ISAKMP
        # ----------------------------------------------------

        ike = get_ike_layer(packet)

        if ike is not None:

            ike_packet_count += 1
            ike_bytes += packet_size

            exchange = classify_ike_packet(
                ike
            )

            if exchange is None:
                exchange = "IKE_UNKNOWN"

            exchange_distribution[
                exchange
            ] += 1

            if exchange == "IKE_SA_INIT":

                ike_sa_init_count += 1

            elif exchange == "IKE_AUTH":

                ike_auth_count += 1

            elif exchange == "CREATE_CHILD_SA":

                create_child_sa_count += 1

            elif exchange == "INFORMATIONAL":

                informational_count += 1

            else:

                ike_unknown_count += 1

            # ------------------------------------------------
            # IKEv2 request / response detection
            # ------------------------------------------------
            #
            # IKEv2 header:
            #   bytes 0-7   = Initiator SPI
            #   bytes 8-15  = Responder SPI
            #   byte 16     = Next Payload
            #   byte 17     = Version
            #   byte 18     = Exchange Type
            #   byte 19     = Flags
            #
            # Response flag = 0x20
            # ------------------------------------------------

            try:

                raw = bytes(ike)

                if len(raw) >= 20:

                    flags_byte = raw[19]

                    if flags_byte & 0x20:
                        ike_response_count += 1
                    else:
                        ike_request_count += 1

            except Exception:

                pass

        else:

            # ------------------------------------------------
            # Fallback IKE transport detection
            #
            # This is important because some Scapy versions may
            # decode UDP/500 or UDP/4500 without exposing the
            # payload as ISAKMP.
            # ------------------------------------------------

            fallback_exchange = classify_ike_by_ports(
                packet
            )

            if fallback_exchange is not None:

                # Do not double-count ESP.
                #
                # UDP 500/4500 is IKE transport.
                ike_packet_count += 1
                ike_bytes += packet_size

                exchange_distribution[
                    fallback_exchange
                ] += 1

                ike_unknown_count += 1

    # --------------------------------------------------------
    # Derived statistics
    # --------------------------------------------------------

    ike_avg_packet_size = (
        ike_bytes / ike_packet_count
        if ike_packet_count
        else 0
    )

    esp_avg_packet_size = (
        esp_bytes / esp_packet_count
        if esp_packet_count
        else 0
    )

    # --------------------------------------------------------
    # Feature object
    # --------------------------------------------------------

    features = {

        "packet_count":
            packet_count,

        "total_bytes":
            total_bytes,

        "avg_packet_size":
            round(
                avg_packet_size,
                3,
            ),

        "min_packet_size":
            min_packet_size,

        "max_packet_size":
            max_packet_size,

        "capture_duration_seconds":
            round(
                capture_duration,
                6,
            ),

        "udp_packet_count":
            udp_packet_count,

        "tcp_packet_count":
            tcp_packet_count,

        "icmp_packet_count":
            icmp_packet_count,

        "udp_500_count":
            udp_500_count,

        "udp_4500_count":
            udp_4500_count,

        "ike_packet_count":
            ike_packet_count,

        "esp_packet_count":
            esp_packet_count,

        "ike_sa_init_count":
            ike_sa_init_count,

        "ike_auth_count":
            ike_auth_count,

        "create_child_sa_count":
            create_child_sa_count,

        "informational_count":
            informational_count,

        "ike_unknown_count":
            ike_unknown_count,

        "ike_request_count":
            ike_request_count,

        "ike_response_count":
            ike_response_count,

        "ike_bytes":
            ike_bytes,

        "ike_avg_packet_size":
            round(
                ike_avg_packet_size,
                3,
            ),

        "esp_bytes":
            esp_bytes,

        "esp_avg_packet_size":
            round(
                esp_avg_packet_size,
                3,
            ),

        "unique_src_ips":
            len(unique_src_ips),

        "unique_dst_ips":
            len(unique_dst_ips),

        "src_dst_pairs":
            len(src_dst_pairs),

        "ike_version_detected":
            (
                "IKEv2"
                if ike_packet_count > 0
                else None
            ),

        "ike_exchange_distribution":
            dict(
                exchange_distribution
            ),
    }

    return features


# ============================================================
# MAIN
# ============================================================

def main():

    print("=" * 70)
    print("IPsec PCAP FEATURE EXTRACTOR")
    print("=" * 70)

    # --------------------------------------------------------
    # Arguments
    # --------------------------------------------------------

    if len(sys.argv) != 2:

        print()
        print("Usage:")
        print(
            r'python extractor.py "..\pcap_factory\captures\file.pcap"'
        )

        sys.exit(1)

    pcap_path = sys.argv[1]

    print()
    print(
        f"PCAP: {pcap_path}"
    )

    print()

    # --------------------------------------------------------
    # Check PCAP
    # --------------------------------------------------------

    absolute_path = os.path.abspath(
        pcap_path
    )

    if not os.path.isfile(
        absolute_path
    ):

        print(
            "ERROR: PCAP file does not exist."
        )

        print(
            f"Absolute path: {absolute_path}"
        )

        sys.exit(1)

    print("PCAP exists.")

    print(
        f"Absolute path: {absolute_path}"
    )

    # --------------------------------------------------------
    # Extract
    # --------------------------------------------------------

    try:

        features = extract_features(
            absolute_path
        )

    except KeyboardInterrupt:

        print()
        print(
            "Extraction interrupted by user."
        )

        sys.exit(1)

    except Exception as error:

        print()
        print(
            "ERROR while reading PCAP:"
        )

        print(
            f"{type(error).__name__}: {error}"
        )

        sys.exit(1)

    # --------------------------------------------------------
    # Print features
    # --------------------------------------------------------

    print()
    print("Extracted features:")
    print("-" * 70)

    for key, value in features.items():

        if key == "ike_exchange_distribution":
            continue

        print(
            f"{key:<28}: {value}"
        )

    print()

    print("IKE exchange distribution:")
    print("-" * 70)

    distribution = features[
        "ike_exchange_distribution"
    ]

    if distribution:

        for exchange, count in sorted(
            distribution.items()
        ):

            print(
                f"{exchange:<24}: {count}"
            )

    else:

        print(
            "No IKE packets detected."
        )

    # --------------------------------------------------------
    # Output directory
    # --------------------------------------------------------

    script_dir = os.path.dirname(
        os.path.abspath(__file__)
    )

    output_dir = os.path.join(
        script_dir,
        "output",
    )

    os.makedirs(
        output_dir,
        exist_ok=True,
    )

    base_name = os.path.splitext(
        os.path.basename(
            absolute_path
        )
    )[0]

    output_file = os.path.join(
        output_dir,
        f"{base_name}_features.json",
    )

    # --------------------------------------------------------
    # Save
    # --------------------------------------------------------

    output_data = {

        "schema_version":
            "1.1",

        "source_pcap":
            absolute_path,

        "features":
            features,
    }

    with open(
        output_file,
        "w",
        encoding="utf-8",
    ) as file:

        json.dump(
            output_data,
            file,
            indent=2,
        )

    # --------------------------------------------------------
    # Finished
    # --------------------------------------------------------

    print()
    print("-" * 70)

    print(
        "Feature file created:"
    )

    print(
        output_file
    )

    print()

    print(
        "Extraction completed successfully."
    )


if __name__ == "__main__":
    main()