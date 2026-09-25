
import json
import csv
import re
from pathlib import Path


# ============================================================
# IPsec ML DATASET BUILDER
# ============================================================
#
# Purpose:
#   Combine extracted PCAP features with ground-truth labels
#   obtained from the PCAP filename.
#
# Example filename:
#
#   AES128_SHA256_DH14_NOPFS_ICMP_rep01.pcap
#
# Labels:
#   encryption = AES128
#   hash       = SHA256
#   dh_group   = DH14
#   pfs_group  = NOPFS
#   traffic    = ICMP
#   repetition = 01
#
# Input:
#   *_features.json
#
# Output:
#   dataset.csv
#
# ============================================================


SCRIPT_DIR = Path(__file__).resolve().parent

OUTPUT_DIR = SCRIPT_DIR / "output"

DATASET_FILE = SCRIPT_DIR / "dataset.csv"


# ============================================================
# FILENAME LABEL PARSER
# ============================================================

def parse_labels(source_pcap):
    """
    Extract ground-truth labels from the original PCAP filename.

    Expected format:

        AES128_SHA256_DH14_NOPFS_ICMP_rep01.pcap

    """

    filename = Path(source_pcap).name

    pattern = re.compile(
        r"^(?P<encryption>AES\d+)_"
        r"(?P<hash>SHA\d+)_"
        r"(?P<dh_group>DH\d+)_"
        r"(?P<pfs_group>PFS\d+|NOPFS)_"
        r"(?P<traffic>[A-Za-z0-9]+)_"
        r"rep(?P<repetition>\d+)"
        r"\.pcap$",
        re.IGNORECASE
    )

    match = pattern.match(filename)

    if not match:
        raise ValueError(
            f"Could not parse labels from PCAP filename:\n"
            f"  {filename}\n\n"
            f"Expected format:\n"
            f"  AES128_SHA256_DH14_NOPFS_ICMP_rep01.pcap"
        )

    labels = match.groupdict()

    # Normalize labels
    labels["encryption"] = labels["encryption"].upper()
    labels["hash"] = labels["hash"].upper()
    labels["dh_group"] = labels["dh_group"].upper()
    labels["pfs_group"] = labels["pfs_group"].upper()
    labels["traffic"] = labels["traffic"].upper()
    labels["repetition"] = int(labels["repetition"])

    return labels


# ============================================================
# LOAD ONE FEATURE FILE
# ============================================================

def load_feature_file(json_path):

    with open(json_path, "r", encoding="utf-8") as file:
        data = json.load(file)

    if "features" not in data:
        raise ValueError(
            f"Missing 'features' object in:\n{json_path}"
        )

    if "source_pcap" not in data:
        raise ValueError(
            f"Missing 'source_pcap' in:\n{json_path}"
        )

    return data


# ============================================================
# MAIN DATASET BUILDER
# ============================================================

def main():

    print("=" * 80)
    print("IPsec ML DATASET BUILDER")
    print("=" * 80)

    print()
    print(f"Feature directory : {OUTPUT_DIR}")
    print(f"Dataset output    : {DATASET_FILE}")
    print()

    # --------------------------------------------------------
    # Find feature JSON files
    # --------------------------------------------------------

    json_files = sorted(
        OUTPUT_DIR.glob("*_features.json")
    )

    print(
        f"Feature files found: {len(json_files)}"
    )

    if not json_files:
        print()
        print("ERROR: No *_features.json files found.")
        print()
        print(
            "Run your feature extractor first."
        )
        return

    print()
    print("-" * 80)

    rows = []

    skipped = 0

    # --------------------------------------------------------
    # Process every JSON file
    # --------------------------------------------------------

    for index, json_path in enumerate(
        json_files,
        start=1
    ):

        print(
            f"[{index}/{len(json_files)}] "
            f"{json_path.name}"
        )

        try:

            data = load_feature_file(
                json_path
            )

            features = data["features"]

            source_pcap = data["source_pcap"]

            labels = parse_labels(
                source_pcap
            )

            # ------------------------------------------------
            # Create one flat ML row
            # ------------------------------------------------

            row = {}

            # Metadata
            row["source_pcap"] = Path(
                source_pcap
            ).name

            row["repetition"] = labels[
                "repetition"
            ]

            row["traffic"] = labels[
                "traffic"
            ]

            # ------------------------------------------------
            # Observable features
            # ------------------------------------------------

            for key, value in features.items():

                # Nested exchange distribution is not directly
                # stored as a CSV cell.
                #
                # We already have the individual counts:
                #
                # ike_sa_init_count
                # ike_auth_count
                # create_child_sa_count
                # informational_count
                # ike_unknown_count

                if key == "ike_exchange_distribution":
                    continue

                # Keep the detected protocol as a feature.
                if key == "ike_version_detected":
                    row["ike_version_detected"] = (
                        value
                        if value is not None
                        else "UNKNOWN"
                    )
                    continue

                row[key] = value

            # ------------------------------------------------
            # Ground-truth labels
            # ------------------------------------------------

            row["encryption"] = labels[
                "encryption"
            ]

            row["hash"] = labels[
                "hash"
            ]

            row["dh_group"] = labels[
                "dh_group"
            ]

            row["pfs_group"] = labels[
                "pfs_group"
            ]

            rows.append(row)

            print(
                "    OK"
            )

        except Exception as error:

            skipped += 1

            print(
                f"    SKIPPED: {error}"
            )

    # --------------------------------------------------------
    # Nothing successfully processed
    # --------------------------------------------------------

    if not rows:

        print()
        print(
            "ERROR: No valid rows were created."
        )

        return

    # --------------------------------------------------------
    # Determine CSV columns
    # --------------------------------------------------------

    columns = [
        "source_pcap",
        "repetition",
        "traffic",

        # Observable features
        "packet_count",
        "total_bytes",
        "avg_packet_size",
        "min_packet_size",
        "max_packet_size",
        "capture_duration_seconds",

        "udp_packet_count",
        "tcp_packet_count",
        "icmp_packet_count",

        "udp_500_count",
        "udp_4500_count",

        "ike_packet_count",
        "esp_packet_count",

        "ike_sa_init_count",
        "ike_auth_count",
        "create_child_sa_count",
        "informational_count",
        "ike_unknown_count",

        "ike_request_count",
        "ike_response_count",

        "ike_bytes",
        "ike_avg_packet_size",

        "esp_bytes",
        "esp_avg_packet_size",

        "unique_src_ips",
        "unique_dst_ips",
        "src_dst_pairs",

        "ike_version_detected",

        # Ground-truth labels
        "encryption",
        "hash",
        "dh_group",
        "pfs_group",
    ]

    # --------------------------------------------------------
    # Write CSV
    # --------------------------------------------------------

    with open(
        DATASET_FILE,
        "w",
        newline="",
        encoding="utf-8"
    ) as file:

        writer = csv.DictWriter(
            file,
            fieldnames=columns
        )

        writer.writeheader()

        for row in rows:

            writer.writerow(
                {
                    column: row.get(
                        column,
                        ""
                    )
                    for column in columns
                }
            )

    # ========================================================
    # SUMMARY
    # ========================================================

    print()
    print("=" * 80)
    print("DATASET CREATED")
    print("=" * 80)

    print()
    print(f"Rows created : {len(rows)}")
    print(f"Skipped      : {skipped}")
    print(f"CSV file     : {DATASET_FILE}")

    # --------------------------------------------------------
    # Label distributions
    # --------------------------------------------------------

    def show_distribution(
        label_name
    ):

        counts = {}

        for row in rows:

            value = row[label_name]

            counts[value] = (
                counts.get(value, 0) + 1
            )

        print()
        print(f"{label_name}:")

        for value, count in sorted(
            counts.items()
        ):

            print(
                f"    {value:<15} {count}"
            )

    print()

    show_distribution(
        "encryption"
    )

    show_distribution(
        "hash"
    )

    show_distribution(
        "dh_group"
    )

    show_distribution(
        "pfs_group"
    )

    show_distribution(
        "traffic"
    )

    # --------------------------------------------------------
    # Final message
    # --------------------------------------------------------

    print()
    print("-" * 80)

    if skipped == 0:

        print(
            "All feature files processed successfully."
        )

    else:

        print(
            f"WARNING: {skipped} file(s) were skipped."
        )

    print()
    print(
        "Next step: inspect dataset.csv before training ML."
    )

    print("=" * 80)


if __name__ == "__main__":
    main()
