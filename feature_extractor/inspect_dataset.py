
import pandas as pd
from pathlib import Path


# ============================================================
# IPsec DATASET INSPECTOR
# ============================================================

SCRIPT_DIR = Path(__file__).resolve().parent
DATASET_FILE = SCRIPT_DIR / "dataset.csv"


def show_distribution(df, column):

    print()
    print("=" * 70)
    print(f"{column.upper()} DISTRIBUTION")
    print("=" * 70)

    counts = df[column].value_counts()

    for value, count in counts.items():

        percentage = (count / len(df)) * 100

        print(
            f"{str(value):<15} "
            f"{count:>4} samples "
            f"({percentage:>6.2f}%)"
        )


def main():

    print("=" * 70)
    print("IPsec DATASET INSPECTION")
    print("=" * 70)

    if not DATASET_FILE.exists():

        print()
        print("ERROR: dataset.csv not found.")
        print(DATASET_FILE)
        return

    df = pd.read_csv(DATASET_FILE)

    print()
    print(f"Dataset: {DATASET_FILE}")
    print(f"Rows   : {len(df)}")
    print(f"Columns: {len(df.columns)}")

    # --------------------------------------------------------
    # Basic structure
    # --------------------------------------------------------

    print()
    print("=" * 70)
    print("COLUMNS")
    print("=" * 70)

    for column in df.columns:
        print(f"  {column}")

    # --------------------------------------------------------
    # Missing values
    # --------------------------------------------------------

    print()
    print("=" * 70)
    print("MISSING VALUES")
    print("=" * 70)

    missing = df.isnull().sum()

    missing_found = False

    for column, count in missing.items():

        if count > 0:

            missing_found = True

            print(
                f"  {column:<30} {count}"
            )

    if not missing_found:
        print("  No missing values found.")

    # --------------------------------------------------------
    # Duplicate rows
    # --------------------------------------------------------

    print()
    print("=" * 70)
    print("DUPLICATES")
    print("=" * 70)

    duplicate_count = df.duplicated().sum()

    print(
        f"Duplicate complete rows: {duplicate_count}"
    )

    # --------------------------------------------------------
    # Label distributions
    # --------------------------------------------------------

    for column in [
        "encryption",
        "hash",
        "dh_group",
        "pfs_group",
        "traffic",
    ]:

        show_distribution(
            df,
            column
        )

    # --------------------------------------------------------
    # EXACT CONFIGURATION DISTRIBUTION
    # --------------------------------------------------------

    print()
    print("=" * 70)
    print("EXACT CRYPTO CONFIGURATION DISTRIBUTION")
    print("=" * 70)

    config_counts = (
        df[
            [
                "encryption",
                "hash",
                "dh_group",
                "pfs_group",
            ]
        ]
        .value_counts()
        .sort_index()
    )

    for config, count in config_counts.items():

        encryption, hash_alg, dh, pfs = config

        print(
            f"{encryption:<8} "
            f"{hash_alg:<8} "
            f"{dh:<5} "
            f"{pfs:<7} "
            f"-> {count} samples"
        )

    # --------------------------------------------------------
    # CONFIGURATION + TRAFFIC
    # --------------------------------------------------------

    print()
    print("=" * 70)
    print("CONFIGURATION + TRAFFIC")
    print("=" * 70)

    combo_counts = (
        df[
            [
                "encryption",
                "hash",
                "dh_group",
                "pfs_group",
                "traffic",
            ]
        ]
        .value_counts()
        .sort_index()
    )

    for combo, count in combo_counts.items():

        encryption, hash_alg, dh, pfs, traffic = combo

        print(
            f"{encryption:<8} "
            f"{hash_alg:<8} "
            f"{dh:<5} "
            f"{pfs:<7} "
            f"{traffic:<5} "
            f"-> {count}"
        )

    # --------------------------------------------------------
    # Repetition distribution
    # --------------------------------------------------------

    print()
    print("=" * 70)
    print("REPETITIONS PER EXACT CONFIGURATION")
    print("=" * 70)

    grouped = (
        df.groupby(
            [
                "encryption",
                "hash",
                "dh_group",
                "pfs_group",
            ]
        )["repetition"]
        .agg(
            [
                "count",
                "min",
                "max",
            ]
        )
        .sort_index()
    )

    print(grouped.to_string())

    # --------------------------------------------------------
    # Numeric feature statistics
    # --------------------------------------------------------

    numeric_columns = [
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
    ]

    print()
    print("=" * 70)
    print("NUMERIC FEATURE STATISTICS")
    print("=" * 70)

    print(
        df[numeric_columns]
        .describe()
        .round(3)
        .to_string()
    )

    # --------------------------------------------------------
    # Feature variation
    # --------------------------------------------------------

    print()
    print("=" * 70)
    print("FEATURE VARIATION")
    print("=" * 70)

    print(
        "Features with only ONE unique value:"
    )

    constant_features = []

    for column in numeric_columns:

        unique_count = df[column].nunique()

        if unique_count <= 1:

            constant_features.append(
                column
            )

            print(
                f"  {column}"
            )

    if not constant_features:

        print(
            "  None. All numeric features vary."
        )

    # --------------------------------------------------------
    # Feature correlation with labels
    # --------------------------------------------------------

    print()
    print("=" * 70)
    print("INSPECTION COMPLETE")
    print("=" * 70)

    print()
    print(
        "Do NOT train yet."
    )

    print(
        "Review the configuration distribution and "
        "feature statistics first."
    )


if __name__ == "__main__":
    main()
