
import pandas as pd
from pathlib import Path


# ============================================================
# IPsec ML DATASET PREPARATION
# ============================================================
#
# Input:
#     dataset.csv
#
# Output:
#     ml_dataset.csv
#
# IMPORTANT DESIGN:
#
#   source_pcap
#       -> REMOVE completely
#
#   repetition
#       -> KEEP in ml_dataset.csv
#       -> used ONLY for grouped cross-validation
#       -> NEVER used as an ML feature
#
#   traffic
#       -> KEEP in ml_dataset.csv
#       -> used ONLY for analysis/context
#       -> NEVER used as an ML feature
#
#   cryptographic labels
#       -> KEEP as targets
#
#   numeric packet/traffic measurements
#       -> ML INPUT FEATURES
#
# ============================================================


SCRIPT_DIR = Path(__file__).resolve().parent

INPUT_FILE = SCRIPT_DIR / "dataset.csv"
OUTPUT_FILE = SCRIPT_DIR / "ml_dataset.csv"


# ============================================================
# REMOVE COMPLETELY
# ============================================================

REMOVE_COLUMNS = [
    "source_pcap",
]


# ============================================================
# KEEP IN DATASET BUT NEVER USE AS ML FEATURES
# ============================================================

CONTEXT_COLUMNS = [
    "repetition",
    "traffic",
]


# ============================================================
# ML TARGETS
# ============================================================

TARGET_COLUMNS = [
    "encryption",
    "hash",
    "dh_group",
    "pfs_group",
]


def main():

    print("=" * 80)
    print("IPsec ML DATASET PREPARATION")
    print("=" * 80)

    # ========================================================
    # LOAD RAW DATASET
    # ========================================================

    if not INPUT_FILE.exists():

        print()
        print("ERROR: dataset.csv not found.")
        print(INPUT_FILE)
        return

    df = pd.read_csv(INPUT_FILE)

    print()
    print(f"Input file : {INPUT_FILE}")
    print(f"Rows       : {len(df)}")
    print(f"Columns    : {len(df.columns)}")

    # ========================================================
    # VERIFY REQUIRED COLUMNS
    # ========================================================

    required_columns = (
        REMOVE_COLUMNS
        + CONTEXT_COLUMNS
        + TARGET_COLUMNS
    )

    missing_columns = [
        column
        for column in required_columns
        if column not in df.columns
    ]

    if missing_columns:

        print()
        print("ERROR: Required columns missing:")

        for column in missing_columns:
            print(f"  - {column}")

        return

    # ========================================================
    # REMOVE source_pcap
    # ========================================================

    print()
    print("-" * 80)
    print("REMOVING FILE METADATA")
    print("-" * 80)

    for column in REMOVE_COLUMNS:

        print(f"  Removed: {column}")

    df = df.drop(
        columns=REMOVE_COLUMNS
    )

    # ========================================================
    # KEEP repetition + traffic
    # ========================================================

    print()
    print("-" * 80)
    print("RETAINING CONTEXT COLUMNS")
    print("-" * 80)

    for column in CONTEXT_COLUMNS:

        print(
            f"  Retained: {column}"
            f"  (NOT an ML feature)"
        )

    # ========================================================
    # IDENTIFY ML FEATURES
    # ========================================================
    #
    # Everything that is:
    #
    #   NOT context
    #   NOT target
    #
    # is considered a candidate ML feature.
    #
    # ========================================================

    candidate_features = [

        column

        for column in df.columns

        if column not in CONTEXT_COLUMNS
        and column not in TARGET_COLUMNS

    ]

    # ========================================================
    # REMOVE CONSTANT ML FEATURES
    # ========================================================

    print()
    print("-" * 80)
    print("CHECKING FOR CONSTANT FEATURES")
    print("-" * 80)

    constant_features = []

    for column in candidate_features:

        if df[column].nunique(
            dropna=False
        ) <= 1:

            constant_features.append(
                column
            )

    if constant_features:

        for column in constant_features:

            print(
                f"  Removing constant feature: "
                f"{column}"
            )

        df = df.drop(
            columns=constant_features
        )

        candidate_features = [

            column

            for column in candidate_features

            if column not in constant_features

        ]

    else:

        print(
            "  No constant features found."
        )

    # ========================================================
    # CHECK MISSING VALUES
    # ========================================================

    print()
    print("-" * 80)
    print("CHECKING MISSING VALUES")
    print("-" * 80)

    check_columns = (
        CONTEXT_COLUMNS
        + candidate_features
        + TARGET_COLUMNS
    )

    missing = df[
        check_columns
    ].isnull().sum()

    missing_columns = missing[
        missing > 0
    ]

    if len(missing_columns) == 0:

        print(
            "  No missing values."
        )

    else:

        print(
            "  WARNING: Missing values found:"
        )

        for column, count in (
            missing_columns.items()
        ):

            print(
                f"    {column}: {count}"
            )

    # ========================================================
    # CHECK ML FEATURE TYPES
    # ========================================================

    print()
    print("-" * 80)
    print("CHECKING ML FEATURE TYPES")
    print("-" * 80)

    non_numeric = []

    for column in candidate_features:

        if not pd.api.types.is_numeric_dtype(
            df[column]
        ):

            non_numeric.append(
                column
            )

    if non_numeric:

        print(
            "  ERROR: Non-numeric ML features:"
        )

        for column in non_numeric:

            print(
                f"    {column}"
            )

        print()
        print(
            "Only numeric packet/network "
            "measurements should be ML features."
        )

        return

    print(
        "  All ML input features are numeric."
    )

    # ========================================================
    # FINAL DATASET ORDER
    # ========================================================
    #
    # IMPORTANT:
    #
    # repetition
    # traffic
    #     ↓
    # context only
    #
    # 18 numeric features
    #     ↓
    # ML input
    #
    # 4 crypto labels
    #     ↓
    # targets
    #
    # ========================================================

    final_columns = (
        CONTEXT_COLUMNS
        + candidate_features
        + TARGET_COLUMNS
    )

    output_df = df[
        final_columns
    ].copy()

    # ========================================================
    # SAVE
    # ========================================================

    output_df.to_csv(
        OUTPUT_FILE,
        index=False
    )

    # ========================================================
    # SUMMARY
    # ========================================================

    print()
    print("=" * 80)
    print("ML DATASET CREATED")
    print("=" * 80)

    print()
    print(
        f"Output file : {OUTPUT_FILE}"
    )

    print(
        f"Rows        : {len(output_df)}"
    )

    print(
        f"Columns     : {len(output_df.columns)}"
    )

    print(
        f"Context     : {len(CONTEXT_COLUMNS)}"
    )

    print(
        f"ML features : {len(candidate_features)}"
    )

    print(
        f"Targets     : {len(TARGET_COLUMNS)}"
    )

    print()
    print("CONTEXT COLUMNS:")
    print("  These remain in ml_dataset.csv")
    print("  but are NOT ML features.")

    for column in CONTEXT_COLUMNS:

        print(
            f"  - {column}"
        )

    print()
    print("ML INPUT FEATURES:")

    for index, column in enumerate(
        candidate_features,
        start=1
    ):

        print(
            f"  {index:>2}. {column}"
        )

    print()
    print("TARGET LABELS:")

    for column in TARGET_COLUMNS:

        print(
            f"  - {column}"
        )

    print()
    print("=" * 80)
    print("Preparation complete.")
    print("=" * 80)


if __name__ == "__main__":
    main()
