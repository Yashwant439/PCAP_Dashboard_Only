
import pandas as pd
from pathlib import Path


# ============================================================
# IPsec ML TRAIN / TEST SPLIT
# ============================================================
#
# Strategy:
#
#   repetitions 1-4 -> TRAIN
#   repetition 5    -> TEST
#
# Repetition is used ONLY to create the split.
# It is NOT included as an ML feature.
#
# ============================================================


SCRIPT_DIR = Path(__file__).resolve().parent

RAW_DATASET = SCRIPT_DIR / "dataset.csv"
ML_DATASET = SCRIPT_DIR / "ml_dataset.csv"

ML_DIR = SCRIPT_DIR / "ml"

TRAIN_FILE = ML_DIR / "train.csv"
TEST_FILE = ML_DIR / "test.csv"


TARGETS = [
    "encryption",
    "hash",
    "dh_group",
    "pfs_group",
]


def main():

    print("=" * 80)
    print("IPsec ML TRAIN / TEST SPLIT")
    print("=" * 80)

    # --------------------------------------------------------
    # Check files
    # --------------------------------------------------------

    if not RAW_DATASET.exists():

        print()
        print("ERROR: dataset.csv not found.")
        return

    if not ML_DATASET.exists():

        print()
        print("ERROR: ml_dataset.csv not found.")
        return

    # --------------------------------------------------------
    # Load datasets
    # --------------------------------------------------------

    raw = pd.read_csv(
        RAW_DATASET
    )

    ml = pd.read_csv(
        ML_DATASET
    )

    print()
    print(
        f"Raw dataset rows : {len(raw)}"
    )

    print(
        f"ML dataset rows  : {len(ml)}"
    )

    # --------------------------------------------------------
    # Verify row alignment
    # --------------------------------------------------------

    if len(raw) != len(ml):

        print()
        print(
            "ERROR: raw dataset and ML dataset "
            "have different row counts."
        )

        return

    # --------------------------------------------------------
    # Create split masks
    # --------------------------------------------------------

    train_mask = raw["repetition"].isin(
        [1, 2, 3, 4]
    )

    test_mask = raw["repetition"] == 5

    train = ml.loc[
        train_mask
    ].copy()

    test = ml.loc[
        test_mask
    ].copy()

    # --------------------------------------------------------
    # Create output directory
    # --------------------------------------------------------

    ML_DIR.mkdir(
        exist_ok=True
    )

    # --------------------------------------------------------
    # Save
    # --------------------------------------------------------

    train.to_csv(
        TRAIN_FILE,
        index=False
    )

    test.to_csv(
        TEST_FILE,
        index=False
    )

    # --------------------------------------------------------
    # Summary
    # --------------------------------------------------------

    print()
    print("=" * 80)
    print("SPLIT CREATED")
    print("=" * 80)

    print()
    print(
        f"Training samples : {len(train)}"
    )

    print(
        f"Testing samples  : {len(test)}"
    )

    print(
        f"Train percentage : "
        f"{len(train) / len(ml) * 100:.1f}%"
    )

    print(
        f"Test percentage  : "
        f"{len(test) / len(ml) * 100:.1f}%"
    )

    # --------------------------------------------------------
    # Verify repetition separation
    # --------------------------------------------------------

    print()
    print("-" * 80)
    print("REPETITION CHECK")
    print("-" * 80)

    train_repetitions = sorted(
        raw.loc[
            train_mask,
            "repetition"
        ].unique()
    )

    test_repetitions = sorted(
        raw.loc[
            test_mask,
            "repetition"
        ].unique()
    )

    print(
        f"Training repetitions: "
        f"{train_repetitions}"
    )

    print(
        f"Testing repetitions : "
        f"{test_repetitions}"
    )

    # --------------------------------------------------------
    # Verify no overlap
    # --------------------------------------------------------

    overlap = set(
        train_repetitions
    ).intersection(
        test_repetitions
    )

    if overlap:

        print()
        print(
            "WARNING: repetition overlap detected!"
        )

        print(
            f"Overlap: {sorted(overlap)}"
        )

    else:

        print()
        print(
            "No repetition overlap."
        )

    # --------------------------------------------------------
    # Target distributions
    # --------------------------------------------------------

    for target in TARGETS:

        print()
        print("-" * 80)
        print(
            f"{target.upper()} - TRAIN"
        )
        print("-" * 80)

        print(
            train[target]
            .value_counts()
            .sort_index()
            .to_string()
        )

        print()
        print(
            f"{target.upper()} - TEST"
        )
        print("-" * 80)

        print(
            test[target]
            .value_counts()
            .sort_index()
            .to_string()
        )

    # --------------------------------------------------------
    # Final
    # --------------------------------------------------------

    print()
    print("=" * 80)
    print("FILES CREATED")
    print("=" * 80)

    print()
    print(
        f"Train: {TRAIN_FILE}"
    )

    print(
        f"Test : {TEST_FILE}"
    )

    print()
    print(
        "Next step: train the baseline models."
    )

    print("=" * 80)


if __name__ == "__main__":
    main()
