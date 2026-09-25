
import pandas as pd

from pathlib import Path

from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import GroupKFold
from sklearn.metrics import accuracy_score, classification_report


# ============================================================
# IPsec GROUPED CROSS-VALIDATION
# ============================================================
#
# IMPORTANT:
#
# repetition -> GROUPING ONLY
# traffic    -> NOT an ML feature
#
# The model must never receive repetition or traffic.
#
# We use repetition as the grouping variable so that an entire
# repetition is kept together during validation.
#
# ============================================================


SCRIPT_DIR = Path(__file__).resolve().parent

DATASET_FILE = (
    SCRIPT_DIR.parent / "ml_dataset.csv"
)


TARGETS = [
    "encryption",
    "hash",
    "dh_group",
    "pfs_group",
]


# These are metadata columns.
# They must NEVER be used as ML inputs.

METADATA_COLUMNS = [
    "repetition",
    "traffic",
]


RANDOM_STATE = 42

N_ESTIMATORS = 300


def run_target(df, features, target):

    print()
    print("=" * 80)
    print(f"TARGET: {target.upper()}")
    print("=" * 80)

    X = df[features]

    y = df[target]

    groups = df["repetition"]

    # --------------------------------------------------------
    # GroupKFold
    # --------------------------------------------------------

    n_groups = groups.nunique()

    print()
    print(f"Unique repetition groups: {n_groups}")

    cv = GroupKFold(
        n_splits=n_groups
    )

    fold_scores = []

    # --------------------------------------------------------
    # Cross-validation
    # --------------------------------------------------------

    for fold, (train_idx, test_idx) in enumerate(
        cv.split(
            X,
            y,
            groups=groups
        ),
        start=1
    ):

        X_train = X.iloc[train_idx]

        X_test = X.iloc[test_idx]

        y_train = y.iloc[train_idx]

        y_test = y.iloc[test_idx]

        train_groups = sorted(
            groups.iloc[train_idx].unique().tolist()
        )

        test_groups = sorted(
            groups.iloc[test_idx].unique().tolist()
        )

        # ----------------------------------------------------
        # Safety check
        # ----------------------------------------------------

        overlap = set(train_groups) & set(test_groups)

        if overlap:

            raise RuntimeError(
                f"GROUP LEAKAGE DETECTED: {overlap}"
            )

        # ----------------------------------------------------
        # Model
        # ----------------------------------------------------

        model = RandomForestClassifier(
            n_estimators=N_ESTIMATORS,
            random_state=RANDOM_STATE,
            class_weight="balanced",
            n_jobs=-1,
        )

        model.fit(
            X_train,
            y_train
        )

        predictions = model.predict(
            X_test
        )

        accuracy = accuracy_score(
            y_test,
            predictions
        )

        fold_scores.append(
            accuracy
        )

        print()
        print(f"Fold {fold}")
        print("-" * 60)

        print(
            f"Training groups: {train_groups}"
        )

        print(
            f"Testing groups : {test_groups}"
        )

        print(
            f"Training samples: {len(train_idx)}"
        )

        print(
            f"Testing samples : {len(test_idx)}"
        )

        print(
            f"Accuracy        : "
            f"{accuracy * 100:.2f}%"
        )

    # --------------------------------------------------------
    # Summary
    # --------------------------------------------------------

    mean_accuracy = sum(
        fold_scores
    ) / len(fold_scores)

    print()
    print("-" * 80)
    print("CROSS-VALIDATION SUMMARY")
    print("-" * 80)

    for i, score in enumerate(
        fold_scores,
        start=1
    ):

        print(
            f"Fold {i}: "
            f"{score * 100:.2f}%"
        )

    print()
    print(
        f"Mean accuracy: "
        f"{mean_accuracy * 100:.2f}%"
    )

    print(
        f"Minimum      : "
        f"{min(fold_scores) * 100:.2f}%"
    )

    print(
        f"Maximum      : "
        f"{max(fold_scores) * 100:.2f}%"
    )

    # --------------------------------------------------------
    # Final model report
    # --------------------------------------------------------

    print()
    print(
        "A high mean accuracy with a small spread between "
        "folds indicates more stable performance."
    )


def main():

    print("=" * 80)
    print("IPsec GROUPED CROSS-VALIDATION")
    print("=" * 80)

    # --------------------------------------------------------
    # Load dataset
    # --------------------------------------------------------

    if not DATASET_FILE.exists():

        print()
        print(
            "ERROR: ml_dataset.csv not found:"
        )

        print(DATASET_FILE)

        return

    df = pd.read_csv(
        DATASET_FILE
    )

    print()
    print(
        f"Dataset: {DATASET_FILE}"
    )

    print(
        f"Rows   : {len(df)}"
    )

    # --------------------------------------------------------
    # Validate required columns
    # --------------------------------------------------------

    required_columns = (
        METADATA_COLUMNS
        + TARGETS
    )

    missing = [
        column
        for column in required_columns
        if column not in df.columns
    ]

    if missing:

        print()
        print(
            "ERROR: Missing required columns:"
        )

        for column in missing:
            print(
                f"  - {column}"
            )

        return

    # --------------------------------------------------------
    # Determine ML features
    # --------------------------------------------------------
    #
    # Exclude:
    #   repetition
    #   traffic
    #   all target labels
    #
    # Everything remaining must be numeric.
    #

    excluded = (
        METADATA_COLUMNS
        + TARGETS
    )

    features = [
        column
        for column in df.columns
        if column not in excluded
    ]

    # --------------------------------------------------------
    # Numeric validation
    # --------------------------------------------------------

    non_numeric = [
        column
        for column in features
        if not pd.api.types.is_numeric_dtype(
            df[column]
        )
    ]

    if non_numeric:

        print()
        print(
            "ERROR: Non-numeric ML features detected:"
        )

        for column in non_numeric:
            print(
                f"  - {column}"
            )

        return

    # --------------------------------------------------------
    # Dataset information
    # --------------------------------------------------------

    print()
    print(
        f"ML features: {len(features)}"
    )

    for i, feature in enumerate(
        features,
        start=1
    ):

        print(
            f"  {i:2d}. {feature}"
        )

    print()
    print(
        f"Repetition groups: "
        f"{sorted(df['repetition'].unique().tolist())}"
    )

    print()
    print(
        "Traffic is metadata only:"
    )

    print(
        df["traffic"].value_counts()
    )

    # --------------------------------------------------------
    # Run every target
    # --------------------------------------------------------

    for target in TARGETS:

        run_target(
            df,
            features,
            target
        )

    # --------------------------------------------------------
    # Complete
    # --------------------------------------------------------

    print()
    print("=" * 80)
    print("GROUPED CROSS-VALIDATION COMPLETE")
    print("=" * 80)

    print()
    print(
        "Repetition and traffic were NOT used as ML features."
    )


if __name__ == "__main__":

    main()
