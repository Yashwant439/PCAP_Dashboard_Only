
import pandas as pd

from pathlib import Path

from sklearn.ensemble import RandomForestClassifier
from sklearn.inspection import permutation_importance
from sklearn.metrics import accuracy_score


# ============================================================
# IPsec FEATURE ANALYSIS
# ============================================================
#
# Purpose:
#
#   Identify which individual ML features actually contribute
#   to prediction performance.
#
# Methods:
#
#   1. Random Forest feature importance
#   2. Permutation importance
#
# Important:
#
#   repetition and traffic are CONTEXT columns.
#   They are retained in train.csv/test.csv for validation
#   and analysis, but MUST NOT be used as ML input features.
#
# Targets:
#
#   encryption
#   hash
#   dh_group
#   pfs_group
#
# ============================================================


SCRIPT_DIR = Path(__file__).resolve().parent

TRAIN_FILE = SCRIPT_DIR / "train.csv"
TEST_FILE = SCRIPT_DIR / "test.csv"


# ============================================================
# CONTEXT COLUMNS
# ============================================================
#
# These are useful for validation/analysis but are NOT
# ML features.
#
# traffic is categorical text such as ICMP/TCP/UDP.
# Therefore passing it directly to RandomForest would cause:
#
# ValueError: could not convert string to float: 'ICMP'
#
# ============================================================

CONTEXT_COLUMNS = [
    "repetition",
    "traffic",
]


# ============================================================
# TARGET LABELS
# ============================================================

TARGETS = [
    "encryption",
    "hash",
    "dh_group",
    "pfs_group",
]


RANDOM_STATE = 42
N_ESTIMATORS = 300
N_REPEATS = 20


# ============================================================
# ANALYZE ONE TARGET
# ============================================================

def analyze_target(
    train,
    test,
    features,
    target
):

    # --------------------------------------------------------
    # Prepare ML data
    # --------------------------------------------------------

    X_train = train[features]
    X_test = test[features]

    y_train = train[target]
    y_test = test[target]

    # --------------------------------------------------------
    # Safety check
    # --------------------------------------------------------
    #
    # Make sure no context column accidentally enters the
    # feature matrix.
    #
    # --------------------------------------------------------

    invalid_features = [

        column
        for column in features

        if column in CONTEXT_COLUMNS
    ]

    if invalid_features:

        raise ValueError(
            "Context columns found in ML features: "
            + ", ".join(invalid_features)
        )

    # --------------------------------------------------------
    # Train model
    # --------------------------------------------------------

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

    # --------------------------------------------------------
    # Baseline accuracy
    # --------------------------------------------------------

    predictions = model.predict(
        X_test
    )

    accuracy = accuracy_score(
        y_test,
        predictions
    )

    print()

    print(
        f"Baseline accuracy: "
        f"{accuracy * 100:.2f}%"
    )

    # --------------------------------------------------------
    # Random Forest feature importance
    # --------------------------------------------------------

    rf_importance = pd.Series(

        model.feature_importances_,

        index=features

    ).sort_values(

        ascending=False
    )

    print()

    print("-" * 80)
    print("RANDOM FOREST FEATURE IMPORTANCE")
    print("-" * 80)

    for feature, value in rf_importance.items():

        print(

            f"{feature:<35}"
            f"{value:.6f}"
        )

    # --------------------------------------------------------
    # Permutation importance
    # --------------------------------------------------------

    print()

    print("-" * 80)
    print("CALCULATING PERMUTATION IMPORTANCE")
    print("-" * 80)

    permutation = permutation_importance(

        model,

        X_test,

        y_test,

        n_repeats=N_REPEATS,

        random_state=RANDOM_STATE,

        scoring="accuracy",

        n_jobs=-1,
    )

    permutation_importance_df = pd.DataFrame(

        {

            "feature": features,

            "importance_mean":
                permutation.importances_mean,

            "importance_std":
                permutation.importances_std,

        }

    ).sort_values(

        "importance_mean",

        ascending=False
    )

    print()

    print(

        "Feature                         "
        "Mean decrease       Std"

    )

    print("-" * 80)

    for _, row in permutation_importance_df.iterrows():

        print(

            f"{row['feature']:<35}"

            f"{row['importance_mean']:>12.6f}"

            f"{row['importance_std']:>12.6f}"

        )

    return (

        accuracy,

        rf_importance,

        permutation_importance_df

    )


# ============================================================
# MAIN
# ============================================================

def main():

    print("=" * 80)
    print("IPsec FEATURE ANALYSIS")
    print("=" * 80)

    # --------------------------------------------------------
    # Load data
    # --------------------------------------------------------

    if not TRAIN_FILE.exists():

        print()

        print("ERROR: train.csv not found.")

        print(TRAIN_FILE)

        return

    if not TEST_FILE.exists():

        print()

        print("ERROR: test.csv not found.")

        print(TEST_FILE)

        return

    train = pd.read_csv(
        TRAIN_FILE
    )

    test = pd.read_csv(
        TEST_FILE
    )

    # --------------------------------------------------------
    # Verify context columns
    # --------------------------------------------------------

    missing_context = [

        column
        for column in CONTEXT_COLUMNS

        if column not in train.columns
    ]

    if missing_context:

        print()

        print(
            "ERROR: Missing context columns:"
        )

        for column in missing_context:

            print(
                f"  - {column}"
            )

        return

    # --------------------------------------------------------
    # Verify targets
    # --------------------------------------------------------

    missing_targets = [

        column
        for column in TARGETS

        if column not in train.columns
    ]

    if missing_targets:

        print()

        print(
            "ERROR: Missing target columns:"
        )

        for column in missing_targets:

            print(
                f"  - {column}"
            )

        return

    # --------------------------------------------------------
    # Context information
    # --------------------------------------------------------

    print()

    print("-" * 80)
    print("CONTEXT COLUMNS")
    print("-" * 80)

    print()

    print(
        "These columns are retained for validation/analysis "
        "but are NOT ML features:"
    )

    for column in CONTEXT_COLUMNS:

        print(
            f"  - {column}"
        )

    # --------------------------------------------------------
    # Feature list
    # --------------------------------------------------------
    #
    # Explicitly exclude:
    #
    #   1. Context columns
    #   2. Target columns
    #
    # Only the remaining columns are ML input features.
    #
    # --------------------------------------------------------

    features = [

        column

        for column in train.columns

        if column not in CONTEXT_COLUMNS

        and column not in TARGETS
    ]

    # --------------------------------------------------------
    # Verify all features are numeric
    # --------------------------------------------------------

    non_numeric_features = [

        column

        for column in features

        if not pd.api.types.is_numeric_dtype(
            train[column]
        )
    ]

    if non_numeric_features:

        print()

        print(
            "ERROR: Non-numeric ML features detected:"
        )

        for column in non_numeric_features:

            print(
                f"  - {column}"
            )

        print()

        print(
            "Feature analysis cannot continue."
        )

        return

    # --------------------------------------------------------
    # Feature information
    # --------------------------------------------------------

    print()

    print("-" * 80)
    print("ML FEATURES")
    print("-" * 80)

    print()

    print(
        f"Number of ML features: {len(features)}"
    )

    print()

    for feature in features:

        print(
            f"  - {feature}"
        )

    # --------------------------------------------------------
    # Analyze every target
    # --------------------------------------------------------

    for target in TARGETS:

        print()

        print("=" * 80)

        print(
            f"TARGET: {target.upper()}"
        )

        print("=" * 80)

        analyze_target(

            train,

            test,

            features,

            target
        )

    # --------------------------------------------------------
    # Done
    # --------------------------------------------------------

    print()

    print("=" * 80)
    print("FEATURE ANALYSIS COMPLETE")
    print("=" * 80)

    print()

    print(
        "Use permutation importance to identify features "
        "whose shuffling reduces test accuracy."
    )

    print()

    print(
        "Context columns repetition and traffic were "
        "excluded from ML input."
    )


if __name__ == "__main__":

    main()
