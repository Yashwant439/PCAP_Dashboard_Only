
import pandas as pd

from pathlib import Path

from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
)


# ============================================================
# IPsec BASELINE ML TRAINING
# ============================================================
#
# Models:
#
#   1. Encryption
#   2. Hash
#   3. DH Group
#   4. PFS Group
#
# Algorithm:
#
#   Random Forest
#
# Dataset:
#
#   train.csv
#   test.csv
#
# Important:
#
#   repetition is NOT used as a feature.
#
# ============================================================


SCRIPT_DIR = Path(__file__).resolve().parent

TRAIN_FILE = SCRIPT_DIR / "train.csv"
TEST_FILE = SCRIPT_DIR / "test.csv"


TARGETS = [
    "encryption",
    "hash",
    "dh_group",
    "pfs_group",
]


# ============================================================
# MODEL CONFIGURATION
# ============================================================

RANDOM_STATE = 42

N_ESTIMATORS = 300


def main():

    print("=" * 80)
    print("IPsec BASELINE ML TRAINING")
    print("=" * 80)

    # --------------------------------------------------------
    # Check files
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

    # --------------------------------------------------------
    # Load datasets
    # --------------------------------------------------------

    train = pd.read_csv(
        TRAIN_FILE
    )

    test = pd.read_csv(
        TEST_FILE
    )

    print()
    print(
        f"Training samples : {len(train)}"
    )

    print(
        f"Testing samples  : {len(test)}"
    )

    # --------------------------------------------------------
    # Determine input features
    # --------------------------------------------------------

    feature_columns = [
        column
        for column in train.columns
        if column not in TARGETS
    ]

    print()
    print(
        f"ML input features: {len(feature_columns)}"
    )

    print()

    for index, feature in enumerate(
        feature_columns,
        start=1
    ):

        print(
            f"  {index:>2}. {feature}"
        )

    # --------------------------------------------------------
    # Create X matrices
    # --------------------------------------------------------

    X_train = train[
        feature_columns
    ]

    X_test = test[
        feature_columns
    ]

    # --------------------------------------------------------
    # Train each target separately
    # --------------------------------------------------------

    print()
    print("=" * 80)
    print("TRAINING MODELS")
    print("=" * 80)

    results = {}

    for target in TARGETS:

        print()
        print("-" * 80)
        print(
            f"TARGET: {target.upper()}"
        )
        print("-" * 80)

        y_train = train[target]
        y_test = test[target]

        print()
        print("Training class distribution:")

        print(
            y_train
            .value_counts()
            .sort_index()
            .to_string()
        )

        # ----------------------------------------------------
        # Create model
        # ----------------------------------------------------

        model = RandomForestClassifier(
            n_estimators=N_ESTIMATORS,
            random_state=RANDOM_STATE,
            class_weight="balanced",
            n_jobs=-1,
        )

        # ----------------------------------------------------
        # Train
        # ----------------------------------------------------

        print()
        print("Training...")

        model.fit(
            X_train,
            y_train
        )

        # ----------------------------------------------------
        # Predict
        # ----------------------------------------------------

        predictions = model.predict(
            X_test
        )

        # ----------------------------------------------------
        # Accuracy
        # ----------------------------------------------------

        accuracy = accuracy_score(
            y_test,
            predictions
        )

        results[target] = accuracy

        print()
        print(
            f"Accuracy: "
            f"{accuracy * 100:.2f}%"
        )

        # ----------------------------------------------------
        # Classification report
        # ----------------------------------------------------

        print()
        print(
            "Classification report:"
        )

        print(
            classification_report(
                y_test,
                predictions,
                zero_division=0
            )
        )

        # ----------------------------------------------------
        # Confusion matrix
        # ----------------------------------------------------

        labels = sorted(
            y_test.unique()
        )

        cm = confusion_matrix(
            y_test,
            predictions,
            labels=labels
        )

        print(
            "Confusion matrix:"
        )

        print(
            "Labels:",
            labels
        )

        print(cm)

        # ----------------------------------------------------
        # Feature importance
        # ----------------------------------------------------

        importance = pd.Series(
            model.feature_importances_,
            index=feature_columns
        ).sort_values(
            ascending=False
        )

        print()
        print(
            "Top feature importance:"
        )

        for feature, value in (
            importance.head(10).items()
        ):

            print(
                f"  {feature:<35} "
                f"{value:.4f}"
            )

    # --------------------------------------------------------
    # Final summary
    # --------------------------------------------------------

    print()
    print("=" * 80)
    print("BASELINE RESULTS")
    print("=" * 80)

    for target, accuracy in results.items():

        print(
            f"{target:<15} "
            f"{accuracy * 100:>7.2f}%"
        )

    print()
    print("=" * 80)
    print("BASELINE TRAINING COMPLETE")
    print("=" * 80)

    print()
    print(
        "These results are a baseline."
    )

    print(
        "Do not interpret high accuracy as final "
        "real-world performance yet."
    )


if __name__ == "__main__":
    main()

