import pandas as pd
import joblib

from pathlib import Path
from sklearn.ensemble import RandomForestClassifier


# ============================================================
# IPsec FINAL MODEL TRAINING
# ============================================================
#
# Purpose:
#   Train the final Random Forest models using the training
#   portion of the dataset.
#
# Models:
#   encryption
#   hash
#   dh_group
#   pfs_group
#
# IMPORTANT:
#   repetition and traffic are NOT ML features.
#
# ============================================================


SCRIPT_DIR = Path(__file__).resolve().parent

TRAIN_FILE = SCRIPT_DIR / "train.csv"
MODEL_DIR = SCRIPT_DIR / "models"

TARGETS = [
    "encryption",
    "hash",
    "dh_group",
    "pfs_group",
]

CONTEXT_COLUMNS = [
    "repetition",
    "traffic",
]

RANDOM_STATE = 42
N_ESTIMATORS = 300


def main():

    print("=" * 80)
    print("IPsec FINAL MODEL TRAINING")
    print("=" * 80)

    # --------------------------------------------------------
    # Load training data
    # --------------------------------------------------------

    if not TRAIN_FILE.exists():

        print()
        print("ERROR: train.csv not found.")
        print(TRAIN_FILE)
        return

    train = pd.read_csv(TRAIN_FILE)

    print()
    print(f"Training dataset : {TRAIN_FILE}")
    print(f"Training samples : {len(train)}")

    # --------------------------------------------------------
    # Determine ML features
    # --------------------------------------------------------

    features = [
        column
        for column in train.columns
        if column not in TARGETS
        and column not in CONTEXT_COLUMNS
    ]

    print()
    print(f"ML features: {len(features)}")

    for index, feature in enumerate(features, start=1):
        print(f"  {index:>2}. {feature}")

    # --------------------------------------------------------
    # Create model directory
    # --------------------------------------------------------

    MODEL_DIR.mkdir(
        parents=True,
        exist_ok=True
    )

    # --------------------------------------------------------
    # Train one model per cryptographic target
    # --------------------------------------------------------

    print()
    print("=" * 80)
    print("TRAINING MODELS")
    print("=" * 80)

    for target in TARGETS:

        print()
        print("-" * 80)
        print(f"TARGET: {target.upper()}")
        print("-" * 80)

        X_train = train[features]
        y_train = train[target]

        print(f"Classes: {sorted(y_train.unique())}")

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

        model_file = MODEL_DIR / f"{target}_model.joblib"

        joblib.dump(
            {
                "model": model,
                "features": features,
                "target": target,
            },
            model_file
        )

        print(f"Model saved: {model_file}")

    # --------------------------------------------------------
    # Save metadata
    # --------------------------------------------------------

    metadata = {
        "features": features,
        "targets": TARGETS,
        "context_columns": CONTEXT_COLUMNS,
        "n_estimators": N_ESTIMATORS,
        "random_state": RANDOM_STATE,
        "training_samples": len(train),
    }

    metadata_file = MODEL_DIR / "model_metadata.joblib"

    joblib.dump(
        metadata,
        metadata_file
    )

    # --------------------------------------------------------
    # Complete
    # --------------------------------------------------------

    print()
    print("=" * 80)
    print("FINAL MODEL TRAINING COMPLETE")
    print("=" * 80)

    print()
    print("Saved models:")

    for target in TARGETS:
        print(
            f"  - models/{target}_model.joblib"
        )

    print()
    print(
        "These models can now be used for inference "
        "on extracted features from a new PCAP."
    )

    print()
    print("=" * 80)


if __name__ == "__main__":
    main()