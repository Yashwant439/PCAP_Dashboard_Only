import json
import joblib
import pandas as pd

from pathlib import Path


# ============================================================
# IPsec ML MODEL EVALUATION
# ============================================================
#
# Purpose:
#   Evaluate the final trained models on the completely
#   held-out test set.
#
# Test set:
#   test.csv
#
# Models:
#   encryption
#   hash
#   dh_group
#   pfs_group
#
# Important:
#   The models were trained only on train.csv.
#   test.csv is used only for evaluation.
#
# ============================================================


SCRIPT_DIR = Path(__file__).resolve().parent

TRAIN_FILE = SCRIPT_DIR / "train.csv"
TEST_FILE = SCRIPT_DIR / "test.csv"
MODEL_DIR = SCRIPT_DIR / "models"

TARGETS = [
    "encryption",
    "hash",
    "dh_group",
    "pfs_group",
]


# ============================================================
# LOAD MODEL
# ============================================================

def load_model(target):

    model_file = MODEL_DIR / f"{target}_model.joblib"

    if not model_file.exists():
        raise FileNotFoundError(
            f"Model not found: {model_file}"
        )

    package = joblib.load(model_file)

    return (
        package["model"],
        package["features"]
    )


# ============================================================
# EVALUATE TARGET
# ============================================================

def evaluate_target(test, target):

    model, features = load_model(target)

    X_test = test[features]
    y_test = test[target]

    predictions = model.predict(X_test)

    correct = predictions == y_test

    accuracy = correct.mean()

    print()
    print("=" * 80)
    print(f"TARGET: {target.upper()}")
    print("=" * 80)

    print()
    print(f"Correct predictions : {correct.sum()} / {len(test)}")
    print(f"Incorrect predictions : {(~correct).sum()} / {len(test)}")
    print(f"Accuracy            : {accuracy * 100:.2f}%")

    # --------------------------------------------------------
    # Per-class results
    # --------------------------------------------------------

    print()
    print("-" * 80)
    print("CLASS RESULTS")
    print("-" * 80)

    classes = sorted(y_test.unique())

    for class_name in classes:

        mask = y_test == class_name

        class_correct = (
            predictions[mask] == y_test[mask]
        ).sum()

        class_total = mask.sum()

        class_accuracy = (
            class_correct / class_total
        )

        print(
            f"{str(class_name):<15}"
            f"{class_correct:>3} / {class_total:<3}"
            f"  {class_accuracy * 100:>7.2f}%"
        )

    # --------------------------------------------------------
    # Misclassifications
    # --------------------------------------------------------

    print()
    print("-" * 80)
    print("MISCLASSIFICATIONS")
    print("-" * 80)

    found_error = False

    for index, is_correct in enumerate(correct):

        if not is_correct:

            found_error = True

            print(
                f"Row {index + 1:<4}"
                f" Actual: {y_test.iloc[index]:<10}"
                f" Predicted: {predictions[index]}"
            )

    if not found_error:

        print("None")

    return accuracy


# ============================================================
# MAIN
# ============================================================

def main():

    print("=" * 80)
    print("IPsec ML MODEL EVALUATION")
    print("=" * 80)

    # --------------------------------------------------------
    # Check files
    # --------------------------------------------------------

    if not TEST_FILE.exists():

        print()
        print("ERROR: test.csv not found.")
        return

    # --------------------------------------------------------
    # Load test set
    # --------------------------------------------------------

    test = pd.read_csv(TEST_FILE)

    print()
    print(f"Test dataset : {TEST_FILE}")
    print(f"Test samples : {len(test)}")

    # --------------------------------------------------------
    # Show repetition information
    # --------------------------------------------------------

    if "repetition" in test.columns:

        print()
        print(
            "Test repetitions:",
            sorted(test["repetition"].unique())
        )

    # --------------------------------------------------------
    # Evaluate every target
    # --------------------------------------------------------

    results = {}

    for target in TARGETS:

        results[target] = evaluate_target(
            test,
            target
        )

    # --------------------------------------------------------
    # Final summary
    # --------------------------------------------------------

    print()
    print("=" * 80)
    print("FINAL TEST SET SUMMARY")
    print("=" * 80)

    print()

    for target, accuracy in results.items():

        print(
            f"{target:<15}"
            f"{accuracy * 100:>8.2f}%"
        )

    print()
    print("=" * 80)
    print("MODEL EVALUATION COMPLETE")
    print("=" * 80)


if __name__ == "__main__":
    main()