
import pandas as pd

from pathlib import Path

from sklearn.ensemble import RandomForestClassifier

from sklearn.metrics import accuracy_score


# ============================================================
# IPsec FEATURE ABLATION EXPERIMENT
# ============================================================
#
# Purpose:
#   Determine which groups of features are responsible for
#   the baseline model's predictions.
#
# Experiments:
#
#   A = All ML features
#   B = Without capture duration
#   C = Without packet-size features
#   D = Structural IKE/ESP features only
#
# Important:
#
#   repetition = CONTEXT / GROUPING ONLY
#   traffic    = CONTEXT / ANALYSIS ONLY
#
#   Neither repetition nor traffic is used as an ML feature.
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
# TARGET LABELS
# ============================================================

TARGETS = [
    "encryption",
    "hash",
    "dh_group",
    "pfs_group",
]


# ============================================================
# CONTEXT / GROUPING COLUMNS
# ============================================================
#
# These columns are retained in the dataset because they are
# useful for validation and analysis.
#
# They MUST NOT be passed to the ML model.
#
# ============================================================

CONTEXT_COLUMNS = [
    "repetition",
    "traffic",
]


RANDOM_STATE = 42

N_ESTIMATORS = 300


# ============================================================
# FEATURE GROUPS
# ============================================================

PACKET_SIZE_FEATURES = [
    "avg_packet_size",
    "min_packet_size",
    "max_packet_size",
    "ike_avg_packet_size",
    "esp_avg_packet_size",
]


STRUCTURAL_FEATURES = [
    "packet_count",
    "total_bytes",
    "udp_packet_count",
    "udp_500_count",
    "ike_packet_count",
    "esp_packet_count",
    "create_child_sa_count",
    "informational_count",
    "ike_request_count",
    "ike_response_count",
    "ike_bytes",
    "esp_bytes",
]


# ============================================================
# TRAIN AND EVALUATE
# ============================================================

def train_and_evaluate(
    train,
    test,
    features,
    target
):

    X_train = train[features]

    X_test = test[features]

    y_train = train[target]

    y_test = test[target]

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

    return accuracy


# ============================================================
# MAIN
# ============================================================

def main():

    print("=" * 90)

    print("IPsec FEATURE ABLATION EXPERIMENT")

    print("=" * 90)


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
    # Determine actual ML features
    # --------------------------------------------------------
    #
    # IMPORTANT:
    #
    # Remove:
    #   - target labels
    #   - repetition
    #   - traffic
    #
    # Only actual ML measurements remain.
    #
    # --------------------------------------------------------

    all_features = [

        column

        for column in train.columns

        if column not in TARGETS

        and column not in CONTEXT_COLUMNS

    ]


    # --------------------------------------------------------
    # Verify all ML features are numeric
    # --------------------------------------------------------

    non_numeric_features = [

        column

        for column in all_features

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
            "These columns must not be used as ML features."
        )

        return


    # --------------------------------------------------------
    # Print context information
    # --------------------------------------------------------

    print()

    print("-" * 90)

    print("CONTEXT COLUMNS")

    print("-" * 90)

    print()

    print(
        "These columns are retained for validation/analysis "
        "but are NOT ML features:"
    )

    for column in CONTEXT_COLUMNS:

        if column in train.columns:

            print(
                f"  - {column}"
            )


    # --------------------------------------------------------
    # Print ML features
    # --------------------------------------------------------

    print()

    print("-" * 90)

    print("ML FEATURES")

    print("-" * 90)

    print()

    print(
        f"Number of ML features: {len(all_features)}"
    )

    print()

    for feature in all_features:

        print(
            f"  - {feature}"
        )


    # --------------------------------------------------------
    # Define experiments
    # --------------------------------------------------------

    experiments = {}


    # --------------------------------------------------------
    # A: ALL ML FEATURES
    # --------------------------------------------------------

    experiments[
        "A - ALL FEATURES"
    ] = all_features


    # --------------------------------------------------------
    # B: Remove capture duration
    # --------------------------------------------------------

    experiments[
        "B - NO CAPTURE DURATION"
    ] = [

        feature

        for feature in all_features

        if feature != "capture_duration_seconds"

    ]


    # --------------------------------------------------------
    # C: Remove packet-size features
    # --------------------------------------------------------

    experiments[
        "C - NO PACKET-SIZE FEATURES"
    ] = [

        feature

        for feature in all_features

        if feature not in PACKET_SIZE_FEATURES

    ]


    # --------------------------------------------------------
    # D: Structural IKE/ESP features only
    # --------------------------------------------------------

    experiments[
        "D - STRUCTURAL FEATURES ONLY"
    ] = [

        feature

        for feature in STRUCTURAL_FEATURES

        if feature in all_features

    ]


    # --------------------------------------------------------
    # Run experiments
    # --------------------------------------------------------

    results = {}


    for experiment_name, features in experiments.items():

        print()

        print("=" * 90)

        print(experiment_name)

        print("=" * 90)

        print()

        print(
            f"Number of features: {len(features)}"
        )

        print()

        print("Features:")

        for feature in features:

            print(
                f"  - {feature}"
            )


        results[
            experiment_name
        ] = {}


        for target in TARGETS:

            accuracy = train_and_evaluate(

                train,

                test,

                features,

                target

            )


            results[
                experiment_name
            ][target] = accuracy


            print(

                f"{target:<15} "

                f"{accuracy * 100:>7.2f}%"

            )


    # --------------------------------------------------------
    # Comparison table
    # --------------------------------------------------------

    print()

    print("=" * 90)

    print("ABLATION RESULTS")

    print("=" * 90)

    print()


    header = (

        f"{'Experiment':<32}"

        f"{'Encryption':>14}"

        f"{'Hash':>10}"

        f"{'DH':>10}"

        f"{'PFS':>10}"

    )


    print(header)

    print("-" * 90)


    for experiment_name, target_results in results.items():

        print(

            f"{experiment_name:<32}"

            f"{target_results['encryption'] * 100:>13.2f}%"

            f"{target_results['hash'] * 100:>9.2f}%"

            f"{target_results['dh_group'] * 100:>9.2f}%"

            f"{target_results['pfs_group'] * 100:>9.2f}%"

        )


    # --------------------------------------------------------
    # Interpretation
    # --------------------------------------------------------

    print()

    print("=" * 90)

    print("INTERPRETATION")

    print("=" * 90)

    print()

    print(
        "Compare Experiment A against B:"
    )

    print(
        "  This shows how much capture duration contributes."
    )

    print()

    print(
        "Compare Experiment A against C:"
    )

    print(
        "  This shows how much packet-size features contribute."
    )

    print()

    print(
        "Compare Experiment A against D:"
    )

    print(
        "  This shows whether structural IKE/ESP features alone"
    )

    print(
        "  contain useful predictive information."
    )

    print()

    print(
        "Do not select a final model based only on accuracy."
    )

    print(
        "Use these results to understand what the model is learning."
    )

    print()

    print("=" * 90)


if __name__ == "__main__":

    main()
