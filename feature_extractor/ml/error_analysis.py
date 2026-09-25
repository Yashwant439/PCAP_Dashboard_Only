import json
import joblib
import pandas as pd

from pathlib import Path


# ============================================================
# IPsec ML ERROR ANALYSIS
# ============================================================
#
# Purpose:
#   Investigate incorrect predictions made by the final
#   trained models on the completely held-out test set.
#
# Primary focus:
#   ENCRYPTION
#
# Also reports:
#   HASH
#   DH_GROUP
#   PFS_GROUP
#
# Data flow:
#
#   test.csv
#       |
#       v
#   trained .joblib models
#       |
#       v
#   predictions
#       |
#       +---- compare actual vs predicted
#       |
#       +---- locate corresponding feature JSON
#       |
#       +---- print feature values
#
# Important:
#   repetition and traffic are context columns only.
#   They are NOT used as ML inputs.
#
# ============================================================


SCRIPT_DIR = Path(__file__).resolve().parent

FEATURE_EXTRACTOR_DIR = SCRIPT_DIR.parent

TEST_FILE = SCRIPT_DIR / "test.csv"

MODEL_DIR = SCRIPT_DIR / "models"

OUTPUT_DIR = FEATURE_EXTRACTOR_DIR / "output"


TARGETS = [
    "encryption",
    "hash",
    "dh_group",
    "pfs_group",
]


# ============================================================
# THE EXACT 18 ML FEATURES
# ============================================================

ML_FEATURES = [
    "packet_count",
    "total_bytes",
    "avg_packet_size",
    "min_packet_size",
    "max_packet_size",
    "capture_duration_seconds",
    "udp_packet_count",
    "udp_500_count",
    "ike_packet_count",
    "esp_packet_count",
    "create_child_sa_count",
    "informational_count",
    "ike_request_count",
    "ike_response_count",
    "ike_bytes",
    "ike_avg_packet_size",
    "esp_bytes",
    "esp_avg_packet_size",
]


# ============================================================
# LOAD MODEL
# ============================================================

def load_model(target):

    model_file = MODEL_DIR / f"{target}_model.joblib"

    if not model_file.exists():

        raise FileNotFoundError(
            f"Model not found:\n{model_file}"
        )

    package = joblib.load(model_file)

    return (
        package["model"],
        package["features"]
    )


# ============================================================
# FIND FEATURE JSON
# ============================================================

def find_feature_json(source_pcap):

    if not source_pcap:
        return None

    pcap_name = Path(source_pcap).name

    if pcap_name.lower().endswith(".pcap"):

        feature_name = (
            pcap_name[:-5]
            + "_features.json"
        )

    else:

        feature_name = (
            pcap_name
            + "_features.json"
        )

    feature_file = OUTPUT_DIR / feature_name

    if feature_file.exists():

        return feature_file

    return None


# ============================================================
# LOAD FEATURE JSON
# ============================================================

def load_feature_json(feature_file):

    if feature_file is None:
        return None

    try:

        with open(
            feature_file,
            "r",
            encoding="utf-8"
        ) as file:

            data = json.load(file)

        return data

    except Exception as error:

        print(
            f"WARNING: Could not read "
            f"{feature_file}: {error}"
        )

        return None


# ============================================================
# PRINT FEATURE VALUES
# ============================================================

def print_features(
    feature_values
):

    print()

    print(
        "FEATURE VALUES"
    )

    print(
        "-" * 80
    )

    for feature in ML_FEATURES:

        value = feature_values.get(
            feature,
            "N/A"
        )

        print(
            f"{feature:<35} {value}"
        )


# ============================================================
# ANALYZE ONE TARGET
# ============================================================

def analyze_target(
    test,
    target
):

    model, model_features = load_model(
        target
    )

    # --------------------------------------------------------
    # Make sure model feature list is compatible
    # --------------------------------------------------------

    missing = [
        feature
        for feature in model_features
        if feature not in test.columns
    ]

    if missing:

        raise ValueError(
            f"Missing features in test.csv "
            f"for {target}: {missing}"
        )

    X_test = test[model_features]

    y_test = test[target]

    predictions = model.predict(
        X_test
    )

    incorrect_indices = []

    for index in range(len(test)):

        actual = y_test.iloc[index]

        predicted = predictions[index]

        if actual != predicted:

            incorrect_indices.append(
                index
            )

    # --------------------------------------------------------
    # Summary
    # --------------------------------------------------------

    print()

    print(
        "=" * 80
    )

    print(
        f"ERROR ANALYSIS: {target.upper()}"
    )

    print(
        "=" * 80
    )

    print()

    print(
        f"Total test samples : {len(test)}"
    )

    print(
        f"Correct            : "
        f"{len(test) - len(incorrect_indices)}"
    )

    print(
        f"Incorrect          : "
        f"{len(incorrect_indices)}"
    )

    if len(test) > 0:

        accuracy = (
            (len(test) - len(incorrect_indices))
            / len(test)
        )

        print(
            f"Accuracy           : "
            f"{accuracy * 100:.2f}%"
        )

    # --------------------------------------------------------
    # No errors
    # --------------------------------------------------------

    if not incorrect_indices:

        print()

        print(
            "No misclassifications."
        )

        return

    # --------------------------------------------------------
    # Detailed errors
    # --------------------------------------------------------

    print()

    print(
        "-" * 80
    )

    print(
        "MISCLASSIFIED SAMPLES"
    )

    print(
        "-" * 80
    )

    for error_number, index in enumerate(
        incorrect_indices,
        start=1
    ):

        row = test.iloc[index]

        actual = row[target]

        predicted = predictions[index]

        print()

        print(
            "=" * 80
        )

        print(
            f"ERROR #{error_number}"
        )

        print(
            "=" * 80
        )

        print(
            f"Test row          : {index + 1}"
        )

        print(
            f"Actual {target:<10}: {actual}"
        )

        print(
            f"Predicted          : {predicted}"
        )

        # ----------------------------------------------------
        # Context information
        # ----------------------------------------------------

        if "repetition" in row:

            print(
                f"Repetition         : "
                f"{row['repetition']}"
            )

        if "traffic" in row:

            print(
                f"Traffic            : "
                f"{row['traffic']}"
            )

        # ----------------------------------------------------
        # Source PCAP
        # ----------------------------------------------------

        source_pcap = None

        if "source_pcap" in row:

            source_pcap = row["source_pcap"]

        print(
            f"Source PCAP        : "
            f"{source_pcap if source_pcap else 'N/A'}"
        )

        # ----------------------------------------------------
        # Find corresponding feature JSON
        # ----------------------------------------------------

        feature_file = find_feature_json(
            source_pcap
        )

        if feature_file:

            print(
                f"Feature JSON       : "
                f"{feature_file}"
            )

            json_data = load_feature_json(
                feature_file
            )

            if json_data:

                feature_values = json_data.get(
                    "features",
                    {}
                )

                print_features(
                    feature_values
                )

        else:

            print(
                "Feature JSON       : NOT FOUND"
            )

            # ------------------------------------------------
            # Fall back to values directly from test.csv
            # ------------------------------------------------

            print()

            print_features(
                row.to_dict()
            )


# ============================================================
# ENCRYPTION-SPECIFIC COMPARISON
# ============================================================

def analyze_encryption_patterns(test):

    print()

    print(
        "=" * 80
    )

    print(
        "ENCRYPTION ERROR PATTERN ANALYSIS"
    )

    print(
        "=" * 80
    )

    model, model_features = load_model(
        "encryption"
    )

    X_test = test[model_features]

    y_test = test["encryption"]

    predictions = model.predict(
        X_test
    )

    # --------------------------------------------------------
    # Create analysis DataFrame
    # --------------------------------------------------------

    analysis = test.copy()

    analysis["predicted_encryption"] = predictions

    analysis["correct"] = (
        analysis["encryption"]
        == analysis["predicted_encryption"]
    )

    # --------------------------------------------------------
    # Correct / incorrect groups
    # --------------------------------------------------------

    groups = {

        "AES128_CORRECT": analysis[
            (analysis["encryption"] == "AES128")
            & (analysis["correct"])
        ],

        "AES128_WRONG": analysis[
            (analysis["encryption"] == "AES128")
            & (~analysis["correct"])
        ],

        "AES256_CORRECT": analysis[
            (analysis["encryption"] == "AES256")
            & (analysis["correct"])
        ],

        "AES256_WRONG": analysis[
            (analysis["encryption"] == "AES256")
            & (~analysis["correct"])
        ],
    }

    # --------------------------------------------------------
    # Print group sizes
    # --------------------------------------------------------

    print()

    print(
        "GROUP COUNTS"
    )

    print(
        "-" * 80
    )

    for name, dataframe in groups.items():

        print(
            f"{name:<20} {len(dataframe)}"
        )

    # --------------------------------------------------------
    # Compare numerical feature means
    # --------------------------------------------------------

    print()

    print(
        "-" * 80
    )

    print(
        "FEATURE MEAN COMPARISON"
    )

    print(
        "-" * 80
    )

    print()

    print(
        f"{'Feature':<35}"
        f"{'A128 correct':>15}"
        f"{'A128 wrong':>15}"
        f"{'A256 correct':>15}"
        f"{'A256 wrong':>15}"
    )

    print(
        "-" * 80
    )

    for feature in ML_FEATURES:

        values = []

        for dataframe in groups.values():

            if len(dataframe) == 0:

                values.append(float("nan"))

            else:

                values.append(
                    pd.to_numeric(
                        dataframe[feature],
                        errors="coerce"
                    ).mean()
                )

        print(
            f"{feature:<35}"
            f"{values[0]:>15.3f}"
            f"{values[1]:>15.3f}"
            f"{values[2]:>15.3f}"
            f"{values[3]:>15.3f}"
        )


# ============================================================
# MAIN
# ============================================================

def main():

    print(
        "=" * 80
    )

    print(
        "IPsec ML ERROR ANALYSIS"
    )

    print(
        "=" * 80
    )

    # --------------------------------------------------------
    # Check test file
    # --------------------------------------------------------

    if not TEST_FILE.exists():

        print()

        print(
            "ERROR: test.csv not found:"
        )

        print(
            TEST_FILE
        )

        return

    # --------------------------------------------------------
    # Load test dataset
    # --------------------------------------------------------

    test = pd.read_csv(
        TEST_FILE
    )

    print()

    print(
        f"Test dataset : {TEST_FILE}"
    )

    print(
        f"Test samples : {len(test)}"
    )

    # --------------------------------------------------------
    # Repetition information
    # --------------------------------------------------------

    if "repetition" in test.columns:

        repetitions = sorted(
            test["repetition"].unique()
        )

        print()

        print(
            f"Test repetitions: {repetitions}"
        )

    # --------------------------------------------------------
    # Analyze every target
    # --------------------------------------------------------

    for target in TARGETS:

        analyze_target(
            test,
            target
        )

    # --------------------------------------------------------
    # Special encryption analysis
    # --------------------------------------------------------

    analyze_encryption_patterns(
        test
    )

    # --------------------------------------------------------
    # Complete
    # --------------------------------------------------------

    print()

    print(
        "=" * 80
    )

    print(
        "ERROR ANALYSIS COMPLETE"
    )

    print(
        "=" * 80
    )


if __name__ == "__main__":

    main()