# import pandas as pd
# import joblib

# from pathlib import Path


# # ============================================================
# # IPsec ML PREDICTION / INFERENCE
# # ============================================================
# #
# # Purpose:
# #   Load the trained IPsec ML models and predict:
# #
# #       encryption
# #       hash
# #       dh_group
# #       pfs_group
# #
# # Input:
# #   A CSV containing the extracted features from a PCAP.
# #
# # Important:
# #   The input must contain the same 18 ML features used during
# #   model training.
# #
# # Context columns such as repetition and traffic are ignored.
# #
# # ============================================================


# SCRIPT_DIR = Path(__file__).resolve().parent

# MODEL_DIR = SCRIPT_DIR / "models"


# # ============================================================
# # TARGET MODELS
# # ============================================================

# TARGETS = [
#     "encryption",
#     "hash",
#     "dh_group",
#     "pfs_group",
# ]


# # ============================================================
# # LOAD MODEL
# # ============================================================

# def load_model(target):

#     model_file = MODEL_DIR / f"{target}_model.joblib"

#     if not model_file.exists():

#         raise FileNotFoundError(
#             f"Model not found: {model_file}"
#         )

#     package = joblib.load(model_file)

#     return (
#         package["model"],
#         package["features"]
#     )


# # ============================================================
# # PREDICT ONE FEATURE ROW
# # ============================================================

# def predict_features(feature_row):

#     predictions = {}

#     probabilities = {}

#     for target in TARGETS:

#         model, features = load_model(target)

#         # ----------------------------------------------------
#         # Create input DataFrame using the exact feature order
#         # used during training.
#         # ----------------------------------------------------

#         X = pd.DataFrame(
#             [feature_row]
#         )

#         missing_features = [
#             feature
#             for feature in features
#             if feature not in X.columns
#         ]

#         if missing_features:

#             raise ValueError(
#                 f"Missing features for {target}: "
#                 f"{missing_features}"
#             )

#         X = X[features]

#         # ----------------------------------------------------
#         # Prediction
#         # ----------------------------------------------------

#         prediction = model.predict(X)[0]

#         predictions[target] = prediction

#         # ----------------------------------------------------
#         # Prediction probabilities
#         # ----------------------------------------------------

#         if hasattr(model, "predict_proba"):

#             probability_values = model.predict_proba(X)[0]

#             classes = model.classes_

#             target_probabilities = {
#                 str(class_name): float(probability)
#                 for class_name, probability
#                 in zip(
#                     classes,
#                     probability_values
#                 )
#             }

#             probabilities[target] = target_probabilities

#     return predictions, probabilities


# # ============================================================
# # PRINT RESULT
# # ============================================================

# def print_prediction(
#     predictions,
#     probabilities
# ):

#     print()
#     print("=" * 80)
#     print("IPsec CRYPTOGRAPHIC PREDICTION")
#     print("=" * 80)

#     print()

#     print(
#         f"Encryption : {predictions['encryption']}"
#     )

#     print(
#         f"Hash       : {predictions['hash']}"
#     )

#     print(
#         f"DH Group   : {predictions['dh_group']}"
#     )

#     print(
#         f"PFS Group  : {predictions['pfs_group']}"
#     )

#     print()

#     print("-" * 80)
#     print("MODEL PROBABILITIES")
#     print("-" * 80)

#     for target in TARGETS:

#         print()
#         print(
#             target.upper()
#         )

#         for class_name, probability in (
#             probabilities[target].items()
#         ):

#             print(
#                 f"  {class_name:<10} "
#                 f"{probability * 100:>6.2f}%"
#             )

#     print()
#     print("=" * 80)


# # ============================================================
# # CSV INPUT
# # ============================================================

# def predict_from_csv(csv_file):

#     csv_file = Path(csv_file)

#     if not csv_file.exists():

#         raise FileNotFoundError(
#             f"Input CSV not found: {csv_file}"
#         )

#     df = pd.read_csv(csv_file)

#     if len(df) == 0:

#         raise ValueError(
#             "Input CSV contains no rows."
#         )

#     if len(df) > 1:

#         print(
#             f"WARNING: CSV contains {len(df)} rows."
#         )

#         print(
#             "Only the first row will be predicted."
#         )

#     feature_row = df.iloc[0].to_dict()

#     return predict_features(
#         feature_row
#     )


# # ============================================================
# # MAIN
# # ============================================================

# def main():

#     print("=" * 80)
#     print("IPsec ML PREDICTION")
#     print("=" * 80)

#     print()
#     print("Enter the path to a CSV containing extracted")
#     print("features from one PCAP.")
#     print()

#     csv_path = input(
#         "Feature CSV path: "
#     ).strip()

#     if not csv_path:

#         print()
#         print("ERROR: No CSV path provided.")
#         return

#     try:

#         predictions, probabilities = (
#             predict_from_csv(csv_path)
#         )

#         print_prediction(
#             predictions,
#             probabilities
#         )

#     except Exception as error:

#         print()
#         print("=" * 80)
#         print("PREDICTION ERROR")
#         print("=" * 80)

#         print()
#         print(error)

#         print()


# if __name__ == "__main__":

#     main()












import json
import pandas as pd
import joblib

from pathlib import Path


# ============================================================
# IPsec ML PREDICTION / INFERENCE
# ============================================================
#
# Input:
#   Extractor-generated *_features.json
#
# Output:
#   Predictions for:
#       encryption
#       hash
#       dh_group
#       pfs_group
#
# The JSON contains more fields than the ML model needs.
# Only the exact features stored with each trained model
# are passed to that model.
#
# ============================================================


SCRIPT_DIR = Path(__file__).resolve().parent
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
# LOAD EXTRACTOR JSON
# ============================================================

def load_feature_json(json_file):

    json_file = Path(json_file)

    if not json_file.exists():
        raise FileNotFoundError(
            f"Feature JSON not found: {json_file}"
        )

    with open(json_file, "r", encoding="utf-8") as file:
        data = json.load(file)

    if "features" not in data:
        raise ValueError(
            "Invalid feature JSON: missing 'features' object."
        )

    feature_data = data["features"]

    if not isinstance(feature_data, dict):
        raise ValueError(
            "Invalid feature JSON: 'features' must be an object."
        )

    return data, feature_data


# ============================================================
# PREDICT ONE FEATURE ROW
# ============================================================

def predict_features(feature_row):

    predictions = {}
    probabilities = {}

    for target in TARGETS:

        model, features = load_model(target)

        # ----------------------------------------------------
        # Check that every feature required by this model
        # exists in the extractor output.
        # ----------------------------------------------------

        missing_features = [
            feature
            for feature in features
            if feature not in feature_row
        ]

        if missing_features:

            raise ValueError(
                f"Missing features for {target}: "
                f"{missing_features}"
            )

        # ----------------------------------------------------
        # Create DataFrame using EXACT training feature order.
        # ----------------------------------------------------

        X = pd.DataFrame(
            [
                {
                    feature: feature_row[feature]
                    for feature in features
                }
            ]
        )

        # ----------------------------------------------------
        # Prediction
        # ----------------------------------------------------

        prediction = model.predict(X)[0]

        predictions[target] = prediction

        # ----------------------------------------------------
        # Prediction probabilities
        # ----------------------------------------------------

        if hasattr(model, "predict_proba"):

            probability_values = model.predict_proba(X)[0]

            classes = model.classes_

            target_probabilities = {
                str(class_name): float(probability)
                for class_name, probability
                in zip(
                    classes,
                    probability_values
                )
            }

            probabilities[target] = target_probabilities

    return predictions, probabilities


# ============================================================
# PRINT RESULT
# ============================================================

def print_prediction(
    json_file,
    metadata,
    predictions,
    probabilities
):

    print()
    print("=" * 80)
    print("IPsec CRYPTOGRAPHIC PREDICTION")
    print("=" * 80)

    print()
    print(f"Input : {json_file}")

    if metadata.get("source_pcap"):
        print(
            f"PCAP  : {metadata['source_pcap']}"
        )

    print()

    print("-" * 80)
    print("PREDICTED CRYPTOGRAPHIC PARAMETERS")
    print("-" * 80)

    print()

    print(
        f"Encryption : {predictions['encryption']}"
    )

    print(
        f"Hash       : {predictions['hash']}"
    )

    print(
        f"DH Group   : {predictions['dh_group']}"
    )

    print(
        f"PFS Group  : {predictions['pfs_group']}"
    )

    print()

    print("-" * 80)
    print("MODEL PROBABILITIES")
    print("-" * 80)

    for target in TARGETS:

        print()
        print(target.upper())

        for class_name, probability in (
            probabilities.get(target, {}).items()
        ):

            print(
                f"  {class_name:<10} "
                f"{probability * 100:>6.2f}%"
            )

    print()
    print("=" * 80)


# ============================================================
# JSON INPUT
# ============================================================

def predict_from_json(json_file):

    metadata, feature_data = load_feature_json(
        json_file
    )

    predictions, probabilities = predict_features(
        feature_data
    )

    return (
        metadata,
        predictions,
        probabilities
    )


# ============================================================
# MAIN
# ============================================================

def main():

    print("=" * 80)
    print("IPsec ML PREDICTION")
    print("=" * 80)

    print()
    print(
        "Enter the path to an extractor-generated "
        "*_features.json file."
    )

    print()

    json_path = input(
        "Feature JSON path: "
    ).strip()

    if not json_path:

        print()
        print("ERROR: No JSON path provided.")
        return

    try:

        (
            metadata,
            predictions,
            probabilities
        ) = predict_from_json(json_path)

        print_prediction(
            json_path,
            metadata,
            predictions,
            probabilities
        )

    except Exception as error:

        print()
        print("=" * 80)
        print("PREDICTION ERROR")
        print("=" * 80)

        print()
        print(error)

        print()


if __name__ == "__main__":
    main()