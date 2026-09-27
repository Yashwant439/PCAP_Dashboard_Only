"""Leakage-aware encrypted-traffic ML feature extraction and training."""

from __future__ import annotations

import argparse
import json
import statistics
from collections import Counter
from pathlib import Path
from typing import Any

import numpy as np
from sklearn.ensemble import HistGradientBoostingClassifier, RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix, f1_score, precision_score, recall_score
from sklearn.model_selection import GroupShuffleSplit
from sklearn.preprocessing import LabelEncoder

FEATURE_NAMES = (
    "packet_count", "total_bytes", "flow_duration", "packets_per_second",
    "bytes_per_second", "avg_packet_size", "std_packet_size", "min_packet_size",
    "max_packet_size", "median_packet_size", "p10_packet_size", "p90_packet_size",
    "avg_iat", "std_iat", "min_iat", "max_iat", "median_iat",
    "forward_packets", "reverse_packets", "forward_bytes", "reverse_bytes",
    "direction_ratio", "burst_count", "avg_burst_size", "max_burst_size",
    "active_time", "idle_time", "packet_size_entropy",
)


def _entropy(values: list[int]) -> float:
    if not values:
        return 0.0
    counts = Counter(values)
    total = len(values)
    return float(-sum((count / total) * np.log2(count / total) for count in counts.values()))


def _percentile(values: list[int], percent: float) -> float:
    return float(np.percentile(values, percent)) if values else 0.0


def extract_flow_features(packets: list[dict[str, Any]]) -> dict[str, float]:
    """Extract behavior features without IP, MAC, filename, SPI, or sequence leakage."""
    usable = [
        packet for packet in packets
        if packet.get("protocol") == "ESP" and packet.get("length") is not None
    ]
    if not usable:
        return {name: 0.0 for name in FEATURE_NAMES}

    lengths = [max(0, int(packet["length"])) for packet in usable]
    times = [float(packet.get("timestamp", 0.0)) for packet in usable]
    first_direction = usable[0].get("source_ip_hash")
    forward = [packet for packet in usable if packet.get("source_ip_hash") == first_direction]
    reverse = [packet for packet in usable if packet.get("source_ip_hash") != first_direction]
    iats = [max(0.0, later - earlier) for earlier, later in zip(times, times[1:])]
    duration = max(0.0, (max(times) - min(times)) / 1000.0) if len(times) > 1 else 0.0
    burst_threshold = 0.1
    burst_count = 0
    burst_sizes: list[int] = []
    current_burst = 0
    for iat in iats:
        if iat <= burst_threshold:
            current_burst += 1
        elif current_burst:
            burst_count += 1
            burst_sizes.append(current_burst)
            current_burst = 0
    if current_burst:
        burst_count += 1
        burst_sizes.append(current_burst)
    active_time = sum(iat for iat in iats if iat <= 1.0)
    idle_time = sum(iat for iat in iats if iat > 1.0)
    forward_bytes = sum(int(packet["length"]) for packet in forward)
    reverse_bytes = sum(int(packet["length"]) for packet in reverse)
    total_bytes = sum(lengths)

    return {
        "packet_count": float(len(usable)),
        "total_bytes": float(total_bytes),
        "flow_duration": duration,
        "packets_per_second": len(usable) / duration if duration else 0.0,
        "bytes_per_second": total_bytes / duration if duration else 0.0,
        "avg_packet_size": statistics.mean(lengths),
        "std_packet_size": statistics.pstdev(lengths) if len(lengths) > 1 else 0.0,
        "min_packet_size": float(min(lengths)),
        "max_packet_size": float(max(lengths)),
        "median_packet_size": statistics.median(lengths),
        "p10_packet_size": _percentile(lengths, 10),
        "p90_packet_size": _percentile(lengths, 90),
        "avg_iat": statistics.mean(iats) if iats else 0.0,
        "std_iat": statistics.pstdev(iats) if len(iats) > 1 else 0.0,
        "min_iat": min(iats) if iats else 0.0,
        "max_iat": max(iats) if iats else 0.0,
        "median_iat": statistics.median(iats) if iats else 0.0,
        "forward_packets": float(len(forward)),
        "reverse_packets": float(len(reverse)),
        "forward_bytes": float(forward_bytes),
        "reverse_bytes": float(reverse_bytes),
        "direction_ratio": min(forward_bytes, reverse_bytes) / max(forward_bytes, reverse_bytes) if max(forward_bytes, reverse_bytes) else 0.0,
        "burst_count": float(burst_count),
        "avg_burst_size": statistics.mean(burst_sizes) if burst_sizes else 0.0,
        "max_burst_size": float(max(burst_sizes, default=0)),
        "active_time": active_time,
        "idle_time": idle_time,
        "packet_size_entropy": _entropy(lengths),
    }


def _vector(features: dict[str, float]) -> list[float]:
    return [float(features.get(name, 0.0)) for name in FEATURE_NAMES]


def train_models(samples: list[dict[str, Any]], test_size: float = 0.25) -> dict[str, Any]:
    """Train grouped baselines; labels must be externally supplied ground truth."""
    if len(samples) < 4:
        return {"status": "INSUFFICIENT_DATA", "reason": "At least four labeled capture sessions are required."}
    labels = [sample.get("label") for sample in samples]
    groups = [sample.get("capture_id") for sample in samples]
    if any(not isinstance(label, str) or not label for label in labels):
        return {"status": "NOT_DETERMINABLE", "reason": "Every sample requires an external ground-truth label."}
    if len(set(labels)) < 2 or len(set(groups)) < 2:
        return {"status": "INSUFFICIENT_DATA", "reason": "At least two labels and two capture groups are required."}

    x = np.asarray([_vector(sample["features"]) for sample in samples], dtype=float)
    encoder = LabelEncoder()
    y = encoder.fit_transform(labels)
    splitter = GroupShuffleSplit(n_splits=1, test_size=test_size, random_state=42)
    train_indices, test_indices = next(splitter.split(x, y, groups))
    if len(set(y[train_indices])) < 2 or len(set(y[test_indices])) < 1:
        return {"status": "INSUFFICIENT_DATA", "reason": "Grouped split does not contain enough class diversity for a valid evaluation."}

    models = {
        "random_forest": RandomForestClassifier(n_estimators=200, random_state=42, class_weight="balanced"),
        "hist_gradient_boosting": HistGradientBoostingClassifier(random_state=42),
    }
    results: dict[str, Any] = {}
    for name, model in models.items():
        model.fit(x[train_indices], y[train_indices])
        predicted = model.predict(x[test_indices])
        results[name] = {
            "accuracy": accuracy_score(y[test_indices], predicted),
            "macro_precision": precision_score(y[test_indices], predicted, average="macro", zero_division=0),
            "macro_recall": recall_score(y[test_indices], predicted, average="macro", zero_division=0),
            "macro_f1": f1_score(y[test_indices], predicted, average="macro", zero_division=0),
            "weighted_f1": f1_score(y[test_indices], predicted, average="weighted", zero_division=0),
            "classification_report": classification_report(y[test_indices], predicted, target_names=encoder.classes_, output_dict=True, zero_division=0),
            "confusion_matrix": confusion_matrix(y[test_indices], predicted).tolist(),
        }

    try:
        from xgboost import XGBClassifier  # type: ignore
        xgb = XGBClassifier(n_estimators=100, max_depth=4, eval_metric="mlogloss", random_state=42)
        xgb.fit(x[train_indices], y[train_indices])
        predicted = xgb.predict(x[test_indices])
        results["xgboost"] = {"accuracy": accuracy_score(y[test_indices], predicted), "macro_f1": f1_score(y[test_indices], predicted, average="macro", zero_division=0)}
    except ImportError:
        results["xgboost"] = {"status": "UNAVAILABLE", "reason": "Optional xgboost dependency is not installed."}

    return {
        "status": "TRAINED",
        "source": "CONTROLLED_GROUND_TRUTH_DATASET",
        "feature_names": list(FEATURE_NAMES),
        "capture_groups": len(set(groups)),
        "classes": list(encoder.classes_),
        "models": results,
    }


def load_manifest(path: Path) -> list[dict[str, Any]]:
    records = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(records, list):
        raise ValueError("Dataset manifest must be a JSON array")
    samples = []
    for record in records:
        if not isinstance(record, dict):
            continue
        packets = record.get("packets", [])
        samples.append({
            "capture_id": record.get("capture_id"),
            "label": record.get("label"),
            "features": extract_flow_features(packets),
        })
    return samples


def main() -> int:
    parser = argparse.ArgumentParser(description="Train leakage-aware encrypted traffic baselines")
    parser.add_argument("manifest", type=Path)
    args = parser.parse_args()
    print(json.dumps(train_models(load_manifest(args.manifest)), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
