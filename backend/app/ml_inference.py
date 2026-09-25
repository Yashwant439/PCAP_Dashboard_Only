"""
IPsec ML Inference Module
=========================

Loads the four trained joblib models once at module level and exposes
a single `run_inference(feature_dict)` function.

Models expected in:
    feature_extractor/ml/models/*.joblib

Each model package contains:
    {
        "model":    <fitted sklearn estimator>,
        "features": <list of str — exact feature names in training order>,
    }

The 18 ML features expected are:
    packet_count, total_bytes, avg_packet_size, min_packet_size,
    max_packet_size, capture_duration_seconds, udp_packet_count,
    udp_500_count, ike_packet_count, esp_packet_count,
    create_child_sa_count, informational_count, ike_request_count,
    ike_response_count, ike_bytes, ike_avg_packet_size,
    esp_bytes, esp_avg_packet_size
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

_BACKEND_DIR = Path(__file__).resolve().parents[1]
_PROJECT_ROOT = _BACKEND_DIR.parent
_MODEL_DIR = _PROJECT_ROOT / "feature_extractor" / "ml" / "models"

# ---------------------------------------------------------------------------
# ML targets
# ---------------------------------------------------------------------------

TARGETS = ["encryption", "hash", "dh_group", "pfs_group"]

# ---------------------------------------------------------------------------
# Lazy-loaded model cache (loaded on first call, not at import time so the
# backend can start without joblib / scikit-learn installed).
# ---------------------------------------------------------------------------

_model_cache: dict[str, tuple[Any, list[str]]] | None = None
_load_error: str | None = None


def _load_models() -> None:
    """Load all four models into the module-level cache."""
    global _model_cache, _load_error

    try:
        import joblib  # type: ignore
    except ImportError:
        _load_error = "joblib is not installed. Run: pip install joblib scikit-learn"
        logger.error(_load_error)
        return

    try:
        import pandas  # noqa: F401  – confirm pandas is also available
    except ImportError:
        _load_error = "pandas is not installed. Run: pip install pandas"
        logger.error(_load_error)
        return

    cache: dict[str, tuple[Any, list[str]]] = {}
    for target in TARGETS:
        model_path = _MODEL_DIR / f"{target}_model.joblib"
        if not model_path.exists():
            _load_error = f"Model file not found: {model_path}"
            logger.error(_load_error)
            return
        try:
            package = joblib.load(model_path)
            model = package["model"]
            features: list[str] = package["features"]
            cache[target] = (model, features)
            logger.info("Loaded model for '%s' (%d features)", target, len(features))
        except Exception as exc:
            _load_error = f"Failed to load model '{target}': {exc}"
            logger.exception(_load_error)
            return

    _model_cache = cache
    logger.info("All four ML models loaded successfully from %s", _MODEL_DIR)


def get_model_metadata() -> dict[str, Any]:
    """Return non-sensitive metadata about the models."""
    if _model_cache is None:
        _load_models()

    if _load_error:
        return {"error": _load_error}

    import joblib  # type: ignore

    meta_path = _MODEL_DIR / "model_metadata.joblib"
    raw: dict[str, Any] = {}
    if meta_path.exists():
        try:
            raw = joblib.load(meta_path)
        except Exception:
            pass

    return {
        "model_dir": str(_MODEL_DIR),
        "targets": TARGETS,
        "models_loaded": list(_model_cache.keys()) if _model_cache else [],
        "feature_counts": {
            target: len(feats)
            for target, (_, feats) in (_model_cache or {}).items()
        },
        "metadata": raw,
    }


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

class InferenceError(Exception):
    """Raised when inference cannot be completed."""


def run_inference(feature_dict: dict[str, Any]) -> dict[str, Any]:
    """
    Run the four trained models against *feature_dict* extracted from a PCAP.

    Returns
    -------
    {
        "encryption": {
            "prediction": "AES256",
            "probabilities": {"AES128": 0.18, "AES256": 0.82},
            "confidence": 0.82,
        },
        "hash": { ... },
        "dh_group": { ... },
        "pfs_group": { ... },
    }
    """
    global _model_cache, _load_error

    if _model_cache is None:
        _load_models()

    if _load_error:
        raise InferenceError(_load_error)

    if _model_cache is None:
        raise InferenceError("Models could not be loaded.")

    try:
        import pandas as pd  # type: ignore
    except ImportError as exc:
        raise InferenceError("pandas is required for inference") from exc

    results: dict[str, Any] = {}

    for target in TARGETS:
        model, feature_names = _model_cache[target]

        # Validate all required features exist
        missing = [f for f in feature_names if f not in feature_dict]
        if missing:
            raise InferenceError(
                f"Missing features for model '{target}': {missing}"
            )

        # Build DataFrame in exact training order
        X = pd.DataFrame([{f: feature_dict[f] for f in feature_names}])

        # Predict
        prediction = str(model.predict(X)[0])

        # Probabilities
        probabilities: dict[str, float] = {}
        confidence: float | None = None
        if hasattr(model, "predict_proba"):
            prob_values = model.predict_proba(X)[0]
            classes = model.classes_
            probabilities = {
                str(cls): float(p) for cls, p in zip(classes, prob_values)
            }
            confidence = probabilities.get(prediction)

        results[target] = {
            "prediction": prediction,
            "probabilities": probabilities,
            "confidence": confidence,
        }

    return results


def preload_models() -> None:
    """Call during app startup to pre-warm the model cache."""
    _load_models()
