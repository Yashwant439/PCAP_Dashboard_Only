"""
Feature Extraction Adapter
===========================

Wraps the existing feature_extractor/extractor.py so it can be called
directly from the FastAPI backend without subprocess invocation.

The extractor lives in a sibling directory at:
    <project_root>/feature_extractor/extractor.py

We temporarily add that directory to sys.path, import extract_features(),
restore sys.path, then return the feature dictionary.
"""

from __future__ import annotations

import importlib.util
import logging
import os
import sys
import tempfile
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

_PROJECT_ROOT = Path(__file__).resolve().parents[2]
_EXTRACTOR_DIR = _PROJECT_ROOT / "feature_extractor"
_EXTRACTOR_FILE = _EXTRACTOR_DIR / "extractor.py"

# The exact 18 feature names the ML models were trained on
ML_FEATURE_NAMES: list[str] = [
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


class ExtractionError(Exception):
    """Raised when feature extraction fails."""


def _import_extractor():
    """Dynamically import the extractor module from the feature_extractor directory."""
    if not _EXTRACTOR_FILE.exists():
        raise ExtractionError(
            f"Extractor script not found at: {_EXTRACTOR_FILE}"
        )

    # Check that scapy is available
    try:
        import scapy  # noqa: F401
    except ImportError:
        raise ExtractionError(
            "scapy is not installed. Run: pip install scapy"
        )

    spec = importlib.util.spec_from_file_location(
        "ipsec_extractor", _EXTRACTOR_FILE
    )
    if spec is None or spec.loader is None:
        raise ExtractionError(f"Could not load extractor spec from {_EXTRACTOR_FILE}")

    module = importlib.util.module_from_spec(spec)

    # Add the feature_extractor directory to sys.path temporarily so that
    # any relative imports inside extractor.py resolve correctly.
    original_path = sys.path[:]
    str_dir = str(_EXTRACTOR_DIR)
    try:
        if str_dir not in sys.path:
            sys.path.insert(0, str_dir)
        spec.loader.exec_module(module)  # type: ignore[union-attr]
    finally:
        sys.path[:] = original_path

    return module


def extract_features_from_bytes(pcap_bytes: bytes, original_filename: str) -> dict[str, Any]:
    """
    Write *pcap_bytes* to a temporary file, run the feature extractor,
    and return the full feature dictionary.

    Parameters
    ----------
    pcap_bytes : bytes
        Raw PCAP / PCAPNG file content.
    original_filename : str
        Original filename (used only for suffix detection).

    Returns
    -------
    dict containing all extracted features (superset of ML_FEATURE_NAMES).
    """
    suffix = Path(original_filename).suffix.lower()
    if suffix not in {".pcap", ".pcapng", ".cap"}:
        raise ExtractionError(
            f"Unsupported file format '{suffix}'. "
            "Only .pcap, .pcapng, and .cap files are supported."
        )

    if not pcap_bytes:
        raise ExtractionError("The uploaded file is empty.")

    # Write to a temporary file
    tmp_path: str | None = None
    try:
        with tempfile.NamedTemporaryFile(
            suffix=suffix, delete=False, prefix="ipsec_analysis_"
        ) as tmp:
            tmp.write(pcap_bytes)
            tmp_path = tmp.name

        logger.info(
            "Running feature extraction on '%s' (%d bytes), temp: %s",
            original_filename,
            len(pcap_bytes),
            tmp_path,
        )

        extractor = _import_extractor()
        features: dict[str, Any] = extractor.extract_features(tmp_path)

        if not isinstance(features, dict):
            raise ExtractionError(
                "Extractor returned unexpected result type."
            )

        logger.info(
            "Feature extraction complete: packet_count=%s",
            features.get("packet_count"),
        )
        return features

    except ExtractionError:
        raise
    except Exception as exc:
        logger.exception("Feature extraction failed for '%s'", original_filename)
        raise ExtractionError(
            f"Feature extraction failed: {type(exc).__name__}: {exc}"
        ) from exc
    finally:
        if tmp_path and os.path.exists(tmp_path):
            try:
                os.unlink(tmp_path)
            except OSError:
                logger.warning("Could not delete temp file: %s", tmp_path)


def validate_ml_features(features: dict[str, Any]) -> dict[str, Any]:
    """
    Extract and validate only the 18 ML feature values from the full
    feature dictionary.

    Returns a dict with exactly the 18 features needed by the models.
    Raises ExtractionError if any required feature is missing.
    """
    missing = [f for f in ML_FEATURE_NAMES if f not in features]
    if missing:
        raise ExtractionError(
            f"Extracted features are missing required ML inputs: {missing}"
        )

    return {f: features[f] for f in ML_FEATURE_NAMES}
