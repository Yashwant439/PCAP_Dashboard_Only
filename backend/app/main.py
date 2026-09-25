import logging
import os
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from fastapi import BackgroundTasks, FastAPI, HTTPException, UploadFile, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from .capture_parser import CaptureParseError, parse_capture
from .feature_extraction import ExtractionError, extract_features_from_bytes, validate_ml_features
from .ml_inference import InferenceError, get_model_metadata, preload_models, run_inference
from .ml_assessment import assess_ml_results
from .models import (
    AnalysisJob,
    CaptureAnalysis,
    CaptureSummary,
    ErrorResponse,
    HealthResponse,
)
from .storage import CaptureStorage

logger = logging.getLogger(__name__)


BASE_DIRECTORY = Path(__file__).resolve().parents[1]
DATA_DIRECTORY = Path(os.getenv("IPSEC_ANALYZER_DATA_DIR", BASE_DIRECTORY / "data"))
storage = CaptureStorage(DATA_DIRECTORY / "metadata.sqlite3", DATA_DIRECTORY / "captures")


def _run_analysis_job(job_id: str, capture_id: str) -> None:
    capture_path = storage.get_capture_path(capture_id)
    if capture_path is None:
        storage.update_job(job_id, "FAILED", 100, "Capture no longer exists.")
        storage.update_capture_analysis_status(capture_id, "FAILED")
        return
    try:
        storage.update_job(job_id, "RUNNING", 10, "Parsing capture packets.")
        analysis = parse_capture(capture_path.read_bytes())
        storage.update_job(job_id, "COMPLETED", 100, f"Analysis completed for {analysis.packet_count} packets.")
        storage.update_capture_analysis_status(capture_id, "COMPLETED", analysis.packet_count)
    except CaptureParseError as error:
        storage.update_job(job_id, "FAILED", 100, str(error))
        storage.update_capture_analysis_status(capture_id, "FAILED")


# ---------------------------------------------------------------------------
# Pydantic models for the ML analysis endpoint
# ---------------------------------------------------------------------------

class MLPredictionResult(BaseModel):
    prediction: str
    probabilities: dict[str, float] = Field(default_factory=dict)
    confidence: float | None = None


class MLPredictions(BaseModel):
    encryption: MLPredictionResult
    hash: MLPredictionResult
    dh_group: MLPredictionResult
    pfs_group: MLPredictionResult


class ObservedFeatures(BaseModel):
    packet_count: int
    total_bytes: int
    avg_packet_size: float
    min_packet_size: int
    max_packet_size: int
    capture_duration_seconds: float
    udp_packet_count: int
    udp_500_count: int
    ike_packet_count: int
    esp_packet_count: int
    create_child_sa_count: int
    informational_count: int
    ike_request_count: int
    ike_response_count: int
    ike_bytes: int
    ike_avg_packet_size: float
    esp_bytes: int
    esp_avg_packet_size: float
    # Additional observed (not ML features)
    ike_version_detected: str | None = None
    ike_exchange_distribution: dict[str, int] = Field(default_factory=dict)
    udp_4500_count: int = 0


class MLAnalysisResult(BaseModel):
    status: str
    analysis_timestamp: str
    file: dict[str, Any]
    observed: ObservedFeatures
    ml_predictions: MLPredictions
    security_findings: list[dict[str, Any]] = Field(default_factory=list)
    provenance: dict[str, Any] = Field(default_factory=dict)
    warnings: list[str] = Field(default_factory=list)


class MLErrorResponse(BaseModel):
    status: str = "error"
    code: str
    message: str
    details: str = ""


# ---------------------------------------------------------------------------
# Lifespan
# ---------------------------------------------------------------------------

@asynccontextmanager
async def lifespan(_: FastAPI):
    # Pre-load ML models on startup
    try:
        preload_models()
        logger.info("ML models preloaded successfully.")
    except Exception as exc:
        logger.warning("ML model preloading failed (non-fatal): %s", exc)
    yield


app = FastAPI(
    title="IPsec VPN Analyzer API",
    version="0.1.0",
    lifespan=lifespan,
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/")
@app.get("/api")
@app.get("/api/")
async def root() -> dict[str, str]:
    """Root endpoint to verify the API is running."""
    return {
        "message": "IPsec VPN Analyzer API is running.",
        "status": "ok",
        "health": "/api/health",
        "docs": "/docs"
    }


@app.get("/api/health", response_model=HealthResponse)
@app.get("/api/health/", response_model=HealthResponse, include_in_schema=False)
async def health() -> HealthResponse:
    return HealthResponse(status="ok", service="ipsec-analyzer-api", version="0.1.0")


@app.get("/api/ml-health")
@app.get("/api/ml-health/", include_in_schema=False)
async def ml_health() -> dict[str, Any]:
    """Check ML engine status and return model metadata."""
    meta = get_model_metadata()
    return {
        "status": "error" if "error" in meta else "ok",
        "models": meta,
    }


@app.post(
    "/api/ml-analyze",
    response_model=MLAnalysisResult,
    responses={
        400: {"model": MLErrorResponse},
        422: {"model": MLErrorResponse},
        503: {"model": MLErrorResponse},
    },
)
@app.post(
    "/api/ml-analyze/",
    response_model=MLAnalysisResult,
    responses={
        400: {"model": MLErrorResponse},
        422: {"model": MLErrorResponse},
        503: {"model": MLErrorResponse},
    },
    include_in_schema=False,
)
async def ml_analyze(file: UploadFile) -> MLAnalysisResult:
    """
    Full PCAP → Feature Extraction → ML Inference → Security Assessment pipeline.

    Accepts a .pcap or .pcapng file and returns:
      - Observed packet features
      - ML-predicted cryptographic parameters (encryption, hash, DH, PFS)
      - Security assessment findings
      - Provenance information
    """
    # ---- Validate upload ----
    if not file.filename:
        raise HTTPException(
            status_code=400,
            detail={"status": "error", "code": "NO_FILE",
                    "message": "No filename provided."},
        )

    suffix = Path(file.filename).suffix.lower()
    if suffix not in {".pcap", ".pcapng", ".cap"}:
        raise HTTPException(
            status_code=400,
            detail={
                "status": "error",
                "code": "UNSUPPORTED_FORMAT",
                "message": f"Unsupported file format '{suffix}'. Use .pcap or .pcapng.",
            },
        )

    content = await file.read()
    if not content:
        raise HTTPException(
            status_code=400,
            detail={"status": "error", "code": "EMPTY_FILE",
                    "message": "The uploaded file is empty."},
        )

    MAX_SIZE = 100 * 1024 * 1024  # 100 MB
    if len(content) > MAX_SIZE:
        raise HTTPException(
            status_code=400,
            detail={"status": "error", "code": "FILE_TOO_LARGE",
                    "message": "File exceeds 100 MB limit."},
        )

    warnings: list[str] = []
    analysis_timestamp = datetime.now(UTC).isoformat()

    # ---- Feature Extraction ----
    try:
        raw_features = extract_features_from_bytes(content, file.filename)
    except ExtractionError as exc:
        logger.warning("Feature extraction failed for '%s': %s", file.filename, exc)
        raise HTTPException(
            status_code=422,
            detail={
                "status": "error",
                "code": "FEATURE_EXTRACTION_FAILED",
                "message": "The PCAP could not be analyzed.",
                "details": str(exc),
            },
        ) from exc
    except Exception as exc:
        logger.exception("Unexpected extraction error for '%s'", file.filename)
        raise HTTPException(
            status_code=422,
            detail={
                "status": "error",
                "code": "EXTRACTION_UNEXPECTED_ERROR",
                "message": "An unexpected error occurred during feature extraction.",
                "details": str(exc),
            },
        ) from exc

    # Warn if very few packets
    if raw_features.get("packet_count", 0) < 5:
        warnings.append(
            f"Only {raw_features.get('packet_count', 0)} packets extracted. "
            "ML predictions may be unreliable for very small captures."
        )

    # ---- Validate ML features ----
    try:
        ml_features = validate_ml_features(raw_features)
    except ExtractionError as exc:
        raise HTTPException(
            status_code=422,
            detail={
                "status": "error",
                "code": "MISSING_ML_FEATURES",
                "message": "Required ML features could not be extracted.",
                "details": str(exc),
            },
        ) from exc

    # ---- ML Inference ----
    try:
        ml_predictions_raw = run_inference(ml_features)
    except InferenceError as exc:
        logger.error("ML inference failed: %s", exc)
        raise HTTPException(
            status_code=503,
            detail={
                "status": "error",
                "code": "ML_INFERENCE_FAILED",
                "message": "ML model inference could not be completed.",
                "details": str(exc),
            },
        ) from exc
    except Exception as exc:
        logger.exception("Unexpected inference error")
        raise HTTPException(
            status_code=503,
            detail={
                "status": "error",
                "code": "ML_UNEXPECTED_ERROR",
                "message": "An unexpected error occurred during ML inference.",
                "details": str(exc),
            },
        ) from exc

    # ---- Security Assessment ----
    security_findings = assess_ml_results(ml_predictions_raw, raw_features)

    # ---- Build response ----
    observed = ObservedFeatures(
        packet_count=raw_features.get("packet_count", 0),
        total_bytes=raw_features.get("total_bytes", 0),
        avg_packet_size=raw_features.get("avg_packet_size", 0.0),
        min_packet_size=raw_features.get("min_packet_size", 0),
        max_packet_size=raw_features.get("max_packet_size", 0),
        capture_duration_seconds=raw_features.get("capture_duration_seconds", 0.0),
        udp_packet_count=raw_features.get("udp_packet_count", 0),
        udp_500_count=raw_features.get("udp_500_count", 0),
        udp_4500_count=raw_features.get("udp_4500_count", 0),
        ike_packet_count=raw_features.get("ike_packet_count", 0),
        esp_packet_count=raw_features.get("esp_packet_count", 0),
        create_child_sa_count=raw_features.get("create_child_sa_count", 0),
        informational_count=raw_features.get("informational_count", 0),
        ike_request_count=raw_features.get("ike_request_count", 0),
        ike_response_count=raw_features.get("ike_response_count", 0),
        ike_bytes=raw_features.get("ike_bytes", 0),
        ike_avg_packet_size=raw_features.get("ike_avg_packet_size", 0.0),
        esp_bytes=raw_features.get("esp_bytes", 0),
        esp_avg_packet_size=raw_features.get("esp_avg_packet_size", 0.0),
        ike_version_detected=raw_features.get("ike_version_detected"),
        ike_exchange_distribution=raw_features.get("ike_exchange_distribution", {}),
    )

    ml_predictions = MLPredictions(
        encryption=MLPredictionResult(**ml_predictions_raw["encryption"]),
        hash=MLPredictionResult(**ml_predictions_raw["hash"]),
        dh_group=MLPredictionResult(**ml_predictions_raw["dh_group"]),
        pfs_group=MLPredictionResult(**ml_predictions_raw["pfs_group"]),
    )

    provenance = {
        "input_file": file.filename,
        "file_size_bytes": len(content),
        "analysis_timestamp": analysis_timestamp,
        "extractor_schema_version": "1.1",
        "model_dir": "feature_extractor/ml/models",
        "models_used": ["encryption_model", "hash_model", "dh_group_model", "pfs_group_model"],
        "confidence_thresholds": {
            "high": 0.80,
            "medium": 0.55,
        },
    }

    return MLAnalysisResult(
        status="success",
        analysis_timestamp=analysis_timestamp,
        file={"name": file.filename, "size_bytes": len(content)},
        observed=observed,
        ml_predictions=ml_predictions,
        security_findings=security_findings,
        provenance=provenance,
        warnings=warnings,
    )


@app.post(
    "/api/captures",
    response_model=CaptureSummary,
    status_code=status.HTTP_201_CREATED,
    responses={400: {"model": ErrorResponse}},
)
@app.post(
    "/api/captures/",
    response_model=CaptureSummary,
    status_code=status.HTTP_201_CREATED,
    responses={400: {"model": ErrorResponse}},
    include_in_schema=False,
)
@app.post(
    "/api/upload",
    response_model=CaptureSummary,
    status_code=status.HTTP_201_CREATED,
    responses={400: {"model": ErrorResponse}},
    include_in_schema=False,
)
@app.post(
    "/api/upload/",
    response_model=CaptureSummary,
    status_code=status.HTTP_201_CREATED,
    responses={400: {"model": ErrorResponse}},
    include_in_schema=False,
)
async def upload_capture(file: UploadFile) -> CaptureSummary:
    if not file.filename:
        raise HTTPException(status_code=400, detail="A capture filename is required.")
    content = await file.read()
    if not content:
        raise HTTPException(status_code=400, detail="The capture file is empty.")
    suffix = Path(file.filename).suffix.lower()
    capture_format = "PCAPNG" if suffix == ".pcapng" else "PCAP" if suffix in {".pcap", ".cap"} else "UNKNOWN"
    return storage.save_capture(file.filename, file.content_type, content, capture_format)


@app.get("/api/captures", response_model=list[CaptureSummary])
@app.get("/api/captures/", response_model=list[CaptureSummary], include_in_schema=False)
async def list_captures() -> list[CaptureSummary]:
    return storage.list_captures()


@app.get(
    "/api/captures/{capture_id}",
    response_model=CaptureSummary,
    responses={404: {"model": ErrorResponse}},
)
async def get_capture(capture_id: str) -> CaptureSummary:
    capture = storage.get_capture(capture_id)
    if capture is None:
        raise HTTPException(status_code=404, detail="Capture not found.")
    return capture


@app.post(
    "/api/captures/{capture_id}/analyze",
    response_model=AnalysisJob,
    status_code=status.HTTP_202_ACCEPTED,
    responses={404: {"model": ErrorResponse}},
)
async def create_analysis_job(capture_id: str, background_tasks: BackgroundTasks) -> AnalysisJob:
    if storage.get_capture(capture_id) is None:
        raise HTTPException(status_code=404, detail="Capture not found.")
    job = storage.create_job(capture_id)
    background_tasks.add_task(_run_analysis_job, job.job_id, capture_id)
    return job


@app.get(
    "/api/analyze/{job_id}",
    response_model=AnalysisJob,
    responses={404: {"model": ErrorResponse}},
)
async def get_analysis_job(job_id: str) -> AnalysisJob:
    job = storage.get_job(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="Analysis job not found.")
    return job


@app.get("/api/captures/{capture_id}/analysis", response_model=CaptureAnalysis)
async def get_analysis(capture_id: str) -> CaptureAnalysis:
    capture_path = storage.get_capture_path(capture_id)
    if capture_path is None:
        raise HTTPException(status_code=404, detail="Capture not found.")
    try:
        return parse_capture(capture_path.read_bytes())
    except CaptureParseError as error:
        raise HTTPException(status_code=422, detail=str(error)) from error
