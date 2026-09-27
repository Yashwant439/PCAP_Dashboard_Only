# API Documentation

## 1. FastAPI Production Backend (`http://127.0.0.1:8000`)

### `POST /api/ml-analyze`
Full end-to-end PCAP ML Inference & Security Assessment pipeline.

- **Request**: `multipart/form-data` with file field (`.pcap`, `.pcapng`, or `.cap`). Max 100 MB.
- **Response**: `200 OK` JSON containing:
  ```json
  {
    "status": "success",
    "analysis_timestamp": "2026-09-26T00:00:00Z",
    "file": { "name": "sample.pcap", "size_bytes": 10240 },
    "observed": { ... },
    "ml_predictions": {
      "encryption": { "prediction": "AES256", "probabilities": { "AES128": 0.03, "AES256": 0.97 }, "confidence": 0.97 },
      "hash": { "prediction": "SHA384", "probabilities": { "SHA256": 0.01, "SHA384": 0.99 }, "confidence": 0.99 },
      "dh_group": { "prediction": "DH15", "probabilities": { "DH14": 0.02, "DH15": 0.98 }, "confidence": 0.98 },
      "pfs_group": { "prediction": "PFS15", "probabilities": { "NOPFS": 0.0, "PFS14": 0.01, "PFS15": 0.99 }, "confidence": 0.99 }
    },
    "security_findings": [ ... ],
    "provenance": { ... },
    "warnings": []
  }
  ```

### `GET /api/ml-health`
Returns health status and model loading metadata for the 4 joblib ML models.

---

## 2. Local Scapy Analyzer (`http://127.0.0.1:8765`)

### `POST /analyze`
- **Headers**:
  - `Content-Type: application/octet-stream`
  - `X-Filename: capture.pcap`
- **Body**: Raw PCAP / PCAPNG bytes
- **Response**: JSON containing `scenarioName`, `packets`, `sa`, `features`, `fileSizeBytes`, `evidence`, `mlPredictions`, `mlSecurityFindings`, `mlWarning`.

---

## 3. Gateway & Persistence API (`http://127.0.0.1:8770`)

- `POST /api/analyze/pcap`: Persists sanitized analysis session and returns `analysisId`.
- `GET /api/analysis/{analysisId}`: Retrieves stored session.
- `GET /api/analysis/{analysisId}/telemetry`: Correlates session with gateway telemetry.
- `POST /api/gateways`: Enrolls a new VPN gateway agent.
- `GET /api/gateways`: Lists enrolled gateways.
