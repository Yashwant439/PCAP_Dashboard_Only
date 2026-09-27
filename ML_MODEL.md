# ML Pipeline & Cryptographic Model Specification

## Overview

The application incorporates a two-layer machine learning system:

1. **IPsec Cryptographic Parameter Predictor** (`feature_extractor/ml/models/` & `backend/app/ml_inference.py`)
2. **Traffic Workload Classifier** (`src/utils/aiClassifier.ts` & `server/ml_pipeline.py`)

---

## 1. Cryptographic Parameter Inference Models

Four trained Random Forest models predict IPsec cryptographic parameters for unknown/encrypted PCAPs without requiring decryption material.

### Model Artifacts (`feature_extractor/ml/models/`)
- `encryption_model.joblib`: Predicts encryption cipher (`AES256`, `AES128`)
- `hash_model.joblib`: Predicts integrity algorithm (`SHA384`, `SHA256`)
- `dh_group_model.joblib`: Predicts key exchange group (`DH15`, `DH14`)
- `pfs_group_model.joblib`: Predicts PFS configuration (`PFS15`, `PFS14`, `NOPFS`)

### Exact Feature Input (18 Features)
Models expect the following feature vector extracted by `feature_extractor/extractor.py`:

```json
[
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
  "esp_avg_packet_size"
]
```

### Output Format & Confidence Thresholds
Each model returns:
- `prediction`: Top predicted class string
- `probabilities`: Dict of class names to probability floats `[0.0, 1.0]`
- `confidence`: Highest probability float

Confidence levels:
- **HIGH**: Confidence ≥ 80% (0.80)
- **MEDIUM**: Confidence ≥ 55% (0.55)
- **LOW**: Confidence < 55% (0.55)

---

## 2. Statistical Workload Classifier

The workload classifier infers tunnel application traffic (VoIP, Video Streaming, Web Browsing, Bulk Data, Telemetry) from ESP flow shape statistics (packet length distribution, entropy, inter-arrival time, burstiness, flow symmetry).

### Leakage Prevention
Raw IP addresses, MAC addresses, filenames, SPIs, and sequence numbers are explicitly excluded from features to prevent identity or session memorization.