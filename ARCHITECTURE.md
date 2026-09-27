# AI-Based IPsec PCAP Analyzer — Production Architecture

## Overview

The system features a hybrid dual-flow analysis engine designed for technical evaluation and SIH demonstration. It distinguishes between deterministic protocol parsing (wire ground-truth) and machine-learning predictions (for unknown/encrypted PCAP files).

```
                            ┌─────────────────────────────────────────┐
                            │            PCAP / PCAPNG Input          │
                            └────────────────────┬────────────────────┘
                                                 │
                        ┌────────────────────────┴────────────────────────┐
                        ▼                                                 ▼
             FLOW A: DETERMINISTIC PARSER                       FLOW B: UNKNOWN PCAP ML INFERENCE
     ┌───────────────────────────────────────┐         ┌─────────────────────────────────────────────────┐
     │ • Layer decoding (IKE, ESP, AH, IP)   │         │ • Extract 18 packet & statistical features      │
     │ • Wire-visible SPI & sequence numbers │         │ • Schema validation & feature ordering          │
     │ • IKE proposal transform parsing      │         │ • Predict: Encryption, Hash, DH Group, PFS      │
     │ • Unencrypted evidence extraction     │         │ • 4 Trained Scikit-Learn Joblib Models          │
     └──────────────────┬────────────────────┘         └────────────────────────┬────────────────────────┘
                        │                                                       │
                        │                       ┌───────────────────────────────┘
                        ▼                       ▼
     ┌───────────────────────────────────────────────────────────────────────────────────────────────────┐
     │                               SECURITY INTERPRETATION ENGINE                                      │
     │  • Explicit provenance tagging: OBSERVED vs ML_INFERRED vs GATEWAY_TELEMETRY vs UNKNOWN           │
     │  • Conservative security rules (NIST SP 800-77, RFC 8221, NSA CNSA Suite)                         │
     │  • Confidence ratings (HIGH >=80%, MEDIUM >=55%, LOW <55%)                                        │
     └──────────────────────────────────────────────────┬────────────────────────────────────────────────┘
                                                        │
                                                        ▼
     ┌───────────────────────────────────────────────────────────────────────────────────────────────────┐
     │                                     UNIFIED BACKEND & FRONTEND                                    │
     │  • FastAPI Backend (/api/ml-analyze, /api/health) & Scapy Server (port 8765)                      │
     │  • Mode 3 Gateway Telemetry correlation (StrongSwan VICI / swanctl exact SPI matching)            │
     │  • Modern React 19 / Vite Dark-Themed SOC Dashboard UI                                            │
     └───────────────────────────────────────────────────────────────────────────────────────────────────┘
```

## Data Flow Architecture

### Flow A: Known / Structured Analysis (Deterministic Wire Ground Truth)
1. **PCAP Parsing**: Scapy & browser decoders extract raw frames, IPv4/IPv6, UDP 500/4500, IKE header structures, ESP/AH headers, SPIs, and sequence numbers.
2. **Transform Extraction**: Parses unencrypted IKEv2 SA proposals (Encryption, PRF, Integrity, DH Group).
3. **Traceability**: All wire observations are assigned `basis: "observed"` with packet index references.

### Flow B: Unknown PCAP ML Analysis (Predictive Inference)
1. **Feature Extraction**: `feature_extractor/extractor.py` extracts 18 features (packet counts, total bytes, min/max/avg packet size, duration, UDP 500/4500 counts, IKE/ESP counts, request/response counts, IKE/ESP bytes & avg sizes).
2. **ML Preprocessing & Validation**: `backend/app/feature_extraction.py` validates feature schema and constructs pandas DataFrame in exact training order.
3. **ML Model Inference**: `backend/app/ml_inference.py` runs 4 trained joblib models:
   - `encryption_model.joblib`: Predicts AES256 vs AES128
   - `hash_model.joblib`: Predicts SHA384 vs SHA256
   - `dh_group_model.joblib`: Predicts DH Group 15 vs DH Group 14
   - `pfs_group_model.joblib`: Predicts PFS15 vs PFS14 vs NOPFS
4. **Probability & Confidence**: Calculates class probability breakdown and assigns confidence thresholds (HIGH ≥80%, MEDIUM ≥55%, LOW <55%).
5. **Security Assessment**: `backend/app/ml_assessment.py` produces structured security findings tagged with `basis: "ml_inferred"`.

### Mode 3 Gateway Correlation
Optional StrongSwan telemetry adapter (VICI or `swanctl --list-sas --raw`) fetches kernel SA state and correlates exact SPI hex strings with PCAP packets.

## Database & Persistence
Local API persists sanitized analysis sessions in SQLite (`data/analyzer.sqlite3` or `data/metadata.sqlite3`). Raw packet payloads, private keys, and pre-shared keys are explicitly excluded.
