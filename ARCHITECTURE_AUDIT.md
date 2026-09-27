# Architecture Audit

Date: 2026-09-23
Scope: Problem Statement 26160 compared with the current repository.

## Executive Summary

The repository is a Vite/React offline dashboard with two packet parsing paths:

1. Browser TypeScript parser in `src/utils/pcapParser.ts`.
2. Optional localhost Python Scapy service in `server/scapy_analyzer.py`, called first by `src/utils/scapyClient.ts`.

The offline parser can inspect classic PCAP and PCAPNG packet bytes and can extract visible IP, UDP, IKE header, IKEv2 SA transform, ESP, AH, and traffic-shape metadata. This is the strongest implemented part of the project.

The repository does not yet implement the three-mode production architecture in the supplied specification. There is no gateway telemetry adapter, local capture agent, live capture API, cloud backend, evidence database, authentication, TLS transport, correlation service, or automated test suite. Those must not be represented as completed features.

## Current Data Flow

`App.tsx` receives a browser `File`, calls the Scapy HTTP service when available, and falls back to the TypeScript parser. The returned result is converted into `VpnCaptureScenario`. Security scoring is computed by `securityAuditor.ts`; traffic classification is computed by `aiClassifier.ts`; React components render the result.

The current path is:

`File -> Scapy or TypeScript parser -> ParsedPcapResult -> VpnCaptureScenario -> security rules + heuristic classifier -> dashboard`

There is no normalized evidence database or shared backend analysis engine yet.

## Implemented Well

- Actual packet bytes are parsed; filename and scenario labels do not determine protocol results.
- Classic PCAP and PCAPNG are accepted.
- PCAPNG section endianness, interface descriptions, enhanced packet blocks, simple packet blocks, timestamp resolution, and common link types are handled in the browser path.
- Scapy provides richer layer decoding when the local service is running.
- IPv4, IPv6, UDP, TCP metadata, ICMP, ESP, and AH are represented.
- UDP/500 and UDP/4500 are checked against IKE header structure rather than blindly labeling all UDP as IKEv2.
- IKEv2 header fields, payload chains, SPIs, message IDs, proposals, transforms, and key-length attributes are extracted when visible.
- Encrypted IKE_AUTH content is not decrypted or guessed.
- ESP SPIs and sequence numbers are kept separate from IKE SPIs.
- Evidence records include packet number, raw transform bytes, source, confidence, and field path for many cryptographic observations.
- PCAP-only unknowns such as replay-window size and unavailable PFS remain undetermined.
- The dashboard now exposes wire-visible packet and IKE observations.
- A shared field-evidence model now records value, source, confidence, status, explanation, and packet references for important SA fields.
- Real byte-level tests now verify observed IKE header fields and explicit unknown handling.
- A read-only StrongSwan telemetry adapter, exact SPI correlation module, metadata sanitizer, local agent, and localhost API boundary are implemented.
- A leakage-aware ML feature/training pipeline is implemented as a baseline; it requires an external labeled capture manifest before training.

## Important Accuracy Defects / Risks

### 1. Dashboard ML remains a heuristic baseline

`src/utils/aiClassifier.ts` remains a hand-written compatibility heuristic. The artificial confidence boost and insufficient-data issue were removed. A separate `server/ml_pipeline.py` now provides grouped capture-level evaluation, but it cannot be considered production-trained until a controlled labeled dataset is supplied.

### 2. Unknown cipher names can be scored as a pass

The security auditor treats any non-empty encryption value that is not explicitly recognized as a modern pass. Unknown transform IDs therefore risk being reported as compliant. Unknown algorithms must produce an unknown/unsupported finding, never a pass.

### 3. Security score is not an evidence-complete posture score

The score starts at 100 and gives zero-penalty Low findings for unavailable values. That can produce a high score despite missing Child-SA, lifetime, replay, and PFS evidence. The UI must distinguish `not assessed` from `safe`; a missing field must not be presented as a security pass.

### 4. IKE coverage is incomplete

The parser is primarily an IKEv2 decoder. IKEv1 is detected conservatively but its vendor/auth/proposal formats are not decoded. IKEv2 notify values, vendor IDs, NAT detection hashes, fragmentation notifications, and detailed traffic selectors are incomplete. Encrypted IKE_AUTH remains intentionally unavailable without keys.

### 5. Tunnel/transport mode is not proven

The current result remains undetermined in PCAP mode. This is correct when evidence is insufficient, but the specification requires a future evidence-based mode detector and telemetry source. It must never be filled from packet size or a demo scenario.

### 6. PFS handling must remain conservative

A visible DH transform in a CREATE_CHILD_SA proposal can support PFS evidence only after correlating the Child SA. Absence of a visible DH transform cannot prove disabled PFS. Gateway telemetry is needed for policy/negotiated certainty in many captures.

### 7. Scapy service is optional but not operationally managed

The frontend silently falls back when the service is unavailable. This is useful for usability but can reduce decoded detail without clearly identifying the active parser in the result. The UI should show parser provenance and service status.

### 8. Gateway telemetry and correlation are local-only foundations

The StrongSwan read-only `swanctl` adapter, exact SPI correlation, and unknown mismatch states now exist. VICI integration and Cisco/FortiGate/Palo Alto adapters remain absent. The adapter cannot report telemetry unless the gateway command is installed and authorized.

### 9. Local agent and localhost API are implemented; public cloud deployment is absent

The local agent, metadata sanitization boundary, HTTPS-only cloud client, request-size validation, token authorization, and localhost API are implemented. There is no persistent database, deployment-grade rate limiting/replay store, or public cloud deployment. Live capture remains unavailable.

### 10. No automated tests or real fixtures

There are no parser, IKEv1/IKEv2, ESP/AH, NAT-T, malformed-input, telemetry, correlation, ML leakage, or security-rule tests. A production claim is not supportable until fixture-based tests exist.

### 11. Demo/testbed path is synthetic, not protocol-real

The synthetic generator intentionally creates byte patterns rather than valid Ethernet/IP/IKE/ESP packets. It must remain clearly labeled as synthetic and must never be used as evidence of parser correctness.

### 12. Type-level evidence coverage is incomplete

`EvidenceRecord` remains for transform-level compatibility, while `IkeSecurityAssociation.fieldEvidence` now provides structured source/status/confidence for important scalar fields. `VpnCaptureScenario.actualTrafficType` remains a UI/testbed field rather than an evidence-backed analysis result.

## Recommended Migration Plan

1. Introduce a shared evidence value type with `value`, `source`, `confidence`, `status`, and evidence references.
2. Make the parser produce a normalized analysis document independent of React.
3. Add fixture-based tests for valid and malformed PCAP/PCAPNG, IKEv1, IKEv2, NAT-T, ESP, AH, IPv4, IPv6, and encrypted IKE_AUTH.
4. Fix security rules so unknown and unavailable values cannot receive Pass findings.
5. Replace or explicitly relabel the heuristic classifier; add minimum-data gating and calibrated confidence before calling it ML.
6. Add detailed IKEv2 notify/vendor/selector decoding and a separate IKEv1 decoder.
7. Add a StrongSwan adapter boundary using authorized VICI/swanctl output only.
8. Add SPI/time/address correlation with explicit confirmed, failed, and unknown outcomes.
9. Add local-agent capture and telemetry collection without sending payloads or keys.
10. Add sanitized authenticated TLS/cloud ingestion only after local analysis is tested.
11. Add dashboard evidence/source/status badges and parser provenance.

## Current Acceptance Status

| Requirement | Status |
|---|---|
| Real PCAP parsing | Partial, implemented offline |
| PCAPNG parsing | Partial, implemented offline |
| Evidence-based IKEv2 detection | Partial |
| Evidence-based IKEv1 detection | Header-level only |
| ESP/AH parsing | Partial |
| Encrypted-field UNKNOWN handling | Partial and improving |
| Gateway telemetry | StrongSwan read-only adapter implemented; VICI and other vendors absent |
| PCAP/telemetry correlation | Exact SPI correlation implemented |
| Local agent/live capture | Local agent implemented for PCAP; live capture absent |
| Cloud/TLS backend | Localhost API and HTTPS client implemented; public deployment/database absent |
| ML traffic classifier | Leakage-aware training baseline implemented; no production dataset/model supplied |
| Evidence traceability | Field-level model and dashboard provenance implemented |
| Security rules | Implemented baseline, requires unknown-state correction |
| Automated tests with real fixtures | Initial byte-level and Python component tests implemented; protocol coverage incomplete |

## Non-negotiable Limitations

- PCAP alone cannot reveal encrypted IKE_AUTH contents without valid decryption material.
- PCAP alone generally cannot prove configured replay-window size or SA lifetime.
- ESP packet shape cannot prove a cipher, key size, PFS policy, or tunnel mode.
- ML can classify traffic behavior only as an inference and cannot establish cryptographic parameters.
- Missing or malformed evidence must remain UNKNOWN/NOT_DETERMINABLE_FROM_PCAP.
