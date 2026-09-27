# Executive security report

Capture: AES128_SHA256_DH14_NOPFS_ICMP_rep01
Generated: 2026-09-27T16:55:09.337Z

## Executive summary
- The IPsec capture (40 packets, 6.8 KB) shows an IKEv2 exchange using AES-128-CBC and HMAC-SHA2-256-128 over DH Group 14. The overall score is 54 (Weak), with 60% evidence coverage. One low-severity observed risk (F1) flags the use of CBC mode, which is susceptible to padding oracle attacks if timing side-channels exist. Two low-severity evidence gaps (F2, F3) indicate that Perfect Forward Secrecy and anti-replay window settings could not be assessed from the capture. Traffic features suggest a VoIP/audio pattern (60% relative pattern score, derived from observed data), but encrypted payload contents are not visible. No confirmed vulnerabilities or compliance claims are made.

## Security and risk
- Evidence-adjusted security score: 54/100 (Weak).
- Observed configuration risk score: 10/100. This is a rule-based penalty, not the probability of an attack.
- Evidence coverage: 60% (PARTIAL). Unknown controls receive no security credit.

## Traffic and metadata inference
- Inferred workload: VoIP / Audio Call.
- Traffic pattern match: 60%. This is a relative heuristic score, not calibrated model confidence.
- Wire metadata: 6 IKE and 40 ESP frames; NAT traversal Not detected.
- Application identity and encrypted contents cannot be confirmed from packet metadata.

## AI confidence
- AI confidence score: 93%.
- Mean predicted-class probability across 4 available cryptographic inference models; this is not measured accuracy.

## Threat matrix and remediation

| Severity | Control / threat | Observed | Penalty | Action |
| --- | --- | --- | --- | --- |
| Low | Symmetric Encryption Cipher: Cipher Block Chaining Mode Padding Attacks | AES-CBC | 10 | Prefer Authenticated Encryption with Associated Data (AEAD) modes like AES-GCM or ChaCha20-Poly1305. |

## Evidence gaps
- Perfect Forward Secrecy (PFS): Not observed in capture. Capture CREATE_CHILD_SA exchanges or provide an explicit Child SA configuration.
- Anti-Replay Window Protection: Not observed in capture. Provide Child SA configuration or negotiated ESN evidence.
