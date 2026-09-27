# Technical security report

Capture: AES128_SHA256_DH14_NOPFS_ICMP_rep01
Generated: 2026-09-27T16:55:09.925Z

## Technical interpretation
- The capture contains 40 packets totaling 6,800 bytes with a mean packet length of 170 bytes and zero standard deviation, indicating uniform packet sizes. The mean inter-arrival time is 2.6 ms with a burst ratio of 0.9 and flow symmetry of 0.99, suggesting a steady, bidirectional flow. Calculated entropy is 7.752, consistent with encrypted traffic. The IKEv2 negotiation specifies AES-128-CBC for encryption and AUTH-HMAC-SHA2-256-128 for integrity, with DH Group 14 (2048-bit MODP). PFS, key lifetime, and replay protection parameters are not present in the capture, leaving these aspects unassessed. The operational mode is not determined from the capture. No plaintext or application-layer data is visible due to encryption.

## Security and risk
- Evidence-adjusted security score: 54/100 (Weak).
- Observed configuration risk score: 10/100. This is a rule-based penalty, not the probability of an attack.
- Evidence coverage: 60% (PARTIAL). Unknown controls receive no security credit.

## Threat matrix and remediation

| Severity | Control / threat | Observed | Penalty | Action |
| --- | --- | --- | --- | --- |
| Low | Symmetric Encryption Cipher: Cipher Block Chaining Mode Padding Attacks | AES-CBC | 10 | Prefer Authenticated Encryption with Associated Data (AEAD) modes like AES-GCM or ChaCha20-Poly1305. |

## Evidence gaps
- Perfect Forward Secrecy (PFS): Not observed in capture. Capture CREATE_CHILD_SA exchanges or provide an explicit Child SA configuration.
- Anti-Replay Window Protection: Not observed in capture. Provide Child SA configuration or negotiated ESN evidence.

## Cryptographic parameters

| Parameter | Observed value |
| --- | --- |
| IKE version | IKEv2 |
| Operating mode | Not determined from capture |
| Encryption | AES-CBC |
| Integrity | AUTH-HMAC-SHA2-256-128 |
| DH group | DH Group 14 (MODP 2048-bit) |
| PFS | Not observed |
| Replay protection | Not observed |
| Key lifetime | Not observed |

## Traffic analysis and metadata inference
- Inferred workload: VoIP / Audio Call.
- Traffic pattern match: 60%. This is a relative heuristic score, not calibrated model confidence.
- ESP packets: 40; mean length: 170.0 bytes; mean inter-arrival: 2.6 ms; entropy: 7.75 bits/byte.
- Wire metadata: 6 IKE and 40 ESP frames; NAT traversal Not detected.
- Application identity and encrypted contents cannot be confirmed from packet metadata.

## AI confidence
- AI confidence score: 93%.
- Mean predicted-class probability across 4 available cryptographic inference models; this is not measured accuracy.

## Cryptographic model predictions

| Target | Prediction | Predicted-class probability |
| --- | --- | --- |
| encryption | AES128 | 73% |
| hash | SHA256 | 100% |
| dh group | DH14 | 100% |
| pfs group | NOPFS | 100% |

## Model-inferred security notes
- These are predictions, not packet-observed configuration findings. Confirm them with gateway telemetry or negotiation evidence.

| Severity | Finding | Basis | Confidence | Recommended check |
| --- | --- | --- | --- | --- |
| low | Encryption: AES-128 (ML prediction) | ml inferred | 73% | Consider upgrading to AES-256 for highest-assurance deployments. |
| info | Integrity: SHA-256 (ML prediction) | ml inferred | 100% | Consider SHA-384 for highest-assurance environments. |
| medium | Key Exchange: DH Group 14 / MODP-2048 (ML prediction) | ml inferred | 100% | Upgrade to DH Group 15 (MODP-3072) or DH Group 19/20 (ECDH). |
| high | Perfect Forward Secrecy: Disabled (ML prediction) | ml inferred | 100% | Enable PFS using CREATE_CHILD_SA with a new DH exchange (DH Group 14 minimum, Group 15+ recommended). |
| info | IKE Handshake Traffic Observed | observed | 100% | IKE control-plane visibility is expected. Ensure IKE_AUTH payloads use encryption (payload type 46). |
| info | ESP Data Tunnel Active | observed | 100% | Verify ESP replay window size is configured appropriately. |

## Wire-visible metadata
- Total frames: 46; IKE: 6; ESP: 40; AH: 0.
- NAT traversal: Not detected; capture duration: 30054.0 ms.
- IKE exchanges: 34, 35, 37.
