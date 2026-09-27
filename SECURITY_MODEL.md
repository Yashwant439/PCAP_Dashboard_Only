# Security Model

The analyzer follows evidence precedence:

`PCAP_OBSERVED > GATEWAY_TELEMETRY > ML_INFERENCE > UNKNOWN`

Important fields carry source, confidence, status, explanation, and packet references through `IkeSecurityAssociation.fieldEvidence`.

Rules:

- A cipher or DH transform must be decoded before it is reported.
- Unknown transforms cannot receive a security pass.
- ESP shape cannot establish cipher, key size, PFS, replay-window configuration, or tunnel mode.
- Encrypted IKE_AUTH content remains unavailable without authorized decryption material.
- ML traffic classification is behavior inference only and cannot set cryptographic fields.
- Correlation is confirmed only by matching real identifiers such as SPI.
