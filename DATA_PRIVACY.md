# Data Privacy

Cloud sanitization is implemented in `server/sanitizer.py`.

Local SQLite persistence is implemented in `server/repository.py` and applies a second storage boundary. Stored packet rows contain protocol, length, timestamp, SPI, sequence, and only pseudonymized endpoint fields when supplied. Raw packet previews, debug dumps, payloads, and source IP strings are excluded.

The default cloud payload allowlist contains packet metadata such as timestamp, direction, length, protocol, SPI, flow identifiers, IAT, and sequence-observed status. Telemetry is limited to recognized SA metadata such as algorithms, mode, selectors, SPI, counters, and lifetimes.

Dropped by default:

- Packet payloads
- Decrypted application data
- PSKs
- Private keys
- Session keys
- Cookies and tokens
- Unknown fields

Cloud mode requires HTTPS and uses Python's default certificate validation. It does not support plaintext HTTP or disabled TLS verification.
