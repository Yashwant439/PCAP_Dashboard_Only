# Working Guide

## 1. Project Purpose

This project analyzes IPsec VPN packet captures and produces evidence-based security results.

It supports:

- PCAP and PCAPNG upload
- IKEv1 and IKEv2 header detection
- IKEv2 proposal and transform parsing when visible
- ESP, ESP-in-UDP/NAT-T, and AH parsing
- IPv4 and IPv6 packet metadata
- Traffic selectors, vendor IDs, notify payloads, NAT detection, and fragmentation evidence
- SPI and sequence-number analysis
- StrongSwan gateway telemetry through `swanctl` or optional VICI
- Local bounded live capture with Scapy
- Evidence/source/status tracking
- SQLite persistence
- Encrypted ESP traffic feature extraction
- Leakage-aware ML training baseline
- Security findings and downloadable reports

The analyzer does not guess encrypted values. A correct `UNKNOWN` result is preferred over an unsupported cryptographic claim.

## 2. Important Accuracy Rules

The system distinguishes:

- `PCAP_OBSERVED`: directly decoded from packet bytes
- `GATEWAY_TELEMETRY`: obtained from an authorized VPN gateway
- `ML_INFERENCE`: inferred from encrypted traffic behavior
- `DERIVED_FROM_OBSERVED_DATA`: calculated from observed metadata
- `UNKNOWN`: unavailable or not determinable

Encrypted IKE_AUTH contents are not reconstructed without authorized decryption material.

The following values may remain unknown from PCAP alone:

- Child-SA encryption when the proposal is inside encrypted IKE_AUTH
- Child-SA integrity when encrypted
- Authentication method when encrypted
- PFS policy without Child-SA evidence or gateway telemetry
- Configured replay-window size
- SA lifetime when it is not visible in an appropriate payload or telemetry
- Tunnel/transport mode when packet evidence is ambiguous
- Exact application traffic type when there are too few ESP packets

## 3. Required Software

- Node.js 18 or newer
- npm
- Python 3.11 or newer recommended
- Scapy
- NumPy
- scikit-learn
- Npcap on Windows for live capture
- StrongSwan and `swanctl` only if gateway telemetry is being tested
- Optional `python-vici` only if VICI telemetry is being tested

## 4. Installation

Open PowerShell in the project directory:

```powershell
npm install
python -m pip install -r requirements.txt
```

Verify the Python environment that will run the services:

```powershell
python -c "import sys; print(sys.executable)"
python -c "import scapy; print(scapy.__version__)"
python -c "import numpy, sklearn; print('ML dependencies ready')"
```

### Python interpreter warning

The Scapy service must be started with the same Python interpreter where Scapy was installed.

This command can fail when Scapy was installed into another Python environment:

```powershell
C:/Users/USER/AppData/Local/Python/pythoncore-3.14-64/python.exe server/scapy_analyzer.py
```

If it reports:

```text
ModuleNotFoundError: No module named 'scapy'
```

Use the interpreter that successfully passed the import check, or install into the exact interpreter:

```powershell
C:/path/to/python.exe -m pip install -r requirements.txt
C:/path/to/python.exe server/scapy_analyzer.py
```

## 5. Normal Browser Startup

### Terminal 1: Scapy analyzer

```powershell
python server/scapy_analyzer.py
```

Expected output:

```text
Scapy analyzer listening on http://127.0.0.1:8765
```

### Terminal 2: React/Vite dashboard

```powershell
npm run dev
```

Open:

```text
http://localhost:3000
```

The browser tries the Scapy service first. If it is unavailable, the browser uses the TypeScript parser fallback.

### Normal upload flow

1. Start the Scapy service.
2. Start Vite.
3. Open `http://localhost:3000`.
4. Upload a `.pcap`, `.pcapng`, or `.cap` file.
5. Open the Security tab.
6. Review cryptographic findings and evidence provenance.
7. Open the Packet tab.
8. Inspect individual packet headers, ports, SPIs, sequences, hex previews, and decoded layer details.
9. Open the AI Traffic tab only when enough ESP packets are available.
10. Download the technical or executive report if required.

## 6. Capturing a Useful IPsec PCAP

For exact IKE proposal values, capture the complete IKE negotiation and ESP traffic.

Linux tcpdump example:

```bash
sudo tcpdump -i any -nn -s 0 -w ipsec_capture.pcap \
  "udp port 500 or udp port 4500 or proto 50 or proto 51"
```

Recommended capture sequence:

1. Start tcpdump or Wireshark.
2. Start or restart the IPsec tunnel.
3. Capture IKE_SA_INIT request and response.
4. Capture IKE_AUTH packets.
5. Generate traffic through the tunnel.
6. Capture ESP or NAT-T ESP packets.
7. Stop the capture.
8. Upload the resulting file.

A capture containing only ESP and encrypted IKE_AUTH cannot reveal every negotiated Child-SA parameter.

Wireshark capture filter:

```text
udp port 500 or udp port 4500 or esp or ah
```

## 7. What the Dashboard Should Show

### Security tab

Review:

- IKE version
- IP version
- Encryption transform
- Encryption key length
- Integrity transform
- PRF
- DH group and strength
- PFS status
- Replay protection status
- IKE and ESP SPIs
- Evidence source and status
- Unknown reasons

Do not interpret `0 (Not assessed)` as `0 (Safe)`. Missing evidence is not proof of security.

### Wire-visible observations

The evidence panel can show:

- Total packet count
- IKE, ESP, AH, UDP, TCP, and ICMP counts
- IKE exchanges
- IKE payload chain
- IKE message IDs
- IKE flags
- Vendor IDs
- Notify payloads
- NAT detection
- Fragmentation support
- Traffic selectors
- NAT-T detection
- ESP SPIs
- AH SPIs
- ESP sequence range
- AH sequence range
- Duplicate ESP sequences
- Out-of-order ESP sequences
- ESP directions
- Capture duration
- Link-layer type

### Packet tab

Inspect:

- Frame number
- Relative timestamp
- Source and destination addresses
- Source and destination ports
- Protocol
- Packet size
- SPI
- Sequence number
- Raw preview
- Scapy decoded-layer details when Scapy was used

## 8. Local API

The local API is optional for browser use.

Start it:

```powershell
python server/api_server.py
```

Expected output:

```text
Local analyzer API listening on http://127.0.0.1:8770
```

### Analyze a PCAP through the API

```powershell
Invoke-WebRequest `
  -UseBasicParsing `
  -Uri http://127.0.0.1:8770/api/analyze/pcap `
  -Method Post `
  -Headers @{ "X-Filename" = "capture.pcap" } `
  -ContentType "application/octet-stream" `
  -InFile .\capture.pcap
```

The response contains an `analysisId`.

### Retrieve persisted analysis

```powershell
Invoke-RestMethod `
  -UseBasicParsing `
  -Uri http://127.0.0.1:8770/api/analysis/YOUR_ANALYSIS_ID
```

SQLite default path:

```text
data/analyzer.sqlite3
```

Override it before starting the API:

```powershell
$env:VPN_ANALYZER_DATABASE = "data/test.sqlite3"
python server/api_server.py
```

Stored data excludes raw packet payloads, raw packet previews, debug dumps, and source IP strings.

## 9. Gateway Telemetry

Gateway telemetry is optional and requires an authorized StrongSwan gateway.

### swanctl adapter

```powershell
python server/vpn_analyzer_agent.py `
  --mode local `
  --pcap .\capture.pcap `
  --gateway strongswan
```

The adapter executes the read-only command:

```text
swanctl --list-sas --raw
```

It never requests PSKs, private keys, or session keys.

### VICI adapter

```powershell
python server/vpn_analyzer_agent.py `
  --mode local `
  --pcap .\capture.pcap `
  --gateway strongswan-vici
```

VICI requires:

- `python-vici`
- VICI socket access
- StrongSwan permissions
- Active SAs

If the gateway command or socket is unavailable, the result is:

```text
NOT_DETERMINABLE
```

### Correlation

PCAP and gateway records are correlated only by exact SPI matches.

Example:

```text
PCAP ESP SPI:       0x12345678
Gateway Child SPI:  0x12345678
Result:             CONFIRMED
```

No timing, filename, IP, or configuration-name guess is used to confirm a match.

## 10. Authenticated Telemetry API

Set a local test token:

```powershell
$env:VPN_ANALYZER_AGENT_TOKEN = "test-token"
python server/api_server.py
```

Example request:

```powershell
$body = '{"analysis_id":"test","packets":[{"protocol":"ESP","spi":"0x1234","payload":"removed"}],"telemetry":[{"outbound_spi":"0x1234","encr":"aes256gcm16","private_key":"removed"}]}'

Invoke-RestMethod `
  -UseBasicParsing `
  -Uri http://127.0.0.1:8770/api/agent/telemetry `
  -Method Post `
  -Headers @{ Authorization = "Bearer test-token" } `
  -ContentType "application/json" `
  -Body $body
```

The response keeps approved metadata, removes payload/secret fields, and reports SPI correlation.

## 11. Bounded Live Capture

Find Windows interface names:

```powershell
Get-NetAdapter
```

Run a bounded metadata-only capture:

```powershell
python server/vpn_analyzer_agent.py `
  --mode local `
  --live `
  --interface "Ethernet" `
  --count 100 `
  --timeout 30
```

Requirements:

- Npcap installed
- Correct interface name
- Capture permissions
- Active traffic

The output includes protocol, length, pseudonymized endpoints, ports, flow ID, SPI, and sequence metadata. Raw packet payloads are not returned.

Do not combine `--live` and `--pcap`.

## 12. ML Pipeline

The production-ready training boundary is:

```text
server/ml_pipeline.py
```

It extracts behavior features from ESP metadata only:

- Packet count
- Total bytes
- Duration
- Packets/second
- Bytes/second
- Packet size statistics
- Inter-arrival statistics
- Direction statistics
- Burst statistics
- Active/idle time
- Packet-size entropy

It excludes:

- IP addresses
- MAC addresses
- Filename
- SPI
- Raw sequence number
- Plaintext content

The dataset manifest must contain external ground-truth labels:

```json
[
  {
    "capture_id": "capture-video-001",
    "label": "video",
    "packets": []
  },
  {
    "capture_id": "capture-web-001",
    "label": "web",
    "packets": []
  }
]
```

Run training:

```powershell
python server/ml_pipeline.py .\dataset_manifest.json
```

The trainer uses capture-level grouped splitting. It refuses to report valid metrics when labels, capture groups, or class diversity are insufficient.

The current dashboard classifier remains a heuristic compatibility baseline. It must not be presented as a production-trained model until a real labeled dataset is supplied.

## 13. Complete Test Commands

Frontend tests:

```powershell
npm test
npm run lint
npm run build
```

Backend tests:

```powershell
python -m unittest discover -s server -p "test_*.py"
```

Python compilation:

```powershell
python -m py_compile `
  server/api_server.py `
  server/correlation.py `
  server/live_capture.py `
  server/ml_pipeline.py `
  server/repository.py `
  server/sanitizer.py `
  server/scapy_analyzer.py `
  server/telemetry.py `
  server/vpn_analyzer_agent.py
```

Patch hygiene:

```powershell
git diff --check
```

Expected current validation:

```text
Frontend tests: 8 passed
Backend tests: 14 passed
TypeScript: passed
Production build: passed
Python compilation: passed
```

## 14. Common Problems

### Scapy module not found

Cause: service started with a different Python interpreter than the one used for installation.

Fix:

```powershell
python -c "import sys; print(sys.executable)"
python -c "import scapy; print(scapy.__version__)"
python server/scapy_analyzer.py
```

### Browser uses fallback parser

Cause: Scapy service is not running on port `8765`.

Fix:

```powershell
python server/scapy_analyzer.py
```

### StrongSwan telemetry unavailable

Cause: `swanctl` is not installed, not on `PATH`, or access is denied.

Expected behavior:

```text
NOT_DETERMINABLE
```

### VICI unavailable

Cause: missing `python-vici`, missing socket, or insufficient permissions.

Expected behavior:

```text
STRONGSWAN_VICI_UNAVAILABLE
```

### Live capture fails

Check:

- Npcap installation
- Interface name from `Get-NetAdapter`
- Administrator permissions
- Correct `--timeout` and `--count`

### Cryptographic fields are unknown

This is expected when the capture does not contain the relevant unencrypted IKE proposal or when the payload is encrypted. Do not treat unknown fields as failed parsing automatically.

## 15. Security Limitations

This project cannot reliably determine from ordinary PCAP alone:

- Session keys
- PSKs
- Private keys
- Plaintext application content
- Encrypted Child-SA proposals
- Configured replay window
- Exact SA lifetime when not visible
- PFS policy without Child-SA or gateway evidence
- Tunnel/transport mode from ambiguous evidence

The analyzer intentionally reports unknown values instead of guessing.
