# AI-Powered IPsec VPN Protocol Analyzer & Security Assessment Framework

> **NTRO Problem Statement 26160** | Smart India Hackathon  
> Automated Cryptographic Security Assessment & Encrypted ESP Traffic Classification

![NTRO Security Framework](https://img.shields.io/badge/Security_Standard-NIST_SP_800--77_Rev._1-blue?style=flat-square)
![RFC Compliance](https://img.shields.io/badge/Standards-RFC_8221_%7C_RFC_7296-emerald?style=flat-square)
![ML Engine](https://img.shields.io/badge/AI_Engine-Random_Forest_Shape_Classifier-purple?style=flat-square)
![License](https://img.shields.io/badge/License-MIT-slate?style=flat-square)

---

## 📌 Executive Summary

Virtual Private Networks (VPNs) built on **IPsec (Internet Protocol Security)** form the backbone of national critical infrastructure, defense networks, and inter-branch banking communications. 

However, an IPsec tunnel can negotiate obsolete, vulnerable 1990s-era ciphers (e.g., 3DES, 1024-bit DH groups, missing Perfect Forward Secrecy) while still reporting **"Connected"** to network administrators. Furthermore, because ESP (Encapsulating Security Payload) encrypts network packets, traditional Deep Packet Inspection (DPI) tools fail to identify what applications are operating within the tunnel, leaving organizations blind to metadata leakage and covert communications.

This framework provides an evidence-driven analysis workflow:
1. **Deterministic Cryptographic Security Auditor**: Inspects IKEv1/IKEv2 handshakes and grades security posture (0–100) against **NIST SP 800-77 Rev. 1**, **RFC 8221**, and the **NSA CNSA Suite**, instantly detecting known attacks (**Sweet32**, **Logjam**, replay risks).
2. **AI Encrypted Traffic Fingerprinting**: Employs supervised machine learning on flow shape characteristics (packet length distributions, inter-arrival time cadence, burst ratios, and Shannon entropy) to classify applications (VoIP, Video Streaming, Web, Bulk Data, Telemetry) inside opaque ESP ciphertext **without breaking encryption**.
3. **Interactive PCAP Dissector**: A web-based packet dissector providing frame-by-frame inspection, SPI tracking, protocol filtering, and raw hexadecimal payload views.
4. **VPN Testbed & Remediation Generator**: Generates strongSwan examples and synthetic test inputs for local testing.
5. **Evidence reporting**: Presents packet provenance, protocol limitations, and observed findings without inventing unavailable negotiated state.

---

## 🏗️ Architecture & Processing Pipeline

```
                       ┌────────────────────────┐
                       │  Uploaded .PCAP / Live │
                       │    Network Capture     │
                       └───────────┬────────────┘
                                   │
                                   ▼
                       ┌────────────────────────┐
                       │ Binary Libpcap Parser  │
                       │   (pcapParser.ts)      │
                       └───────────┬────────────┘
                                   │
                 ┌─────────────────┴─────────────────┐
                 ▼                                   ▼
     ┌────────────────────────┐         ┌────────────────────────┐
     │ IKE Handshake Auditor  │         │ ESP Flow Feature       │
     │  (securityAuditor.ts)  │         │ Extraction Engine      │
     └───────────┬────────────┘         └───────────┬────────────┘
                 │                                  │
                 ▼                                  ▼
     ┌────────────────────────┐         ┌────────────────────────┐
     │ NIST SP 800-77 / RFC   │         │ AI Shape Classifier    │
     │ Compliance Scoring     │         │   (aiClassifier.ts)    │
     │ • Sweet32 (3DES)       │         │ • Packet Length Mean/SD│
     │ • Logjam (DH Group 2)  │         │ • Inter-Arrival Times  │
     │ • Perfect Forward Sec. │         │ • Shannon Entropy (H)  │
     └───────────┬────────────┘         └───────────┬────────────┘
                 │                                  │
                 └─────────────────┬────────────────┘
                                   │
                                   ▼
                       ┌────────────────────────┐
                       │ Interactive Dashboard  │
                       │ • Metric Cards         │
                       │ • Hex Dissector Table  │
                       │ • strongSwan Fixes     │
                       │ • Executive / Tech MD  │
                       └────────────────────────┘
```

---

## 🛡️ Security Audit Engine (NIST & RFC Benchmark)

The security auditor evaluates security associations (SA) against official standards:

| Parameter | Recommended (Hardened) | Deprecated / Vulnerable | Security Impact |
| :--- | :--- | :--- | :--- |
| **Protocol Version** | **IKEv2 (RFC 7296)** | IKEv1 (RFC 2409) | IKEv1 is vulnerable to offline PSK dictionary attacks and aggressive mode identity exposure. |
| **Encryption Algorithm** | **AES-256-GCM / AES-128-GCM** | 3DES-CBC, DES, Blowfish | 3DES has a 64-bit block size vulnerable to collision attacks (**Sweet32 / CVE-2016-2183**). |
| **Key Exchange (DH)** | **DH Group 19, 20 (ECDH) or 14+** | DH Group 1 (768b), Group 2 (1024b) | 1024-bit MODP groups can be broken by state actors using precomputed discrete logs (**Logjam attack**). |
| **Data Integrity** | **AEAD Combined / SHA-256+** | MD5, SHA-1 | MD5 and SHA-1 suffer from collision and length-extension attacks. |
| **Forward Secrecy** | **PFS Enabled (Mandatory)** | Disabled | Compromise of the long-term private key enables retroactive decryption of all recorded historical traffic. |
| **Replay Protection** | **Enabled (64-packet window)** | Disabled | Allows adversaries to intercept and re-inject valid captured packets to duplicate transactions. |

---

## 🧠 AI Encrypted Traffic Fingerprinting Methodology

### The Fundamental Problem
When IPsec enters Phase 2 (ESP), packets are encrypted. Plaintext payload inspection is mathematically impossible without the ephemeral session keys.

### The Machine Learning Solution
Even military-grade encryption does not mask the **physical transmission characteristics** of user behavior:
1. **Packet Size Histograms ($L_\mu, L_\sigma$)**: Audio calls transmit small, fixed-length frames (~120–160 bytes); file downloads saturate the network MTU (~1420–1500 bytes).
2. **Inter-Arrival Time ($IAT_\mu$)**: Interactive voice streams pulse at strict isochronous intervals (~20ms); web traffic produces bursty gaps; video buffers in chunked bursts.
3. **Flow Symmetry ($S_{flow}$)**: Video streaming is highly asymmetric ($\ge 90\%$ downlink); VoIP is balanced ($\approx 50/50$).
4. **Shannon Entropy Verification ($H$)**:
   $$H(X) = -\sum_{i=1}^{n} P(x_i) \log_2 P(x_i)$$
   True encrypted ESP ciphertext scores between **7.60 and 7.99 bits per byte**. Computing this verifies that the payload is genuinely encrypted and that the AI's classification is based entirely on statistical shape rather than plaintext data leakage.

---

## 🚀 Getting Started & Local Development

### Prerequisites
- **Node.js**: v18.0.0 or higher
- **npm** or **bun**
- **Python**: 3.11 or higher

### Installation
```bash
# Clone repository
git clone https://github.com/YOUR_USERNAME/ai-ipsec-vpn-analyzer.git
cd ai-ipsec-vpn-analyzer

# Install dependencies
npm install

# Start Vite development server
npm run dev
```
The application will launch at `http://localhost:3000`.

In a second terminal, start the evidence API:

```bash
python -m uvicorn backend.app.main:app --reload --port 8000
```

The frontend uses `http://localhost:8000` by default. Set `VITE_API_BASE_URL` when the API runs elsewhere.

### Production Build
```bash
npm run build
```

---

## 📡 Live Packet Capture Instructions

### Option 1: Capture with Linux `tcpdump`
Capture both the IKE negotiation handshake and encrypted ESP payloads on your VPN gateway:

```bash
sudo tcpdump -i any -nn -s 0 -w ipsec_capture.pcap \
  "udp port 500 or udp port 4500 or proto 50"
```

1. Run the command above on your client or server.
2. Bring up the IPsec tunnel (e.g., `sudo swanctl --initiate --child net-net`).
3. Generate traffic across the tunnel (VoIP call, video stream, or large file copy).
4. Stop the capture (`Ctrl+C`) and upload `ipsec_capture.pcap` directly into the web interface.

### Option 2: Capture with Wireshark
1. Open Wireshark and choose your active network adapter.
2. In the capture filter box, enter:
   ```
   udp port 500 or udp port 4500 or esp
   ```
3. Start the capture, start your VPN, and generate traffic.
4. Go to **File → Save As... → Wireshark/tcpdump pcap (`.pcap`)**.
5. Drag and drop the saved file into the web analyzer dropzone.

---

## 🧪 VPN Testbed Lab (strongSwan / Libreswan)

The built-in **VPN Testbed Lab** allows engineers to generate compliant configurations and synthetic `.pcap` files on demand:

```
# Example generated strongSwan configuration (swanctl.conf)
connections {
    defense-tunnel {
        version = 2
        local_addrs  = 192.168.1.1
        remote_addrs = 192.168.2.1

        local {
            auth = psk
            id = vpn-gw-delhi
        }
        remote {
            auth = psk
            id = vpn-gw-mumbai
        }

        children {
            net-net {
                local_ts  = 10.0.1.0/24
                remote_ts = 10.0.2.0/24
                esp_proposals = aes256gcm128-ecp256
                dpd_action = restart
            }
        }
        proposals = aes256-sha256-ecp256
    }
}
```

---

## 📂 Project Structure

```
├── public/                     # Static web assets
├── backend/
│   ├── app/                    # FastAPI API, parser, correlation, storage & security analysis
│   └── tests/                  # Parser, API, lifecycle and evidence regressions
├── src/
│   ├── components/             # UI Components
│   │   ├── Header.tsx          # Top navigation, upload triggers & trace tabs
│   │   ├── MetricCards.tsx     # High-level security posture & mode cards
│   │   ├── SecurityAssessment.tsx # Compliance matrix & threat vector analyzer
│   │   ├── AiTrafficAnalysis.tsx  # ML classification, entropy & shape breakdown
│   │   ├── PacketViewer.tsx    # Interactive packet table & hex dump inspector
│   │   ├── ReportModal.tsx     # Executive & Technical Markdown report generator
│   │   └── TestbedGeneratorModal.tsx # strongSwan / PCAP synthetic testbed lab
│   ├── services/               # Backend analysis API client
│   ├── utils/
│   │   ├── aiClassifier.ts     # Supervised ML inference & Shannon entropy engine
│   │   ├── securityAuditor.ts  # NIST SP 800-77 & RFC compliance scoring engine
│   │   └── pcapParser.ts       # Binary Libpcap parser & synthetic packet builder
│   ├── types.ts                # TypeScript interfaces for SA, packets & metrics
│   ├── App.tsx                 # Main application state orchestration
│   ├── main.tsx                # React DOM root entry point
│   └── index.css               # Tailwind CSS imports & base styles
├── package.json                # Project dependencies & build scripts
├── metadata.json               # AI Studio project configuration
├── vite.config.ts              # Vite bundler configuration
└── README.md                   # Project documentation
```

---

## 📜 Problem Statement Deliverables Checklist

- [x] **Deliverable a**: VPN Testbed with varying parameters (IKEv1/IKEv2, Tunnel/Transport, multiple ciphers, DH groups, PFS on/off).
- [x] **Deliverable b**: Dataset collection of IPsec packet captures with diverse traffic types.
- [x] **Deliverable c**: Binary packet capture parser extracting IKE negotiation parameters & ESP features.
- [x] **Deliverable d**: Security assessment module auditing against NIST & RFC standards and identifying vulnerabilities.
- [x] **Deliverable e**: AI/ML classification model for traffic fingerprinting on encrypted ESP payloads.
- [x] **Deliverable f**: User-friendly interactive GUI dashboard with metrics, packet table, and reports.
- [x] **Deliverable g**: Automated Executive and Technical report generator.

---

## 📄 License
This project is licensed under the MIT License - see the LICENSE file for details.
