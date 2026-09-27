# VPN / PCAP Analyzer Runtime Trace

This file is the exact runtime trace for the browser-driven PCAP analysis flow and the server startup/entrypoints that power it.

Scope is intentionally limited to the files involved in the actual upload runtime:

- src/App.tsx
- src/utils/scapyClient.ts
- server/scapy_analyzer.py
- package.json

The already-verified gateway telemetry backend is excluded from this trace by scope, and this file does not re-audit those files.

---

## 1) Browser upload flow

### A. File selection / drop event
File: [src/App.tsx](src/App.tsx)

```tsx
const handleFileUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
  const file = e.target.files?.[0];
  if (file) {
    await processFile(file);
  }
};

const handleDrop = async (e: React.DragEvent) => {
  e.preventDefault();
  setIsDragging(false);
  const file = e.dataTransfer.files?.[0];
  if (file) {
    await processFile(file);
  }
};
```

Function chain:
`handleFileUpload` / `handleDrop` → `processFile(file)`

Request body:
- browser `File` object from the selected `.pcap` / `.pcapng` / `.cap`

No HTTP request happens here yet.

---

### B. Upload orchestration in App.tsx
File: [src/App.tsx](src/App.tsx)

```tsx
const processFile = async (file: File) => {
  try {
    showToast(`Analyzing real capture "${file.name}" with Scapy...`);

    let parsed;
    try {
      parsed = await parseWithScapy(file);
    } catch (scapyError) {
      console.warn('Scapy analyzer unavailable; using browser parser.', scapyError);
      parsed = await parseUploadedFile(file);
    }

    if (parsed.packets.length === 0) {
      showToast('No packets found in capture file.');
      return;
    }

    const newScenario: VpnCaptureScenario = {
      id: `uploaded-${Date.now()}`,
      name: parsed.scenarioName,
      organization: 'Real Captured Network Trace',
      badge: 'Live Capture File',
      description: `Parsed from "${file.name}" (${(parsed.fileSizeBytes / 1024).toFixed(1)} KB) containing ${parsed.packets.length} analyzed packets.`,
      sa: addSecurityAssociationEvidence(parsed.sa),
      features: parsed.features,
      packets: parsed.packets,
      actualTrafficType: 'Live Real Capture',
    };

    setScenarios((prev) => [newScenario, ...prev]);
    setSelectedScenario(newScenario);
    showToast(`Analyzed ${parsed.packets.length} packets from "${file.name}"!`);
  } catch (err: unknown) {
    console.error(err);
    const errorMsg = err instanceof Error ? err.message : 'Ensure it is a valid .pcap or network capture.';
    showToast(`Error parsing file: ${errorMsg}`);
  }
};
```

Function chain:
`processFile(file)` → `parseWithScapy(file)` → returns `parsed` → `setSelectedScenario(newScenario)`

This is the runtime entrypoint for the current upload flow.

---

### C. Browser HTTP client for parser backend
File: [src/utils/scapyClient.ts](src/utils/scapyClient.ts)

```ts
import type { ParsedPcapResult } from './pcapParser';

const SCAPY_ANALYZER_URL = 'http://127.0.0.1:8765/analyze';

export async function parseWithScapy(file: File): Promise<ParsedPcapResult> {
  const response = await fetch(SCAPY_ANALYZER_URL, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/octet-stream',
      'X-Filename': file.name,
    },
    body: await file.arrayBuffer(),
  });

  const payload = (await response.json()) as ParsedPcapResult | { error?: string };

  if (!response.ok) {
    throw new Error('Scapy analyzer: ' + ('error' in payload && payload.error ? payload.error : 'analysis failed'));
  }

  return payload as ParsedPcapResult;
}
```

Function chain:
`parseWithScapy(file)` → `fetch('http://127.0.0.1:8765/analyze')`

HTTP method:
- `POST`

URL:
- `http://127.0.0.1:8765/analyze`

Request body:
- raw file bytes: `await file.arrayBuffer()`
- plus headers:
  - `Content-Type: application/octet-stream`
  - `X-Filename: file.name`

Response structure:
```ts
ParsedPcapResult | { error?: string }
```

If `response.ok` is false, it throws:
```ts
new Error('Scapy analyzer: ' + ...)
```

Otherwise it returns the parsed payload as `ParsedPcapResult`.

---

## 2) Server on port 8765: actual HTTP endpoint

File: [server/scapy_analyzer.py](server/scapy_analyzer.py)

```python
HOST = "127.0.0.1"
PORT = 8765
```

```python
class Handler(BaseHTTPRequestHandler):
    def do_OPTIONS(self) -> None:
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, X-Filename")
        self.end_headers()

    def do_POST(self) -> None:
        if self.path != "/analyze":
            self.send_error(404)
            return
        try:
            size = int(self.headers.get("Content-Length", "0"))
            result = analyze(self.rfile.read(size), self.headers.get("X-Filename", "capture.pcap"))
            body = json.dumps(result).encode()
            self.send_response(200)
        except Exception as exc:
            body = json.dumps({"error": str(exc)}).encode()
            self.send_response(400)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
```

Function chain:
`Handler.do_POST()` → `analyze(self.rfile.read(size), filename)`

HTTP method:
- `POST`

Path:
- `/analyze`

Request body:
- raw bytes read from `Content-Length`
- filename from header `X-Filename`

Response structure:
```python
json.dumps(result)
```
where `result` is the dictionary returned by `analyze(...)`

On failure:
```python
{"error": str(exc)}
```

---

## 3) Backend PCAP parser function

File: [server/scapy_analyzer.py](server/scapy_analyzer.py)

```python
def analyze(data: bytes, filename: str) -> dict[str, Any]:
    packets = rdpcap(BytesIO(data))
    if not packets:
        raise ValueError("No packets found in capture file")
    first_time = float(packets[0].time)
    parsed_packets: list[dict[str, Any]] = []
    proposals: list[dict[str, Any]] = []
    evidence: list[dict[str, Any]] = []
    ...

    return {
        "scenarioName": filename.rsplit(".", 1)[0],
        "packets": parsed_packets,
        "sa": sa,
        "features": {
            "packetCount": len(esp_lengths),
            "totalBytes": total,
            "meanPacketLength": round(mean),
            "stdPacketLength": round(std),
            "minPacketLength": min(esp_lengths, default=0),
            "maxPacketLength": max(esp_lengths, default=0),
            "meanInterArrivalTimeMs": round(statistics.mean(iats), 1) if iats else 0,
            "burstRatio": 0.9 if iats and statistics.mean(iats) < 10 else 0.6 if iats and statistics.mean(iats) < 40 else 0.25 if iats else 0,
            "flowSymmetry": round(symmetry, 2),
            "calculatedEntropy": entropy(bytes(esp_bytes)),
            "flowDurationMs": round((float(packets[-1].time) - first_time) * 1000, 3)
        },
        "fileSizeBytes": len(data),
        "evidence": evidence
    }
```

Function chain:
`analyze(data, filename)` → `rdpcap(BytesIO(data))` → iterate packets → build `parsed_packets`, `sa`, `features`, `evidence` → return JSON-serializable dict

This is the actual backend parser result returned to the browser.

---

## 4) Returned JSON structure to the browser

The `analyze(...)` function returns a dict that contains:

```python
{
  "scenarioName": filename.rsplit(".", 1)[0],
  "packets": parsed_packets,
  "sa": sa,
  "features": {...},
  "fileSizeBytes": len(data),
  "evidence": evidence
}
```

Inside the browser, `parseWithScapy(file)` returns this as `ParsedPcapResult` and `processFile` immediately converts it into a UI scenario.

---

## 5) App.tsx receives the parsed result and displays it

File: [src/App.tsx](src/App.tsx)

```tsx
const newScenario: VpnCaptureScenario = {
  id: `uploaded-${Date.now()}`,
  name: parsed.scenarioName,
  organization: 'Real Captured Network Trace',
  badge: 'Live Capture File',
  description: `Parsed from "${file.name}" (${(parsed.fileSizeBytes / 1024).toFixed(1)} KB) containing ${parsed.packets.length} analyzed packets.`,
  sa: addSecurityAssociationEvidence(parsed.sa),
  features: parsed.features,
  packets: parsed.packets,
  actualTrafficType: 'Live Real Capture',
};

setScenarios((prev) => [newScenario, ...prev]);
setSelectedScenario(newScenario);
```

This is the last stage of the current runtime:
`parsed JSON` → `VpnCaptureScenario` → React state → `selectedScenario` renders UI

---

## 6) Frontend startup and server startup config

### Frontend start
File: [package.json](package.json)

```json
"scripts": {
  "dev": "vite --port=3000 --host=0.0.0.0"
}
```

This starts the React/Vite app on:
- `http://localhost:3000`

### Backend parser start
File: [server/scapy_analyzer.py](server/scapy_analyzer.py)

```python
if __name__ == "__main__":
    print(f"Scapy analyzer listening on http://{HOST}:{PORT}")
    ThreadingHTTPServer((HOST, PORT), Handler).serve_forever()
```

This starts the parser server on:
- `http://127.0.0.1:8765`

---

## 7) Exact runtime chain from upload to display

Browser upload
→ [src/App.tsx](src/App.tsx) `handleFileUpload` / `handleDrop`
→ [src/App.tsx](src/App.tsx) `processFile(file)`
→ [src/utils/scapyClient.ts](src/utils/scapyClient.ts) `parseWithScapy(file)`
→ HTTP `POST` to `http://127.0.0.1:8765/analyze`
→ [server/scapy_analyzer.py](server/scapy_analyzer.py) `Handler.do_POST`
→ [server/scapy_analyzer.py](server/scapy_analyzer.py) `analyze(data, filename)`
→ returned dict JSON
→ [src/utils/scapyClient.ts](src/utils/scapyClient.ts) resolves `ParsedPcapResult`
→ [src/App.tsx](src/App.tsx) `processFile` builds `newScenario`
→ `setSelectedScenario(newScenario)`
→ UI display

---

## 8) Answer to your questions

### A. Where should gateway telemetry be integrated into the existing PCAP upload flow with the fewest architectural changes?

The fewest-change insertion point is directly inside [src/App.tsx](src/App.tsx) `processFile`, immediately after the successful `parseWithScapy(file)` call and before the app builds `newScenario` and calls `setSelectedScenario(newScenario)`.

This is the narrowest existing orchestrator point because:
- upload is already centralized there
- the parser result is already available as `parsed`
- the final scenario object is already assembled there
- no parser rewrite is needed

### B. Can the existing server on port 8765 directly call the existing telemetry adapter, or is the separate api_server.py on port 8770 required?

The existing 8765 server cannot do it without code changes, because [server/scapy_analyzer.py](server/scapy_analyzer.py) currently only implements `Handler.do_POST` for `/analyze` and calls only `analyze(...)`.

The separate telemetry logic is not in the 8765 server. The dedicated telemetry backend is in the separate API backend, and that is the existing path designed to handle telemetry correlation. So the separate [server/api_server.py](server/api_server.py) on port 8770 is the required existing telemetry path for the separate gateway logic.

### C. What is the smallest connection we could add so that one PCAP upload can produce PCAP analysis + real StrongSwan telemetry + exact SPI correlation without rewriting the existing parser?

The smallest existing-architecture connection is:

1. keep [server/scapy_analyzer.py](server/scapy_analyzer.py) as the PCAP parser endpoint on 8765
2. keep [src/App.tsx](src/App.tsx) as the upload orchestrator
3. after `parseWithScapy(file)` succeeds, make one additional frontend request to the existing telemetry API endpoint in [server/api_server.py](server/api_server.py)
4. pass the parsed SPI values and the telemetry payload through the existing correlation logic already implemented elsewhere
5. merge the returned telemetry/correlation result into the same scenario before rendering

This preserves the parser and requires only one additional orchestration step in the browser flow.

### D. What exact files would need to change?

Minimal file set if you want the existing architecture to support the required flow:

1. [src/App.tsx](src/App.tsx)  
   - `processFile`  
   - to trigger the telemetry fetch and merge result into the scenario

2. [src/utils/scapyClient.ts](src/utils/scapyClient.ts)  
   - add a second helper for the telemetry/correlation API call, or extend the existing client layer to support a second HTTP request

No change is required to the existing PCAP parser endpoint at [server/scapy_analyzer.py](server/scapy_analyzer.py) as long as the goal is to keep it as the upload parser.

---

## Final conclusion

The current browser runtime is cleanly separated:
- browser upload enters via [src/App.tsx](src/App.tsx)
- browser HTTP client is [src/utils/scapyClient.ts](src/utils/scapyClient.ts)
- parser backend is [server/scapy_analyzer.py](server/scapy_analyzer.py)
- startup is via [package.json](package.json) and `ThreadingHTTPServer` in [server/scapy_analyzer.py](server/scapy_analyzer.py)

The existing telemetry adapter implementation is verified, but it is not part of the port 8765 parser runtime and therefore must be reached through the separate telemetry API path rather than from inside the parser server itself.
