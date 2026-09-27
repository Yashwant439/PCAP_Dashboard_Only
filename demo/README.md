# Prototype demonstration

[Watch the demonstration video](prototype-demo.webm) (silent, approximately 11 seconds). It shows the local dashboard, dark theme, upload of a bundled controlled PCAP, the automated assessment, optional AI prose, and both report views. The video is assembled from actual browser screenshots at those stages with captions; it is not a claim of a continuous live screen recording. The sample is `pcap_factory/captures/AES128_SHA256_DH14_NOPFS_ICMP_rep01.pcap`.

For a live demonstration, start the API, Scapy model analyzer, and frontend from the project root in separate terminals:

```powershell
python server/api_server.py
python server/scapy_analyzer.py
npm run dev
```

Open `http://127.0.0.1:3000`, upload the sample PCAP, inspect the risk and confidence cards and threat matrix, then open the executive and technical reports. Both reports are generated from deterministic evidence immediately. If the local API has a valid `GROQ_API_KEY` in the ignored `.env`, it requests optional narrative text when a report is opened.

The reproducible capture script is [`record_demo.mjs`](record_demo.mjs). It requires Chrome started with a remote debugging port and the local services running. It writes the video and a dark mode preview image into this folder.

The included [executive PDF](sample-executive-report.pdf) and [technical PDF](sample-technical-report.pdf) are example exports for the bundled synthetic capture. Their Markdown counterparts are also in this folder. Run `node demo/export_sample_reports.mjs` after the recording script to regenerate them from the open browser report.
