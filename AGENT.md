# VPN Analyzer Agent

`server/vpn_analyzer_agent.py` is a non-GUI agent for local/offline analysis and optional cloud metadata submission.

## Local PCAP analysis

```powershell
python server/vpn_analyzer_agent.py --mode local --pcap capture.pcapng --gateway none
```

## StrongSwan telemetry

```powershell
python server/vpn_analyzer_agent.py --mode local --pcap capture.pcap --gateway strongswan
```

When the optional `python-vici` package and authorized VICI socket are available:

```powershell
python server/vpn_analyzer_agent.py --mode local --pcap capture.pcap --gateway strongswan-vici
```

The StrongSwan adapter invokes the read-only `swanctl --list-sas --raw` command without a shell. If `swanctl` is unavailable or returns unparseable data, the result is `NOT_DETERMINABLE`.

## Cloud mode

Cloud mode requires an HTTPS endpoint and a token stored in `VPN_ANALYZER_AGENT_TOKEN` or the variable named by `--token-env`:

```powershell
$env:VPN_ANALYZER_AGENT_TOKEN = '<short-lived-token>'
python server/vpn_analyzer_agent.py --mode cloud --pcap capture.pcap --endpoint https://example.invalid/api/agent/telemetry
```

The agent sends sanitized metadata only.

## Bounded live capture

Live capture is explicit, bounded, and metadata-only:

```powershell
python server/vpn_analyzer_agent.py --mode local --live --interface Ethernet --count 100 --timeout 30
```

Use either a packet count or the timeout bound; `--pcap` and `--live` cannot be combined. Raw packet payloads are never returned.
