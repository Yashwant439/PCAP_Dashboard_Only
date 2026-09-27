# Limitations

PCAP-only analysis cannot reliably determine values that are encrypted or not carried on the wire:

- Child-SA fields inside encrypted IKE_AUTH
- Authentication method when the relevant payload is encrypted
- Configured SA lifetime when no visible lifetime notification exists
- Replay-window size
- PFS policy without correlated Child-SA or gateway evidence
- Tunnel/transport mode when inner packet evidence is unavailable
- Session keys and plaintext content

The local Scapy service must run in an environment where Scapy is installed. The browser parser remains available as a fallback. The classifier is a heuristic baseline, not a trained and calibrated production ML model. Live capture, persistent database storage, and cloud API deployment are not yet implemented.
