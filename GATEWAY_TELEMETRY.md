# Gateway Telemetry

The current adapter boundary is `server/telemetry.py`.

Implemented adapter:

- `StrongSwanAdapter`: read-only `swanctl --list-sas --raw` execution
- `ViciAdapter`: optional read-only VICI `list-sas` request
- No shell interpolation
- No PSKs, private keys, or session keys are requested
- Unknown output fields are ignored
- Missing command, command failure, and empty output return `NOT_DETERMINABLE`
- Missing `python-vici` or VICI socket access returns `NOT_DETERMINABLE`

Telemetry records are correlated with PCAP ESP SPIs only through exact normalized SPI matches in `server/correlation.py`. Source/destination or timing similarity cannot confirm a match. Unmatched records remain `UNKNOWN`.

Cisco, Fortinet, and Palo Alto adapters are intentionally not claimed as implemented.
