import unittest
from types import SimpleNamespace
from unittest.mock import patch

from correlation import correlate_spi
from sanitizer import sanitize_analysis_payload
from telemetry import (
    StrongSwanAdapter,
    ViciAdapter,
    collect_xfrm_state_metadata,
    merge_xfrm_state_metadata,
    parse_swanctl_records,
    parse_vici_records,
    parse_xfrm_state_records,
)
from scapy_analyzer import parse_ike
from live_capture import capture_from_packets
from scapy.layers.inet import IP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.ipsec import ESP
from scapy.packet import Raw


class SecurityComponentTests(unittest.TestCase):
    def test_ikev2_visible_metadata(self):
        header = bytearray(28)
        header[16] = 41
        header[17] = 0x20
        header[18] = 34
        header[19] = 0x28
        notify = bytes([43, 0, 0, 8, 0, 0]) + (16388).to_bytes(2, "big")
        vendor = bytes([0, 0, 0, 8]) + b"TEST"
        message = header + notify + vendor
        message[24:28] = len(message).to_bytes(4, "big")
        result = parse_ike(bytes(message))
        self.assertEqual(result["ikeVersion"], "IKEv2")
        self.assertIn("Response", result["flags"])
        self.assertIn("Initiator", result["flags"])
        self.assertIn("NAT_DETECTION_SOURCE_IP", result["notifications"])
        self.assertIn("0x54455354", result["vendorIds"])

    def test_ikev1_payload_names_without_v2_proposal_decode(self):
        header = bytearray(28)
        header[16] = 13
        header[17] = 0x10
        header[18] = 2
        vendor = bytes([0, 0, 0, 8]) + b"V1ID"
        message = header + vendor
        message[24:28] = len(message).to_bytes(4, "big")
        result = parse_ike(bytes(message))
        self.assertEqual(result["ikeVersion"], "IKEv1")
        self.assertEqual(result["payloads"], ["VENDOR"])
        self.assertEqual(result["proposals"], [])
        self.assertEqual(result["vendorIds"], ["0x56314944"])

    def test_correlation_requires_exact_spi(self):
        result = correlate_spi(
            ["0x1234"],
            [{"outbound_spi": "0x1234", "encr": "aes256gcm16"}, {"outbound_spi": "0x9999"}],
        )
        self.assertEqual(result["correlation_status"], "CONFIRMED")
        self.assertEqual(result["matched"][0]["matched_spis"], ["0x1234"])
        self.assertEqual(result["unmatchedTelemetry"][0]["correlation_status"], "UNKNOWN")

    def test_sanitizer_drops_payload_and_secret_fields(self):
        result = sanitize_analysis_payload({
            "analysis_id": "capture-1",
            "packets": [{"protocol": "ESP", "spi": "0x1234", "payload": "secret", "session_key": "secret"}],
            "telemetry": [{
                "encr": "aes256gcm16",
                "life_time": 3600,
                "replay_window_in": 32,
                "replay_protection": True,
                "esn_in": False,
                "xfrm_spi_in": "0x1234",
                "private_key": "secret",
                "unknown": "secret",
            }],
        })
        self.assertNotIn("payload", result["packets"][0])
        self.assertNotIn("session_key", result["packets"][0])
        self.assertNotIn("private_key", result["telemetry"][0])
        self.assertNotIn("unknown", result["telemetry"][0])
        self.assertEqual(result["telemetry"][0]["life_time"], 3600)
        self.assertEqual(result["telemetry"][0]["replay_window_in"], 32)
        self.assertIs(result["telemetry"][0]["replay_protection"], True)
        self.assertIs(result["telemetry"][0]["esn_in"], False)
        self.assertEqual(result["telemetry"][0]["xfrm_spi_in"], "0x1234")

    def test_swanctl_parser_keeps_only_recognized_metadata(self):
        records = parse_swanctl_records(
            "name: site-a\n"
            "outbound-spi: 0x1234\n"
            "encr: aes256gcm16\n"
            "private-key: must-not-be-kept\n"
        )
        self.assertEqual(records[0]["outbound_spi"], "0x1234")
        self.assertNotIn("private_key", records[0])

    def test_swanctl_parser_preserves_explicit_child_sa_fields(self):
        records = parse_swanctl_records(
            "list-sa={site-a={version=2 state=ESTABLISHED child-sas={child-1={"
            "protocol=ESP spi-in=00001234 spi-out=00005678 mode=tunnel "
            "encr-alg=AES_GCM_16 encr-keysize=256 integ-alg=HMAC_SHA2_256_128 "
            "dh-group=MODP_2048 esn=1 "
            "rekey-time=120 life-time=3600 local-ts=[10.0.0.0/24] "
            "remote-ts=[10.1.0.0/24]}}}}"
        )
        child = next(record for record in records if record.get("protocol") == "ESP")
        self.assertEqual(child["inbound_spi"], "0x00001234")
        self.assertEqual(child["mode"], "tunnel")
        self.assertEqual(child["encr"], "AES_GCM_16_256")
        self.assertEqual(child["integ"], "HMAC_SHA2_256_128")
        self.assertEqual(child["dh"], "MODP_2048")
        self.assertIs(child["esn"], True)
        self.assertEqual(child["rekey_time"], 120)
        self.assertEqual(child["life_time"], 3600)
        self.assertEqual(child["local_ts"], "10.0.0.0/24")

    def test_vici_parser_keeps_only_sa_metadata(self):
        records = parse_vici_records({
            "site-a": {
                "state": "ESTABLISHED",
                "outbound_spi": "0x1234",
                "encr": "aes256gcm16",
                "session_key": "secret",
            }
        })
        self.assertEqual(records[0]["outbound_spi"], "0x1234")
        self.assertNotIn("session_key", records[0])

    def test_vici_parser_normalizes_child_sa_runtime_fields(self):
        records = parse_vici_records({
            "site-a": {
                "child-sas": {
                    "child-1": {
                        "protocol": "ESP",
                        "spi-in": "00001234",
                        "spi-out": "00005678",
                        "encr-alg": "AES_GCM_16",
                        "encr-keysize": 256,
                        "integ-alg": "HMAC_SHA2_256_128",
                        "dh-group": "MODP_2048",
                        "esn": "1",
                        "mode": "tunnel",
                        "life-time": 3600,
                        "session-key": "secret",
                    }
                }
            }
        })
        child = next(record for record in records if record.get("protocol") == "ESP")
        self.assertEqual(child["inbound_spi"], "0x00001234")
        self.assertEqual(child["outbound_spi"], "0x00005678")
        self.assertEqual(child["encr"], "AES_GCM_16_256")
        self.assertEqual(child["integ"], "HMAC_SHA2_256_128")
        self.assertEqual(child["dh"], "MODP_2048")
        self.assertIs(child["esn"], True)
        self.assertEqual(child["life_time"], 3600)
        self.assertNotIn("session_key", child)

    def test_vici_adapter_uses_read_only_list_sas_request(self):
        class FakeSession:
            requests = []

            def request(self, name, payload):
                self.requests.append((name, payload))
                return {"site-a": {"state": "ESTABLISHED", "mode": "tunnel"}}

        result = ViciAdapter(client_factory=FakeSession).collect()
        self.assertEqual(result.status, "CONFIRMED")
        self.assertEqual(FakeSession.requests, [("list-sas", {})])

    def test_swanctl_permission_error_is_not_determinable(self):
        with patch("telemetry.shutil.which", return_value="swanctl"), patch(
            "telemetry.subprocess.run", side_effect=PermissionError()
        ):
            result = StrongSwanAdapter().collect()
        self.assertEqual(result.status, "NOT_DETERMINABLE")
        self.assertEqual(result.records, [])

    def test_xfrm_parser_discards_key_bearing_lines(self):
        output = """src 172.20.0.3 dst 172.20.0.2
proto esp spi 0xc7583da6(3344448934) reqid 1(0x00000001) mode tunnel
 replay-window 32 seq 0x00000000 flag af-unspec (0x00100000)
 auth-trunc hmac(sha256) 0xPRIVATE_AUTH_KEY 128
 enc cbc(aes) 0xPRIVATE_ENCRYPTION_KEY
lifetime current:
 replay-window 0 replay 0 failed 0
src 172.20.0.2 dst 172.20.0.3
proto esp spi 0xc0451983(3225753987) reqid 1(0x00000001) mode tunnel
 replay-window 0 seq 0x00000000 flag af-unspec (0x00100000)
lifetime current:
 replay-window 9 replay 0 failed 0
 enc cbc(aes) 0xANOTHER_PRIVATE_KEY"""
        states = parse_xfrm_state_records(output)
        self.assertEqual(states, [
            {"protocol": "esp", "spi": "0xc7583da6", "mode": "tunnel", "replay_window": 32, "esn": False},
            {"protocol": "esp", "spi": "0xc0451983", "mode": "tunnel", "replay_window": 0, "esn": False},
        ])
        self.assertNotIn("PRIVATE", repr(states))

    def test_xfrm_merge_requires_exact_directional_spi(self):
        records = [{
            "protocol": "ESP",
            "inbound_spi": "0x00001234",
            "outbound_spi": "0x5678",
        }]
        merge_xfrm_state_metadata(records, [
            {"protocol": "esp", "spi": "0x1234", "replay_window": 32, "esn": False},
            {"protocol": "esp", "spi": "0x9999", "replay_window": 0, "esn": True},
        ])
        self.assertEqual(records[0]["replay_window_in"], 32)
        self.assertEqual(records[0]["xfrm_spi_in"], "0x1234")
        self.assertIs(records[0]["replay_protection"], True)
        self.assertIs(records[0]["esn_in"], False)
        self.assertNotIn("replay_window_out", records[0])
        self.assertNotIn("esn_out", records[0])

    def test_xfrm_collector_uses_fixed_read_only_command_and_handles_permission_error(self):
        with patch("telemetry.shutil.which", return_value="/usr/sbin/ip"), patch(
            "telemetry.subprocess.run",
            return_value=SimpleNamespace(
                returncode=0,
                stdout="""proto esp spi 0x1234 reqid 1 mode tunnel
 replay-window 64 seq 0x00000000 flag esn""",
                stderr="private key must never be returned",
            ),
        ) as run:
            states, error = collect_xfrm_state_metadata()
        self.assertIsNone(error)
        self.assertEqual(states[0]["spi"], "0x1234")
        self.assertEqual(states[0]["replay_window"], 64)
        self.assertIs(states[0]["esn"], True)
        self.assertEqual(run.call_args.args[0], ("/usr/sbin/ip", "-s", "xfrm", "state"))
        self.assertFalse(run.call_args.kwargs.get("shell", False))

        with patch("telemetry.shutil.which", return_value="/usr/sbin/ip"), patch(
            "telemetry.subprocess.run", side_effect=PermissionError()
        ):
            states, error = collect_xfrm_state_metadata()
        self.assertEqual(states, [])
        self.assertEqual(error, "XFRM_QUERY_FAILED_PermissionError")

    def test_live_metadata_extracts_native_esp_without_payload(self):
        result = capture_from_packets([
            IP(src="192.0.2.1", dst="198.51.100.1") / ESP(spi=0x1234, seq=9) / Raw(b"secret")
        ])[0]
        self.assertEqual(result["protocol"], "ESP")
        self.assertEqual(result["spi"], "0x00001234")
        self.assertEqual(result["sequence_observed"], 9)
        self.assertNotIn("payload", result)

    def test_live_metadata_detects_nat_t_esp(self):
        result = capture_from_packets([
            IPv6(src="2001:db8::1", dst="2001:db8::2") / UDP(sport=4500, dport=4500) /
            Raw((0x12345678).to_bytes(4, "big") + (4).to_bytes(4, "big") + b"secret")
        ])[0]
        self.assertEqual(result["protocol"], "ESP")
        self.assertEqual(result["spi"], "0x12345678")
        self.assertNotIn("secret", result.values())


if __name__ == "__main__":
    unittest.main()
