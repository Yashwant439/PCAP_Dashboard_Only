import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from testbed_control import build_manual_commands, render_swanctl_config, validate_testbed_settings
from vpn_analyzer_agent import apply_testbed_job, build_parser


def sample_settings():
    return {
        "ikeVersion": "IKEv2",
        "mode": "Tunnel Mode",
        "cipher": "AES-256-GCM",
        "dhGroup": 19,
        "pfs": True,
        "ipVersion": "IPv4",
        "localAddress": "172.20.0.2",
        "remoteAddress": "172.20.0.3",
        "localId": "peerB",
        "remoteId": "peerA",
        "authMethod": "psk",
        "localTs": "172.20.0.2/32",
        "remoteTs": "172.20.0.3/32",
        "trafficType": "Video Streaming",
    }


class TestbedControlTests(unittest.TestCase):
    def test_rendered_config_matches_selected_settings_without_credentials(self):
        config = render_swanctl_config(sample_settings())
        self.assertIn("version = 2", config)
        self.assertIn("aes256gcm16-prfsha384-ecp256", config)
        self.assertIn("esp_proposals = aes256gcm16-ecp256", config)
        self.assertIn("mode = tunnel", config)
        self.assertIn("local_ts = 172.20.0.2/32", config)
        self.assertIn("remote_ts = 172.20.0.3/32", config)
        self.assertIn("auth = psk", config)
        self.assertNotIn("secret =", config.lower())
        self.assertNotIn("data =", config.lower())
        self.assertNotIn("private_key", config.lower())

    def test_manual_cli_preview_contains_only_fixed_commands_and_config_path(self):
        commands = build_manual_commands(sample_settings())
        self.assertEqual(commands.splitlines(), [
            "sudo install -m 0644 lab-testbed.conf /etc/swanctl/conf.d/lab-testbed.conf",
            "sudo swanctl --load-conns --file /etc/swanctl/conf.d/lab-testbed.conf",
            "sudo swanctl --initiate --child lab_child --ike lab_testbed",
            "sudo swanctl --list-sas --raw",
        ])
        with self.assertRaises(ValueError):
            build_manual_commands(sample_settings(), "/tmp/config;touch /tmp/pwned")

    def test_settings_reject_injection_unknown_fields_and_address_family_mismatch(self):
        invalid = sample_settings()
        invalid["localId"] = "peerB\nproposals = 3des-md5-modp1024"
        with self.assertRaisesRegex(ValueError, "TESTBED_LOCAL_ID_INVALID"):
            validate_testbed_settings(invalid)

        invalid = sample_settings()
        invalid["unexpected"] = "value"
        with self.assertRaisesRegex(ValueError, "TESTBED_SETTINGS_UNSUPPORTED_FIELD"):
            validate_testbed_settings(invalid)

        invalid = sample_settings()
        invalid["ipVersion"] = "IPv6"
        with self.assertRaisesRegex(ValueError, "TESTBED_ADDRESS_FAMILY_MISMATCH"):
            validate_testbed_settings(invalid)

    def test_agent_apply_uses_fixed_swanctl_argv_and_deletes_temporary_config(self):
        job = {
            "connectionName": "lab_testbed_1234567890",
            "childName": "lab_child_1234567890",
            "settings": sample_settings(),
        }
        calls = []

        def fake_run(command, **kwargs):
            calls.append(tuple(command))
            self.assertNotIn("shell", kwargs)
            if "--load-conns" in command:
                config_path = Path(command[-1])
                self.assertTrue(config_path.exists())
                self.assertIn("aes256gcm16-ecp256", config_path.read_text(encoding="utf-8"))
                config_text = config_path.read_text(encoding="utf-8")
                self.assertNotIn("secret =", config_text.lower())
                self.assertNotIn("data =", config_text.lower())
            return SimpleNamespace(returncode=0, stdout="", stderr="")

        with patch("vpn_analyzer_agent.shutil.which", return_value="/usr/sbin/swanctl"), patch(
            "vpn_analyzer_agent.subprocess.run", side_effect=fake_run
        ):
            result = apply_testbed_job(job)

        self.assertEqual(result["status"], "SUCCEEDED")
        self.assertEqual(calls[0][:3], ("/usr/sbin/swanctl", "--load-conns", "--file"))
        self.assertEqual(calls[1], (
            "/usr/sbin/swanctl", "--initiate", "--child", job["childName"],
            "--ike", job["connectionName"], "--timeout", "35",
        ))
        self.assertFalse(Path(calls[0][-1]).exists())

    def test_agent_apply_reports_failure_without_returning_command_output(self):
        job = {
            "connectionName": "lab_testbed_1234567890",
            "childName": "lab_child_1234567890",
            "settings": sample_settings(),
        }
        with patch("vpn_analyzer_agent.shutil.which", return_value="/usr/sbin/swanctl"), patch(
            "vpn_analyzer_agent.subprocess.run",
            return_value=SimpleNamespace(returncode=1, stdout="private detail", stderr="secret material"),
        ):
            result = apply_testbed_job(job)
        self.assertEqual(result["status"], "FAILED")
        self.assertNotIn("secret", result["message"].lower())
        self.assertNotIn("private detail", result["message"])

    def test_agent_testbed_apply_is_opt_in(self):
        parser = build_parser()
        default_args = parser.parse_args(["run"])
        enabled_args = parser.parse_args(["run", "--allow-testbed-apply"])
        self.assertFalse(default_args.allow_testbed_apply)
        self.assertTrue(enabled_args.allow_testbed_apply)


if __name__ == "__main__":
    unittest.main()
