import json
import unittest
from unittest.mock import patch

from ai_reporting import (
    GroqReportError,
    _validate_pcap_narrative,
    _validate_narrative,
    build_gateway_ai_context,
    build_pcap_ai_context,
    generate_groq_narrative,
    generate_groq_pcap_narrative,
)


class AiReportingTests(unittest.TestCase):
    def test_ai_context_omits_gateway_identity_addresses_spis_and_payload(self):
        context = build_gateway_ai_context({
            "gateway": {"gateway_id": "gw-private", "display_name": "Secret Site", "gateway_type": "STRONGSWAN", "status": "CONNECTED"},
            "telemetry": {
                "status": "CONFIRMED",
                "ikeRecords": [{"local_host": "192.0.2.10", "initiator_spi": "0x1234"}],
                "childRecords": [{"inbound_spi": "0x5678", "local_ts": "10.0.0.0/24"}],
            },
            "securityAssessment": {
                "score": {"value": 80, "evidenceCoveragePercent": 70, "status": "PARTIAL"},
                "findings": [{"category": "CHILD_SA_REPLAY_WINDOW", "severity": "Medium", "value": "32 packets", "detail": "Below recommendation."}],
                "configurationRecommendations": [{"id": "R1", "setting": "Replay", "current": "32", "recommended": "64", "basis": "Use a larger window."}],
                "limitations": ["Lifetime policy not observed."],
            },
        })
        serialized = json.dumps(context)
        self.assertNotIn("gw-private", serialized)
        self.assertNotIn("Secret Site", serialized)
        self.assertNotIn("192.0.2.10", serialized)
        self.assertNotIn("0x1234", serialized)
        self.assertNotIn("10.0.0.0/24", serialized)
        self.assertIn("R1", serialized)

    def test_pcap_context_contains_only_aggregate_report_evidence(self):
        context = build_pcap_ai_context({
            "scenario": {
                "name": "Private Site",
                "organization": "Secret Organization",
                "packets": [{"payload": "private packet payload"}],
                "sa": {
                    "ikeVersion": "IKEv2",
                    "encryptionAlgorithm": "AES_GCM_16_256",
                    "initiatorSpi": "0x12345678",
                    "evidence": [{"evidence": "10.0.0.1"}],
                },
                "features": {"packetCount": 9, "calculatedEntropy": 7.2},
            },
            "scorecard": {
                "totalScore": 82,
                "rating": "Secure",
                "findings": [{"severity": "Medium", "parameter": "PFS", "detectedValue": "Disabled", "penalty": 15}],
            },
            "prediction": {
                "predictedClass": "Web",
                "confidenceScore": 63,
                "source": "DERIVED_FROM_OBSERVED_DATA",
                "primaryFeatures": [{"name": "mean packet length", "value": "128"}],
            },
        })
        serialized = json.dumps(context)
        self.assertNotIn("Private Site", serialized)
        self.assertNotIn("Secret Organization", serialized)
        self.assertNotIn("private packet payload", serialized)
        self.assertNotIn("10.0.0.1", serialized)
        self.assertNotIn("0x12345678", serialized)
        self.assertEqual(context["findings"][0]["id"], "F1")
        self.assertEqual(context["findings"][0]["finding_type"], "OBSERVED_RISK")
        self.assertEqual(context["traffic_prediction"]["relative_pattern_score_percent"], 63)
        self.assertIsNone(context["traffic_prediction"]["model_confidence_percent"])
        self.assertEqual(context["traffic_features"]["packetCount"], 9)

    def test_pcap_narrative_rejects_notes_for_unknown_findings(self):
        narrative = {
            "executive_summary": "The assessment is partial.",
            "technical_interpretation": "Only captured negotiation data is assessed.",
            "traffic_interpretation": "The classifier output is uncertain.",
            "finding_notes": [{"id": "F1", "why_it_matters": "PFS was not observed."}],
        }
        self.assertEqual(_validate_pcap_narrative(narrative, {"F1"}), narrative)
        with self.assertRaises(GroqReportError):
            _validate_pcap_narrative({
                **narrative,
                "finding_notes": [{"id": "F99", "why_it_matters": "Invented finding."}],
            }, {"F1"})

    def test_pcap_groq_request_uses_safe_prompt_and_validates_response(self):
        narrative = {
            "executive_summary": "The evidence supports a partial assessment.",
            "technical_interpretation": "Only fields observed in the capture are discussed.",
            "traffic_interpretation": "The predicted category remains an uncertain inference.",
            "finding_notes": [{"id": "F1", "why_it_matters": "Review the observed setting."}],
        }
        response_body = json.dumps({"choices": [{"message": {"content": json.dumps(narrative)}}]}).encode()

        class FakeResponse:
            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

            def read(self, _size):
                return response_body

        context = {"findings": [{"id": "F1", "severity": "Medium"}], "traffic_prediction": {"status": "INFERRED"}}
        with patch("ai_reporting.urllib.request.urlopen", return_value=FakeResponse()) as urlopen:
            result = generate_groq_pcap_narrative(context, api_key="test-key", model="test-model")

        self.assertEqual(result, narrative)
        request = urlopen.call_args.args[0]
        self.assertEqual(request.full_url, "https://api.groq.com/openai/v1/chat/completions")
        self.assertEqual(request.get_header("Authorization"), "Bearer test-key")
        body = json.loads(request.data)
        self.assertEqual(body["model"], "test-model")
        self.assertIn("Encrypted payload contents are not visible", body["messages"][0]["content"])

    def test_narrative_validation_rejects_unapproved_recommendations_and_extra_keys(self):
        valid = {
            "executive_summary": "The snapshot is partial.",
            "technical_interpretation": "Only reported controls are discussed.",
            "finding_notes": [{"id": "F1", "why_it_matters": "This finding affects the observed security posture."}],
            "recommendation_notes": [{"id": "R1", "note": "Review the configured window."}],
        }
        self.assertEqual(_validate_narrative(valid, {"R1"}, {"F1"}), valid)
        with self.assertRaises(GroqReportError):
            _validate_narrative({**valid, "extra": "invented"}, {"R1"}, {"F1"})
        with self.assertRaises(GroqReportError):
            _validate_narrative({**valid, "recommendation_notes": [{"id": "NEW", "note": "Do something"}]}, {"R1"}, {"F1"})
        with self.assertRaises(GroqReportError):
            _validate_narrative({**valid, "finding_notes": [{"id": "F99", "why_it_matters": "Unknown finding."}]}, {"R1"}, {"F1"})

    def test_missing_api_key_returns_actionable_configuration_error(self):
        with patch.dict("os.environ", {"GROQ_API_KEY": ""}):
            with self.assertRaises(GroqReportError) as raised:
                generate_groq_narrative({"approved_recommendations": []})
        self.assertEqual(raised.exception.code, "GROQ_API_KEY_NOT_CONFIGURED")
        self.assertEqual(raised.exception.status, 503)

    def test_groq_request_uses_fixed_endpoint_and_strict_system_prompt(self):
        narrative = {
            "executive_summary": "Observed controls are mostly strong; evidence is partial.",
            "technical_interpretation": "The model only summarizes the supplied fields.",
            "finding_notes": [{"id": "F1", "why_it_matters": "This finding affects the observed security posture."}],
            "recommendation_notes": [{"id": "R1", "note": "Use the approved recommendation."}],
        }
        response_body = json.dumps({"choices": [{"message": {"content": json.dumps(narrative)}}]}).encode()

        class FakeResponse:
            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

            def read(self, _size):
                return response_body

        context = {
            "approved_recommendations": [{"id": "R1", "recommended": "AES-GCM"}],
            "findings": [{"id": "F1", "severity": "High", "value": "IKEv1"}],
        }
        with patch("ai_reporting.urllib.request.urlopen", return_value=FakeResponse()) as urlopen:
            result = generate_groq_narrative(context, api_key="test-key", model="test-model")

        self.assertEqual(result, narrative)
        request = urlopen.call_args.args[0]
        self.assertEqual(request.full_url, "https://api.groq.com/openai/v1/chat/completions")
        self.assertEqual(request.get_header("Authorization"), "Bearer test-key")
        self.assertEqual(request.get_header("User-agent"), "VPNAnalyzer/1.0")
        body = json.loads(request.data)
        self.assertEqual(body["response_format"], {"type": "json_object"})
        self.assertIn("Unknown means unknown", body["messages"][0]["content"])


if __name__ == "__main__":
    unittest.main()
