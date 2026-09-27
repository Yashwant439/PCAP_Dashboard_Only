import tempfile
import unittest
from pathlib import Path

from repository import AnalysisRepository


class RepositoryTests(unittest.TestCase):
    def test_persists_metadata_without_packet_payload_fields(self):
        with tempfile.TemporaryDirectory() as directory:
            repository = AnalysisRepository(Path(directory) / "analysis.sqlite3")
            analysis_id = repository.save_analysis({
                "scenarioName": "capture",
                "sa": {"encryptionAlgorithm": "AES-GCM", "rawPayload": "secret"},
                "features": {"packetCount": 1},
                "packets": [{
                    "id": 1,
                    "timestamp": 0,
                    "protocol": "ESP",
                    "length": 100,
                    "sourceIp": "192.0.2.1",
                    "rawPreview": "deadbeef",
                    "debug": "payload details",
                    "spi": "0x1234",
                    "seq": 1,
                }],
            })
            result = repository.get_analysis(analysis_id)
            self.assertIsNotNone(result)
            self.assertNotIn("rawPayload", result["sa"])
            self.assertNotIn("rawPreview", result["packets"][0])
            self.assertNotIn("debug", result["packets"][0])
            self.assertNotIn("sourceIp", result["packets"][0])
            self.assertEqual(result["packets"][0]["spi"], "0x1234")

    def test_unknown_analysis_is_not_created(self):
        with tempfile.TemporaryDirectory() as directory:
            repository = AnalysisRepository(Path(directory) / "analysis.sqlite3")
            self.assertIsNone(repository.get_analysis("missing"))


if __name__ == "__main__":
    unittest.main()
