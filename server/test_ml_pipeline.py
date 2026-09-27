import unittest

from ml_pipeline import FEATURE_NAMES, extract_flow_features, train_models


class MlPipelineTests(unittest.TestCase):
    def test_features_do_not_use_identity_fields(self):
        packets = [
            {"protocol": "ESP", "length": 1000, "timestamp": 0, "source_ip_hash": "a", "spi": "0x1", "seq": 1},
            {"protocol": "ESP", "length": 1100, "timestamp": 20, "source_ip_hash": "b", "spi": "0x2", "seq": 2},
        ]
        features = extract_flow_features(packets)
        self.assertEqual(set(features), set(FEATURE_NAMES))
        self.assertNotIn("spi", features)
        self.assertNotIn("seq", features)
        self.assertNotIn("source_ip_hash", features)

    def test_training_requires_multiple_labeled_capture_groups(self):
        result = train_models([{
            "capture_id": "capture-1",
            "label": "video",
            "features": {name: 1.0 for name in FEATURE_NAMES},
        }])
        self.assertEqual(result["status"], "INSUFFICIENT_DATA")

    def test_training_rejects_missing_ground_truth(self):
        result = train_models([
            {"capture_id": "capture-1", "label": "video", "features": {name: 1.0 for name in FEATURE_NAMES}},
            {"capture_id": "capture-2", "label": None, "features": {name: 1.0 for name in FEATURE_NAMES}},
            {"capture_id": "capture-3", "label": "web", "features": {name: 1.0 for name in FEATURE_NAMES}},
            {"capture_id": "capture-4", "label": "web", "features": {name: 1.0 for name in FEATURE_NAMES}},
        ])
        self.assertEqual(result["status"], "NOT_DETERMINABLE")


if __name__ == "__main__":
    unittest.main()
