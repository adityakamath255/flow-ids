import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

import numpy as np
import pandas as pd
from sklearn.preprocessing import LabelEncoder

import train
from model_artifacts import ModelArtifacts


class TrainingDataTests(unittest.TestCase):
    def test_prepare_groups_labels_and_removes_unusable_features(self) -> None:
        frame = pd.DataFrame(
            {
                "Label": ["BENIGN", "PortScan", "Web Attack"],
                "flow_duration": [1.0, np.inf, 3.0],
                "dst_port": [80, 443, 8080],
            }
        )

        features, labels = train.prepare(frame)

        self.assertEqual(labels.tolist(), ["BENIGN", "RECON"])
        self.assertEqual(features.columns.tolist(), ["flow_duration"])
        self.assertTrue(np.isnan(features.iloc[1, 0]))

    def test_load_data_reports_an_empty_dataset(self) -> None:
        with patch.object(train, "DATASET_DIR", train.HERE / "missing"):
            with self.assertRaisesRegex(FileNotFoundError, "No CSV files"):
                train.load_data()

    def test_training_artifacts_preserve_the_model_contract(self) -> None:
        features = pd.DataFrame(
            {
                "flow_duration": np.arange(10, dtype=float),
                "tot_fwd_pkts": np.tile([1.0, 10.0], 5),
            }
        )
        labels = np.tile([0, 1], 5)

        model = train.train(features, labels)
        encoder = LabelEncoder().fit(["BENIGN", "DOS"])

        with TemporaryDirectory() as directory:
            artifacts = ModelArtifacts(Path(directory))
            artifacts.save(model, encoder, {"score": 1.0})
            loaded = artifacts.load()
            saved_files = {path.name for path in Path(directory).iterdir()}

        self.assertEqual(model.predict_proba(features).shape, (10, 2))
        self.assertEqual(
            loaded.features,
            ("flow_duration", "tot_fwd_pkts"),
        )
        self.assertEqual(loaded.classes, ("BENIGN", "DOS"))
        self.assertEqual(loaded.metrics, {"score": 1.0})
        self.assertEqual(saved_files, {"artifacts.zip"})


if __name__ == "__main__":
    unittest.main()
