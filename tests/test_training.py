import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

import numpy as np
import pandas as pd

import train
from classifier import Classifier


class TrainingDataTests(unittest.TestCase):
    def test_prepare_groups_labels_and_removes_unusable_features(self) -> None:
        columns = {
            "Label": ["BENIGN", "PortScan", "Web Attack"],
            "flow_duration": [1.0, np.inf, 3.0],
        }
        columns.update({feature: [0, 0, 0] for feature in train.DROP_FEATURES})
        frame = pd.DataFrame(columns)

        features, labels = train.prepare(frame)

        self.assertEqual(labels.tolist(), ["BENIGN", "RECON"])
        self.assertEqual(features.columns.tolist(), ["flow_duration"])
        self.assertTrue(np.isnan(features.iloc[1, 0]))

    def test_prepare_rejects_an_incomplete_schema(self) -> None:
        frame = pd.DataFrame({"Label": ["BENIGN"], "flow_duration": [1.0]})

        with self.assertRaises(KeyError):
            train.prepare(frame)

    def test_load_data_reports_an_empty_dataset(self) -> None:
        with patch.object(train, "DATASET_DIR", train.HERE / "missing"):
            with self.assertRaisesRegex(FileNotFoundError, "No CSV files"):
                train.load_data()

    def test_saved_classifier_preserves_the_model_contract(self) -> None:
        features = pd.DataFrame(
            {
                "flow_duration": np.arange(20, dtype=float),
                "tot_fwd_pkts": np.tile(np.arange(5, dtype=float), 4),
            }
        )
        labels = np.tile(np.arange(5), 4)
        classes = ("E", "A", "D", "B", "C")

        model = train.train(features, labels)
        with TemporaryDirectory() as directory:
            model_path = Path(directory) / "model.json"
            Classifier(model, classes).save(model_path)
            loaded = Classifier.load(model_path)
            saved_files = {path.name for path in Path(directory).iterdir()}
            prediction = loaded.classify(
                {"flow_duration": 1, "tot_fwd_pkts": 1}
            )

        self.assertEqual(model.predict_proba(features).shape, (20, 5))
        self.assertEqual(tuple(prediction), classes)
        self.assertEqual(saved_files, {"model.json"})


if __name__ == "__main__":
    unittest.main()
