import json
from collections.abc import Mapping
from dataclasses import dataclass
from io import BytesIO
from os import replace
from pathlib import Path
from tempfile import TemporaryDirectory
from zipfile import ZIP_DEFLATED, ZipFile

import joblib
from sklearn.preprocessing import LabelEncoder
from xgboost import XGBClassifier

ARTIFACT_FILE = "artifacts.zip"
MODEL_ENTRY = "model.json"
ENCODER_ENTRY = "encoder.pkl"
METRICS_ENTRY = "metrics.json"


@dataclass(frozen=True)
class LoadedModel:
    model: XGBClassifier
    features: tuple[str, ...]
    classes: tuple[str, ...]
    metrics: Mapping[str, object]


@dataclass(frozen=True)
class ModelArtifacts:
    directory: Path

    def load(self) -> LoadedModel:
        with ZipFile(self.directory / ARTIFACT_FILE) as archive:
            model_json = archive.read(MODEL_ENTRY)
            encoder = joblib.load(BytesIO(archive.read(ENCODER_ENTRY)))
            metrics = json.loads(archive.read(METRICS_ENTRY))

        if not isinstance(encoder, LabelEncoder):
            raise ValueError("Encoder artifact has the wrong type")
        if not isinstance(metrics, dict):
            raise ValueError("Metrics artifact is not an object")

        with TemporaryDirectory(dir=self.directory) as temporary:
            model_path = Path(temporary) / MODEL_ENTRY
            model_path.write_bytes(model_json)
            model = XGBClassifier()
            model.load_model(model_path)

        features, classes = self._contract(model, encoder)
        return LoadedModel(model, features, classes, metrics)

    def save(
        self,
        model: XGBClassifier,
        encoder: LabelEncoder,
        metrics: Mapping[str, object],
    ) -> None:
        self._contract(model, encoder)
        metrics_json = json.dumps(metrics, indent=2, allow_nan=False)
        self.directory.mkdir(parents=True, exist_ok=True)
        with TemporaryDirectory(dir=self.directory) as temporary:
            temporary_path = Path(temporary)
            model_path = temporary_path / MODEL_ENTRY
            archive_path = temporary_path / ARTIFACT_FILE
            model.save_model(model_path)

            encoder_buffer = BytesIO()
            joblib.dump(encoder, encoder_buffer)
            with ZipFile(archive_path, "w", ZIP_DEFLATED) as archive:
                archive.write(model_path, MODEL_ENTRY)
                archive.writestr(ENCODER_ENTRY, encoder_buffer.getvalue())
                archive.writestr(METRICS_ENTRY, metrics_json)

            replace(archive_path, self.directory / ARTIFACT_FILE)

    @staticmethod
    def _contract(
        model: XGBClassifier,
        encoder: LabelEncoder,
    ) -> tuple[tuple[str, ...], tuple[str, ...]]:
        feature_names = model.get_booster().feature_names
        features = tuple(feature_names) if feature_names else ()
        if not features:
            raise ValueError("Model artifact does not contain feature names")

        try:
            class_names = encoder.classes_
        except AttributeError:
            raise ValueError("Encoder artifact does not contain classes")
        if class_names is None:
            raise ValueError("Encoder artifact does not contain classes")
        classes = tuple(str(label) for label in class_names)
        if len(classes) != model.n_classes_:
            raise ValueError("Model and encoder artifacts disagree on classes")
        return features, classes
