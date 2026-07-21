import json
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

import joblib
from sklearn.preprocessing import LabelEncoder
from xgboost import XGBClassifier

MODEL_FILE = "model.json"
ENCODER_FILE = "encoder.pkl"
METRICS_FILE = "metrics.json"


@dataclass(frozen=True)
class LoadedModel:
    model: XGBClassifier
    features: tuple[str, ...]
    classes: tuple[str, ...]


@dataclass(frozen=True)
class ModelArtifacts:
    directory: Path

    def load(self) -> LoadedModel:
        model = XGBClassifier()
        model.load_model(self.directory / MODEL_FILE)
        encoder = joblib.load(self.directory / ENCODER_FILE)
        if not isinstance(encoder, LabelEncoder):
            raise ValueError("Encoder artifact has the wrong type")
        return self._validate(model, encoder)

    def save(
        self,
        model: XGBClassifier,
        encoder: LabelEncoder,
        metrics: Mapping[str, object],
    ) -> None:
        self._validate(model, encoder)
        metrics_json = json.dumps(metrics, indent=2, allow_nan=False)
        self.directory.mkdir(parents=True, exist_ok=True)
        model.save_model(self.directory / MODEL_FILE)
        joblib.dump(encoder, self.directory / ENCODER_FILE)
        (self.directory / METRICS_FILE).write_text(
            metrics_json,
            encoding="utf-8",
        )

    @staticmethod
    def _validate(
        model: XGBClassifier,
        encoder: LabelEncoder,
    ) -> LoadedModel:
        feature_names = model.get_booster().feature_names
        features = tuple(feature_names) if feature_names else ()
        if not features:
            raise ValueError("Model artifact does not contain feature names")

        class_names = encoder.classes_
        if class_names is None:
            raise ValueError("Encoder artifact does not contain classes")
        classes = tuple(str(label) for label in class_names)
        if len(classes) != model.n_classes_:
            raise ValueError("Model and encoder artifacts disagree on classes")
        return LoadedModel(model, features, classes)
