from xgboost import XGBClassifier
from sklearn.preprocessing import StandardScaler, LabelEncoder
from pathlib import Path
import joblib
import numpy as np
import pandas as pd

from .flow_extractor import Flow

Prediction = dict[str, float]


class Classifier:
    def __init__(
        self,
        model: XGBClassifier,
        scaler: StandardScaler,
        encoder: LabelEncoder
    ):
        self._model = model
        self._scaler = scaler
        self._features = scaler.feature_names_in_
        self._classes = encoder.classes_

    @classmethod
    def from_artifacts(cls, model_dir: Path) -> 'Classifier':
        model = XGBClassifier()
        model.load_model(str(model_dir / "model.json"))
        scaler = joblib.load(model_dir / "scaler.pkl")
        encoder = joblib.load(model_dir / "encoder.pkl")
        return cls(model, scaler, encoder)

    def _preprocess(self, flow: Flow) -> np.ndarray:
        values = np.array(
            [flow.get(feature, 0.0) for feature in self._features],
            dtype=np.float64
        )
        values = np.nan_to_num(values, nan=0.0, posinf=0.0, neginf=0.0)
        df = pd.DataFrame([values], columns=self._features)
        return self._scaler.transform(df)

    def classify(self, flow: Flow) -> Prediction:
        data = self._preprocess(flow)
        probs = self._model.predict_proba(data)[0]
        return dict(zip(self._classes, probs))
