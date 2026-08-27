import json
from os import replace
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import cast

import numpy as np
from xgboost import XGBClassifier

from cicflowmeter.schema import Features

_CLASSES_ATTRIBUTE = "flow_ids_classes"


class Classifier:
    def __init__(
        self,
        model: XGBClassifier,
        classes: tuple[str, ...],
    ) -> None:
        self._model = model
        self._classes = classes
        self._features = tuple(
            cast(list[str], model.get_booster().feature_names)
        )

    @classmethod
    def load(cls, path: Path) -> "Classifier":
        model = XGBClassifier()
        model.load_model(path)
        encoded_classes = cast(
            str,
            model.get_booster().attr(_CLASSES_ATTRIBUTE),
        )
        classes = tuple(
            cast(
                list[str],
                json.loads(encoded_classes),
            )
        )
        return cls(model, classes)

    def save(self, path: Path) -> None:
        self._model.get_booster().set_attr(
            **{
                _CLASSES_ATTRIBUTE: json.dumps(
                    self._classes,
                    separators=(",", ":"),
                )
            }
        )
        path.parent.mkdir(parents=True, exist_ok=True)
        with TemporaryDirectory(dir=path.parent) as temporary:
            staged = Path(temporary) / path.name
            self._model.save_model(staged)
            replace(staged, path)

    def classify(self, features: Features) -> dict[str, float]:
        values = np.array(
            [features[name] for name in self._features],
            dtype=np.float64,
        )
        cleaned = np.where(np.isinf(values), np.nan, values)
        probabilities = self._model.predict_proba(cleaned.reshape(1, -1))[0]
        return {
            label: float(probability)
            for label, probability in zip(
                self._classes,
                probabilities,
                strict=True,
            )
        }
