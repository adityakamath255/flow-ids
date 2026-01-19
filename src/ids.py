from typing import Any, Optional
from queue import Queue, Empty
from pathlib import Path
from threading import Thread, Event
from dataclasses import dataclass
import time
import joblib
import numpy as np

from xgboost import XGBClassifier
from sklearn.preprocessing import StandardScaler, LabelEncoder

from . import cicflowmeter

Flow = dict[str, Any]
Prediction = dict[str, float]


class FlowExtractor:

    class CustomWriter:
        def __init__(self, output_queue: Queue[Flow]):
            self._output_queue = output_queue

        def write(self, data: Flow):
            self._output_queue.put(data)

    def __init__(
        self,
        interface: str,
        expired_update: int,
        output_queue: Queue[Flow]
    ):
        writer = self.CustomWriter(output_queue)
        self._sniffer, self._session = cicflowmeter.create_sniffer(
            input_file=None,
            input_interface=interface,
            output_mode="custom",
            output=writer,
            expired_update=expired_update
        )

    def start(self):
        self._sniffer.start()
        self._sniffer.join(1.0)

        if not self._sniffer.running:
            raise RuntimeError(
                "Packet capture failed to start "
                "(check permissions and interface name)"
            )

    def stop(self):
        self._sniffer.stop()
        current_time = time.time() * 1_000_000
        self._session.garbage_collect(current_time)


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
        return cls(
            joblib.load(model_dir / "model.pkl"),
            joblib.load(model_dir / "scaler.pkl"),
            joblib.load(model_dir / "encoder.pkl")
        )

    def _preprocess(self, flow: Flow) -> np.ndarray:
        values = np.array(
            [flow.get(feature, 0.0) for feature in self._features],
            dtype=np.float64
        )
        values = np.nan_to_num(values, nan=0.0, posinf=0.0, neginf=0.0)
        values = values.reshape(1, -1)
        return self._scaler.transform(values)

    def classify(self, flow: Flow) -> Prediction:
        data = self._preprocess(flow)
        probs = self._model.predict_proba(data)[0]
        return dict(zip(self._classes, probs))


@dataclass
class ClassifiedFlow:
    flow: Flow
    prediction: Prediction


class Ids(Thread):
    def __init__(
        self,
        flow_extractor: FlowExtractor,
        classifier: Classifier,
        flow_queue: Queue[Flow],
        output_queue: Queue[Optional[ClassifiedFlow]],
        poll_interval: float
    ):
        super().__init__(name="Ids")
        self._flow_extractor = flow_extractor
        self._classifier = classifier
        self._flow_queue = flow_queue
        self._output_queue = output_queue
        self._poll_interval = poll_interval
        self._stop_event = Event()

    @classmethod
    def from_config(
        cls,
        interface: str,
        expired_update: int,
        model_dir: Path,
        poll_interval: float,
        output_queue: Queue[Optional[ClassifiedFlow]]
    ):
        flow_queue = Queue()
        return cls(
            FlowExtractor(interface, expired_update, flow_queue),
            Classifier.from_artifacts(model_dir),
            flow_queue,
            output_queue,
            poll_interval,
        )

    def run(self):
        try:
            self._flow_extractor.start()

            while not self._stop_event.is_set():
                try:
                    flow = self._flow_queue.get(timeout=self._poll_interval)
                except Empty:
                    continue

                prediction = self._classifier.classify(flow)
                classified_flow = ClassifiedFlow(flow, prediction)
                self._output_queue.put(classified_flow)

        finally:
            self._flow_extractor.stop()
            self._output_queue.put(None)

    def stop(self):
        self._stop_event.set()
        self.join()
