from queue import Queue, Empty
import uuid
from . import cicflowmeter
import time
from pathlib import Path
from threading import Thread, Event
from dataclasses import dataclass

Flow = dict
Prediction = float


class FlowExtractor:

    class CustomWriter:
        def __init__(self, output_queue: Queue):
            self.output_queue = output_queue

        def write(self, data: dict):
            data["id"] = uuid.uuid4()
            self.output_queue.put(data)

    def __init__(
        self,
        interface: str,
        expired_update: int,
        output_queue: Queue
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
        # TODO: REPLACE LATER WITH ACTUAL PERMISSION CHECK LOGIC
        self._sniffer.join(0.1)

    def stop(self):
        self._sniffer.stop()
        current_time = time.time() * 1_000_000
        self._session.garbage_collect(current_time)


class Classifier:
    @classmethod
    def from_artifacts(cls, model_dir: Path) -> 'Classifier':
        ...

    def classify(self, flow: Flow) -> Prediction:
        ...


@dataclass
class ClassifiedFlow:
    flow: Flow
    prediction: Prediction


class Ids(Thread):
    def __init__(
        self,
        interface: str,
        expired_update: int,
        model_dir: Path,
        refresh_rate: float,
        output_queue: Queue
    ):
        super().__init__(name="Ids")
        self._flow_queue = Queue()
        self._flow_extractor = FlowExtractor(
            interface, 
            expired_update, 
            self._flow_queue
        )
        self._classifier = Classifier.from_artifacts(model_dir)
        self._refresh_rate = refresh_rate
        self._output_queue = output_queue
        self._stop_event = Event()

    def run(self):
        self._flow_extractor.start()

        while not self._stop_event.is_set():
            try:
                flow = self._flow_queue.get(timeout=self._refresh_rate)
            except Empty:
                continue

            prediction = self._classifier.classify(flow)
            classified_flow = ClassifiedFlow(flow, prediction)
            self._output_queue.put(classified_flow)

        self._flow_extractor.stop()

    def stop(self):
        self._stop_event.set()
