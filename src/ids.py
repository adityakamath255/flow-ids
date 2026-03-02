from typing import Optional
from queue import Queue, Empty
from pathlib import Path
from threading import Thread, Event
from dataclasses import dataclass

from .flow_extractor import Flow, FlowExtractor
from .classifier import Prediction, Classifier

IDS_POLL_INTERVAL = 1.0


@dataclass
class ClassifiedFlow:
    flow: Flow
    prediction: Prediction


@dataclass
class IDSFinished:
    pass


class IDS(Thread):
    def __init__(
        self,
        flow_extractor: FlowExtractor,
        classifier: Classifier,
        flow_queue: Queue[Flow],
        output_queue: Queue[ClassifiedFlow | IDSFinished],
    ):
        super().__init__(name="IDS")
        self._flow_extractor = flow_extractor
        self._classifier = classifier
        self._flow_queue = flow_queue
        self._output_queue = output_queue
        self._stop_event = Event()

    @classmethod
    def from_config(
        cls,
        model_dir: Path,
        output_queue: Queue[ClassifiedFlow | IDSFinished],
        expired_update: int,
        interface: Optional[str],
        pcap_file: Optional[str]
    ):
        flow_queue = Queue()
        return cls(
            FlowExtractor(expired_update, flow_queue, interface, pcap_file),
            Classifier.from_artifacts(model_dir),
            flow_queue,
            output_queue,
        )

    def run(self):
        try:
            self._flow_extractor.start()

            while not self._stop_event.is_set():
                try:
                    flow = self._flow_queue.get(timeout=IDS_POLL_INTERVAL)
                except Empty:
                    if self._flow_extractor.is_done():
                        break
                    continue

                prediction = self._classifier.classify(flow)
                classified_flow = ClassifiedFlow(flow, prediction)
                self._output_queue.put(classified_flow)

        finally:
            self._flow_extractor.stop()
            self._output_queue.put(IDSFinished())

    def stop(self):
        self._stop_event.set()
        self.join()
