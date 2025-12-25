from dataclasses import dataclass
from abc import ABC
from typing import Protocol
from pandas import DataFrame
from queue import Queue, Empty
from pathlib import Path
from threading import Thread, Event

REFRESH_RATE = 1.0

Flow = dict
HoneypotEvent = dict


@dataclass
class FlowMessage:
    data: Flow


@dataclass 
class HoneypotEventMessage:
    data: HoneypotEvent


Message = FlowMessage | HoneypotEventMessage


@dataclass
class Prediction:
    ...


class PolicyUpdate:
    ...


class MessageBus:
    def __init__(self):
        self.queue: Queue[Message] = Queue()

    def put_flow(self, flow: Flow):
        self.queue.put(FlowMessage(flow))

    def put_hp_event(self, hp_event: HoneypotEvent):
        self.queue.put(HoneypotEventMessage(hp_event))


class Component(ABC):
    def start(self):
        ...

    def stop(self):
        ...


class Model(Protocol):
    def predict(self, data: DataFrame) -> Prediction:
        ...


class FlowExtractor(Component):
    def __init__(
        self, 
        interface: str, 
        expiry_timeout: float, 
        message_bus: MessageBus
    ):
        ...


class Classifier:  # not a component, it can be stateless
    def __init__(self, model: Model):
        self._model = model

    @classmethod
    def from_model_dir(cls, model_dir: Path) -> 'Classifier':
        ...

    def preprocess(self, flow: Flow) -> DataFrame:
        ...

    def predict(self, flow: Flow) -> Prediction:
        df = self.preprocess(flow)
        return self._model.predict(df)


class Honeypot(Component):
    def __init__(
        self, 
        cowrie_dir: Path, 
        message_bus: MessageBus
    ):
        ...

    def process_pred(self, pred: Prediction) -> PolicyUpdate:
        ...


class Dashboard(Component):
    def __init__(self):
        ...

    def put_pred(self, pred: Prediction):
        ...

    def put_hp_event(self, hp_event: HoneypotEvent):
        ...

    def put_pol_update(self, pol_update: PolicyUpdate):
        ...


class Persister:  # stateless
    def __init__(self, log_dir: Path):
        self._log_dir = log_dir

    def put_pred(self, pred: Prediction):
        ...

    def put_pol_update(self, pol_update: PolicyUpdate):
        ...


class Pipeline(Thread):
    def __init__(
        self,
        interface: str,
        expiry_timeout: float,
        model_dir: Path,
        cowrie_dir: Path,
        log_dir: Path
    ):
        super().__init__()
        self._message_bus = MessageBus()
        self._flow_extractor = FlowExtractor(
            interface,
            expiry_timeout,
            self._message_bus
        )
        self._classifier = Classifier.from_model_dir(model_dir)
        self._honeypot = Honeypot(cowrie_dir, self._message_bus)
        self._dashboard = Dashboard()
        self._persister = Persister(log_dir)
        self._stop_event = Event()

    def _start_components(self):
        self._flow_extractor.start()
        self._honeypot.start()
        self._dashboard.start()

    def _stop_components(self):
        self._flow_extractor.stop()
        self._honeypot.stop()
        self._dashboard.stop()

    def _process_flow(self, flow: Flow):
        pred = self._classifier.predict(flow)
        self._dashboard.put_pred(pred)
        self._persister.put_pred(pred)
        if pol_update := self._honeypot.process_pred(pred):
            self._dashboard.put_pol_update(pol_update)
            self._persister.put_pol_update(pol_update)

    def _process_hp_event(self, hp_event: HoneypotEvent):
        self._dashboard.put_hp_event(hp_event)

    def run(self):
        self._start_components()

        while not self._stop_event.is_set():
            try:
                message = self._message_bus.queue.get(timeout=REFRESH_RATE)
            except Empty:
                continue

            match message:
                case FlowMessage(flow):
                    self._process_flow(flow)
                case HoneypotEventMessage(hp_event):
                    self._process_hp_event(hp_event)

        self._stop_components()

    def stop(self):
        self._stop_event.set()
