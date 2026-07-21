import argparse
from collections.abc import Iterable, Iterator, Sequence
from dataclasses import dataclass
from pathlib import Path
from queue import Empty, Queue
from typing import Protocol, TypeAlias

import numpy as np

import cicflowmeter
from flow_database import Classified, Flow, Prediction, open_flow_store
from model_artifacts import ModelArtifacts

FLOW_POLL_TIMEOUT = 1.0


class ProbabilityModel(Protocol):
    def predict_proba(self, X: np.ndarray) -> np.ndarray: ...


@dataclass(frozen=True)
class InterfaceSource:
    name: str

    @property
    def description(self) -> str:
        return f"interface:{self.name}"


@dataclass(frozen=True)
class PcapSource:
    path: Path

    @property
    def description(self) -> str:
        return f"pcap:{self.path}"


CaptureSource: TypeAlias = InterfaceSource | PcapSource


@dataclass(frozen=True)
class Config:
    source: CaptureSource
    model_dir: Path
    db_path: Path


class FlowStream:
    def __init__(self, source: CaptureSource):
        self._queue: Queue[Flow] = Queue()
        interface = (
            source.name if isinstance(source, InterfaceSource) else None
        )
        pcap_file = (
            str(source.path) if isinstance(source, PcapSource) else None
        )
        self._sniffer, self._session = cicflowmeter.create_sniffer(
            input_file=pcap_file,
            input_interface=interface,
            mode="callback",
            writer=self._queue.put,
        )
        self._closed = False

    def __enter__(self) -> "FlowStream":
        self._sniffer.start()
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def close(self) -> None:
        if self._closed:
            return
        if self._sniffer.running:
            self._sniffer.stop()
        self._sniffer.join()
        self._session.close()
        self._closed = True

    def __iter__(self) -> Iterator[Flow]:
        while not self._closed:
            try:
                yield self._queue.get(timeout=FLOW_POLL_TIMEOUT)
            except Empty:
                if not self._sniffer.running:
                    self.close()
        yield from self._drain()

    def _drain(self) -> Iterator[Flow]:
        while True:
            try:
                yield self._queue.get_nowait()
            except Empty:
                return


@dataclass(frozen=True)
class Classifier:
    _model: ProbabilityModel
    _features: tuple[str, ...]
    _classes: tuple[str, ...]

    @classmethod
    def load(cls, model_dir: Path) -> "Classifier":
        loaded = ModelArtifacts(model_dir).load()
        return cls(loaded.model, loaded.features, loaded.classes)

    def _classify(self, flow: Flow) -> Prediction:
        values = np.array(
            [flow.get(feature, np.nan) for feature in self._features],
            dtype=np.float64,
        )
        cleaned = np.where(np.isinf(values), np.nan, values)
        reshaped = cleaned.reshape(1, -1)
        probs = self._model.predict_proba(reshaped)[0]
        return {
            label: float(probability)
            for label, probability in zip(self._classes, probs, strict=True)
        }

    def stream(self, flows: Iterable[Flow]) -> Iterator[Classified]:
        return (Classified(flow, self._classify(flow)) for flow in flows)


def parse_args(argv: Sequence[str] | None = None) -> Config:
    parser = argparse.ArgumentParser()
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-i", "--interface", help="Live capture interface")
    group.add_argument("-p", "--pcap", type=Path, help="Path to pcap file")
    parser.add_argument(
        "-m",
        "--model-dir",
        default=Path("models"),
        type=Path,
        help="Model output directory",
    )
    parser.add_argument(
        "-d",
        "--db",
        default=Path("flows.db"),
        type=Path,
        help="SQLite output path",
    )
    args = parser.parse_args(argv)
    source: CaptureSource
    if args.interface is not None:
        source = InterfaceSource(args.interface)
    else:
        source = PcapSource(args.pcap)
    return Config(source, args.model_dir, args.db)


def run(config: Config, classifier: Classifier) -> None:
    with (
        FlowStream(config.source) as flows,
        open_flow_store(config.db_path, config.source.description) as store,
    ):
        try:
            store.write_all(classifier.stream(flows))
        except KeyboardInterrupt:
            flows.close()
            store.write_all(classifier.stream(flows))


def main() -> None:
    config = parse_args()
    run(config, Classifier.load(config.model_dir))


if __name__ == "__main__":
    main()
