import argparse
from collections.abc import Iterable, Iterator, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

import numpy as np

import cicflowmeter
from flow_database import Classified, Prediction, open_flow_store
from model_artifacts import ModelArtifacts


class ProbabilityModel(Protocol):
    def predict_proba(self, X: np.ndarray) -> np.ndarray: ...


@dataclass(frozen=True)
class Config:
    source: cicflowmeter.CaptureSource
    model_dir: Path
    db_path: Path


@dataclass(frozen=True)
class Classifier:
    _model: ProbabilityModel
    _features: tuple[str, ...]
    _classes: tuple[str, ...]

    @classmethod
    def load(cls, model_dir: Path) -> "Classifier":
        loaded = ModelArtifacts(model_dir).load()
        return cls(loaded.model, loaded.features, loaded.classes)

    def _classify(self, flow: cicflowmeter.FlowData) -> Prediction:
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

    def stream(
        self,
        flows: Iterable[cicflowmeter.FlowData],
    ) -> Iterator[Classified]:
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
    source: cicflowmeter.CaptureSource
    if args.interface is not None:
        source = cicflowmeter.InterfaceSource(args.interface)
    else:
        source = cicflowmeter.PcapSource(args.pcap)
    return Config(source, args.model_dir, args.db)


def run(config: Config, classifier: Classifier) -> None:
    with (
        cicflowmeter.open_flows(config.source) as flows,
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
