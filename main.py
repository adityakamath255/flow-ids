import argparse
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

from cicflowmeter.capture import (
    CaptureSource,
    InterfaceSource,
    PcapSource,
    open_flows,
)
from classifier import Classifier
from flow_database import open_flow_store


@dataclass(frozen=True)
class Config:
    source: CaptureSource
    model_path: Path
    db_path: Path


def parse_args(argv: Sequence[str] | None = None) -> Config:
    parser = argparse.ArgumentParser()
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-i", "--interface", help="Live capture interface")
    group.add_argument("-p", "--pcap", type=Path, help="Path to pcap file")
    parser.add_argument(
        "-m",
        "--model",
        default=Path("models/model.json"),
        type=Path,
        help="Trained model path",
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
    return Config(source, args.model, args.db)


def run(
    source: CaptureSource,
    db_path: Path,
    classifier: Classifier,
) -> None:
    with (
        open_flows(source) as flows,
        open_flow_store(db_path, source.description) as store,
    ):
        try:
            for flow in flows:
                store.write(flow, classifier.classify(flow.features))
        except KeyboardInterrupt:
            for flow in flows.finish():
                store.write(flow, classifier.classify(flow.features))


def main() -> None:
    config = parse_args()
    run(
        config.source,
        config.db_path,
        Classifier.load(config.model_path),
    )


if __name__ == "__main__":
    main()
