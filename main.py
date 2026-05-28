import argparse
import joblib
import json
import sqlite3
import time
from collections.abc import Iterator, Sequence
from dataclasses import dataclass
from pathlib import Path
from queue import Queue, Empty
from typing import Any

import numpy as np
from xgboost import XGBClassifier

import cicflowmeter

FLOW_POLL_TIMEOUT = 1.0

Flow = dict[str, Any]
Prediction = dict[str, float]


class FlowStream:
    def __init__(
        self,
        idle_timeout: int,
        interface: str | None,
        pcap_file: str | None,
    ):
        self._queue: Queue[Flow] = Queue()
        self._sniffer, _ = cicflowmeter.create_sniffer(
            input_file=pcap_file,
            input_interface=interface,
            output_mode="callback",
            output=self._queue.put,
            expired_update=idle_timeout
        )

    def __enter__(self) -> "FlowStream":
        self._sniffer.start()
        return self

    def __exit__(self, *exc):
        self._sniffer.stop()
        self._sniffer.join()

    def __iter__(self) -> Iterator[Flow]:
        while True:
            try:
                yield self._queue.get(timeout=FLOW_POLL_TIMEOUT)
            except Empty:
                if not self._sniffer.running:
                    return


@dataclass
class Classifier:
    _model: XGBClassifier
    _features: Sequence[str]
    _classes: Sequence[str]
    
    @classmethod
    def load(cls, model_dir: Path) -> "Classifier":
        model = XGBClassifier()
        model.load_model(model_dir / "model.json")
        features = model.get_booster().feature_names
        encoder = joblib.load(model_dir / "encoder.pkl")
        classes = encoder.classes_
        return cls(model, features, classes)

    def classify(self, flow: Flow) -> Prediction:
        values = np.array(
            [flow.get(feature, np.nan) for feature in self._features],
            dtype=np.float64
        )
        cleaned = np.where(np.isinf(values), np.nan, values)
        reshaped = cleaned.reshape(1, -1)
        probs = self._model.predict_proba(reshaped)[0]
        return dict(zip(self._classes, probs))


class FlowStore:
    def __init__(self, db_path: Path):
        self._conn = sqlite3.connect(db_path)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("""
            CREATE TABLE IF NOT EXISTS flows (
                id          INTEGER PRIMARY KEY,
                recorded_at REAL    NOT NULL,
                src_ip      TEXT,
                dst_ip      TEXT,
                src_port    INTEGER,
                dst_port    INTEGER,
                protocol    INTEGER,
                label       TEXT    NOT NULL,
                confidence  REAL    NOT NULL,
                flow        TEXT    NOT NULL,
                prediction  TEXT    NOT NULL
            )
        """)
        self._conn.commit()

    def __enter__(self) -> "FlowStore":
        return self

    def __exit__(self, *exc) -> None:
        self._conn.close()

    def record(self, flow: Flow, prediction: Prediction) -> None:
        label = max(prediction, key=prediction.get)
        self._conn.execute(
            "INSERT INTO flows (recorded_at, src_ip, dst_ip, src_port, "
            "dst_port, protocol, label, confidence, flow, prediction) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                time.time(),
                flow.get("src_ip"), flow.get("dst_ip"),
                flow.get("src_port"), flow.get("dst_port"),
                flow.get("protocol"),
                str(label), float(prediction[label]),
                json.dumps(flow, default=str),
                json.dumps({str(k): float(v) for k, v in prediction.items()}),
            ),
        )
        self._conn.commit()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-i", "--interface", help="Live capture interface")
    group.add_argument("-p", "--pcap", help="Path to pcap file")
    parser.add_argument("-m", "--model-dir", default="models/", type=Path, 
                        help="Model output directory")
    parser.add_argument("-t", "--idle-timeout", default=10, type=int,
                        help="Expired flow update interval")
    parser.add_argument("-d", "--db", default="flows.db", type=Path,
                        help="SQLite output path")
    return parser.parse_args()


def main():
    args = parse_args()
    classifier = Classifier.load(args.model_dir)
    with (
        FlowStream(args.idle_timeout, args.interface, args.pcap) as stream,
        FlowStore(args.db) as store,
    ):
        for flow in stream:
            prediction = classifier.classify(flow)
            store.record(flow, prediction)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass
