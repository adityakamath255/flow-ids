import argparse
import joblib
import json
import sqlite3
import time
from collections.abc import Iterable, Iterator, Sequence
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


@dataclass(frozen=True)
class Classified:
    flow: Flow
    prediction: Prediction


class FlowStream:
    def __init__(
        self,
        interface: str | None,
        pcap_file: str | None,
    ):
        self._queue: Queue[Flow] = Queue()
        self._sniffer, _ = cicflowmeter.create_sniffer(
            input_file=pcap_file,
            input_interface=interface,
            mode="callback",
            writer=self._queue.put,
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


def classify_stream(
    flows: Iterable[Flow], classifier: Classifier
) -> Iterator[Classified]:
    return (Classified(flow, classifier.classify(flow)) for flow in flows)


class FlowStore:
    def __init__(self, db_path: Path, source: str):
        self._source = source
        self._session_id: int | None = None
        self._conn = sqlite3.connect(db_path)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("""
            CREATE TABLE IF NOT EXISTS sessions (
                id         INTEGER PRIMARY KEY,
                source     TEXT NOT NULL,
                started_at REAL NOT NULL,
                ended_at   REAL
            )
        """)
        self._conn.execute("""
            CREATE TABLE IF NOT EXISTS flows (
                id          INTEGER PRIMARY KEY,
                session_id  INTEGER NOT NULL REFERENCES sessions(id),
                recorded_at REAL    NOT NULL,
                flow        TEXT    NOT NULL,
                prediction  TEXT    NOT NULL
            )
        """)
        self._conn.execute("""
            CREATE VIEW IF NOT EXISTS classified_flow AS
            SELECT
                f.id, f.session_id, f.recorded_at,
                json_extract(f.flow, '$.src_ip')   AS src_ip,
                json_extract(f.flow, '$.dst_ip')   AS dst_ip,
                json_extract(f.flow, '$.src_port') AS src_port,
                json_extract(f.flow, '$.dst_port') AS dst_port,
                json_extract(f.flow, '$.protocol') AS protocol,
                (SELECT key FROM json_each(f.prediction)
                     ORDER BY value DESC LIMIT 1) AS label,
                (SELECT MAX(value) FROM json_each(f.prediction)) AS confidence
            FROM flows f
        """)
        self._conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_flows_recorded_at "
            "ON flows(recorded_at)"
        )
        self._conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_flows_session_id "
            "ON flows(session_id)"
        )
        self._conn.commit()

    def __enter__(self) -> "FlowStore":
        cursor = self._conn.execute(
            "INSERT INTO sessions (source, started_at) VALUES (?, ?)",
            (self._source, time.time()),
        )
        self._session_id = cursor.lastrowid
        self._conn.commit()
        return self

    def __exit__(self, *exc) -> None:
        self._conn.execute(
            "UPDATE sessions SET ended_at = ? WHERE id = ?",
            (time.time(), self._session_id),
        )
        self._conn.commit()
        self._conn.close()

    def write_all(self, classified: Iterator[Classified]) -> None:
        for item in classified:
            self._conn.execute(
                "INSERT INTO flows (session_id, recorded_at, flow, prediction) "
                "VALUES (?, ?, ?, ?)",
                (
                    self._session_id, time.time(),
                    json.dumps(item.flow, default=str),
                    json.dumps(
                        {str(k): float(v) for k, v in item.prediction.items()}
                    ),
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
    parser.add_argument("-d", "--db", default="flows.db", type=Path,
                        help="SQLite output path")
    return parser.parse_args()


def main():
    args = parse_args()
    classifier = Classifier.load(args.model_dir)
    source = (
        f"interface:{args.interface}" 
        if args.interface 
        else f"pcap:{args.pcap}"
    )
    with (
        FlowStream(args.interface, args.pcap) as stream,
        FlowStore(args.db, source) as store,
    ):
        store.write_all(classify_stream(stream, classifier))


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass
