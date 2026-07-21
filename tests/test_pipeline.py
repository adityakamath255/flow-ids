import sqlite3
import unittest
from contextlib import closing
from json import loads
from pathlib import Path
from tempfile import TemporaryDirectory

import numpy as np
from scapy.layers.inet import IP, TCP
from scapy.utils import wrpcap

from flow_database import (
    Classified,
    RECENT_FLOWS_QUERY,
    SESSIONS_QUERY,
    initialize,
    open_flow_store,
)
from main import Classifier, Config, PcapSource, run
from train import DROP_FEATURES, FEATURE_MAPPING


class StubModel:
    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        return np.tile([0.1, 0.9], (len(X), 1))


class PipelineTests(unittest.TestCase):
    def test_replay_is_classified_and_stored(self) -> None:
        with TemporaryDirectory() as directory:
            pcap_path = Path(directory) / "flow.pcap"
            db_path = Path(directory) / "flows.db"
            packets = [
                IP(src="10.0.0.1", dst="10.0.0.2")
                / TCP(sport=1234, dport=80, flags="S"),
                IP(src="10.0.0.2", dst="10.0.0.1")
                / TCP(sport=80, dport=1234, flags="SA"),
                IP(src="10.0.0.1", dst="10.0.0.2")
                / TCP(sport=1234, dport=80, flags="FA"),
                IP(src="10.0.0.2", dst="10.0.0.1")
                / TCP(sport=80, dport=1234, flags="FA"),
                IP(src="10.0.0.1", dst="10.0.0.2")
                / TCP(sport=1234, dport=80, flags="A"),
            ]
            for offset, packet in enumerate(packets):
                packet.time = 1000 + offset * 0.25
            wrpcap(str(pcap_path), packets)

            classifier = Classifier(
                StubModel(),
                ("tot_fwd_pkts",),
                ("BENIGN", "DOS"),
            )
            run(
                Config(PcapSource(pcap_path), Path("unused"), db_path),
                classifier,
            )

            with closing(sqlite3.connect(db_path)) as connection:
                recent = connection.execute(
                    RECENT_FLOWS_QUERY, (10,)
                ).fetchone()
                session = connection.execute(
                    SESSIONS_QUERY, ("BENIGN",)
                ).fetchone()
                stored_flow = loads(
                    connection.execute("SELECT flow FROM flows").fetchone()[0]
                )

        self.assertEqual(
            recent[1:7],
            ("10.0.0.1", "10.0.0.2", 80, 6, "DOS", 0.9),
        )
        self.assertEqual(stored_flow["tot_fwd_pkts"], 3)
        self.assertEqual(stored_flow["tot_bwd_pkts"], 2)
        self.assertEqual(stored_flow["flow_iat_mean"], 250_000)
        self.assertEqual(stored_flow["flow_duration"], 1_000_000)
        expected_features = set(FEATURE_MAPPING.values()) - set(DROP_FEATURES)
        self.assertLessEqual(expected_features, stored_flow.keys())
        self.assertEqual(session[1], f"pcap:{pcap_path}")
        self.assertIsNotNone(session[3])
        self.assertEqual(session[4:], (1, 1))


class DatabaseMigrationTests(unittest.TestCase):
    def test_preserves_old_session_end_times(self) -> None:
        connection = sqlite3.connect(":memory:")
        connection.executescript(
            """
            CREATE TABLE sessions (
                id INTEGER PRIMARY KEY,
                source TEXT NOT NULL,
                started_at REAL NOT NULL,
                ended_at REAL
            );
            INSERT INTO sessions VALUES (1, 'old', 10, 20);
            """
        )

        initialize(connection)
        ended_at = connection.execute(
            "SELECT ended_at FROM session_ends WHERE session_id = 1"
        ).fetchone()[0]
        connection.close()

        self.assertEqual(ended_at, 20)

    def test_rejects_non_finite_json(self) -> None:
        with TemporaryDirectory() as directory:
            db_path = Path(directory) / "flows.db"
            with open_flow_store(db_path, "test") as store:
                with self.assertRaises(ValueError):
                    store.write_all(
                        [Classified({"flow_duration": np.nan}, {"BENIGN": 1})]
                    )


if __name__ == "__main__":
    unittest.main()
