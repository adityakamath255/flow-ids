import sqlite3
import unittest
from contextlib import closing
from json import loads
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import cast

import numpy as np
from scapy.layers.inet import IP, TCP
from scapy.utils import wrpcap
from xgboost import XGBClassifier

from cicflowmeter.capture import PcapSource
from cicflowmeter.schema import Flow, FlowKey
from classifier import Classifier
from flow_database import (
    RECENT_FLOWS_QUERY,
    SESSIONS_QUERY,
    open_flow_store,
)
from main import run


class StubBooster:
    feature_names = ["tot_fwd_pkts"]


class StubModel:
    def get_booster(self) -> StubBooster:
        return StubBooster()

    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        return np.tile([0.01, 0.02, 0.03, 0.9, 0.04], (len(X), 1))


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
                cast(XGBClassifier, StubModel()),
                ("BENIGN", "BRUTE-FORCE", "DDOS", "DOS", "RECON"),
            )
            run(PcapSource(pcap_path), db_path, classifier)

            with closing(sqlite3.connect(db_path)) as connection:
                recent = connection.execute(
                    RECENT_FLOWS_QUERY, (10,)
                ).fetchone()
                session = connection.execute(
                    SESSIONS_QUERY, ("BENIGN",)
                ).fetchone()
                stored_features = loads(
                    connection.execute(
                        "SELECT features FROM flows"
                    ).fetchone()[0]
                )
                captured_at = connection.execute(
                    "SELECT captured_at FROM flows"
                ).fetchone()[0]

        self.assertEqual(
            recent[1:7],
            ("10.0.0.1", "10.0.0.2", 80, "TCP", "DOS", 0.9),
        )
        self.assertEqual(captured_at, 1000)
        self.assertEqual(stored_features["tot_fwd_pkts"], 3)
        self.assertEqual(stored_features["tot_bwd_pkts"], 2)
        self.assertEqual(stored_features["flow_iat_mean"], 250_000)
        self.assertEqual(stored_features["flow_duration"], 1_000_000)
        self.assertNotIn("src_ip", stored_features)
        self.assertEqual(session[1], f"pcap:{pcap_path}")
        self.assertIsNotNone(session[3])
        self.assertEqual(session[4:], (1, 1))


class DatabaseTests(unittest.TestCase):
    def test_rejects_non_finite_json(self) -> None:
        with TemporaryDirectory() as directory:
            db_path = Path(directory) / "flows.db"
            with open_flow_store(db_path, "test") as store:
                with self.assertRaises(ValueError):
                    store.write(
                        Flow(
                            FlowKey("TCP", "a", "b", 1, 2),
                            0,
                            {"flow_duration": np.nan},
                        ),
                        {"BENIGN": 1},
                    )


if __name__ == "__main__":
    unittest.main()
