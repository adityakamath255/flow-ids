import csv
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from scapy.layers.inet import IP, TCP, UDP
from scapy.packet import Raw
from scapy.utils import wrpcap

from cicflowmeter.cli import parse_args, run
from cicflowmeter.features.context import packet_flow_key
from cicflowmeter.flow_session import FlowSession

REPRESENTATIVE_FLOW = (
    (0.0, False, "S", 1000, 0),
    (0.1, True, "SA", 2000, 0),
    (0.2, False, "A", 1000, 0),
    (0.3, False, "A", 1000, 1),
    (0.4, False, "A", 1000, 2),
    (0.5, False, "A", 1000, 3),
    (0.6, False, "A", 1000, 4),
    (0.7, False, "A", 1000, 5),
    (0.8, True, "A", 2000, 6),
    (0.9, True, "A", 2000, 7),
    (1.0, True, "A", 2000, 8),
    (1.1, True, "A", 2000, 9),
    (7.0, False, "A", 1000, 10),
    (7.1, False, "FA", 1000, 0),
    (7.2, True, "FA", 2000, 0),
    (7.3, False, "A", 1000, 0),
)


def flow_packet(
    offset: float,
    reverse: bool = False,
    flags: str = "A",
    window: int = 1000,
    payload_size: int = 0,
):
    if reverse:
        packet = IP(src="10.0.0.2", dst="10.0.0.1") / TCP(
            sport=80,
            dport=1234,
            flags=flags,
            window=window,
        )
    else:
        packet = IP(src="10.0.0.1", dst="10.0.0.2") / TCP(
            sport=1234,
            dport=80,
            flags=flags,
            window=window,
        )
    if payload_size:
        packet /= Raw(b"x" * payload_size)
    packet.time = 1000 + offset
    return packet


class FlowIdentityTests(unittest.TestCase):
    def test_transport_and_direction_are_part_of_flow_identity(self) -> None:
        tcp = IP(src="10.0.0.1", dst="10.0.0.2") / TCP(
            sport=1234,
            dport=80,
        )
        udp = IP(src="10.0.0.1", dst="10.0.0.2") / UDP(
            sport=1234,
            dport=80,
        )

        tcp_key = packet_flow_key(tcp)
        udp_key = packet_flow_key(udp)

        self.assertNotEqual(tcp_key, udp_key)
        self.assertEqual(tcp_key.reverse().reverse(), tcp_key)


class FlowFeatureTests(unittest.TestCase):
    def test_flow_closes_after_both_fins_and_final_ack(self) -> None:
        output = []
        session = FlowSession(emit=output.append)

        session.process(flow_packet(0, flags="S"))
        session.process(flow_packet(0.1, flags="FA"))
        session.process(flow_packet(0.2, reverse=True, flags="FA"))
        self.assertEqual(output, [])

        session.process(flow_packet(0.3))
        session.close()

        self.assertEqual(len(output), 1)

    def test_feature_views_preserve_cic_values(self) -> None:
        output = []
        with FlowSession(emit=output.append) as session:
            for spec in REPRESENTATIVE_FLOW:
                session.process(flow_packet(*spec))

        flow = output[0]
        self.assertEqual(flow["tot_fwd_pkts"], 10)
        self.assertEqual(flow["tot_bwd_pkts"], 6)
        self.assertEqual(flow["init_fwd_win_byts"], 1000)
        self.assertEqual(flow["init_bwd_win_byts"], 2000)
        self.assertEqual(flow["ack_flag_cnt"], 15)
        self.assertEqual(flow["fwd_byts_b_avg"], 15)
        self.assertEqual(flow["fwd_pkts_b_avg"], 5)
        self.assertEqual(flow["bwd_byts_b_avg"], 30)
        self.assertEqual(flow["bwd_pkts_b_avg"], 4)
        self.assertAlmostEqual(flow["fwd_blk_rate_avg"], 37.5)
        self.assertAlmostEqual(flow["bwd_blk_rate_avg"], 100)
        self.assertAlmostEqual(flow["active_max"], 1_100_000)
        self.assertAlmostEqual(flow["active_min"], 300_000)
        self.assertAlmostEqual(flow["idle_mean"], 5_900_000)


class CliTests(unittest.TestCase):
    def test_replay_projects_requested_csv_fields(self) -> None:
        with TemporaryDirectory() as directory:
            pcap_path = Path(directory) / "flow.pcap"
            csv_path = Path(directory) / "flows.csv"
            wrpcap(str(pcap_path), [flow_packet(0, flags="S")])

            run(
                parse_args(
                    [
                        "--file",
                        str(pcap_path),
                        "--fields",
                        "src_ip,dst_port",
                        str(csv_path),
                    ]
                )
            )

            with csv_path.open(newline="", encoding="utf-8") as output:
                rows = list(csv.DictReader(output))

        self.assertEqual(
            rows,
            [{"src_ip": "10.0.0.1", "dst_port": "80"}],
        )


if __name__ == "__main__":
    unittest.main()
