import csv
import time
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from scapy.layers.inet import IP, TCP, UDP
from scapy.packet import Raw
from scapy.utils import wrpcap

from cicflowmeter.capture import PcapSource, _FlowStream
from cicflowmeter.cli import parse_args, run
from cicflowmeter.feature_extraction import extract_features
from cicflowmeter.flow import FlowTable, PacketRecord, packet_flow_key

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
        table = FlowTable()

        table.accept(PacketRecord.from_packet(flow_packet(0, flags="S")))
        table.accept(PacketRecord.from_packet(flow_packet(0.1, flags="FA")))
        completed = table.accept(
            PacketRecord.from_packet(
                flow_packet(0.2, reverse=True, flags="FA")
            )
        )
        self.assertEqual(completed, ())

        completed = table.accept(PacketRecord.from_packet(flow_packet(0.3)))

        self.assertEqual(len(completed), 1)

    def test_feature_extraction_preserves_cic_values(self) -> None:
        table = FlowTable()
        completed = []
        for spec in REPRESENTATIVE_FLOW:
            completed.extend(
                table.accept(PacketRecord.from_packet(flow_packet(*spec)))
            )
        completed.extend(table.close())

        flow = extract_features(completed[0]).features
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
        for field in (
            "totlen_fwd_pkts",
            "totlen_bwd_pkts",
            "fwd_pkt_len_max",
            "fwd_pkt_len_min",
            "bwd_pkt_len_max",
            "bwd_pkt_len_min",
            "pkt_len_max",
            "pkt_len_min",
        ):
            self.assertIsInstance(flow[field], int)

    def test_expired_reverse_packet_starts_a_new_forward_flow(self) -> None:
        table = FlowTable(expired_update=1)
        table.accept(PacketRecord.from_packet(flow_packet(0)))

        expired = table.accept(
            PacketRecord.from_packet(flow_packet(2, reverse=True))
        )
        next_flow = extract_features(table.close()[0])

        self.assertEqual(len(expired), 1)
        self.assertEqual(next_flow.key.src_ip, "10.0.0.2")
        self.assertEqual(next_flow.features["tot_fwd_pkts"], 1)


class CliTests(unittest.TestCase):
    def test_finish_drains_a_full_packet_handoff(self) -> None:
        with TemporaryDirectory() as directory:
            pcap_path = Path(directory) / "backlog.pcap"
            wrpcap(
                str(pcap_path),
                [flow_packet(offset / 100) for offset in range(50)],
            )
            stream = _FlowStream(PcapSource(pcap_path))
            stream.start()

            deadline = time.monotonic() + 1
            while not stream._packets.full() and time.monotonic() < deadline:
                time.sleep(0.001)
            self.assertTrue(stream._packets.full())

            flows = stream.finish()
            captured_packets = stream._sniffer.count

        emitted_packets = sum(
            flow.features["tot_fwd_pkts"] + flow.features["tot_bwd_pkts"]
            for flow in flows
        )
        self.assertEqual(emitted_packets, captured_packets)

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
