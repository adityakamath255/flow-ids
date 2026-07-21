from scapy.packet import Packet

from . import constants
from .bulk import BulkTracker
from .features.context import FlowKey, PacketDirection
from .features.flag_count import FlagCount
from .features.flow_bytes import FlowBytes
from .features.packet_count import PacketCount
from .features.packet_length import PacketLength
from .features.packet_time import PacketTime
from .schema import FEATURE_ALIASES, FlowData
from .snapshot import FlowSnapshot, PacketSnapshot
from .termination import TcpTermination
from .statistics import get_statistics

MICROSECONDS_PER_SECOND = 1_000_000


class Flow:
    __slots__ = (
        "_key",
        "_packets",
        "_latest_timestamp",
        "_bulk",
        "_termination",
    )

    def __init__(
        self,
        packet: Packet,
        direction: PacketDirection,
        key: FlowKey,
    ) -> None:
        self._key = key
        snapshot = PacketSnapshot.from_packet(packet, direction)
        self._packets = [snapshot]
        self._latest_timestamp = snapshot.timestamp
        self._bulk = BulkTracker()
        self._termination = TcpTermination()
        self._record_packet_state(packet, snapshot)

    def get_data(self) -> FlowData:
        snapshot = self._snapshot()
        flow_bytes = FlowBytes(snapshot)
        flag_count = FlagCount(snapshot)
        packet_count = PacketCount(snapshot)
        packet_length = PacketLength(snapshot)
        packet_time = PacketTime(snapshot)
        flow_iat = get_statistics(
            packet_time.flow_iat(),
            MICROSECONDS_PER_SECOND,
        )
        forward_iat = get_statistics(
            packet_time.iat(PacketDirection.FORWARD),
            MICROSECONDS_PER_SECOND,
        )
        backward_iat = get_statistics(
            packet_time.iat(PacketDirection.REVERSE),
            MICROSECONDS_PER_SECOND,
        )
        active, idle = packet_time.activity(constants.ACTIVE_TIMEOUT)
        active_stat = get_statistics(active, MICROSECONDS_PER_SECOND)
        idle_stat = get_statistics(idle, MICROSECONDS_PER_SECOND)
        forward_window, reverse_window = self._initial_window_sizes(snapshot)

        data = {
            "src_ip": snapshot.key.src_ip,
            "dst_ip": snapshot.key.dst_ip,
            "src_port": snapshot.key.src_port,
            "dst_port": snapshot.key.dst_port,
            "protocol": snapshot.protocol,
            "timestamp": packet_time.timestamp,
            "flow_duration": packet_time.duration * MICROSECONDS_PER_SECOND,
            "flow_byts_s": flow_bytes.rate,
            "flow_pkts_s": packet_count.rate(),
            "fwd_pkts_s": packet_count.rate(PacketDirection.FORWARD),
            "bwd_pkts_s": packet_count.rate(PacketDirection.REVERSE),
            "tot_fwd_pkts": packet_count.total(PacketDirection.FORWARD),
            "tot_bwd_pkts": packet_count.total(PacketDirection.REVERSE),
            "totlen_fwd_pkts": packet_length.total(PacketDirection.FORWARD),
            "totlen_bwd_pkts": packet_length.total(PacketDirection.REVERSE),
            "fwd_pkt_len_max": packet_length.maximum(PacketDirection.FORWARD),
            "fwd_pkt_len_min": packet_length.minimum(PacketDirection.FORWARD),
            "fwd_pkt_len_mean": packet_length.mean(PacketDirection.FORWARD),
            "fwd_pkt_len_std": packet_length.standard_deviation(
                PacketDirection.FORWARD
            ),
            "bwd_pkt_len_max": packet_length.maximum(PacketDirection.REVERSE),
            "bwd_pkt_len_min": packet_length.minimum(PacketDirection.REVERSE),
            "bwd_pkt_len_mean": packet_length.mean(PacketDirection.REVERSE),
            "bwd_pkt_len_std": packet_length.standard_deviation(
                PacketDirection.REVERSE
            ),
            "pkt_len_max": packet_length.maximum(),
            "pkt_len_min": packet_length.minimum(),
            "pkt_len_mean": packet_length.mean(),
            "pkt_len_std": packet_length.standard_deviation(),
            "pkt_len_var": packet_length.variance(),
            "fwd_header_len": flow_bytes.header_bytes(PacketDirection.FORWARD),
            "bwd_header_len": flow_bytes.header_bytes(PacketDirection.REVERSE),
            "fwd_seg_size_min": flow_bytes.minimum_header_bytes(
                PacketDirection.FORWARD
            ),
            "fwd_act_data_pkts": packet_count.payload_packets(
                PacketDirection.FORWARD
            ),
            "flow_iat_mean": flow_iat.mean,
            "flow_iat_max": flow_iat.maximum,
            "flow_iat_min": flow_iat.minimum,
            "flow_iat_std": flow_iat.standard_deviation,
            "fwd_iat_tot": forward_iat.total,
            "fwd_iat_max": forward_iat.maximum,
            "fwd_iat_min": forward_iat.minimum,
            "fwd_iat_mean": forward_iat.mean,
            "fwd_iat_std": forward_iat.standard_deviation,
            "bwd_iat_tot": backward_iat.total,
            "bwd_iat_max": backward_iat.maximum,
            "bwd_iat_min": backward_iat.minimum,
            "bwd_iat_mean": backward_iat.mean,
            "bwd_iat_std": backward_iat.standard_deviation,
            "fwd_psh_flags": flag_count.count("PSH", PacketDirection.FORWARD),
            "bwd_psh_flags": flag_count.count("PSH", PacketDirection.REVERSE),
            "fwd_urg_flags": flag_count.count("URG", PacketDirection.FORWARD),
            "bwd_urg_flags": flag_count.count("URG", PacketDirection.REVERSE),
            "fin_flag_cnt": flag_count.count("FIN"),
            "syn_flag_cnt": flag_count.count("SYN"),
            "rst_flag_cnt": flag_count.count("RST"),
            "psh_flag_cnt": flag_count.count("PSH"),
            "ack_flag_cnt": flag_count.count("ACK"),
            "urg_flag_cnt": flag_count.count("URG"),
            "cwr_flag_count": flag_count.count("CWR"),
            "ece_flag_cnt": flag_count.count("ECE"),
            "down_up_ratio": packet_count.down_up_ratio(),
            "pkt_size_avg": packet_length.mean(),
            "init_fwd_win_byts": forward_window,
            "init_bwd_win_byts": reverse_window,
            "active_max": active_stat.maximum,
            "active_min": active_stat.minimum,
            "active_mean": active_stat.mean,
            "active_std": active_stat.standard_deviation,
            "idle_max": idle_stat.maximum,
            "idle_min": idle_stat.minimum,
            "idle_mean": idle_stat.mean,
            "idle_std": idle_stat.standard_deviation,
            "fwd_byts_b_avg": flow_bytes.bytes_per_bulk(
                PacketDirection.FORWARD
            ),
            "fwd_pkts_b_avg": flow_bytes.packets_per_bulk(
                PacketDirection.FORWARD
            ),
            "bwd_byts_b_avg": flow_bytes.bytes_per_bulk(
                PacketDirection.REVERSE
            ),
            "bwd_pkts_b_avg": flow_bytes.packets_per_bulk(
                PacketDirection.REVERSE
            ),
            "fwd_blk_rate_avg": flow_bytes.bulk_rate(PacketDirection.FORWARD),
            "bwd_blk_rate_avg": flow_bytes.bulk_rate(PacketDirection.REVERSE),
        }

        data.update({alias: data[source] for alias, source in FEATURE_ALIASES})

        return data

    def add_packet(self, packet: Packet, direction: PacketDirection) -> None:
        snapshot = PacketSnapshot.from_packet(packet, direction)
        self._packets.append(snapshot)
        self._latest_timestamp = max(
            snapshot.timestamp,
            self._latest_timestamp,
        )
        self._record_packet_state(packet, snapshot)

    def _record_packet_state(
        self,
        packet: Packet,
        snapshot: PacketSnapshot,
    ) -> None:
        if snapshot.payload_length:
            self._bulk.observe(
                snapshot.direction,
                snapshot.payload_length,
                snapshot.timestamp,
            )
        self._termination.observe(packet, snapshot.direction)

    def _snapshot(self) -> FlowSnapshot:
        return FlowSnapshot(
            key=self._key,
            packets=tuple(self._packets),
            bulk=self._bulk.snapshot(),
        )

    @staticmethod
    def _initial_window_sizes(
        snapshot: FlowSnapshot,
    ) -> tuple[int, int]:
        forward = None
        reverse = None
        for packet in snapshot.packets:
            if packet.tcp_window is None:
                continue
            if packet.direction is PacketDirection.FORWARD and forward is None:
                forward = packet.tcp_window
            elif (
                packet.direction is PacketDirection.REVERSE and reverse is None
            ):
                reverse = packet.tcp_window
            if forward is not None and reverse is not None:
                break
        return forward or 0, reverse or 0

    @property
    def duration(self) -> float:
        return self._latest_timestamp - self._packets[0].timestamp

    @property
    def latest_timestamp(self) -> float:
        return self._latest_timestamp

    @property
    def ended(self) -> bool:
        return self._termination.ended
