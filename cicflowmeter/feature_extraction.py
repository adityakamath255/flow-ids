from collections.abc import Iterable
from math import sqrt
from typing import NamedTuple

from . import constants
from .bulk import bulk_metrics
from .flow import CompletedFlow, FlowPacket, PacketDirection
from .schema import FEATURE_ALIASES, Flow

MICROSECONDS_PER_SECOND = 1_000_000

FIN = 0x01
SYN = 0x02
RST = 0x04
PSH = 0x08
ACK = 0x10
URG = 0x20
ECE = 0x40
CWR = 0x80


class _Statistics(NamedTuple):
    total: float
    maximum: float
    minimum: float
    mean: float
    variance: float
    standard_deviation: float


def _statistics(
    values: Iterable[float],
    scale: float = 1,
) -> _Statistics:
    samples = tuple(values)
    if not samples:
        return _Statistics(0, 0, 0, 0, 0, 0)

    total = sum(samples)
    mean = total / len(samples)
    variance = sum((value - mean) ** 2 for value in samples) / len(samples)
    return _Statistics(
        total * scale,
        max(samples) * scale,
        min(samples) * scale,
        mean * scale,
        variance * scale**2,
        sqrt(variance) * scale,
    )


def _direction(
    flow: CompletedFlow,
    direction: PacketDirection,
) -> tuple[FlowPacket, ...]:
    return tuple(
        packet for packet in flow.packets if packet.direction == direction
    )


def _interarrival_times(
    packets: tuple[FlowPacket, ...],
) -> tuple[float, ...]:
    timestamps = tuple(packet.timestamp for packet in packets)
    return tuple(
        current - previous
        for previous, current in zip(timestamps, timestamps[1:])
    )


def _flow_interarrival_times(
    packets: tuple[FlowPacket, ...],
) -> tuple[float, ...]:
    latest = packets[0].timestamp
    intervals: list[float] = []
    for packet in packets[1:]:
        intervals.append(packet.timestamp - latest)
        latest = max(packet.timestamp, latest)
    return tuple(intervals)


def _activity(
    packets: tuple[FlowPacket, ...],
) -> tuple[tuple[float, ...], tuple[float, ...]]:
    active: list[float] = []
    idle: list[float] = []
    active_start = packets[0].timestamp
    previous = active_start

    for packet in packets[1:]:
        timestamp = max(packet.timestamp, previous)
        gap = timestamp - previous
        if gap > constants.ACTIVE_TIMEOUT:
            duration = previous - active_start
            if duration > 0:
                active.append(duration)
            idle.append(gap)
            active_start = timestamp
        previous = timestamp

    duration = previous - active_start
    if duration > 0:
        active.append(duration)
    return tuple(active), tuple(idle)


def _flag_count(packets: tuple[FlowPacket, ...], bit: int) -> int:
    return sum(bool(packet.tcp_flags & bit) for packet in packets)


def _minimum_header(packets: tuple[FlowPacket, ...]) -> int:
    return min(
        (packet.header_length for packet in packets),
        default=0,
    )


def _initial_window(packets: tuple[FlowPacket, ...]) -> int:
    return next(
        (
            packet.tcp_window
            for packet in packets
            if packet.tcp_window is not None
        ),
        0,
    )


def extract_features(flow: CompletedFlow) -> Flow:
    packets = flow.packets
    forward = _direction(flow, "forward")
    reverse = _direction(flow, "reverse")

    lengths = _statistics(packet.length for packet in packets)
    forward_lengths = _statistics(packet.length for packet in forward)
    reverse_lengths = _statistics(packet.length for packet in reverse)
    flow_iat = _statistics(
        _flow_interarrival_times(packets),
        MICROSECONDS_PER_SECOND,
    )
    forward_iat = _statistics(
        _interarrival_times(forward),
        MICROSECONDS_PER_SECOND,
    )
    reverse_iat = _statistics(
        _interarrival_times(reverse),
        MICROSECONDS_PER_SECOND,
    )
    active, idle = _activity(packets)
    active_stat = _statistics(active, MICROSECONDS_PER_SECOND)
    idle_stat = _statistics(idle, MICROSECONDS_PER_SECOND)
    duration = flow.duration
    bulk = bulk_metrics(flow)
    forward_bulk = bulk.forward
    reverse_bulk = bulk.reverse

    data = {
        "flow_duration": duration * MICROSECONDS_PER_SECOND,
        "flow_byts_s": lengths.total / duration if duration else 0,
        "flow_pkts_s": len(packets) / duration if duration else 0,
        "fwd_pkts_s": len(forward) / duration if duration else 0,
        "bwd_pkts_s": len(reverse) / duration if duration else 0,
        "tot_fwd_pkts": len(forward),
        "tot_bwd_pkts": len(reverse),
        "totlen_fwd_pkts": forward_lengths.total,
        "totlen_bwd_pkts": reverse_lengths.total,
        "fwd_pkt_len_max": forward_lengths.maximum,
        "fwd_pkt_len_min": forward_lengths.minimum,
        "fwd_pkt_len_mean": forward_lengths.mean,
        "fwd_pkt_len_std": forward_lengths.standard_deviation,
        "bwd_pkt_len_max": reverse_lengths.maximum,
        "bwd_pkt_len_min": reverse_lengths.minimum,
        "bwd_pkt_len_mean": reverse_lengths.mean,
        "bwd_pkt_len_std": reverse_lengths.standard_deviation,
        "pkt_len_max": lengths.maximum,
        "pkt_len_min": lengths.minimum,
        "pkt_len_mean": lengths.mean,
        "pkt_len_std": lengths.standard_deviation,
        "pkt_len_var": lengths.variance,
        "fwd_header_len": sum(packet.header_length for packet in forward),
        "bwd_header_len": sum(packet.header_length for packet in reverse),
        "fwd_seg_size_min": _minimum_header(forward),
        "fwd_act_data_pkts": sum(
            packet.payload_length > 0 for packet in forward
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
        "bwd_iat_tot": reverse_iat.total,
        "bwd_iat_max": reverse_iat.maximum,
        "bwd_iat_min": reverse_iat.minimum,
        "bwd_iat_mean": reverse_iat.mean,
        "bwd_iat_std": reverse_iat.standard_deviation,
        "fwd_psh_flags": _flag_count(forward, PSH),
        "bwd_psh_flags": _flag_count(reverse, PSH),
        "fwd_urg_flags": _flag_count(forward, URG),
        "bwd_urg_flags": _flag_count(reverse, URG),
        "fin_flag_cnt": _flag_count(packets, FIN),
        "syn_flag_cnt": _flag_count(packets, SYN),
        "rst_flag_cnt": _flag_count(packets, RST),
        "psh_flag_cnt": _flag_count(packets, PSH),
        "ack_flag_cnt": _flag_count(packets, ACK),
        "urg_flag_cnt": _flag_count(packets, URG),
        "cwr_flag_count": _flag_count(packets, CWR),
        "ece_flag_cnt": _flag_count(packets, ECE),
        "down_up_ratio": len(reverse) / len(forward) if forward else 0,
        "pkt_size_avg": lengths.mean,
        "init_fwd_win_byts": _initial_window(forward),
        "init_bwd_win_byts": _initial_window(reverse),
        "active_max": active_stat.maximum,
        "active_min": active_stat.minimum,
        "active_mean": active_stat.mean,
        "active_std": active_stat.standard_deviation,
        "idle_max": idle_stat.maximum,
        "idle_min": idle_stat.minimum,
        "idle_mean": idle_stat.mean,
        "idle_std": idle_stat.standard_deviation,
        "fwd_byts_b_avg": forward_bulk.bytes_per_bulk,
        "fwd_pkts_b_avg": forward_bulk.packets_per_bulk,
        "bwd_byts_b_avg": reverse_bulk.bytes_per_bulk,
        "bwd_pkts_b_avg": reverse_bulk.packets_per_bulk,
        "fwd_blk_rate_avg": forward_bulk.rate,
        "bwd_blk_rate_avg": reverse_bulk.rate,
    }
    data.update({alias: data[source] for alias, source in FEATURE_ALIASES})
    return Flow(flow.key, packets[0].timestamp, data)
