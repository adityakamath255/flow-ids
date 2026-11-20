from dataclasses import dataclass
from typing import Literal

from scapy.packet import Packet, Padding

from .constants import EXPIRED_UPDATE, FLOW_DURATION_TIMEOUT, PACKETS_PER_GC
from .schema import FlowKey

PacketDirection = Literal["forward", "reverse"]

FIN = 0x01
SYN = 0x02
RST = 0x04
PSH = 0x08
ACK = 0x10
URG = 0x20
ECE = 0x40
CWR = 0x80


def packet_flow_key(packet: Packet) -> FlowKey | None:
    """Return None for packets other than TCP or UDP over IPv4."""
    if "IP" not in packet:
        return None
    if "TCP" in packet:
        transport = "TCP"
    elif "UDP" in packet:
        transport = "UDP"
    else:
        return None

    return FlowKey(
        transport,
        packet["IP"].src,
        packet["IP"].dst,
        packet[transport].sport,
        packet[transport].dport,
    )


@dataclass(frozen=True, slots=True)
class PacketValues:
    # CIC-IDS2017 measures packet lengths as transport payload bytes and
    # header lengths as TCP or UDP header bytes.
    timestamp: float
    header_length: int
    payload_length: int
    tcp_flags: int
    tcp_window: int | None


@dataclass(frozen=True, slots=True)
class FlowPacket(PacketValues):
    direction: PacketDirection


@dataclass(frozen=True, slots=True)
class PacketRecord(PacketValues):
    key: FlowKey

    @classmethod
    def from_packet(cls, packet: Packet) -> "PacketRecord | None":
        """Return None for packets other than TCP or UDP over IPv4."""
        key = packet_flow_key(packet)
        if key is None:
            return None
        transport = packet[key.transport]
        tcp = packet["TCP"] if "TCP" in packet else None
        # scapy parses Ethernet frame padding as part of the transport payload
        padding = packet.getlayer(Padding)
        payload_length = len(transport.payload) - (
            len(padding) if padding is not None else 0
        )
        return cls(
            key=key,
            timestamp=float(packet.time),
            header_length=len(transport) - len(transport.payload),
            payload_length=payload_length,
            tcp_flags=int(tcp.flags) if tcp is not None else 0,
            tcp_window=int(tcp.window or 0) if tcp is not None else None,
        )

    def for_flow(self, direction: PacketDirection) -> FlowPacket:
        return FlowPacket(
            timestamp=self.timestamp,
            header_length=self.header_length,
            payload_length=self.payload_length,
            tcp_flags=self.tcp_flags,
            tcp_window=self.tcp_window,
            direction=direction,
        )


@dataclass(frozen=True, slots=True)
class CompletedFlow:
    key: FlowKey
    packets: tuple[FlowPacket, ...]
    duration: float


class _Flow:
    __slots__ = (
        "key",
        "_packets",
        "_latest_timestamp",
        "_forward_fin",
        "_reverse_fin",
        "_ended",
    )

    def __init__(self, packet: PacketRecord) -> None:
        self.key = packet.key
        first = packet.for_flow("forward")
        self._packets = [first]
        self._latest_timestamp = packet.timestamp
        self._forward_fin = False
        self._reverse_fin = False
        self._ended = False
        self._observe_termination(first)

    def add(self, packet: PacketRecord) -> None:
        direction: PacketDirection = (
            "forward" if packet.key == self.key else "reverse"
        )
        flow_packet = packet.for_flow(direction)
        self._packets.append(flow_packet)
        self._latest_timestamp = max(
            packet.timestamp,
            self._latest_timestamp,
        )
        self._observe_termination(flow_packet)

    def complete(self) -> CompletedFlow:
        return CompletedFlow(self.key, tuple(self._packets), self.duration)

    def _observe_termination(self, packet: FlowPacket) -> None:
        if self._ended:
            return
        if packet.tcp_flags & RST:
            self._ended = True
            return
        if packet.tcp_flags & FIN:
            if packet.direction == "forward":
                self._forward_fin = True
            else:
                self._reverse_fin = True
            return
        if packet.tcp_flags & ACK and self._forward_fin and self._reverse_fin:
            self._ended = True

    @property
    def duration(self) -> float:
        return self._latest_timestamp - self._packets[0].timestamp

    @property
    def latest_timestamp(self) -> float:
        return self._latest_timestamp

    @property
    def ended(self) -> bool:
        return self._ended


class FlowTable:
    def __init__(self, expired_update: float = EXPIRED_UPDATE) -> None:
        if expired_update <= 0:
            raise ValueError("Flow expiry must be positive")
        self._flows: dict[FlowKey, _Flow] = {}
        self._expired_update = expired_update
        self._packets_count = 0

    def accept(self, packet: PacketRecord) -> tuple[CompletedFlow, ...]:
        completed = list(self._record(packet))
        self._packets_count += 1
        if self._packets_count % PACKETS_PER_GC == 0:
            completed.extend(self.expire(packet.timestamp))
        return tuple(completed)

    def _record(self, packet: PacketRecord) -> tuple[CompletedFlow, ...]:
        flow = self._flows.get(packet.key)
        if flow is None:
            flow = self._flows.get(packet.key.reverse())

        completed: list[CompletedFlow] = []
        if flow is None:
            flow = _Flow(packet)
            self._flows[flow.key] = flow
        elif packet.timestamp - flow.latest_timestamp >= self._expired_update:
            completed.append(self._flows.pop(flow.key).complete())
            flow = _Flow(packet)
            self._flows[flow.key] = flow
        else:
            flow.add(packet)

        if flow.ended or flow.duration >= FLOW_DURATION_TIMEOUT:
            completed.append(self._flows.pop(flow.key).complete())
        return tuple(completed)

    def expire(self, latest_time: float) -> tuple[CompletedFlow, ...]:
        expired = [
            key
            for key, flow in self._flows.items()
            if latest_time - flow.latest_timestamp >= self._expired_update
            or flow.duration >= FLOW_DURATION_TIMEOUT
        ]
        return tuple(self._flows.pop(key).complete() for key in expired)

    def close(self) -> tuple[CompletedFlow, ...]:
        completed = tuple(flow.complete() for flow in self._flows.values())
        self._flows.clear()
        return completed
