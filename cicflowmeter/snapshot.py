from dataclasses import dataclass

from scapy.layers.inet import IP
from scapy.packet import Packet

from .bulk import BulkSnapshot
from .features.context import FlowKey, PacketDirection


@dataclass(frozen=True, slots=True)
class PacketSnapshot:
    timestamp: float
    direction: PacketDirection
    length: int
    header_length: int
    payload_length: int
    tcp_flags: int
    tcp_window: int | None

    @classmethod
    def from_packet(
        cls,
        packet: Packet,
        direction: PacketDirection,
    ) -> "PacketSnapshot":
        tcp = packet["TCP"] if "TCP" in packet else None
        if tcp is not None:
            tcp_flags = int(tcp.flags)
            tcp_window = int(tcp.window or 0)
        else:
            tcp_flags = 0
            tcp_window = None

        header_length = 0
        if IP in packet:
            header_length = (packet[IP].ihl or 5) * 4

        transport = "TCP" if tcp is not None else "UDP"
        return cls(
            timestamp=float(packet.time),
            direction=direction,
            length=len(packet),
            header_length=header_length,
            payload_length=len(packet[transport].payload),
            tcp_flags=tcp_flags,
            tcp_window=tcp_window,
        )


@dataclass(frozen=True, slots=True)
class FlowSnapshot:
    key: FlowKey
    packets: tuple[PacketSnapshot, ...]
    bulk: BulkSnapshot

    @property
    def protocol(self) -> int:
        if self.key.transport == "TCP":
            return 6
        return 17

    @property
    def duration(self) -> float:
        start = self.packets[0].timestamp
        return max(packet.timestamp for packet in self.packets) - start
