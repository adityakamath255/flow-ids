from ..snapshot import FlowSnapshot
from .context import PacketDirection


class FlowBytes:
    def __init__(self, flow: FlowSnapshot) -> None:
        self._flow = flow
        self._total = sum(packet.length for packet in flow.packets)
        self._forward_headers = tuple(
            packet.header_length
            for packet in flow.packets
            if packet.direction is PacketDirection.FORWARD
        )
        self._reverse_headers = tuple(
            packet.header_length
            for packet in flow.packets
            if packet.direction is PacketDirection.REVERSE
        )

    @property
    def rate(self) -> float:
        duration = self._flow.duration
        return self._total / duration if duration else 0

    def header_bytes(self, direction: PacketDirection) -> int:
        return sum(self._headers(direction))

    def minimum_header_bytes(self, direction: PacketDirection) -> int:
        headers = self._headers(direction)
        return min(headers) if headers else 0

    def bytes_per_bulk(self, direction: PacketDirection) -> float:
        return self._flow.bulk.for_direction(direction).bytes_per_bulk

    def packets_per_bulk(self, direction: PacketDirection) -> float:
        return self._flow.bulk.for_direction(direction).packets_per_bulk

    def bulk_rate(self, direction: PacketDirection) -> float:
        return self._flow.bulk.for_direction(direction).rate

    def _headers(self, direction: PacketDirection) -> tuple[int, ...]:
        if direction is PacketDirection.FORWARD:
            return self._forward_headers
        return self._reverse_headers
