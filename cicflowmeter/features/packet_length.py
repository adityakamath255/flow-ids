from math import sqrt
from statistics import fmean, pvariance

from ..snapshot import FlowSnapshot
from .context import PacketDirection


class PacketLength:
    def __init__(self, flow: FlowSnapshot) -> None:
        self._all = tuple(packet.length for packet in flow.packets)
        self._forward = tuple(
            packet.length
            for packet in flow.packets
            if packet.direction is PacketDirection.FORWARD
        )
        self._reverse = tuple(
            packet.length
            for packet in flow.packets
            if packet.direction is PacketDirection.REVERSE
        )

    def maximum(self, direction: PacketDirection | None = None) -> int:
        values = self._for_direction(direction)
        return max(values) if values else 0

    def minimum(self, direction: PacketDirection | None = None) -> int:
        values = self._for_direction(direction)
        return min(values) if values else 0

    def total(self, direction: PacketDirection | None = None) -> int:
        return sum(self._for_direction(direction))

    def mean(self, direction: PacketDirection | None = None) -> float:
        values = self._for_direction(direction)
        return fmean(values) if values else 0

    def variance(self, direction: PacketDirection | None = None) -> float:
        values = self._for_direction(direction)
        return pvariance(values) if values else 0

    def standard_deviation(
        self,
        direction: PacketDirection | None = None,
    ) -> float:
        return sqrt(self.variance(direction))

    def _for_direction(
        self,
        direction: PacketDirection | None,
    ) -> tuple[int, ...]:
        if direction is PacketDirection.FORWARD:
            return self._forward
        if direction is PacketDirection.REVERSE:
            return self._reverse
        return self._all
