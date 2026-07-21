from dataclasses import dataclass

from . import constants
from .features.context import PacketDirection


@dataclass
class _Candidate:
    start: float
    latest: float
    packets: int
    size: int


@dataclass
class _Totals:
    bulks: int = 0
    packets: int = 0
    size: int = 0
    duration: float = 0


class _DirectionBulk:
    def __init__(self) -> None:
        self.latest: float | None = None
        self.candidate: _Candidate | None = None
        self.totals = _Totals()

    def observe(
        self,
        payload_size: int,
        timestamp: float,
        interrupted: bool,
    ) -> None:
        candidate = self.candidate
        if (
            interrupted
            or candidate is None
            or timestamp - candidate.latest > constants.CLUMP_TIMEOUT
        ):
            self.candidate = _Candidate(timestamp, timestamp, 1, payload_size)
            self.latest = timestamp
            return

        candidate.packets += 1
        candidate.size += payload_size
        if candidate.packets == constants.BULK_BOUND:
            self.totals.bulks += 1
            self.totals.packets += candidate.packets
            self.totals.size += candidate.size
            self.totals.duration += timestamp - candidate.start
        elif candidate.packets > constants.BULK_BOUND:
            self.totals.packets += 1
            self.totals.size += payload_size
            self.totals.duration += timestamp - candidate.latest

        candidate.latest = timestamp
        self.latest = timestamp


class BulkTracker:
    def __init__(self) -> None:
        self._forward = _DirectionBulk()
        self._reverse = _DirectionBulk()

    def observe(
        self,
        direction: PacketDirection,
        payload_size: int,
        timestamp: float,
    ) -> None:
        current, opposite = self._directions(direction)
        candidate = current.candidate
        interrupted = (
            candidate is not None
            and opposite.latest is not None
            and opposite.latest > candidate.start
        )
        current.observe(payload_size, timestamp, interrupted)

    def bytes_per_bulk(self, direction: PacketDirection) -> float:
        totals = self._directions(direction)[0].totals
        return totals.size / totals.bulks if totals.bulks else 0

    def packets_per_bulk(self, direction: PacketDirection) -> float:
        totals = self._directions(direction)[0].totals
        return totals.packets / totals.bulks if totals.bulks else 0

    def rate(self, direction: PacketDirection) -> float:
        totals = self._directions(direction)[0].totals
        return totals.size / totals.duration if totals.duration else 0

    def _directions(
        self, direction: PacketDirection
    ) -> tuple[_DirectionBulk, _DirectionBulk]:
        if direction is PacketDirection.FORWARD:
            return self._forward, self._reverse
        return self._reverse, self._forward
