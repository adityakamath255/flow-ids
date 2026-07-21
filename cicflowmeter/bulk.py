from dataclasses import dataclass

from . import constants
from .features.context import PacketDirection


@dataclass(slots=True)
class _Candidate:
    start: float
    latest: float
    packets: int
    size: int


@dataclass(frozen=True, slots=True)
class DirectionBulk:
    bytes_per_bulk: float
    packets_per_bulk: float
    rate: float


@dataclass(frozen=True, slots=True)
class BulkSnapshot:
    forward: DirectionBulk
    reverse: DirectionBulk

    def for_direction(self, direction: PacketDirection) -> DirectionBulk:
        if direction is PacketDirection.FORWARD:
            return self.forward
        return self.reverse


class _DirectionBulk:
    __slots__ = (
        "latest",
        "candidate",
        "bulks",
        "packets",
        "size",
        "duration",
    )

    def __init__(self) -> None:
        self.latest: float | None = None
        self.candidate: _Candidate | None = None
        self.bulks = 0
        self.packets = 0
        self.size = 0
        self.duration = 0.0

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
            self.bulks += 1
            self.packets += candidate.packets
            self.size += candidate.size
            self.duration += timestamp - candidate.start
        elif candidate.packets > constants.BULK_BOUND:
            self.packets += 1
            self.size += payload_size
            self.duration += timestamp - candidate.latest

        candidate.latest = timestamp
        self.latest = timestamp

    def snapshot(self) -> DirectionBulk:
        return DirectionBulk(
            bytes_per_bulk=(self.size / self.bulks if self.bulks else 0),
            packets_per_bulk=(self.packets / self.bulks if self.bulks else 0),
            rate=self.size / self.duration if self.duration else 0,
        )


class BulkTracker:
    __slots__ = ("_forward", "_reverse")

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

    def snapshot(self) -> BulkSnapshot:
        return BulkSnapshot(
            forward=self._forward.snapshot(),
            reverse=self._reverse.snapshot(),
        )

    def _directions(
        self, direction: PacketDirection
    ) -> tuple[_DirectionBulk, _DirectionBulk]:
        if direction is PacketDirection.FORWARD:
            return self._forward, self._reverse
        return self._reverse, self._forward
