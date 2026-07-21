from datetime import datetime

from ..snapshot import FlowSnapshot
from .context import PacketDirection


class PacketTime:
    def __init__(self, flow: FlowSnapshot) -> None:
        self._timestamps = tuple(packet.timestamp for packet in flow.packets)
        self._forward = tuple(
            packet.timestamp
            for packet in flow.packets
            if packet.direction is PacketDirection.FORWARD
        )
        self._reverse = tuple(
            packet.timestamp
            for packet in flow.packets
            if packet.direction is PacketDirection.REVERSE
        )

    def iat(
        self,
        direction: PacketDirection,
    ) -> tuple[float, ...]:
        timestamps = (
            self._forward
            if direction is PacketDirection.FORWARD
            else self._reverse
        )
        return tuple(
            current - previous
            for previous, current in zip(timestamps, timestamps[1:])
        )

    def flow_iat(self) -> tuple[float, ...]:
        latest = self._timestamps[0]
        intervals = []
        for observed in self._timestamps[1:]:
            intervals.append(observed - latest)
            latest = max(observed, latest)
        return tuple(intervals)

    def activity(
        self,
        timeout: float,
    ) -> tuple[tuple[float, ...], tuple[float, ...]]:
        active = []
        idle = []
        active_start = self._timestamps[0]
        previous = active_start

        for observed in self._timestamps[1:]:
            timestamp = max(observed, previous)
            gap = timestamp - previous
            if gap > timeout:
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

    @property
    def timestamp(self) -> str:
        return datetime.fromtimestamp(self._timestamps[0]).strftime(
            "%Y-%m-%d %H:%M:%S"
        )

    @property
    def duration(self) -> float:
        return max(self._timestamps) - self._timestamps[0]
