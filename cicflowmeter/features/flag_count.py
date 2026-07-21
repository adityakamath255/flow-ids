from collections import Counter

from ..snapshot import FlowSnapshot
from .context import PacketDirection

FLAG_BITS = (
    ("FIN", 0x01),
    ("SYN", 0x02),
    ("RST", 0x04),
    ("PSH", 0x08),
    ("ACK", 0x10),
    ("URG", 0x20),
    ("ECE", 0x40),
    ("CWR", 0x80),
)


class FlagCount:
    def __init__(self, flow: FlowSnapshot) -> None:
        self._all = Counter()
        self._forward = Counter()
        self._reverse = Counter()

        for packet in flow.packets:
            direction = packet.direction
            directional = (
                self._forward
                if direction is PacketDirection.FORWARD
                else self._reverse
            )
            for name, bit in FLAG_BITS:
                if packet.tcp_flags & bit:
                    self._all[name] += 1
                    directional[name] += 1

    def count(
        self,
        flag: str,
        direction: PacketDirection | None = None,
    ) -> int:
        if direction is PacketDirection.FORWARD:
            return self._forward[flag]
        if direction is PacketDirection.REVERSE:
            return self._reverse[flag]
        return self._all[flag]
