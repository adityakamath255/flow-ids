from ..snapshot import FlowSnapshot
from .context import PacketDirection


class PacketCount:
    def __init__(self, flow: FlowSnapshot) -> None:
        self._duration = flow.duration
        self._total = len(flow.packets)
        self._forward = 0
        self._reverse = 0
        self._forward_payload = 0
        self._reverse_payload = 0

        for packet in flow.packets:
            direction = packet.direction
            has_payload = packet.payload_length > 0
            if direction is PacketDirection.FORWARD:
                self._forward += 1
                self._forward_payload += has_payload
            else:
                self._reverse += 1
                self._reverse_payload += has_payload

    def total(self, direction: PacketDirection | None = None) -> int:
        if direction is PacketDirection.FORWARD:
            return self._forward
        if direction is PacketDirection.REVERSE:
            return self._reverse
        return self._total

    def rate(self, direction: PacketDirection | None = None) -> float:
        return self.total(direction) / self._duration if self._duration else 0

    def down_up_ratio(self) -> float:
        return self._reverse / self._forward if self._forward else 0

    def payload_packets(
        self,
        direction: PacketDirection | None = None,
    ) -> int:
        if direction is PacketDirection.FORWARD:
            return self._forward_payload
        if direction is PacketDirection.REVERSE:
            return self._reverse_payload
        return self._forward_payload + self._reverse_payload
