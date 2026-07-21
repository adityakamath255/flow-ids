from scapy.packet import Packet

from .features.context import PacketDirection


class TcpTermination:
    __slots__ = ("_forward_fin", "_reverse_fin", "_ended")

    def __init__(self) -> None:
        self._forward_fin = False
        self._reverse_fin = False
        self._ended = False

    def observe(self, packet: Packet, direction: PacketDirection) -> None:
        if "TCP" not in packet or self._ended:
            return

        flags = int(packet["TCP"].flags)
        if flags & 0x04:
            self._ended = True
            return
        if flags & 0x01:
            if direction is PacketDirection.FORWARD:
                self._forward_fin = True
            else:
                self._reverse_fin = True
            return
        if flags & 0x10 and self._forward_fin and self._reverse_fin:
            self._ended = True

    @property
    def ended(self) -> bool:
        return self._ended
