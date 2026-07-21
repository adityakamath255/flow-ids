from enum import Enum, auto
from typing import Literal, NamedTuple

from scapy.packet import Packet


Transport = Literal["TCP", "UDP"]


class PacketDirection(Enum):
    FORWARD = auto()
    REVERSE = auto()


class FlowKey(NamedTuple):
    transport: Transport
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int

    def reverse(self) -> "FlowKey":
        return FlowKey(
            self.transport,
            self.dst_ip,
            self.src_ip,
            self.dst_port,
            self.src_port,
        )


def packet_flow_key(packet: Packet) -> FlowKey:
    if "TCP" in packet:
        transport = "TCP"
    elif "UDP" in packet:
        transport = "UDP"
    else:
        raise ValueError("Only TCP and UDP packets are supported")

    return FlowKey(
        transport,
        packet["IP"].src,
        packet["IP"].dst,
        packet[transport].sport,
        packet[transport].dport,
    )
