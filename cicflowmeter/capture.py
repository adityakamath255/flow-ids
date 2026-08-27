import logging
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from queue import Empty, Queue
from typing import Protocol, TypeAlias

from scapy.error import Scapy_Exception
from scapy.packet import Packet
from scapy.sendrecv import AsyncSniffer

from .feature_extraction import extract_features
from .flow import CompletedFlow, FlowTable, PacketRecord
from .schema import Flow

FLOW_POLL_TIMEOUT = 1.0
GC_INTERVAL = 1.0
LOGGER = logging.getLogger(__name__)
_PACKET_ERRORS = (
    AttributeError,
    IndexError,
    KeyError,
    TypeError,
    ValueError,
)


@dataclass(frozen=True, slots=True)
class InterfaceSource:
    name: str

    @property
    def description(self) -> str:
        return f"interface:{self.name}"


@dataclass(frozen=True, slots=True)
class PcapSource:
    path: Path

    @property
    def description(self) -> str:
        return f"pcap:{self.path}"


CaptureSource: TypeAlias = InterfaceSource | PcapSource


class FlowStream(Protocol):
    def __iter__(self) -> Iterator[Flow]: ...

    def finish(self) -> tuple[Flow, ...]: ...


class _FlowStream:
    def __init__(self, source: CaptureSource) -> None:
        self._packets: Queue[Packet] = Queue(maxsize=1)
        self._flows = FlowTable()
        self._sniffer = _create_sniffer(source, self._packets.put)
        self._next_gc = (
            time.monotonic() + GC_INTERVAL
            if isinstance(source, InterfaceSource)
            else None
        )
        self._started = False
        self._closed = False

    def start(self) -> None:
        self._sniffer.start()
        self._started = True

    def finish(self) -> tuple[Flow, ...]:
        if self._closed:
            return ()
        self._closed = True
        completed: list[CompletedFlow] = []
        try:
            if self._started:
                self._stop_sniffer()
                while self._sniffer.running:
                    try:
                        packet = self._packets.get(timeout=FLOW_POLL_TIMEOUT)
                    except Empty:
                        continue
                    completed.extend(self._record(packet))
                self._sniffer.join()
        finally:
            while True:
                try:
                    packet = self._packets.get_nowait()
                except Empty:
                    break
                completed.extend(self._record(packet))
            completed.extend(self._flows.close())
        return self._project(tuple(completed))

    def _stop_sniffer(self) -> None:
        if not self._sniffer.running:
            return
        try:
            self._sniffer.stop(join=False)
        except Scapy_Exception:
            if self._sniffer.running:
                raise

    def __iter__(self) -> Iterator[Flow]:
        try:
            while not self._closed:
                try:
                    packet = self._packets.get(timeout=FLOW_POLL_TIMEOUT)
                except Empty:
                    if not self._sniffer.running:
                        yield from self.finish()
                else:
                    yield from self._accept(packet)
                yield from self._expire()
        except KeyboardInterrupt:
            yield from self.finish()
            raise
        yield from self.finish()

    def _accept(self, packet: Packet) -> tuple[Flow, ...]:
        return self._project(self._record(packet))

    def _record(self, packet: Packet) -> tuple[CompletedFlow, ...]:
        if "TCP" not in packet and "UDP" not in packet:
            return ()
        try:
            return self._flows.accept(PacketRecord.from_packet(packet))
        except _PACKET_ERRORS:
            LOGGER.debug("Ignored malformed packet", exc_info=True)
            return ()

    def _expire(self) -> tuple[Flow, ...]:
        if self._next_gc is None:
            return ()
        observed = time.monotonic()
        if observed < self._next_gc:
            return ()
        self._next_gc = observed + GC_INTERVAL
        return self._project(self._flows.expire(time.time()))

    @staticmethod
    def _project(completed: tuple[CompletedFlow, ...]) -> tuple[Flow, ...]:
        return tuple(extract_features(flow) for flow in completed)


def _create_sniffer(
    source: CaptureSource,
    emit: Callable[[Packet], None],
) -> AsyncSniffer:
    if isinstance(source, PcapSource):
        return AsyncSniffer(
            offline=str(source.path),
            prn=emit,
            store=False,
        )
    return AsyncSniffer(
        iface=source.name,
        filter="ip and (tcp or udp)",
        prn=emit,
        store=False,
    )


@contextmanager
def open_flows(source: CaptureSource) -> Iterator[FlowStream]:
    stream = _FlowStream(source)
    try:
        stream.start()
        yield stream
    finally:
        stream.finish()
