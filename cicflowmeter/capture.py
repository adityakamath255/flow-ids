from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from queue import Empty, Queue
from typing import Protocol, TypeAlias

from scapy.sendrecv import AsyncSniffer

from .flow_session import FlowSession
from .schema import FlowData

FLOW_POLL_TIMEOUT = 1.0
GC_INTERVAL = 1.0


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
    def __iter__(self) -> Iterator[FlowData]: ...

    def close(self) -> None: ...


class _FlowStream:
    def __init__(self, source: CaptureSource) -> None:
        self._queue: Queue[FlowData] = Queue()
        self._session = FlowSession(emit=self._queue.put)
        self._sniffer = _create_sniffer(source, self._session)
        self._started = False
        self._closed = False

    def start(self) -> None:
        self._sniffer.start()
        self._started = True

    def close(self) -> None:
        if self._closed:
            return
        try:
            if self._started:
                if self._sniffer.running:
                    self._sniffer.stop()
                self._sniffer.join()
        finally:
            try:
                self._session.close()
            finally:
                self._closed = True

    def __iter__(self) -> Iterator[FlowData]:
        while not self._closed:
            try:
                yield self._queue.get(timeout=FLOW_POLL_TIMEOUT)
            except Empty:
                if not self._sniffer.running:
                    self.close()
        yield from self._drain()

    def _drain(self) -> Iterator[FlowData]:
        while True:
            try:
                yield self._queue.get_nowait()
            except Empty:
                return


def _create_sniffer(
    source: CaptureSource,
    session: FlowSession,
) -> AsyncSniffer:
    if isinstance(source, PcapSource):
        return AsyncSniffer(
            offline=str(source.path),
            prn=session.process,
            store=False,
        )
    return AsyncSniffer(
        iface=source.name,
        filter="ip and (tcp or udp)",
        prn=session.process,
        store=False,
        started_callback=lambda: session.start_periodic_gc(GC_INTERVAL),
    )


@contextmanager
def open_flows(source: CaptureSource) -> Iterator[FlowStream]:
    stream = _FlowStream(source)
    try:
        stream.start()
        yield stream
    finally:
        stream.close()
