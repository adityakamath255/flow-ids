import threading
import time
from collections.abc import Collection

from scapy.packet import Packet
from scapy.sessions import DefaultSession

from .constants import EXPIRED_UPDATE, FLOW_DURATION_TIMEOUT, PACKETS_PER_GC
from .features.context import FlowKey, PacketDirection, packet_flow_key
from .flow import Flow
from .utils import get_logger
from .writer import Output, open_output


class FlowSession(DefaultSession):
    def __init__(
        self,
        *args,
        output: Output,
        fields: str | Collection[str] | None = None,
        verbose: bool = False,
        expired_update: float = EXPIRED_UPDATE,
        **kwargs,
    ) -> None:
        super().__init__(*args, **kwargs)
        if expired_update <= 0:
            raise ValueError("Flow expiry must be positive")
        self._flows: dict[FlowKey, Flow] = {}
        self._expired_update = expired_update
        if isinstance(fields, str):
            self._fields = tuple(field.strip() for field in fields.split(","))
        elif fields is None:
            self._fields = None
        else:
            self._fields = tuple(fields)
        self._logger = get_logger(verbose)
        self._packets_count = 0
        self._output_writer = open_output(output)
        self._flows_lock = threading.Lock()
        self._writer_lock = threading.Lock()
        self._gc_stop = threading.Event()
        self._gc_thread: threading.Thread | None = None
        self._closed = False

    def start_periodic_gc(self, interval: float) -> None:
        if interval <= 0:
            raise ValueError("Flow collection interval must be positive")
        if self._closed:
            raise RuntimeError("Flow session is closed")
        if self._gc_thread is not None:
            raise RuntimeError("Periodic flow collection already started")
        self._gc_thread = threading.Thread(
            target=self._collect_periodically,
            args=(interval,),
            name="flow-gc",
            daemon=True,
        )
        self._gc_thread.start()

    def _collect_periodically(self, interval: float) -> None:
        while not self._gc_stop.wait(interval):
            try:
                self.garbage_collect(time.time())
            except Exception:
                self._logger.exception("Periodic flow collection failed")

    def process(self, pkt: Packet) -> None:
        if "TCP" not in pkt and "UDP" not in pkt:
            return

        try:
            key = packet_flow_key(pkt)
        except (AttributeError, IndexError, KeyError, TypeError, ValueError):
            self._logger.debug("Ignored malformed packet", exc_info=True)
            return

        timestamp = float(pkt.time)
        completed = self._record(pkt, timestamp, key)
        self._packets_count += 1
        self._write(completed)
        if self._packets_count % PACKETS_PER_GC == 0:
            self.garbage_collect(timestamp)

    def _record(
        self,
        packet: Packet,
        timestamp: float,
        packet_key: FlowKey,
    ) -> list[Flow]:
        completed = []
        reverse_key = packet_key.reverse()

        with self._flows_lock:
            flow = self._flows.get(packet_key)
            if flow is not None:
                key = packet_key
                direction = PacketDirection.FORWARD
            else:
                flow = self._flows.get(reverse_key)
                key = reverse_key
                direction = PacketDirection.REVERSE

            if flow is None:
                key = packet_key
                direction = PacketDirection.FORWARD
                flow = Flow(packet, direction, key)
                self._flows[key] = flow
            elif timestamp - flow.latest_timestamp >= self._expired_update:
                completed.append(self._flows.pop(key))
                flow = Flow(packet, direction, key)
                self._flows[key] = flow
            else:
                flow.add_packet(packet, direction)

            if flow.ended or flow.duration >= FLOW_DURATION_TIMEOUT:
                completed.append(self._flows.pop(key))

        return completed

    def garbage_collect(self, latest_time: float) -> None:
        with self._flows_lock:
            expired = [
                key
                for key, flow in self._flows.items()
                if latest_time - flow.latest_timestamp >= self._expired_update
                or flow.duration >= FLOW_DURATION_TIMEOUT
            ]
            completed = [self._flows.pop(key) for key in expired]
        self._write(completed)

    def _write(self, flows: list[Flow]) -> None:
        with self._writer_lock:
            for flow in flows:
                self._output_writer.write(flow.get_data(self._fields))

    def flush_flows(self) -> None:
        with self._flows_lock:
            completed = list(self._flows.values())
            self._flows.clear()
        self._write(completed)

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        self._gc_stop.set()
        if self._gc_thread is not None:
            self._gc_thread.join()
        try:
            self.flush_flows()
        finally:
            self._output_writer.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        self.close()
