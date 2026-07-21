import threading
import time

from scapy.packet import Packet
from scapy.sessions import DefaultSession

from .constants import EXPIRED_UPDATE, FLOW_DURATION_TIMEOUT, PACKETS_PER_GC
from .features.context import PacketDirection, get_packet_flow_key
from .flow import Flow
from .utils import get_logger
from .writer import output_writer_factory


class FlowSession(DefaultSession):
    def __init__(
        self,
        mode=None,
        writer=None,
        fields=None,
        verbose=False,
        expired_update=EXPIRED_UPDATE,
        *args,
        **kwargs,
    ):
        super().__init__(*args, **kwargs)
        if expired_update <= 0:
            raise ValueError("Flow expiry must be positive")
        self._flows: dict[tuple, Flow] = {}
        self._expired_update = expired_update
        if isinstance(fields, str):
            self._fields = tuple(field.strip() for field in fields.split(","))
        elif fields is None:
            self._fields = None
        else:
            self._fields = tuple(fields)
        self._logger = get_logger(verbose)
        self._packets_count = 0
        self._output_writer = output_writer_factory(mode, writer)
        self._flows_lock = threading.Lock()
        self._writer_lock = threading.Lock()
        self._gc_stop = threading.Event()
        self._gc_thread: threading.Thread | None = None
        self._closed = False

    def start_periodic_gc(self, interval: float) -> None:
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
            forward_key = get_packet_flow_key(pkt, PacketDirection.FORWARD)
            reverse_key = get_packet_flow_key(pkt, PacketDirection.REVERSE)
        except (AttributeError, IndexError, KeyError, TypeError):
            self._logger.debug("Ignored malformed packet", exc_info=True)
            return

        timestamp = float(pkt.time)
        completed = self._record(pkt, timestamp, forward_key, reverse_key)
        self._packets_count += 1
        self._write(completed)
        if self._packets_count % PACKETS_PER_GC == 0:
            self.garbage_collect(timestamp)

    def _record(
        self,
        packet: Packet,
        timestamp: float,
        forward_key: tuple,
        reverse_key: tuple,
    ) -> list[Flow]:
        completed = []

        with self._flows_lock:
            flow = self._flows.get(forward_key)
            if flow is not None:
                key = forward_key
                direction = PacketDirection.FORWARD
            else:
                flow = self._flows.get(reverse_key)
                key = reverse_key
                direction = PacketDirection.REVERSE

            if flow is None:
                key = forward_key
                direction = PacketDirection.FORWARD
                flow = Flow(packet, direction)
                self._flows[key] = flow
            elif timestamp - flow.latest_timestamp > self._expired_update:
                completed.append(self._flows.pop(key))
                flow = Flow(packet, direction)
                self._flows[key] = flow
            else:
                flow.add_packet(packet, direction)

            if self._ends_flow(packet, flow) or (
                flow.duration >= FLOW_DURATION_TIMEOUT
            ):
                completed.append(self._flows.pop(key))

        return completed

    @staticmethod
    def _ends_flow(packet: Packet, flow: Flow) -> bool:
        if "TCP" not in packet:
            return False

        flags = int(packet["TCP"].flags)
        if flags & 0x04:
            return True
        if flags & 0x01 or not flags & 0x10:
            return False

        fin_directions = {
            direction
            for flow_packet, direction in flow.packets
            if "TCP" in flow_packet and int(flow_packet["TCP"].flags) & 0x01
        }
        return len(fin_directions) == 2

    def garbage_collect(self, latest_time: float | None) -> None:
        with self._flows_lock:
            expired = [
                key
                for key, flow in self._flows.items()
                if latest_time is None
                or latest_time - flow.latest_timestamp
                >= self._expired_update
                or flow.duration >= FLOW_DURATION_TIMEOUT
            ]
            completed = [self._flows.pop(key) for key in expired]
        self._write(completed)

    def _write(self, flows: list[Flow]) -> None:
        with self._writer_lock:
            for flow in flows:
                self._output_writer.write(flow.get_data(self._fields))

    def flush_flows(self) -> None:
        self.garbage_collect(None)

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
