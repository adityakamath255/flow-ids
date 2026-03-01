from typing import Any, Optional
from queue import Queue
import time

from . import cicflowmeter

Flow = dict[str, Any]


class FlowExtractor:

    class CustomWriter:
        def __init__(self, output_queue: Queue[Flow]):
            self._output_queue = output_queue

        def write(self, data: Flow):
            self._output_queue.put(data)

    def __init__(
        self,
        expired_update: int,
        output_queue: Queue[Flow],
        interface: Optional[str],
        pcap_file: Optional[str]
    ):
        writer = self.CustomWriter(output_queue)
        self._sniffer, self._session = cicflowmeter.create_sniffer(
            input_file=pcap_file,
            input_interface=interface,
            output_mode="custom",
            output=writer,
            expired_update=expired_update
        )
        self._is_live = interface is not None

    def start(self):
        self._sniffer.start()
        if self._is_live:
            self._sniffer.join(1.0)
            if not self._sniffer.running:
                raise RuntimeError(
                    "Packet capture failed to start "
                    "(check permissions and interface name)"
                )

    def stop(self):
        if self._is_live:
            self._sniffer.stop()
        else:
            self._sniffer.join()
        current_time = time.time() * 1_000_000
        self._session.garbage_collect(current_time)

    def is_done(self) -> bool:
        return not self._is_live and not self._sniffer.running
