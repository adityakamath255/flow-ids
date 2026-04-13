from typing import Optional, Any
from types import SimpleNamespace
from queue import Queue
import time

from . import cicflowmeter


class FlowExtractor:
    def __init__(
        self,
        expired_update: int,
        output_queue: Queue[dict[str, Any]],
        interface: Optional[str],
        pcap_file: Optional[str]
    ):
        writer = SimpleNamespace(write=output_queue.put)
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
