from queue import Queue
import uuid
from . import cicflowmeter
import time


class FlowExtractor:

    class CustomWriter:
        def __init__(self, output_queue: Queue):
            self.output_queue = output_queue

        def write(self, data: dict):
            data["id"] = uuid.uuid4()
            self.output_queue.put(data)

    def __init__(
        self,
        interface: str,
        expired_update: int,
        output_queue: Queue
    ):
        writer = self.CustomWriter(output_queue)
        self._sniffer, self._session = cicflowmeter.create_sniffer(
            input_file=None,
            input_interface=interface,
            output_mode="custom",
            output=writer,
            expired_update=expired_update
        )

    def start(self):
        self._sniffer.start()
        # REPLACE LATER WITH ACTUAL PERMISSION CHECK LOGIC
        self._sniffer.join(0.1)

    def stop(self):
        self._sniffer.stop()
        current_time = time.time() * 1_000_000
        self._session.garbage_collect(current_time)
