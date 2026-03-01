import csv
from datetime import datetime
from pathlib import Path

from .ids import ClassifiedFlow


class FlowLogger:
    def __init__(self, log_dir: Path, source: str):
        log_dir.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        filename = f"{timestamp}-{source}.csv"
        self._file = open(log_dir / filename, "w", newline="")
        self._writer = csv.writer(self._file)
        self._header_written = False

    def log(self, classified_flow: ClassifiedFlow):
        row = classified_flow.flow | classified_flow.prediction
        if not self._header_written:
            self._writer.writerow(row.keys())
            self._header_written = True
        self._writer.writerow(row.values())
        self._file.flush()

    def close(self):
        self._file.close()
