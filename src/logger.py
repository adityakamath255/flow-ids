import json
from datetime import datetime
from pathlib import Path

from .ids import ClassifiedFlow


class FlowLogger:
    def __init__(self, log_dir: Path, source: str):
        log_dir.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        filename = f"{timestamp}-{source}.csv"
        self._file = open(log_dir / filename, "w", newline="")

    def log(self, classified_flow: ClassifiedFlow):
        record = {
            "flow": classified_flow.flow,
            "prediction": classified_flow.prediction
        }

        self._file.write(f"{json.dumps(record)}\n")
        self._file.flush()

    def close(self):
        self._file.close()
