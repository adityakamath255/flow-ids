import json
from typing import Any
from datetime import datetime
from pathlib import Path


class FlowLogger:
    def __init__(self, log_dir: Path, source: str):
        log_dir.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        filename = f"{timestamp}-{source}.jsonl"
        self._file = open(log_dir / filename, "w", newline="")

    def log(self, flow: dict[str, Any], prediction: dict[str, float]):
        record = {"flow": flow, "prediction": prediction}
        obj = json.dumps(record, default=float)
        self._file.write(f"{obj}\n")
        self._file.flush()

    def close(self):
        self._file.close()
