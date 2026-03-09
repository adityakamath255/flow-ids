from pathlib import Path
from threading import Lock
from queue import Queue
import json

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from sse_starlette.sse import EventSourceResponse

from .ids import ClassifiedFlow

PROTOCOL_NAMES = {6: "TCP", 17: "UDP"}


def _load_html() -> str:
    path = Path(__file__).parent / "dashboard.html"
    return path.read_text()


def _flow_to_event(classified_flow: ClassifiedFlow) -> dict:
    flow = classified_flow.flow
    prediction = classified_flow.prediction
    predicted_class = max(prediction, key=prediction.get)
    confidence = prediction[predicted_class]

    return {
        "timestamp": flow["timestamp"],
        "src": f"{flow['src_ip']}:{flow['src_port']}",
        "dst": f"{flow['dst_ip']}:{flow['dst_port']}",
        "protocol": PROTOCOL_NAMES.get(
            flow["protocol"],
            str(flow["protocol"])
        ),
        "duration": round(float(flow["flow_duration"]), 3),
        "packets": flow["tot_fwd_pkts"] + flow["tot_bwd_pkts"],
        "bytes": flow["totlen_fwd_pkts"] + flow["totlen_bwd_pkts"],
        "class": predicted_class,
        "confidence": round(float(confidence), 3),
        "threat": round(float(1.0 - prediction.get("BENIGN", 0.0)), 3),
    }


class _Stats:
    def __init__(self):
        self._lock = Lock()
        self._total_flows = 0
        self._total_bytes = 0
        self._classes: dict[str, int] = {}
        self._flows: list[dict] = []

    def record(self, event: dict):
        with self._lock:
            self._total_flows += 1
            cls = event["class"]
            self._classes[cls] = self._classes.get(cls, 0) + 1
            self._total_bytes += event["bytes"]
            self._flows.append(event)

    def snapshot(self) -> dict:
        with self._lock:
            return {
                "flows": list(self._flows),
                "total_flows": self._total_flows,
                "total_bytes": self._total_bytes,
                "classes": dict(self._classes),
            }


class Dashboard:
    def __init__(self, log_dir: Path):
        self._log_dir = log_dir
        self._clients: list[Queue[dict]] = []
        self._clients_lock = Lock()
        self._stats = _Stats()
        self.app = self._create_app()

    def push(self, classified_flow: ClassifiedFlow):
        event = _flow_to_event(classified_flow)
        self._stats.record(event)
        with self._clients_lock:
            for client in self._clients:
                client.put(event)

    def _create_app(self) -> FastAPI:
        app = FastAPI()
        html = _load_html()

        @app.get("/")
        def index():
            return HTMLResponse(html)

        @app.get("/api/flows")
        def flows_sse():
            return EventSourceResponse(self._flow_generator())

        @app.get("/api/snapshot")
        def get_snapshot():
            return self._stats.snapshot()

        @app.get("/api/logs")
        def list_logs():
            files = sorted(self._log_dir.glob("*.jsonl"))
            return [f.name for f in files]

        @app.get("/api/logs/{filename}")
        def get_log(filename: str):
            path = (self._log_dir / filename).resolve()
            if not path.is_relative_to(self._log_dir.resolve()):
                raise HTTPException(status_code=403)

            with open(path) as f:
                records = (
                    json.loads(line)
                    for line in f
                )
                flows = [
                    _flow_to_event(
                        ClassifiedFlow(record["flow"], record["prediction"])
                    )
                    for record in records
                ]
            return flows

        return app

    def _flow_generator(self):
        q = Queue()
        with self._clients_lock:
            self._clients.append(q)
        try:
            while True:
                yield json.dumps(q.get())
        finally:
            with self._clients_lock:
                self._clients.remove(q)
