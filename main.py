from dataclasses import dataclass
from queue import Queue, Empty
from typing import Optional, Any, TextIO
from types import SimpleNamespace
from pathlib import Path
import joblib
import json
from datetime import datetime
from threading import Thread, Lock
import argparse

import numpy as np
import pandas as pd
from xgboost import XGBClassifier
from sklearn.preprocessing import StandardScaler, LabelEncoder
import uvicorn
from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from sse_starlette.sse import EventSourceResponse

import cicflowmeter

FLOW_POLL_TIMEOUT = 1.0
PROTOCOL_NAMES = {6: "TCP", 17: "UDP"}

Flow = dict[str, Any]
Prediction = dict[str, float]


class FlowExtractor:
    @dataclass
    class Captured:
        flow: Flow

    class Done:
        pass

    class Waiting:
        pass

    Result = Captured | Done | Waiting

    def __init__(
        self,
        expired_update: int,
        interface: Optional[str],
        pcap_file: Optional[str]
    ):
        self._queue: Queue[Flow] = Queue()
        # cicflowmeter expects a class with a write method
        writer = SimpleNamespace(write=self._queue.put)  
        self._sniffer, self._session = cicflowmeter.create_sniffer(
            input_file=pcap_file,
            input_interface=interface,
            output_mode="custom",
            output=writer,
            expired_update=expired_update
        )
        self._is_live = interface is not None

    def __enter__(self):
        self._sniffer.start()
        if self._is_live:
            self._sniffer.join(1.0)
            if not self._sniffer.running:
                raise RuntimeError(
                    "Packet capture failed to start "
                    "(check permissions and interface name)"
                )
        return self

    def __exit__(self, *exc):
        if self._is_live:
            self._sniffer.stop()
        else:
            self._sniffer.join()
        return False

    def get_flow(self, timeout: float) -> Result:
        try:
            flow = self._queue.get(timeout=timeout)
            return self.Captured(flow)
        except Empty:
            return self.Done() if self._is_done() else self.Waiting()

    def _is_done(self) -> bool:
        return not self._is_live and not self._sniffer.running


class Classifier:
    def __init__(
        self,
        model: XGBClassifier,
        scaler: StandardScaler,
        encoder: LabelEncoder
    ):
        self._model = model
        self._scaler = scaler
        self._features = scaler.feature_names_in_
        self._classes = encoder.classes_

    @classmethod
    def from_artifacts(cls, model_dir: Path) -> 'Classifier':
        model = XGBClassifier()
        model.load_model(str(model_dir / "model.json"))
        scaler = joblib.load(model_dir / "scaler.pkl")
        encoder = joblib.load(model_dir / "encoder.pkl")
        return cls(model, scaler, encoder)

    def _preprocess(self, flow: Flow) -> np.ndarray:
        values = np.array(
            [flow.get(feature, 0.0) for feature in self._features],
            dtype=np.float64
        )
        values = np.nan_to_num(values, nan=0.0, posinf=0.0, neginf=0.0)
        df = pd.DataFrame([values], columns=self._features)
        return self._scaler.transform(df)

    def classify(self, flow: Flow) -> Prediction:
        data = self._preprocess(flow)
        probs = self._model.predict_proba(data)[0]
        return dict(zip(self._classes, probs))


class Dashboard:
    def __init__(self, log_dir: Path, host: str, port: int):
        self._log_dir = log_dir
        self._clients: list[Queue[dict]] = []
        self._clients_lock = Lock()
        self._flows: list[Flow] = []
        self._host = host
        self._port = port
        self._app = self._create_app()

    def __enter__(self):
        Thread(
            target=uvicorn.run,
            args=(self._app,),
            kwargs={"host": self._host, "port": self._port},
            daemon=True,
        ).start()
        return self

    def __exit__(self, *exc):
        return False

    def push(self, flow: Flow, prediction: Prediction):
        event = self._flow_to_event(flow, prediction)
        with self._clients_lock:
            self._flows.append(event)
            for client in self._clients:
                client.put(event)

    def _create_app(self) -> FastAPI:
        app = FastAPI()
        html = self._load_html()

        @app.get("/")
        def index():
            return HTMLResponse(html)

        @app.get("/api/flows")
        def flows_sse():
            return EventSourceResponse(self._flow_generator())

        @app.get("/api/snapshot")
        def get_snapshot():
            return {"flows": list(self._flows)}

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
                    self._flow_to_event(
                        record["flow"], record["prediction"]
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

    @staticmethod
    def _load_html() -> str:
        path = Path(__file__).parent / "dashboard.html"
        return path.read_text()

    @staticmethod
    def _flow_to_event(flow: Flow, prediction: Prediction) -> dict:
        predicted_class = max(prediction, key=lambda k: prediction[k])
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


def parse_args():
    parser = argparse.ArgumentParser()
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-i", "--interface", help="Live capture interface")
    group.add_argument("-p", "--pcap", help="Path to pcap file")
    parser.add_argument("-l", "--log-dir", default="logs/", 
                        help="Log output directory")
    parser.add_argument("-e", "--expired_update", default=10, type=int,
                        help="Expired flow update interval")
    parser.add_argument("-P", "--port", type=int, default=8000, 
                        help="Dashboard port")
    return parser.parse_args()


def make_log_path(log_dir: Path, source: str) -> Path:
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")                                                                                                                                   
    return log_dir / f"{timestamp}-{source}.jsonl"


def log_flow(file: TextIO, flow: Flow, prediction: Prediction):
    record = {"flow": flow, "prediction": prediction}
    obj = json.dumps(record, default=float)
    file.write(f"{obj}\n")
    file.flush()


def main():
    args = parse_args()

    source = args.interface or Path(args.pcap).stem

    log_dir = Path(args.log_dir)
    log_dir.mkdir(parents=True, exist_ok=True)
    log_path = make_log_path(log_dir, source)

    classifier = Classifier.from_artifacts(Path("models/"))

    with (
        FlowExtractor(
            args.expired_update, args.interface, args.pcap
        ) as extractor,
        log_path.open("w", newline="") as log_file,
        Dashboard(Path(args.log_dir), "0.0.0.0", args.port) as dashboard,
    ):
        try:
            while True:
                match extractor.get_flow(timeout=FLOW_POLL_TIMEOUT):
                    case FlowExtractor.Captured(flow):
                        prediction = classifier.classify(flow)
                        log_flow(log_file, flow, prediction)
                        dashboard.push(flow, prediction)
                    case FlowExtractor.Done():
                        break
                    case FlowExtractor.Waiting():
                        pass

        except KeyboardInterrupt:
            pass


if __name__ == "__main__":
    main()
