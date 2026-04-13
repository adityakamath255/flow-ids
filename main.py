from queue import Queue, Empty
from typing import Optional, Any
from types import SimpleNamespace
from xgboost import XGBClassifier
from sklearn.preprocessing import StandardScaler, LabelEncoder
from pathlib import Path
import joblib
import numpy as np
import pandas as pd
import json
from datetime import datetime
from threading import Thread, Lock
import time
import argparse

import uvicorn
from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from sse_starlette.sse import EventSourceResponse

import cicflowmeter

PROTOCOL_NAMES = {6: "TCP", 17: "UDP"}


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

    def _preprocess(self, flow: dict) -> np.ndarray:
        values = np.array(
            [flow.get(feature, 0.0) for feature in self._features],
            dtype=np.float64
        )
        values = np.nan_to_num(values, nan=0.0, posinf=0.0, neginf=0.0)
        df = pd.DataFrame([values], columns=self._features)
        return self._scaler.transform(df)

    def classify(self, flow: dict[str, Any]) -> dict[str, float]:
        data = self._preprocess(flow)
        probs = self._model.predict_proba(data)[0]
        return dict(zip(self._classes, probs))


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


class Dashboard:
    def __init__(self, log_dir: Path):
        self._log_dir = log_dir
        self._clients: list[Queue[dict]] = []
        self._clients_lock = Lock()
        self._flows: list[dict] = []
        self.app = self._create_app()

    def push(self, flow: dict, prediction: dict):
        event = self._flow_to_event(flow, prediction)
        self._flows.append(event)
        with self._clients_lock:
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
    def _flow_to_event(flow: dict, prediction: dict) -> dict:
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


def main():
    parser = argparse.ArgumentParser()
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-i", "--interface", help="Live capture interface")
    group.add_argument("-p", "--pcap", help="Path to pcap file")
    parser.add_argument("-l", "--log-dir", default="logs/", 
                        help="Log output directory")
    parser.add_argument("-e", "--expired_update", default=10,
                        help="Expired flow update interval")
    parser.add_argument("-P", "--port", type=int, default=8000, 
                        help="Dashboard port")
    args = parser.parse_args()

    source = args.interface if args.interface else Path(args.pcap).stem
    flow_queue = Queue()

    flow_extractor = FlowExtractor(
        args.expired_update, flow_queue, args.interface, args.pcap
    )
    classifier = Classifier.from_artifacts(Path("models/"))
    logger = FlowLogger(Path(args.log_dir), source)
    dashboard = Dashboard(Path(args.log_dir))

    Thread(
        target=uvicorn.run,
        args=(dashboard.app,),
        kwargs={"host": "0.0.0.0", "port": args.port},
        daemon=True,
    ).start()

    flow_extractor.start()

    try:
        while True:
            try:
                flow = flow_queue.get(timeout=1.0)
            except Empty:
                if flow_extractor.is_done():
                    break
                continue
            prediction = classifier.classify(flow)
            logger.log(flow, prediction)
            dashboard.push(flow, prediction)

    except KeyboardInterrupt:
        pass

    finally:
        flow_extractor.stop()
        logger.close()


if __name__ == "__main__":
    main()
