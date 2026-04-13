from src.flow_extractor import FlowExtractor
from src.classifier import Classifier
from src.dashboard import Dashboard
from src.logger import FlowLogger

from queue import Queue, Empty
from pathlib import Path
import argparse
from threading import Thread
import uvicorn


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
