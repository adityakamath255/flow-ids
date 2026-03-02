from src.dashboard import Dashboard
from src.logger import FlowLogger
from src.ids import IDS

from queue import Queue
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

    if args.interface:
        source = args.interface
    else:
        source = Path(args.pcap).stem

    output_queue = Queue()

    ids = IDS.from_config(
        model_dir=Path("models/"),
        output_queue=output_queue,
        expired_update=args.expired_update,
        interface=args.interface,
        pcap_file=args.pcap
    )

    logger = FlowLogger(Path(args.log_dir), source)

    dashboard = Dashboard(Path(args.log_dir))

    Thread(
        target=uvicorn.run,
        args=(dashboard.app,),
        kwargs={"host": "0.0.0.0", "port": args.port},
        daemon=True,
    ).start()

    ids.start()

    try:
        while True:
            msg = output_queue.get()
            if msg is None:
                break
            else:
                logger.log(msg)
                dashboard.push(msg)
    except KeyboardInterrupt:
        ids.stop()
    finally:
        logger.close()


if __name__ == "__main__":
    main()
