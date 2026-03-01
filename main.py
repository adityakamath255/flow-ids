from queue import Queue
from src.ids import Ids
from src.logger import FlowLogger
from pprint import pprint
from pathlib import Path
import argparse


def main():
    parser = argparse.ArgumentParser()
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-i", "--interface", help="Live capture interface")
    group.add_argument("-p", "--pcap", help="Path to pcap file")
    parser.add_argument("-l", "--log-dir", default="logs/", 
                        help="Log output directory")
    parser.add_argument("-e", "--expired_update", default=10,
                        help="Expired flow update interval")
    args = parser.parse_args()

    if args.interface:
        source = args.interface
    else:
        source = Path(args.pcap).stem

    output_queue = Queue()

    ids = Ids.from_config(
        model_dir=Path("models/"),
        output_queue=output_queue,
        expired_update=args.expired_update,
        interface=args.interface,
        pcap_file=args.pcap
    )

    logger = FlowLogger(Path(args.log_dir), source)

    ids.start()
    while True:
        msg = output_queue.get()
        if msg is None:
            break
        else:
            pprint(msg.prediction)
            logger.log(msg)


if __name__ == "__main__":
    main()
