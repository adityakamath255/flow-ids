from queue import Queue
from src.ids import Ids
from pprint import pprint
from pathlib import Path
import argparse


def main():
    parser = argparse.ArgumentParser()
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-i", "--interface", help="Live capture interface")
    group.add_argument("-p", "--pcap", help="Path to pcap file")
    args = parser.parse_args()

    output_queue = Queue()

    ids = Ids.from_config(
        model_dir=Path("models/"),
        output_queue=output_queue,
        expired_update=10,
        interface=args.interface,
        pcap_file=args.pcap
    )
    ids.start()
    while True:
        msg = output_queue.get()
        if msg is None:
            break
        else:
            pprint(msg.prediction)


if __name__ == "__main__":
    main()
