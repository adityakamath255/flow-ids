from queue import Queue
from src.ids import Ids
from pprint import pprint
from pathlib import Path


def main():
    output_queue = Queue()
    ids = Ids.from_config(
        interface="enp0s20f0u1",
        expired_update=10,
        model_dir=Path("models/"),
        poll_interval=1.0,
        output_queue=output_queue
    )
    ids.start()
    while True:
        x = output_queue.get()
        print("FLOW:")
        pprint(x.flow)
        print("PREDICTION:")
        pprint(x.prediction)


if __name__ == "__main__":
    main()
