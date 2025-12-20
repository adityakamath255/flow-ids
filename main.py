from queue import Queue
from src.capture import FlowExtractor
from pprint import pprint


def main():
    queue = Queue()
    extractor = FlowExtractor(
        interface="enp0s20f0u2",
        expired_update=10,
        output_queue=queue
    )
    extractor.start()
    while True:
        x = queue.get()
        pprint(x)


if __name__ == "__main__":
    main()
