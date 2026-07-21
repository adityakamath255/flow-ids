import csv
import logging
from typing import Protocol

import requests

LOGGER = logging.getLogger("cicflowmeter")


class OutputWriter(Protocol):
    def write(self, data: dict) -> None: ...

    def close(self) -> None: ...


class CSVWriter(OutputWriter):
    def __init__(self, output_file) -> None:
        self._file = open(output_file, "w", encoding="utf-8", newline="")
        self._header_written = False
        self._writer = csv.writer(self._file)

    def write(self, data: dict) -> None:
        if not self._header_written:
            self._writer.writerow(data.keys())
            self._header_written = True

        self._writer.writerow(data.values())
        self._file.flush()

    def close(self) -> None:
        self._file.close()


class HttpWriter(OutputWriter):
    def __init__(self, output_url) -> None:
        self._url = output_url
        self._session = requests.Session()

    def write(self, data: dict) -> None:
        try:
            response = self._session.post(self._url, json=data, timeout=5)
            response.raise_for_status()
        except requests.RequestException:
            LOGGER.exception("Failed to post flow")

    def close(self) -> None:
        self._session.close()


class CallbackWriter(OutputWriter):
    def __init__(self, callback) -> None:
        self._callback = callback

    def write(self, data: dict) -> None:
        self._callback(data)

    def close(self) -> None:
        pass


def output_writer_factory(mode, writer) -> OutputWriter:
    match mode:
        case "url":
            return HttpWriter(writer)
        case "csv":
            return CSVWriter(writer)
        case "callback":
            return CallbackWriter(writer)
        case _:
            raise RuntimeError(f"unknown output mode: {mode!r}")
