import csv
import logging
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from os import PathLike
from typing import Protocol, TextIO, TypeAlias

import requests

LOGGER = logging.getLogger("cicflowmeter")
FlowValue: TypeAlias = str | int | float | bool | None
FlowData: TypeAlias = Mapping[str, FlowValue]
WriterCallback = Callable[[FlowData], None]
WriterTarget = str | PathLike[str] | WriterCallback


@dataclass(frozen=True, slots=True)
class CsvOutput:
    path: str | PathLike[str]


@dataclass(frozen=True, slots=True)
class HttpOutput:
    url: str


@dataclass(frozen=True, slots=True)
class CallbackOutput:
    callback: WriterCallback


Output: TypeAlias = CsvOutput | HttpOutput | CallbackOutput


class OutputWriter(Protocol):
    def write(self, data: FlowData) -> None: ...

    def close(self) -> None: ...


class CSVWriter(OutputWriter):
    def __init__(self, output_file: str | PathLike[str]) -> None:
        self._file: TextIO = open(
            output_file,
            "w",
            encoding="utf-8",
            newline="",
        )
        self._writer: csv.DictWriter | None = None

    def write(self, data: FlowData) -> None:
        if self._writer is None:
            self._writer = csv.DictWriter(
                self._file,
                fieldnames=tuple(data),
            )
            self._writer.writeheader()

        self._writer.writerow(data)
        self._file.flush()

    def close(self) -> None:
        self._file.close()


class HttpWriter(OutputWriter):
    def __init__(self, output_url: str) -> None:
        self._url = output_url
        self._session = requests.Session()

    def write(self, data: FlowData) -> None:
        try:
            response = self._session.post(self._url, json=data, timeout=5)
            response.raise_for_status()
        except requests.RequestException:
            LOGGER.exception("Failed to post flow")

    def close(self) -> None:
        self._session.close()


class CallbackWriter(OutputWriter):
    def __init__(
        self,
        callback: WriterCallback,
    ) -> None:
        self._callback = callback

    def write(self, data: FlowData) -> None:
        self._callback(data)

    def close(self) -> None:
        pass


def output_from_legacy(
    mode: str | None,
    writer: WriterTarget | None,
) -> Output:
    match mode:
        case "url":
            if not isinstance(writer, str):
                raise TypeError("URL output requires a URL string")
            return HttpOutput(writer)
        case "csv":
            if not isinstance(writer, (str, PathLike)):
                raise TypeError("CSV output requires a file path")
            return CsvOutput(writer)
        case "callback":
            if not callable(writer):
                raise TypeError("Callback output requires a callable")
            return CallbackOutput(writer)
        case _:
            raise ValueError(f"Unknown output mode: {mode!r}")


def open_output(output: Output) -> OutputWriter:
    if isinstance(output, CsvOutput):
        return CSVWriter(output.path)
    if isinstance(output, HttpOutput):
        return HttpWriter(output.url)
    return CallbackWriter(output.callback)
