import argparse
import csv
import logging
from collections.abc import Iterable, Iterator, Sequence
from dataclasses import dataclass
from itertools import chain
from pathlib import Path
from typing import TypeAlias

from .capture import CaptureSource, InterfaceSource, PcapSource, open_flows
from .schema import FlowData


@dataclass(frozen=True, slots=True)
class SingleConfig:
    source: CaptureSource
    output: Path
    fields: tuple[str, ...] | None
    verbose: bool


@dataclass(frozen=True, slots=True)
class DirectoryConfig:
    input_path: Path
    output_path: Path
    fields: tuple[str, ...] | None
    merge: bool
    verbose: bool


CliConfig: TypeAlias = SingleConfig | DirectoryConfig


def _flows(source: CaptureSource) -> Iterator[FlowData]:
    with open_flows(source) as flows:
        try:
            yield from flows
        except KeyboardInterrupt:
            flows.close()
            yield from flows
            raise


def _write_csv(
    path: Path,
    sources: Iterable[CaptureSource],
    requested_fields: tuple[str, ...] | None,
) -> None:
    flows = chain.from_iterable(_flows(source) for source in sources)
    with path.open("w", encoding="utf-8", newline="") as output:
        first = next(flows, None)
        if first is None:
            return

        fields = requested_fields or tuple(first)
        writer = csv.DictWriter(output, fieldnames=fields)
        writer.writeheader()
        for flow in chain((first,), flows):
            writer.writerow(
                {field: flow[field] for field in fields if field in flow}
            )
            output.flush()


def _pcap_files(input_path: Path) -> list[Path]:
    return sorted((*input_path.glob("*.pcap"), *input_path.glob("*.pcapng")))


def _prepare_directory(
    input_path: Path,
    output_path: Path,
) -> list[Path]:
    if not input_path.is_dir():
        raise ValueError(f"Input directory does not exist: {input_path}")
    pcap_files = _pcap_files(input_path)
    if not pcap_files:
        raise ValueError(f"No pcap files found in {input_path}")
    if output_path.is_file():
        raise ValueError(f"Output path is a file: {output_path}")
    output_path.mkdir(parents=True, exist_ok=True)
    return pcap_files


def _process_directory(
    input_path: Path,
    output_path: Path,
    fields: tuple[str, ...] | None,
    merge: bool,
) -> None:
    pcap_files = _prepare_directory(input_path, output_path)
    if merge:
        sources = (PcapSource(path) for path in pcap_files)
        _write_csv(output_path / "merged_output.csv", sources, fields)
        return

    for pcap_file in pcap_files:
        output_file = output_path / f"{pcap_file.stem}.csv"
        _write_csv(output_file, (PcapSource(pcap_file),), fields)


def _fields(value: str) -> tuple[str, ...]:
    fields = tuple(field.strip() for field in value.split(","))
    if not fields or any(not field for field in fields):
        raise argparse.ArgumentTypeError("fields must be non-empty names")
    if len(set(fields)) != len(fields):
        raise argparse.ArgumentTypeError("fields must be unique")
    return fields


def parse_args(argv: Sequence[str] | None = None) -> CliConfig:
    parser = argparse.ArgumentParser()
    inputs = parser.add_mutually_exclusive_group(required=True)
    inputs.add_argument("-i", "--interface")
    inputs.add_argument("-f", "--file", type=Path)
    inputs.add_argument("-d", "--directory", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--fields", type=_fields)
    parser.add_argument("--merge", action="store_true")
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args(argv)
    if args.merge and args.directory is None:
        parser.error("--merge requires --directory")
    if args.directory is not None:
        return DirectoryConfig(
            args.directory,
            args.output,
            args.fields,
            args.merge,
            args.verbose,
        )
    source = (
        InterfaceSource(args.interface)
        if args.interface is not None
        else PcapSource(args.file)
    )
    return SingleConfig(source, args.output, args.fields, args.verbose)


def run(config: CliConfig) -> None:
    logging.basicConfig(
        level=logging.DEBUG if config.verbose else logging.WARNING
    )
    if isinstance(config, DirectoryConfig):
        _process_directory(
            config.input_path,
            config.output_path,
            config.fields,
            config.merge,
        )
        return

    _write_csv(config.output, (config.source,), config.fields)


def main() -> None:
    try:
        run(parse_args())
    except KeyboardInterrupt:
        return
    except ValueError as error:
        raise SystemExit(str(error)) from None


if __name__ == "__main__":
    main()
