import argparse
from collections.abc import Collection
from pathlib import Path

from scapy.sendrecv import AsyncSniffer

from .constants import EXPIRED_UPDATE
from .flow_session import FlowSession
from .writer import CsvOutput, output_from_legacy

GC_INTERVAL = 1.0


def _run_sniffer(sniffer: AsyncSniffer) -> None:
    sniffer.start()
    try:
        sniffer.join()
    finally:
        if sniffer.running:
            sniffer.stop()
        sniffer.join()


def _run_file(path: Path, session: FlowSession) -> None:
    _run_sniffer(
        AsyncSniffer(
            offline=str(path),
            prn=session.process,
            store=False,
        )
    )


def create_sniffer(
    input_file: str | None,
    input_interface: str | None,
    mode: str,
    writer,
    fields: str | Collection[str] | None = None,
    verbose: bool = False,
    expired_update: float = EXPIRED_UPDATE,
) -> tuple[AsyncSniffer, FlowSession]:
    if (input_file is None) == (input_interface is None):
        raise ValueError("Provide exactly one packet source")

    output = output_from_legacy(mode, writer)
    session = FlowSession(
        output=output,
        fields=fields,
        verbose=verbose,
        expired_update=expired_update,
    )

    try:
        if input_file is not None:
            sniffer = AsyncSniffer(
                offline=input_file,
                prn=session.process,
                store=False,
            )
        else:
            sniffer = AsyncSniffer(
                iface=input_interface,
                filter="ip and (tcp or udp)",
                prn=session.process,
                store=False,
                started_callback=lambda: session.start_periodic_gc(
                    GC_INTERVAL
                ),
            )
    except Exception:
        session.close()
        raise
    return sniffer, session


def _prepare_batch(
    input_dir: str | Path,
    output_dir: str | Path,
) -> tuple[Path, list[Path]] | None:
    input_path = Path(input_dir)
    output_path = Path(output_dir)

    if not input_path.exists():
        print(f"Error: Input directory '{input_dir}' does not exist")
        return None

    if not input_path.is_dir():
        print(f"Error: Input path '{input_dir}' is not a directory")
        return None

    pcap_files = sorted(
        (*input_path.glob("*.pcap"), *input_path.glob("*.pcapng"))
    )
    if not pcap_files:
        print(f"Error: No pcap files found in {input_dir}")
        return None

    if output_path.exists() and output_path.is_file():
        print(f"Error: Output path '{output_dir}' already exists as a file.")
        print("Please provide a directory path for batch processing.")
        return None

    try:
        output_path.mkdir(parents=True, exist_ok=True)
    except OSError as error:
        print(
            f"Error: Could not create output directory '{output_dir}': {error}"
        )
        return None

    return output_path, pcap_files


def process_directory(
    input_dir: str | Path,
    output_dir: str | Path,
    fields: str | Collection[str] | None = None,
    verbose: bool = False,
    merge: bool = False,
) -> None:
    batch = _prepare_batch(input_dir, output_dir)
    if batch is None:
        return
    output_path, pcap_files = batch

    print(f"Found {len(pcap_files)} pcap file(s) to process")
    if merge:
        output_file = output_path / "merged_output.csv"
        print(f"Merging all flows into: {output_file.name}")
        with FlowSession(
            output=CsvOutput(output_file),
            fields=fields,
            verbose=verbose,
        ) as session:
            for index, pcap_file in enumerate(pcap_files, 1):
                progress = f"[{index}/{len(pcap_files)}]"
                print(f"{progress} Processing {pcap_file.name}...")
                try:
                    _run_file(pcap_file, session)
                    print(f"{progress} Completed {pcap_file.name}")
                except Exception as error:
                    print(f"Error processing {pcap_file.name}: {error}")
                finally:
                    session.flush_flows()
        print(f"\nAll done! Merged output saved to: {output_file}")
        return

    for pcap_file in pcap_files:
        output_file = output_path / f"{pcap_file.stem}.csv"
        print(f"Processing {pcap_file.name} -> {output_file.name}")
        try:
            with FlowSession(
                output=CsvOutput(output_file),
                fields=fields,
                verbose=verbose,
            ) as session:
                _run_file(pcap_file, session)
            print(f"Completed {pcap_file.name}")
        except Exception as error:
            print(f"Error processing {pcap_file.name}: {error}")

    print(f"\nAll done! Output files saved to: {output_dir}")


def main() -> None:
    parser = argparse.ArgumentParser()

    input_group = parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument(
        "-i",
        "--interface",
        action="store",
        dest="input_interface",
        help="capture online data from INPUT_INTERFACE",
    )
    input_group.add_argument(
        "-f",
        "--file",
        action="store",
        dest="input_file",
        help="capture offline data from INPUT_FILE",
    )
    input_group.add_argument(
        "-d",
        "--directory",
        action="store",
        dest="input_directory",
        help="process all pcap files from INPUT_DIRECTORY",
    )

    output_group = parser.add_mutually_exclusive_group(required=True)
    output_group.add_argument(
        "-c",
        "--csv",
        action="store_const",
        const="csv",
        dest="output_mode",
        help="output flows as csv",
    )
    output_group.add_argument(
        "-u",
        "--url",
        action="store_const",
        const="url",
        dest="output_mode",
        help="output flows as request to url",
    )

    parser.add_argument(
        "output",
        help=(
            "output file name (CSV mode), URL (URL mode), or output "
            "directory (directory mode)"
        ),
    )

    parser.add_argument(
        "--fields",
        action="store",
        dest="fields",
        help="comma separated fields to include in output (default: all)",
    )

    parser.add_argument(
        "--merge",
        action="store_true",
        help="merge pcaps into one CSV (directory mode only)",
    )

    parser.add_argument(
        "-v", "--verbose", action="store_true", help="more verbose"
    )

    args = parser.parse_args()
    if args.merge and not args.input_directory:
        parser.error("--merge can only be used with -d/--directory mode")
    if args.input_directory and args.output_mode != "csv":
        parser.error("directory mode requires CSV output")
    if args.input_directory:
        process_directory(
            args.input_directory,
            args.output,
            args.fields,
            args.verbose,
            args.merge,
        )
        return

    sniffer, session = create_sniffer(
        input_file=args.input_file,
        input_interface=args.input_interface,
        mode=args.output_mode,
        writer=args.output,
        fields=args.fields,
        verbose=args.verbose,
    )
    with session:
        try:
            _run_sniffer(sniffer)
        except KeyboardInterrupt:
            pass


if __name__ == "__main__":
    main()
