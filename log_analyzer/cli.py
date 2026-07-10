from __future__ import annotations
import argparse
import json
import sys
import time
from datetime import datetime
from typing import Optional

from log_analyzer.processor import LogProcessor
from log_analyzer.stats import StatsAggregator
from log_analyzer import report

_TIME_FILTER_FORMATS = (
    "%Y-%m-%d %H:%M:%S",
    "%Y-%m-%d %H:%M",
    "%Y-%m-%d",
    "%d/%b/%Y:%H:%M:%S",
)


def parse_args(argv: Optional[list[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="log-analyzer",
        description=(),
    )
    parser.add_argument(
        "logfile",
        help="Path to the access log file. May be plain text or .gz compressed.",
    )
    parser.add_argument(
        "--top",
        type=int,
        default=10,
        metavar="N",
        help="Number of top endpoints to show (default: 10).",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output the report as JSON instead of a human-readable table.",
    )
    parser.add_argument(
        "--start",
        metavar="TIME",
        help=(
            "Only include entries at or after this time. "
            "Accepts 'YYYY-MM-DD', 'YYYY-MM-DD HH:MM', or 'YYYY-MM-DD HH:MM:SS'."
        ),
    )
    parser.add_argument(
        "--end",
        metavar="TIME",
        help="Only include entries at or before this time. Same formats as --start.",
    )
    parser.add_argument(
        "--show-invalid-samples",
        action="store_true",
        help="Print a few example lines that failed to parse.",
    )
    parser.add_argument(
        "--timing",
        action="store_true",
        help="Print how long processing took.",
    )
    return parser.parse_args(argv)


def _parse_time_filter(value: str, flag_name: str) -> datetime:
    for fmt in _TIME_FILTER_FORMATS:
        try:
            return datetime.strptime(value, fmt)
        except ValueError:
            continue
    raise SystemExit(
        f"error: could not parse {flag_name} value {value!r}. "
        f"Try a format like 'YYYY-MM-DD' or 'YYYY-MM-DD HH:MM:SS'."
    )


def _in_range(
    timestamp: datetime, start: Optional[datetime], end: Optional[datetime]
) -> bool:
    naive_ts = timestamp.replace(tzinfo=None)
    if start is not None and naive_ts < start:
        return False
    if end is not None and naive_ts > end:
        return False
    return True


def run(argv: Optional[list[str]] = None) -> int:
    args = parse_args(argv)

    start_filter = _parse_time_filter(args.start, "--start") if args.start else None
    end_filter = _parse_time_filter(args.end, "--end") if args.end else None

    processor = LogProcessor(args.logfile)
    aggregator = StatsAggregator()

    started_at = time.perf_counter()

    try:
        for entry in processor.process():
            if not _in_range(entry.timestamp, start_filter, end_filter):
                continue
            aggregator.add(entry)
    except FileNotFoundError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    elapsed = time.perf_counter() - started_at

    summary = aggregator.summary(top_n=args.top)

    if args.json:
        payload = summary.to_dict()
        payload["invalid_lines"] = processor.invalid_count
        payload["total_lines_read"] = processor.total_lines
        if args.timing:
            payload["elapsed_seconds"] = round(elapsed, 4)
        print(json.dumps(payload, indent=2))
    else:
        report.print_report(
            summary,
            invalid_count=processor.invalid_count,
            total_lines=processor.total_lines,
            invalid_samples=processor.invalid_samples if args.show_invalid_samples else None,
        )
        if args.timing:
            print(f"\nProcessed in {elapsed:.3f}s")

    return 0


def main() -> None:
    sys.exit(run())


if __name__ == "__main__":
    main()
