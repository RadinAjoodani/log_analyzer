from __future__ import annotations
import argparse
import csv
import json
import sys
import time
from datetime import datetime
from typing import Optional
from log_analyzer.processor import LogProcessor
from log_analyzer.stats import StatsAggregator
from log_analyzer.anomalies import SuspiciousActivityDetector, ErrorSpikeDetector
from log_analyzer import report
from pathlib import Path

_TIME_FILTER_FORMATS = (
    "%Y-%m-%d %H:%M:%S",
    "%Y-%m-%d %H:%M",
    "%Y-%m-%d",
    "%d/%b/%Y:%H:%M:%S",
)

_HOURLY_CSV_PATH = "output/hourly_distribution.csv"


def parse_args(argv: Optional[list[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="log-analyzer",
        description=(
            "Analyze a web server access log (Combined Log Format) and "
            "produce request statistics, top endpoints, error rate, and "
            "an hourly request histogram."
        ),
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
        "-o",
        "--output",
        metavar="PATH",
        default="output/report.json",
        help=(
            "File path to save the JSON report to (only used together with "
            "--json). Defaults to 'report.json' in the current directory."
        ),
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
    parser.add_argument(
        "--detect-anomalies",
        action="store_true",
        help=(
            "Enable anomaly detection: flags IPs with suspiciously many "
            "failed login attempts, and time windows with abnormal 5xx "
            "error rates."
        ),
    )
    parser.add_argument(
        "--min-failed-auth",
        type=int,
        default=5,
        metavar="N",
        help="Minimum failed-login count before an IP is flagged (default: 5).",
    )
    parser.add_argument(
        "--auth-status",
        type=int,
        default=401,
        metavar="CODE",
        help="Status code treated as a failed authentication attempt (default: 401).",
    )
    parser.add_argument(
        "--auth-endpoint-keyword",
        default="login",
        metavar="TEXT",
        help="Case-insensitive substring identifying auth endpoints (default: 'login').",
    )
    parser.add_argument(
        "--spike-window",
        type=int,
        default=60,
        metavar="SECONDS",
        help="Time window size in seconds for 5xx spike detection (default: 60).",
    )
    parser.add_argument(
        "--spike-zscore",
        type=float,
        default=2.0,
        metavar="Z",
        help="How many standard deviations above the mean counts as a spike (default: 2.0).",
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

def _write_hourly_csv(hourly_distribution: dict[int, int], path: str) -> None:
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["hour", "request_count"])
        for hour in range(24):
            writer.writerow([f"{hour:02d}:00", hourly_distribution.get(hour, 0)])


def run(argv: Optional[list[str]] = None) -> int:
    args = parse_args(argv)
    
    start_filter = None;
    end_filter = None;
    if args.start :
        start_filter = _parse_time_filter(args.start, "--start")
    else:
        None
    
    if args.end :
        end_filter = _parse_time_filter(args.end, "--end")
    else:
        None

    processor = LogProcessor(args.logfile)
    aggregator = StatsAggregator()

    suspicious_detector: Optional[SuspiciousActivityDetector] = None
    spike_detector: Optional[ErrorSpikeDetector] = None
    if args.detect_anomalies:
        suspicious_detector = SuspiciousActivityDetector(
            auth_status=args.auth_status,
            endpoint_keyword=args.auth_endpoint_keyword,
        )
        spike_detector = ErrorSpikeDetector(window_seconds=args.spike_window)

    started_at = time.perf_counter()

    try:
        for entry in processor.process():
            if not _in_range(entry.timestamp, start_filter, end_filter):
                continue
            aggregator.add(entry)
            if suspicious_detector is not None:
                suspicious_detector.add(entry)
                spike_detector.add(entry)
    except FileNotFoundError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    elapsed = time.perf_counter() - started_at
    summary = aggregator.summary(top_n=args.top)

    # Save the hourly distribution to a CSV file automatically
    try:
        _write_hourly_csv(summary.hourly_distribution, _HOURLY_CSV_PATH)
        print(f"Hourly distribution saved to {_HOURLY_CSV_PATH}\n", file=sys.stderr)
    except OSError as exc:
        print(f"error: could not write hourly CSV to {_HOURLY_CSV_PATH!r}: {exc}", file=sys.stderr)
        return 1

    suspicious_ips = []
    error_spikes = []
    if args.detect_anomalies:
        suspicious_ips = suspicious_detector.flagged(min_count=args.min_failed_auth)
        error_spikes = spike_detector.detect_spikes(z_threshold=args.spike_zscore)

    if args.json:
        payload = summary.to_dict()
        payload["invalid_lines"] = processor.invalid_count
        payload["total_lines_read"] = processor.total_lines
        if args.timing:
            payload["elapsed_seconds"] = round(elapsed, 4)
        if args.detect_anomalies:
            payload["suspicious_ips"] = [
                {
                    "ip": s.ip,
                    "failed_auth_count": s.failed_auth_count,
                    "total_requests": s.total_requests,
                    "failed_auth_ratio": round(s.failed_auth_ratio, 4),
                }
                for s in suspicious_ips
            ]
            payload["error_spikes"] = [
                {
                    "window_start": s.window_start.isoformat(),
                    "total_requests": s.total_requests,
                    "error_count": s.error_count,
                    "error_rate_percent": round(s.error_rate, 2),
                    "baseline_rate_percent": round(s.baseline_rate, 2),
                }
                for s in error_spikes
            ]

        rendered = json.dumps(payload, indent=3)
        print(rendered)

        try:
            Path(args.output).parent.mkdir(parents=True, exist_ok=True)
            with open(args.output, "w", encoding="utf-8") as f:
                f.write(rendered)
                f.write("\n")
        except OSError as exc:
            print(f"error: could not write JSON report to {args.output!r}: {exc}", file=sys.stderr)
            return 1

        print(f"\nJSON report saved to {args.output}", file=sys.stderr)
    else:
        report.print_report(
            summary,
            invalid_count=processor.invalid_count,
            total_lines=processor.total_lines,
            invalid_samples=processor.invalid_samples if args.show_invalid_samples else None,
            suspicious_ips=suspicious_ips if args.detect_anomalies else None,
            error_spikes=error_spikes if args.detect_anomalies else None,
        )
        if args.timing:
            print(f"\nProcessed in {elapsed:.3f}s")

    return 0


def main() -> None:
    sys.exit(run())


if __name__ == "__main__":
    main()