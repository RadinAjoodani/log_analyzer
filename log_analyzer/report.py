from __future__ import annotations
from typing import Optional
from log_analyzer.stats import StatsSummary

_RULE_WIDTH = 60
_MAX_BAR_WIDTH = 40


def print_report(
    summary: StatsSummary,
    invalid_count: int,
    total_lines: int,
    invalid_samples: Optional[list[str]] = None,
) -> None:
    _print_header("LOG ANALYSIS REPORT")
    _print_overview(summary, invalid_count, total_lines)

    _print_header("TOP ENDPOINTS")
    _print_top_endpoints(summary.top_endpoints)

    _print_header("STATUS CODE BREAKDOWN")
    _print_status_codes(summary.status_code_counts, summary.total_requests)

    _print_header("HOURLY REQUEST DISTRIBUTION")
    _print_hourly_histogram(summary.hourly_distribution)

    if invalid_samples:
        _print_header("SAMPLE INVALID LINES")
        _print_invalid_samples(invalid_samples)

def _print_header(title: str) -> None:
    print()
    print(title)
    print("-" * _RULE_WIDTH)


def _print_overview(summary: StatsSummary, invalid_count: int, total_lines: int) -> None:
    rows = [
        ("Total lines read", total_lines),
        ("Valid requests", summary.total_requests),
        ("Invalid/skipped lines", invalid_count),
        ("Unique IP addresses", summary.unique_ip_count),
        ("Error rate (4xx/5xx)", f"{summary.error_rate:.2f}%"),
        ("Total errors", summary.error_count),
    ]
    label_width = max(len(label) for label, _ in rows)
    for label, value in rows:
        print(f"{label.ljust(label_width)} : {value}")


def _print_top_endpoints(top_endpoints: list[tuple[str, int]]) -> None:
    if not top_endpoints:
        print("(no requests recorded)")
        return

    rank_width = len(str(len(top_endpoints)))
    endpoint_width = max(len(ep) for ep, _ in top_endpoints)
    count_width = max(len(str(count)) for _, count in top_endpoints)

    for rank, (endpoint, count) in enumerate(top_endpoints, start=1):
        print(
            f"{str(rank).rjust(rank_width)}. "
            f"{endpoint.ljust(endpoint_width)}  "
            f"{str(count).rjust(count_width)} requests"
        )

def _print_status_codes(status_code_counts: dict[int, int], total_requests: int) -> None:
    if not status_code_counts:
        print("(no requests recorded)")
        return

    for status in sorted(status_code_counts):
        count = status_code_counts[status]
        pct = (count / total_requests * 100) if total_requests else 0.0
        print(f"{status}  {str(count).rjust(6)} requests  ({pct:5.2f}%)")

def _print_hourly_histogram(hourly_distribution: dict[int, int]) -> None:
    total = sum(hourly_distribution.values())
    max_count = max(hourly_distribution.values(), default=0)
    peak_hour = max(hourly_distribution, key=hourly_distribution.get) if max_count else None

    for hour in range(24):
        count = hourly_distribution.get(hour, 0)
        pct = (count / total * 100) if total else 0.0
        bar = _make_bar(count, max_count)
        marker = " *peak*" if hour == peak_hour else ""
        print(f"{hour:02d}:00  {str(count).rjust(6)}  ({pct:5.1f}%)  {bar}{marker}")


def _make_bar(count: int, max_count: int) -> str:
    if max_count == 0 or count == 0:
        return ""
    blocks = "▏▎▍▌▋▊▉█"
    exact = (count / max_count) * _MAX_BAR_WIDTH
    full_blocks = int(exact)
    remainder = exact - full_blocks
    partial = blocks[int(remainder * 8) - 1] if remainder > 0 else ""
    return "█" * full_blocks + partial

def _print_invalid_samples(invalid_samples: list[str]) -> None:
    for line in invalid_samples:
        display = line if line else "(blank line)"
        print(f"  {display!r}")
