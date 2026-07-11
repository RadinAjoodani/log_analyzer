from __future__ import annotations
from typing import Optional
from log_analyzer.stats import StatsSummary
from log_analyzer.anomalies import SuspiciousIP, ErrorSpike

_RULE_WIDTH = 60
_MAX_BAR_WIDTH = 60


def print_report(
    summary: StatsSummary,
    invalid_count: int,
    total_lines: int,
    invalid_samples: Optional[list[str]] = None,
    suspicious_ips: Optional[list[SuspiciousIP]] = None,
    error_spikes: Optional[list[ErrorSpike]] = None,
) -> None:
    print("*** LOG ANALYSIS REPORT ***")
    _print_header("SUMMARY: ")
    _print_overview(summary, invalid_count, total_lines)
    print("-" * _RULE_WIDTH)

    _print_header("TOP ENDPOINTS:")
    _print_top_endpoints(summary.top_endpoints)
    print("-" * _RULE_WIDTH)

    _print_header("STATUS CODE BREAKDOWN: ")
    _print_status_codes(summary.status_code_counts, summary.total_requests)
    print("-" * _RULE_WIDTH)

    _print_header("HOURLY REQUEST DISTRIBUTION: ")
    _print_hourly_histogram(summary.hourly_distribution)
    print("-" * _RULE_WIDTH)

    if suspicious_ips is not None:
        _print_header("SUSPICIOUS ACTIVITY (possible brute-force login attempts):")
        _print_suspicious_ips(suspicious_ips)
        print("-" * _RULE_WIDTH)

    if error_spikes is not None:
        _print_header("5xx ERROR SPIKES (abnormal time windows):")
        _print_error_spikes(error_spikes)
        print("-" * _RULE_WIDTH)

    if invalid_samples:
        _print_header("SAMPLE INVALID LINES: ")
        _print_invalid_samples(invalid_samples)
        print("-" * _RULE_WIDTH)

def _print_header(title: str) -> None:
    print()
    print(f"-> {title}")
    print()

def _print_overview(summary: StatsSummary, invalid_count: int, total_lines: int) -> None:
    rows = [
        ("Total lines read", total_lines),
        ("Valid requests", summary.total_requests),
        ("Invalid/skipped lines", invalid_count),
        ("Unique IP addresses", summary.unique_ip_count),
        ("4xx errors (client errors)", f"{summary.client_error_count} ({summary.client_error_rate:.2f}%)"),
        ("5xx errors (server errors)", f"{summary.server_error_count} ({summary.server_error_rate:.2f}%)"),
        ("Total errors", summary.client_error_count + summary.server_error_count),
        ("Total error rate", f"{(summary.client_error_rate + summary.server_error_rate):.2f}%"),
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
        
        pct = 0.0
        if total_requests:
            pct = (count / total_requests * 100)

        print(f"{status}  {str(count).rjust(6)} requests  ({pct:5.2f}%)")

def _print_hourly_histogram(hourly_distribution: dict[int, int]) -> None:
    total = sum(hourly_distribution.values())
    max_count = max(hourly_distribution.values(), default=0)
    peak_hour = None
    
    if max_count:
        peak_hour = max(hourly_distribution, key=hourly_distribution.get)

    for hour in range(24):
        count = hourly_distribution.get(hour, 0)
        pct = 0.0

        if total:
            pct = (count / total * 100)

        bar = _make_bar(count, max_count)

        marker = ""
        if hour == peak_hour:
            marker = " *peak*"

        print(f"{hour:02d}:00  {str(count).rjust(6)}  ({pct:5.2f}%)  {bar}{marker}")


def _make_bar(count: int, max_count: int) -> str:
    if max_count == 0 or count == 0:
        return ""
    blocks = "▏▎▍▌▋▊▉█"
    exact = (count / max_count) * _MAX_BAR_WIDTH
    full_blocks = int(exact)
    remainder = exact - full_blocks

    partial = ""
    
    if remainder > 0:
        partial = blocks[int(remainder * 8) - 1]

    return "█" * full_blocks + partial

def _print_invalid_samples(invalid_samples: list[str]) -> None:
    for line in invalid_samples:
        display = line if line else "(blank line)"
        print(f"  {display!r}")

def _print_suspicious_ips(suspicious_ips: list[SuspiciousIP]) -> None:
    if not suspicious_ips:
        print("(none detected)")
        return

    ip_width = max(len(s.ip) for s in suspicious_ips)
    for s in suspicious_ips:
        print(
            f"{s.ip.ljust(ip_width)}  "
            f"{s.failed_auth_count} failed logins  "
            f"/ {s.total_requests} total requests  "
            f"({s.failed_auth_ratio * 100:.1f}% of its traffic)"
        )

def _print_error_spikes(error_spikes: list[ErrorSpike]) -> None:
    if not error_spikes:
        print("(none detected)")
        return

    for s in error_spikes:
        window_str = s.window_start.strftime("%Y-%m-%d %H:%M:%S")
        print(
            f"{window_str}  "
            f"error rate {s.error_rate:5.1f}%  "
            f"(baseline {s.baseline_rate:4.1f}%)  "
            f"{s.error_count}/{s.total_requests} requests failed"
        )