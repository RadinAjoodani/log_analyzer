from __future__ import annotations
from collections import Counter
from dataclasses import dataclass, field
from typing import Iterable, Iterator
from log_analyzer.parser import LogEntry

@dataclass
class StatsSummary:
    total_requests: int
    unique_ip_count: int
    top_endpoints: list[tuple[str, int]]
    error_rate: float
    error_count: int
    hourly_distribution: dict[int, int]
    status_code_counts: dict[int, int]

    def to_dict(self) -> dict:
        return {
            "total_requests": self.total_requests,
            "unique_ip_count": self.unique_ip_count,
            "top_endpoints": [
                {"endpoint": ep, "count": count} for ep, count in self.top_endpoints
            ],
            "error_rate_percent": round(self.error_rate, 2),
            "error_count": self.error_count,
            "hourly_distribution": self.hourly_distribution,
            "status_code_counts": self.status_code_counts,
        }


class StatsAggregator:
    def __init__(self):
        self._total_requests = 0
        self._unique_ips: set[str] = set()
        self._endpoint_counts: Counter[str] = Counter()
        self._status_code_counts: Counter[int] = Counter()
        self._hourly_counts: Counter[int] = Counter()
        self._error_count = 0

    def add(self, entry: LogEntry) -> None:
        """Fold a single LogEntry into the running totals."""
        self._total_requests += 1
        self._unique_ips.add(entry.ip)
        self._endpoint_counts[entry.endpoint] += 1
        self._status_code_counts[entry.status] += 1
        self._hourly_counts[entry.timestamp.hour] += 1

        if entry.is_error:
            self._error_count += 1

    def add_all(self, entries: Iterable[LogEntry]) -> None:
        """Convenience helper: fold in a whole iterable of entries."""
        for entry in entries:
            self.add(entry)

    def summary(self, top_n: int = 10) -> StatsSummary:
        total = self._total_requests
        error_rate = (self._error_count / total * 100) if total else 0.0
        top_endpoints = self._endpoint_counts.most_common(top_n)
        hourly_distribution = {
            hour: self._hourly_counts.get(hour, 0) for hour in range(24)
        }

        return StatsSummary(
            total_requests=total,
            unique_ip_count=len(self._unique_ips),
            top_endpoints=top_endpoints,
            error_rate=error_rate,
            error_count=self._error_count,
            hourly_distribution=hourly_distribution,
            status_code_counts=dict(self._status_code_counts),
        )

    @property
    def total_requests(self) -> int:
        return self._total_requests

    @property
    def unique_ips(self) -> set[str]:
        return self._unique_ips

    @property
    def endpoint_counts(self) -> Counter[str]:
        return self._endpoint_counts

    @property
    def status_code_counts(self) -> Counter[int]:
        return self._status_code_counts

    @property
    def hourly_counts(self) -> Counter[int]:
        return self._hourly_counts