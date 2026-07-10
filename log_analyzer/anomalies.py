from __future__ import annotations

import statistics
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime
from typing import Optional

from log_analyzer.parser import LogEntry

@dataclass
class SuspiciousIP:
    ip: str
    failed_auth_count: int
    total_requests: int

    @property
    def failed_auth_ratio(self) -> float:
        if self.total_requests == 0:
            return 0.0
        return self.failed_auth_count / self.total_requests


class SuspiciousActivityDetector:
    def __init__(self, auth_status: int = 401, endpoint_keyword: str = "login"):
        self.auth_status = auth_status
        self.endpoint_keyword = endpoint_keyword.lower()
        self._failed_auth_counts: Counter[str] = Counter()
        self._total_requests_by_ip: Counter[str] = Counter()

    def add(self, entry: LogEntry) -> None:
        self._total_requests_by_ip[entry.ip] += 1
        if entry.status == self.auth_status and self.endpoint_keyword in entry.endpoint.lower():
            self._failed_auth_counts[entry.ip] += 1

    def flagged(self, min_count: int = 5, min_ratio: float = 0.0) -> list[SuspiciousIP]:
        results = []
        for ip, failed_count in self._failed_auth_counts.items():
            if failed_count < min_count:
                continue
            total = self._total_requests_by_ip[ip]
            candidate = SuspiciousIP(ip=ip, failed_auth_count=failed_count, total_requests=total)
            if candidate.failed_auth_ratio < min_ratio:
                continue
            results.append(candidate)

        results.sort(key=lambda s: s.failed_auth_count, reverse=True)
        return results

@dataclass
class ErrorSpike:
    window_start: datetime
    total_requests: int
    error_count: int
    error_rate: float 
    baseline_rate: float 


class ErrorSpikeDetector:
    def __init__(self, window_seconds: int = 60):
        if window_seconds <= 0:
            raise ValueError("window_seconds must be positive")
        self.window_seconds = window_seconds
        self._total_by_window: Counter[datetime] = Counter()
        self._errors_by_window: Counter[datetime] = Counter()

    def add(self, entry: LogEntry) -> None:
        bucket = self._bucket_for(entry.timestamp)
        self._total_by_window[bucket] += 1
        if entry.is_error and 500 <= entry.status < 600:
            self._errors_by_window[bucket] += 1

    def _bucket_for(self, timestamp: datetime) -> datetime:
        naive = timestamp.replace(tzinfo=None)
        epoch_seconds = int(naive.timestamp())
        floored = (epoch_seconds // self.window_seconds) * self.window_seconds
        return datetime.fromtimestamp(floored)

    def detect_spikes(
        self,
        z_threshold: float = 2.0,
        min_requests: int = 5,
        min_error_rate: float = 5.0,
    ) -> list[ErrorSpike]:
        windows = [w for w, total in self._total_by_window.items() if total >= min_requests]
        if len(windows) < 2:
            return []

        rates = []
        for window in windows:
            total = self._total_by_window[window]
            errors = self._errors_by_window.get(window, 0)
            rates.append(errors / total * 100)

        mean_rate = statistics.mean(rates)
        try:
            stdev_rate = statistics.stdev(rates)
        except statistics.StatisticsError:
            stdev_rate = 0.0

        spikes = []
        for window, rate in zip(windows, rates):
            if rate < min_error_rate:
                continue
            if stdev_rate > 0 and (rate - mean_rate) / stdev_rate < z_threshold:
                continue
            if stdev_rate == 0 and rate <= mean_rate:
                continue

            total = self._total_by_window[window]
            errors = self._errors_by_window.get(window, 0)
            spikes.append(
                ErrorSpike(
                    window_start=window,
                    total_requests=total,
                    error_count=errors,
                    error_rate=rate,
                    baseline_rate=mean_rate,
                )
            )

        spikes.sort(key=lambda s: s.error_rate, reverse=True)
        return spikes
