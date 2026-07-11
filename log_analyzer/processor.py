from __future__ import annotations
import gzip
from pathlib import Path
from typing import Iterator, Union
from log_analyzer.parser import LogEntry, parse_line

PathLike = Union[str, Path]

class LogProcessor:
    def __init__(self, path: PathLike):
        self.path = Path(path)
        self.total_lines = 0
        self.valid_count = 0
        self.invalid_count = 0
        self.invalid_samples: list[str] = []
        self._max_invalid_samples = 10

    def process(self) -> Iterator[LogEntry]:
        with self._open() as f:
            for raw_line in f:
                self.total_lines += 1
                entry = parse_line(raw_line)
                if entry is None:
                    self.invalid_count += 1
                    if len(self.invalid_samples) < self._max_invalid_samples:
                        self.invalid_samples.append(raw_line.rstrip("\n"))
                    continue
                self.valid_count += 1
                yield entry

    def _open(self):
        if not self.path.exists():
            raise FileNotFoundError(f"log file not found: {self.path}")

        if self.path.suffix == ".gz":
            return gzip.open(self.path, mode="rt", encoding="utf-8", errors="replace")

        return open(self.path, mode="r", encoding="utf-8", errors="replace")