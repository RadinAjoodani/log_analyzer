from __future__ import annotations
import re
from dataclasses import dataclass
from datetime import datetime
from typing import Optional
 
# Creating the class of entries:
@dataclass(frozen=True)
class LogEntry:
    ip: str
    timestamp: datetime
    method: str
    endpoint: str
    protocol: str
    status: int
    size: int  
    referrer: Optional[str] = None
    user_agent: Optional[str] = None
 
    @property
    def is_error(self) -> bool:
        return 400 <= self.status < 600

LOG_PATTERN = re.compile(
    r'^(?P<ip>\S+)\s+\S+\s+\S+'
    r'\s+\[(?P<timestamp>[^\]]+)\]'
    r'\s+"(?P<method>\S+)\s+(?P<endpoint>\S+)\s+(?P<protocol>[^"]+)"'
    r'\s+(?P<status>\d{3})'
    r'\s+(?P<size>\d+|-)'
    r'(?:\s+"(?P<referrer>[^"]*)")?'
    r'(?:\s+"(?P<user_agent>[^"]*)")?'
    r'\s*$'
)
 

TIMESTAMP_FORMAT = "%d/%b/%Y:%H:%M:%S %z"
 
# Creating a new error for parsing errors:
class LogParseError(ValueError):
    """Raised when a log line does not match the expected format or contains invalid data."""
    pass

def parse_line(line: str) -> Optional[LogEntry]:
    if not line or not line.strip(): # if a line is empty or just spaces:
        return None
 
    try:
        return _parse_line_strict(line)
    except LogParseError:
        return None
 
 
def _parse_line_strict(line: str) -> LogEntry:
    match = LOG_PATTERN.match(line.strip())
    if match is None:
        raise LogParseError(f"line does not match expected format: {line!r}")
 
    fields = match.groupdict()
 
    ip = fields["ip"]
    if not _ip_checker(ip):
        raise LogParseError(f"invalid IP address: {ip!r}")
 
    timestamp = _parse_timestamp(fields["timestamp"])
 
    method = fields["method"]
    if not method.isalpha():
        raise LogParseError(f"invalid HTTP method: {method!r}")
 
    endpoint = fields["endpoint"]
    protocol = fields["protocol"]
 
    status = int(fields["status"])
    if not (100 <= status <= 599):
        raise LogParseError(f"status code out of range: {status}")
 
    raw_size = fields["size"]
    if raw_size == "-":
        size = 0 
    else:
        size = int(raw_size)
 
    referrer = fields.get("referrer") or None
    user_agent = fields.get("user_agent") or None
 
    return LogEntry(
        ip=ip,
        timestamp=timestamp,
        method=method,
        endpoint=endpoint,
        protocol=protocol,
        status=status,
        size=size,
        referrer=referrer,
        user_agent=user_agent,
    )
 
 
def _parse_timestamp(raw: str) -> datetime:
    try:
        return datetime.strptime(raw, TIMESTAMP_FORMAT)
    except ValueError as exc:
        raise LogParseError(f"invalid timestamp {raw!r}: {exc}") from exc
 
 
def _ip_checker(value: str) -> bool:
    parts = value.split(".")
    if len(parts) != 4:
        return False
    return all(part.isdigit() and 0 <= int(part) <= 255 for part in parts)