"""Small, deterministic parsers for common text and CSV log formats."""

import csv
import io
import re
from dataclasses import dataclass
from datetime import datetime

IP_PATTERN = r"(?:\d{1,3}\.){3}\d{1,3}|[0-9A-Fa-f:]{2,45}"
TIMESTAMP_PATTERNS = ("%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%d %H:%M:%S", "%b %d %H:%M:%S")


@dataclass(frozen=True)
class ParsedRecord:
    line_number: int
    timestamp: datetime | None
    source_ip: str | None
    destination_ip: str | None
    source_port: int | None
    destination_port: int | None
    username: str | None
    event_type: str | None
    status: str | None
    message: str | None
    raw_line: str


def _parse_timestamp(value: str | None) -> datetime | None:
    if not value:
        return None
    normalized = value.strip().replace("Z", "+00:00")
    for pattern in TIMESTAMP_PATTERNS:
        try:
            return datetime.strptime(normalized, pattern)
        except ValueError:
            continue
    return None


def _first(pattern: str, line: str) -> str | None:
    match = re.search(pattern, line, re.IGNORECASE)
    return match.group(1) if match else None


def _port(value: str | None) -> int | None:
    return int(value) if value and value.isdigit() and int(value) <= 65535 else None


def parse_text_log(content: bytes) -> list[ParsedRecord]:
    """Extract SIEM fields from common key-value, authentication, and network lines."""
    records: list[ParsedRecord] = []
    for line_number, raw_line in enumerate(content.decode("utf-8").splitlines(), start=1):
        line = raw_line.strip()
        if not line:
            continue
        timestamp = _parse_timestamp(_first(r"^(\S+(?:\s+\d{1,2}\s+\d\d:\d\d:\d\d)?)", line))
        source_ip = _first(r"(?:src(?:_ip)?|from)[= :]+(" + IP_PATTERN + r")", line)
        destination_ip = _first(r"(?:dst|destination(?:_ip)?|to)[= :]+(" + IP_PATTERN + r")", line)
        ips = re.findall(IP_PATTERN, line)
        source_ip = source_ip or (ips[0] if ips else None)
        destination_ip = destination_ip or (ips[1] if len(ips) > 1 else None)
        username = _first(r"(?:user(?:name)?|for (?:invalid user )?)[= :]+([A-Za-z0-9_.@-]+)", line)
        event_type = _first(r"(?:event(?:_type)?|type)[= :]+([A-Za-z0-9_.-]+)", line)
        result = _first(r"(?:status|result)[= :]+([A-Za-z]+)", line)
        lowered = line.lower()
        result = result or ("failed" if "failed" in lowered or "invalid" in lowered else "success" if "accepted" in lowered or "success" in lowered else None)
        event_type = event_type or ("authentication" if "ssh" in lowered or "login" in lowered else "network" if source_ip else None)
        records.append(ParsedRecord(line_number, timestamp, source_ip, destination_ip, _port(_first(r"(?:sport|src_port)[= :]+(\d+)", line)), _port(_first(r"(?:dport|dst_port|port)[= :]+(\d+)", line)), username, event_type, result, line, raw_line))
    return records


def parse_csv_log(content: bytes) -> list[ParsedRecord]:
    """Parse header-based CSV logs using common SIEM column aliases."""
    records: list[ParsedRecord] = []
    for line_number, row in enumerate(csv.DictReader(io.StringIO(content.decode("utf-8"))), start=2):
        fields = {str(key).strip().lower(): (value or "").strip() for key, value in row.items() if key}
        def get(*names: str) -> str | None:
            return next((fields[name] for name in names if fields.get(name)), None)
        records.append(ParsedRecord(line_number, _parse_timestamp(get("timestamp", "time", "datetime")), get("source_ip", "src_ip", "source", "src"), get("destination_ip", "dest_ip", "dst_ip", "destination", "dst"), _port(get("source_port", "src_port", "sport")), _port(get("destination_port", "dest_port", "dst_port", "dport", "port")), get("username", "user"), get("event_type", "type", "event"), get("status", "result"), get("message", "description", "log"), ",".join(row.values())))
    return records


def parse_log(content: bytes, filename: str) -> list[ParsedRecord]:
    return parse_csv_log(content) if filename.lower().endswith(".csv") else parse_text_log(content)
