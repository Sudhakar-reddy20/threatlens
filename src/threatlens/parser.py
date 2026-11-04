"""Parser for Linux SSH authentication log entries."""

from dataclasses import dataclass
from datetime import datetime
import ipaddress
import re
from typing import Literal


@dataclass(frozen=True)
class AuthEvent:
    """A normalized SSH authentication event."""

    timestamp: datetime
    hostname: str
    service: str
    pid: int | None
    username: str
    source_ip: str
    source_port: int
    outcome: Literal["success", "failure"]
    method: str
    raw_line: str


SYSLOG_PATTERN = re.compile(
    r"^(?P<timestamp>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})"
    r"\s+(?P<hostname>\S+)"
    r"\s+sshd(?:\[(?P<pid>\d+)\])?:\s+"
    r"(?P<message>.+)$"
)

AUTH_PATTERN = re.compile(
    r"^(?P<result>Failed|Accepted)\s+"
    r"(?P<method>\S+)\s+for\s+"
    r"(?:(?:invalid|illegal)\s+user\s+)?"
    r"(?P<username>\S+)\s+from\s+"
    r"(?P<ip>\S+)\s+port\s+"
    r"(?P<port>\d+)(?:\s|$)",
    re.IGNORECASE,
)


def parse_auth_log_line(
    line: str,
    year: int | None = None,
) -> AuthEvent | None:
    """
    Parse one Linux SSH authentication log line.

    Returns None for unsupported or malformed entries.

    Traditional syslog timestamps do not contain a year or timezone.
    The caller may supply the year; otherwise the current year is used.
    The resulting datetime is timezone-naive.
    """
    raw_line = line.rstrip("\r\n")

    header = SYSLOG_PATTERN.match(raw_line)
    if not header:
        return None

    message = header.group("message")
    auth = AUTH_PATTERN.match(message)
    if not auth:
        return None

    try:
        timestamp = datetime.strptime(
            f"{year or datetime.now().year} {header.group('timestamp')}",
            "%Y %b %d %H:%M:%S",
        )
        source_ip = str(ipaddress.ip_address(auth.group("ip")))
        source_port = int(auth.group("port"))
        pid = int(header.group("pid")) if header.group("pid") else None
    except (ValueError, OverflowError):
        return None

    if not 1 <= source_port <= 65535:
        return None

    result = auth.group("result").lower()

    return AuthEvent(
        timestamp=timestamp,
        hostname=header.group("hostname"),
        service="sshd",
        pid=pid,
        username=auth.group("username"),
        source_ip=source_ip,
        source_port=source_port,
        outcome="success" if result == "accepted" else "failure",
        method=auth.group("method").lower(),
        raw_line=raw_line,
    )
