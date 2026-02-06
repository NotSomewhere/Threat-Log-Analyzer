import re
from dataclasses import dataclass
from datetime import datetime
from typing import Iterable, List, Optional


@dataclass
class AuthEvent:
    kind: str                 # "failed_password", "invalid_user", "accepted_password"
    ip: str
    user: Optional[str]
    ts: Optional[datetime]
    raw: str


# Examples:
# Failed password for invalid user admin from 1.2.3.4 port 123 ssh2
# Failed password for root from 1.2.3.4 port 123 ssh2
# Invalid user test from 1.2.3.4 port 123
# Accepted password for joel from 1.2.3.4 port 123 ssh2

RE_FAILED = re.compile(r"Failed password for (invalid user )?(?P<user>[\w\-\.\@]+) from (?P<ip>\d+\.\d+\.\d+\.\d+)")
RE_INVALID = re.compile(r"Invalid user (?P<user>[\w\-\.\@]+) from (?P<ip>\d+\.\d+\.\d+\.\d+)")
RE_ACCEPTED = re.compile(r"Accepted password for (?P<user>[\w\-\.\@]+) from (?P<ip>\d+\.\d+\.\d+\.\d+)")
RE_TS = re.compile(r"^(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})")


_MONTHS = {
    "Jan": 1,
    "Feb": 2,
    "Mar": 3,
    "Apr": 4,
    "May": 5,
    "Jun": 6,
    "Jul": 7,
    "Aug": 8,
    "Sep": 9,
    "Oct": 10,
    "Nov": 11,
    "Dec": 12,
}


def _parse_ts(line: str, now: Optional[datetime]) -> Optional[datetime]:
    m = RE_TS.search(line)
    if not m:
        return None
    month = _MONTHS.get(m.group("mon"))
    if not month:
        return None
    day = int(m.group("day"))
    hour, minute, second = (int(x) for x in m.group("time").split(":"))
    base = now or datetime.now()
    ts = datetime(base.year, month, day, hour, minute, second)
    # If the parsed timestamp is in the future, assume it belongs to last year.
    if now and ts > now:
        ts = datetime(base.year - 1, month, day, hour, minute, second)
    return ts


def parse_auth_log(lines: Iterable[str], now: Optional[datetime] = None) -> List[AuthEvent]:
    events: List[AuthEvent] = []
    for line in lines:
        clean = line.lstrip("\ufeff")
        ts = _parse_ts(clean, now)
        m = RE_FAILED.search(clean)
        if m:
            events.append(AuthEvent("failed_password", m.group("ip"), m.group("user"), ts, clean))
            continue

        m = RE_INVALID.search(clean)
        if m:
            events.append(AuthEvent("invalid_user", m.group("ip"), m.group("user"), ts, clean))
            continue

        m = RE_ACCEPTED.search(clean)
        if m:
            events.append(AuthEvent("accepted_password", m.group("ip"), m.group("user"), ts, clean))
            continue

    return events
