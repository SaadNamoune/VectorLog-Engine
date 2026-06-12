from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Any


class LogSource(str, Enum):
    OPENSSH = "openssh"
    SYSLOG = "syslog"
    WINDOWS_EVENT = "windows_event"
    GENERIC = "generic"


@dataclass
class ParsedLog:
    source: LogSource
    timestamp: datetime | None
    level: str
    host: str | None
    process: str | None
    pid: int | None
    message: str
    raw: str
    extra: dict[str, Any]


# ── OpenSSH ──────────────────────────────────────────────────────────────────

_SSH_RE = re.compile(
    r"^(?P<month>\w+)\s+(?P<day>\d+)\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+(?P<process>\w+)(?:\[(?P<pid>\d+)\])?:\s+(?P<message>.+)$"
)
_SSH_FAIL_RE = re.compile(r"Failed (?P<method>\S+) for (?:invalid user )?(?P<user>\S+) from (?P<ip>[\d.]+)")
_SSH_ACCEPT_RE = re.compile(r"Accepted (?P<method>\S+) for (?P<user>\S+) from (?P<ip>[\d.]+)")
_SSH_DISCONNECT_RE = re.compile(r"Received disconnect from (?P<ip>[\d.]+)")


def parse_openssh(line: str, year: int = 2024) -> ParsedLog | None:
    m = _SSH_RE.match(line.strip())
    if not m:
        return None
    try:
        ts = datetime.strptime(
            f"{year} {m['month']} {m['day']} {m['time']}", "%Y %b %d %H:%M:%S"
        )
    except ValueError:
        ts = None

    msg = m["message"]
    level = "ERROR" if any(k in msg for k in ("Failed", "error", "Invalid", "illegal")) else "INFO"

    extra: dict[str, Any] = {}
    for pattern, key in [(_SSH_FAIL_RE, "auth_failure"), (_SSH_ACCEPT_RE, "auth_success"), (_SSH_DISCONNECT_RE, "disconnect")]:
        em = pattern.search(msg)
        if em:
            extra[key] = em.groupdict()

    return ParsedLog(
        source=LogSource.OPENSSH,
        timestamp=ts,
        level=level,
        host=m["host"],
        process=m["process"],
        pid=int(m["pid"]) if m["pid"] else None,
        message=msg,
        raw=line,
        extra=extra,
    )


# ── Syslog RFC 5424 ──────────────────────────────────────────────────────────

_SYSLOG_RE = re.compile(
    r"^<(?P<pri>\d+)>(?P<version>\d)\s+(?P<ts>\S+)\s+(?P<host>\S+)\s+"
    r"(?P<app>\S+)\s+(?P<procid>\S+)\s+(?P<msgid>\S+)\s+(?P<structured_data>\S+)\s+(?P<msg>.+)$"
)

_SEVERITY_MAP = {0: "EMERG", 1: "ALERT", 2: "CRIT", 3: "ERROR", 4: "WARN", 5: "NOTICE", 6: "INFO", 7: "DEBUG"}


def parse_syslog(line: str) -> ParsedLog | None:
    m = _SYSLOG_RE.match(line.strip())
    if not m:
        return None
    pri = int(m["pri"])
    severity = pri % 8
    try:
        ts = datetime.fromisoformat(m["ts"].replace("Z", "+00:00"))
    except ValueError:
        ts = None
    pid_str = m["procid"]
    pid = int(pid_str) if pid_str.isdigit() else None
    return ParsedLog(
        source=LogSource.SYSLOG,
        timestamp=ts,
        level=_SEVERITY_MAP.get(severity, "INFO"),
        host=m["host"],
        process=m["app"],
        pid=pid,
        message=m["msg"],
        raw=line,
        extra={"facility": pri >> 3, "severity": severity, "msgid": m["msgid"]},
    )


# ── Windows Event Log (text export format) ──────────────────────────────────

_WIN_RE = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})\s+"
    r"(?P<level>\w+)\s+(?P<source>[^\s]+)\s+(?P<event_id>\d+)\s+(?P<msg>.+)$"
)


def parse_windows_event(line: str) -> ParsedLog | None:
    m = _WIN_RE.match(line.strip())
    if not m:
        return None
    try:
        ts = datetime.fromisoformat(m["ts"])
    except ValueError:
        ts = None
    return ParsedLog(
        source=LogSource.WINDOWS_EVENT,
        timestamp=ts,
        level=m["level"].upper(),
        host=None,
        process=m["source"],
        pid=None,
        message=m["msg"],
        raw=line,
        extra={"event_id": int(m["event_id"])},
    )


# ── Generic fallback ─────────────────────────────────────────────────────────

_TS_RE = re.compile(r"(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2})")
_LEVEL_RE = re.compile(r"\b(DEBUG|INFO|NOTICE|WARN(?:ING)?|ERROR|CRIT(?:ICAL)?|ALERT|EMERG(?:ENCY)?)\b", re.I)


def parse_generic(line: str) -> ParsedLog:
    ts = None
    tm = _TS_RE.search(line)
    if tm:
        try:
            ts = datetime.fromisoformat(tm.group(1).replace(" ", "T"))
        except ValueError:
            pass
    lm = _LEVEL_RE.search(line)
    level = lm.group(1).upper() if lm else "INFO"
    return ParsedLog(
        source=LogSource.GENERIC,
        timestamp=ts,
        level=level,
        host=None,
        process=None,
        pid=None,
        message=line.strip(),
        raw=line,
        extra={},
    )


# ── Auto-detect dispatcher ───────────────────────────────────────────────────

def parse_line(line: str, source_hint: LogSource | None = None, year: int = 2024) -> ParsedLog:
    if source_hint == LogSource.OPENSSH:
        return parse_openssh(line, year) or parse_generic(line)
    if source_hint == LogSource.SYSLOG:
        return parse_syslog(line) or parse_generic(line)
    if source_hint == LogSource.WINDOWS_EVENT:
        return parse_windows_event(line) or parse_generic(line)

    # Auto-detect
    if line.startswith("<") and ">" in line[:6]:
        result = parse_syslog(line)
        if result:
            return result
    if re.match(r"^\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2}", line):
        result = parse_openssh(line, year)
        if result:
            return result
    result = parse_windows_event(line)
    if result:
        return result
    return parse_generic(line)
