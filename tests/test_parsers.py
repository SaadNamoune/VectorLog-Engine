from __future__ import annotations

import pytest
from vectorlog.parsers import (
    LogSource,
    parse_generic,
    parse_line,
    parse_openssh,
    parse_syslog,
    parse_windows_event,
)


class TestOpenSSHParser:
    SSH_FAIL = "Jun 15 03:08:11 combo sshd[20882]: Failed password for invalid user admin from 218.145.123.45 port 6000 ssh2"
    SSH_ACCEPT = "Jun 15 03:08:12 combo sshd[20883]: Accepted password for root from 192.168.1.1 port 22 ssh2"

    def test_parses_timestamp(self):
        result = parse_openssh(self.SSH_FAIL, year=2024)
        assert result is not None
        assert result.timestamp.month == 6
        assert result.timestamp.day == 15

    def test_detects_error_level_on_failure(self):
        result = parse_openssh(self.SSH_FAIL)
        assert result.level == "ERROR"

    def test_detects_info_level_on_success(self):
        result = parse_openssh(self.SSH_ACCEPT)
        assert result.level == "INFO"

    def test_extracts_auth_failure_ip(self):
        result = parse_openssh(self.SSH_FAIL)
        assert result.extra.get("auth_failure", {}).get("ip") == "218.145.123.45"

    def test_extracts_process_and_pid(self):
        result = parse_openssh(self.SSH_FAIL)
        assert result.process == "sshd"
        assert result.pid == 20882

    def test_returns_none_on_garbage(self):
        assert parse_openssh("not a syslog line") is None


class TestSyslogParser:
    RFC5424 = "<34>1 2024-06-15T10:00:00Z mymachine myapp 1234 ID47 - BOM'su root' failed for user saad"

    def test_parses_facility_severity(self):
        result = parse_syslog(self.RFC5424)
        assert result is not None
        assert result.level == "CRIT"

    def test_parses_host_and_process(self):
        result = parse_syslog(self.RFC5424)
        assert result.host == "mymachine"
        assert result.process == "myapp"

    def test_parses_pid(self):
        result = parse_syslog(self.RFC5424)
        assert result.pid == 1234

    def test_returns_none_on_openssh_line(self):
        assert parse_syslog("Jun 15 03:08:11 combo sshd[1]: msg") is None


class TestWindowsEventParser:
    WIN_LINE = "2024-06-15T10:00:00 ERROR Microsoft-Windows-Security-Auditing 4625 An account failed to log on"

    def test_parses_timestamp(self):
        result = parse_windows_event(self.WIN_LINE)
        assert result is not None
        assert result.timestamp.year == 2024

    def test_parses_level(self):
        result = parse_windows_event(self.WIN_LINE)
        assert result.level == "ERROR"

    def test_parses_event_id(self):
        result = parse_windows_event(self.WIN_LINE)
        assert result.extra["event_id"] == 4625

    def test_returns_none_on_invalid(self):
        assert parse_windows_event("just some text") is None


class TestGenericParser:
    def test_extracts_level(self):
        result = parse_generic("2024-06-15T10:00:00 ERROR Something went wrong")
        assert result.level == "ERROR"

    def test_extracts_timestamp(self):
        result = parse_generic("2024-06-15T10:00:00 INFO Service started")
        assert result.timestamp is not None
        assert result.timestamp.year == 2024

    def test_defaults_to_info(self):
        result = parse_generic("no level here at all")
        assert result.level == "INFO"


class TestAutoDispatch:
    def test_detects_openssh(self):
        line = "Jun 15 03:08:11 combo sshd[1]: Failed password for root from 1.2.3.4 port 22 ssh2"
        result = parse_line(line)
        assert result.source == LogSource.OPENSSH

    def test_detects_syslog(self):
        line = "<34>1 2024-06-15T10:00:00Z host app 1 ID1 - msg"
        result = parse_line(line)
        assert result.source == LogSource.SYSLOG
