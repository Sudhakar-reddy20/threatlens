from datetime import datetime

import pytest

from threatlens.parser import parse_auth_log_line


def test_failed_password_login():
    line = "Nov  4 10:15:22 server01 sshd[1234]: Failed password for admin from 192.0.2.50 port 51234 ssh2"

    event = parse_auth_log_line(line, year=2026)

    assert event is not None
    assert event.outcome == "failure"
    assert event.username == "admin"
    assert event.source_ip == "192.0.2.50"
    assert event.source_port == 51234
    assert event.method == "password"
    assert event.timestamp == datetime(2026, 11, 4, 10, 15, 22)


def test_successful_public_key_login():
    line = "Nov  4 10:16:22 server01 sshd[1235]: Accepted publickey for sudhakar from 198.51.100.25 port 44322 ssh2"

    event = parse_auth_log_line(line, year=2026)

    assert event is not None
    assert event.outcome == "success"
    assert event.username == "sudhakar"
    assert event.method == "publickey"


def test_invalid_user_login():
    line = "Nov  4 10:17:22 server01 sshd[1236]: Failed password for invalid user testadmin from 203.0.113.10 port 40000 ssh2"

    event = parse_auth_log_line(line, year=2026)

    assert event is not None
    assert event.outcome == "failure"
    assert event.username == "testadmin"


def test_ipv6_address():
    line = "Nov  4 10:18:22 server01 sshd[1237]: Failed password for root from 2001:db8::10 port 40001 ssh2"

    event = parse_auth_log_line(line, year=2026)

    assert event is not None
    assert event.source_ip == "2001:db8::10"


@pytest.mark.parametrize(
    "line",
    [
        "This is not a valid SSH log",
        "",
        "Nov  4 10:15:22 server01 sshd[1234]: Connection closed",
        "Nov  4 10:15:22 server01 sshd[1234]: Failed password for admin from invalid-ip port 51234 ssh2",
        "Nov  4 10:15:22 server01 sshd[1234]: Failed password for admin from 192.0.2.50 port 0 ssh2",
        "Nov  4 10:15:22 server01 sshd[1234]: Failed password for admin from 192.0.2.50 port 65536 ssh2",
        "Bad 99 99:99:99 server01 sshd[1234]: Failed password for admin from 192.0.2.50 port 51234 ssh2",
    ],
)
def test_malformed_or_unsupported_entries(line):
    assert parse_auth_log_line(line, year=2026) is None


def test_original_evidence_is_preserved():
    line = "Nov  4 10:15:22 server01 sshd[1234]: Failed password for admin from 192.0.2.50 port 51234 ssh2"

    event = parse_auth_log_line(line, year=2026)

    assert event is not None
    assert event.raw_line == line
