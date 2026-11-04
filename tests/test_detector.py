from datetime import datetime, timedelta

import pytest

from threatlens.detector import detect_threats
from threatlens.parser import parse_auth_log_line


def make_event(second, ip="192.0.2.50", outcome="failure", username="admin"):
    timestamp = datetime(2026, 11, 4, 10, 0, 0) + timedelta(seconds=second)
    result = "Failed" if outcome == "failure" else "Accepted"

    line = (
        f"{timestamp.strftime('%b')} {timestamp.day:2d} "
        f"{timestamp.strftime('%H:%M:%S')} server01 sshd[1234]: "
        f"{result} password for {username} from {ip} "
        f"port 51234 ssh2"
    )

    return parse_auth_log_line(line, year=2026)


def test_detect_repeated_failed_logins():
    events = [make_event(i * 60) for i in range(5)]

    alerts = detect_threats(events)

    brute_force_alerts = [
        alert for alert in alerts if alert.rule_id == "TL-SSH-001"
    ]

    assert len(brute_force_alerts) == 1
    assert brute_force_alerts[0].severity == "HIGH"
    assert brute_force_alerts[0].event_count == 5
    assert brute_force_alerts[0].source_ip == "192.0.2.50"


def test_detect_success_after_repeated_failures():
    events = [
        make_event(0),
        make_event(60),
        make_event(120),
        make_event(180, outcome="success"),
    ]

    alerts = detect_threats(events)

    correlation_alerts = [
        alert for alert in alerts if alert.rule_id == "TL-SSH-002"
    ]

    assert len(correlation_alerts) == 1
    assert correlation_alerts[0].severity == "CRITICAL"
    assert correlation_alerts[0].event_count == 4


def test_no_alert_below_failure_threshold():
    events = [make_event(i * 60) for i in range(4)]

    alerts = detect_threats(events)

    assert not any(alert.rule_id == "TL-SSH-001" for alert in alerts)


def test_no_correlation_between_different_ips():
    events = [
        make_event(0, ip="192.0.2.50"),
        make_event(60, ip="192.0.2.50"),
        make_event(120, ip="192.0.2.50"),
        make_event(180, ip="198.51.100.25", outcome="success"),
    ]

    alerts = detect_threats(events)

    assert not any(alert.rule_id == "TL-SSH-002" for alert in alerts)


def test_failures_outside_time_window_do_not_trigger():
    events = [
        make_event(0),
        make_event(700),
        make_event(1400),
        make_event(2100),
        make_event(2800),
    ]

    alerts = detect_threats(events)

    assert not any(alert.rule_id == "TL-SSH-001" for alert in alerts)


@pytest.mark.parametrize(
    "kwargs",
    [
        {"failure_threshold": 0},
        {"correlation_threshold": 0},
        {"window_minutes": 0},
    ],
)
def test_invalid_detection_configuration(kwargs):
    with pytest.raises(ValueError):
        detect_threats([], **kwargs)


def test_alert_preserves_original_evidence():
    events = [make_event(i * 60) for i in range(5)]

    alerts = detect_threats(events)

    alert = next(
        alert for alert in alerts if alert.rule_id == "TL-SSH-001"
    )

    assert len(alert.evidence) == 5
    assert all("Failed password" in line for line in alert.evidence)
