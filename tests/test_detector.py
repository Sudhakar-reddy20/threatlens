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
        f"{result} password for {username} from {ip} port 51234 ssh2"
    )
    return parse_auth_log_line(line, year=2026)


def test_detect_repeated_failed_logins():
    events = [make_event(i * 60) for i in range(5)]
    alerts = detect_threats(events)
    brute_force_alerts = [a for a in alerts if a.rule_id == "TL-SSH-001"]
    assert len(brute_force_alerts) == 1
    assert brute_force_alerts[0].severity == "HIGH"
    assert brute_force_alerts[0].event_count == 5
    assert brute_force_alerts[0].source_ip == "192.0.2.50"


def test_detect_success_after_repeated_failures():
    events = [make_event(0), make_event(60), make_event(120),
              make_event(180, outcome="success")]
    alerts = detect_threats(events)
    correlation_alerts = [a for a in alerts if a.rule_id == "TL-SSH-002"]
    assert len(correlation_alerts) == 1
    assert correlation_alerts[0].severity == "CRITICAL"
    assert correlation_alerts[0].event_count == 4


def test_no_alert_below_failure_threshold():
    events = [make_event(i * 60) for i in range(4)]
    alerts = detect_threats(events)
    assert not any(a.rule_id == "TL-SSH-001" for a in alerts)


def test_no_correlation_between_different_ips():
    events = [
        make_event(0), make_event(60), make_event(120),
        make_event(180, ip="198.51.100.25", outcome="success"),
    ]
    alerts = detect_threats(events)
    assert not any(a.rule_id == "TL-SSH-002" for a in alerts)


def test_failures_outside_time_window_do_not_trigger():
    events = [make_event(i * 700) for i in range(5)]
    alerts = detect_threats(events)
    assert not any(a.rule_id == "TL-SSH-001" for a in alerts)


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
    alert = next(a for a in detect_threats(events) if a.rule_id == "TL-SSH-001")
    assert len(alert.evidence) == 5
    assert all("Failed password" in line for line in alert.evidence)


def test_brute_force_alert_includes_all_targeted_usernames():
    events = [
        make_event(0, username="admin"),
        make_event(30, username="root"),
        make_event(60, username="guest"),
        make_event(90, username="admin"),
        make_event(120, username="service"),
    ]
    alert = next(a for a in detect_threats(events) if a.rule_id == "TL-SSH-001")
    assert alert.targeted_users == ("admin", "guest", "root", "service")
    assert "Targeted accounts" in alert.description


def test_separate_brute_force_bursts_generate_separate_alerts():
    events = (
        [make_event(i * 30) for i in range(5)]
        + [make_event(1200 + i * 30) for i in range(5)]
    )
    alerts = [a for a in detect_threats(events) if a.rule_id == "TL-SSH-001"]
    assert len(alerts) == 2


def test_one_continuous_burst_does_not_create_overlapping_duplicate_alerts():
    events = [make_event(i * 30) for i in range(12)]
    alerts = [a for a in detect_threats(events) if a.rule_id == "TL-SSH-001"]
    assert len(alerts) == 1


def test_detection_is_independent_of_input_order():
    events = [make_event(i * 30) for i in range(5)]
    forward = detect_threats(events)
    reverse = detect_threats(list(reversed(events)))
    assert [(a.rule_id, a.first_seen, a.last_seen) for a in forward] == [
        (a.rule_id, a.first_seen, a.last_seen) for a in reverse
    ]


def test_failure_exactly_at_window_boundary_is_excluded():
    events = [make_event(0), make_event(60), make_event(120),
              make_event(600), make_event(660)]
    alerts = [a for a in detect_threats(events) if a.rule_id == "TL-SSH-001"]
    assert not alerts


def test_success_alert_lists_failed_and_successful_account_names():
    events = [
        make_event(0, username="admin"),
        make_event(30, username="root"),
        make_event(60, username="guest"),
        make_event(90, outcome="success", username="operator"),
    ]
    alert = next(a for a in detect_threats(events) if a.rule_id == "TL-SSH-002")
    assert alert.username == "operator"
    assert alert.targeted_users == ("admin", "guest", "operator", "root")


def test_multiple_successes_are_correlated_individually():
    events = [
        make_event(0), make_event(30), make_event(60),
        make_event(90, outcome="success", username="admin"),
        make_event(120, outcome="success", username="root"),
    ]
    alerts = [a for a in detect_threats(events) if a.rule_id == "TL-SSH-002"]
    assert len(alerts) == 2
