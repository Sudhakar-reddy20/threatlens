import csv
import json

from threatlens.detector import detect_threats
from threatlens.parser import parse_auth_log_line
from threatlens.reporter import generate_csv_report, generate_json_report


def create_alerts():
    events = []

    for i in range(5):
        line = (
            f"Nov  4 10:{i:02d}:00 server01 sshd[1234]: "
            f"Failed password for admin from 192.0.2.50 "
            f"port 51234 ssh2"
        )
        events.append(parse_auth_log_line(line, year=2026))

    return detect_threats(events)


def test_generate_json_report(tmp_path):
    alerts = create_alerts()
    output = tmp_path / "reports" / "alerts.json"

    result = generate_json_report(alerts, output)

    assert result.exists()

    data = json.loads(result.read_text())

    assert data["tool"] == "ThreatLens"
    assert data["total_alerts"] == 1
    assert data["alerts"][0]["rule_id"] == "TL-SSH-001"
    assert len(data["alerts"][0]["evidence"]) == 5


def test_generate_csv_report(tmp_path):
    alerts = create_alerts()
    output = tmp_path / "reports" / "alerts.csv"

    result = generate_csv_report(alerts, output)

    assert result.exists()

    with result.open(encoding="utf-8") as file:
        rows = list(csv.DictReader(file))

    assert len(rows) == 1
    assert rows[0]["rule_id"] == "TL-SSH-001"
    assert rows[0]["severity"] == "HIGH"
    assert rows[0]["source_ip"] == "192.0.2.50"


def test_empty_alert_report(tmp_path):
    json_output = generate_json_report([], tmp_path / "empty.json")
    csv_output = generate_csv_report([], tmp_path / "empty.csv")

    data = json.loads(json_output.read_text())

    assert data["total_alerts"] == 0

    with csv_output.open(encoding="utf-8") as file:
        rows = list(csv.DictReader(file))

    assert rows == []


def test_csv_sanitizes_formula_injection_values():
    from threatlens.reporter import sanitize_csv_value

    assert sanitize_csv_value("=1+1") == "'=1+1"
    assert sanitize_csv_value("+SUM(A1:A2)") == "'+SUM(A1:A2)"
    assert sanitize_csv_value("-1+2") == "'-1+2"
    assert sanitize_csv_value("@SUM(A1)") == "'@SUM(A1)"
    assert sanitize_csv_value("Normal username") == "Normal username"
    assert sanitize_csv_value("192.0.2.50") == "192.0.2.50"


def test_csv_sanitizes_values_with_leading_whitespace():
    from threatlens.reporter import sanitize_csv_value

    assert sanitize_csv_value("  =1+1") == "'  =1+1"
    assert sanitize_csv_value("\t=1+1") == "'\t=1+1"
    assert sanitize_csv_value("\n=1+1") == "'\n=1+1"
