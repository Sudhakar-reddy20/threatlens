"""Export ThreatLens security alerts into JSON and CSV reports."""

import csv
import json
from dataclasses import asdict
from datetime import datetime
from pathlib import Path

from threatlens.detector import Alert


def serialize_alert(alert: Alert) -> dict:
    """Convert an alert into a JSON-compatible dictionary."""

    data = asdict(alert)
    data["first_seen"] = alert.first_seen.isoformat()
    data["last_seen"] = alert.last_seen.isoformat()
    data["evidence"] = list(alert.evidence)

    return data


def sanitize_csv_value(value):
    """Reduce spreadsheet formula-injection risk in untrusted CSV values."""

    if not isinstance(value, str):
        return value

    stripped = value.lstrip(" \t\r\n")

    if stripped.startswith(("=", "+", "-", "@")):
        return "'" + value

    if value.startswith(("\t", "\r", "\n")):
        return "'" + value

    return value


def generate_json_report(
    alerts: list[Alert],
    output_path: str | Path,
) -> Path:
    """Generate a structured JSON security report."""

    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    report = {
        "tool": "ThreatLens",
        "generated_at": datetime.now().astimezone().isoformat(),
        "total_alerts": len(alerts),
        "alerts": [serialize_alert(alert) for alert in alerts],
    }

    path.write_text(
        json.dumps(report, indent=4),
        encoding="utf-8",
    )

    return path


def generate_csv_report(
    alerts: list[Alert],
    output_path: str | Path,
) -> Path:
    """Generate a spreadsheet-friendly CSV security report."""

    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    fields = [
        "rule_id",
        "severity",
        "title",
        "description",
        "source_ip",
        "username",
        "first_seen",
        "last_seen",
        "event_count",
        "recommendation",
        "evidence",
    ]

    with path.open("w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=fields)
        writer.writeheader()

        for alert in alerts:
            row = serialize_alert(alert)
            row["evidence"] = " | ".join(row["evidence"])

            safe_row = {
                key: sanitize_csv_value(value)
                for key, value in row.items()
            }

            writer.writerow(safe_row)

    return path
