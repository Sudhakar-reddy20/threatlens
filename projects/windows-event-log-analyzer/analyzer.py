"""Analyze exported Windows Security Event XML (not binary EVTX files)."""

from __future__ import annotations

import argparse
import csv
import json
import sys
import xml.etree.ElementTree as ET
from collections import defaultdict
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path


@dataclass(frozen=True)
class WindowsEvent:
    event_id: int
    timestamp: datetime | None
    computer: str
    record_id: str
    channel: str
    username: str
    source_ip: str
    logon_type: str
    target_username: str
    member_name: str
    raw_xml: str


@dataclass(frozen=True)
class Alert:
    rule_id: str
    severity: str
    title: str
    description: str
    source_ip: str
    username: str
    targeted_users: tuple[str, ...]
    event_ids: tuple[int, ...]
    first_seen: str
    last_seen: str
    event_count: int
    evidence: tuple[str, ...]
    recommendation: str


def _local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _child(parent: ET.Element | None, name: str) -> ET.Element | None:
    if parent is None:
        return None
    return next((node for node in parent if _local_name(node.tag) == name), None)


def _text(parent: ET.Element | None, name: str, default: str = "") -> str:
    node = _child(parent, name)
    return (node.text or "").strip() if node is not None else default


def _event_data(event_data: ET.Element | None) -> dict[str, str]:
    values: dict[str, str] = {}
    if event_data is None:
        return values
    for node in event_data:
        if _local_name(node.tag) == "Data":
            key = node.attrib.get("Name", "")
            if key:
                values[key] = (node.text or "").strip()
    return values


def _parse_timestamp(value: str) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed
    except ValueError:
        return None


def parse_event(element: ET.Element) -> WindowsEvent | None:
    """Parse one Windows Event XML element; return None if malformed."""
    system = _child(element, "System")
    if system is None:
        return None
    try:
        event_id = int(_text(system, "EventID"))
    except ValueError:
        return None

    time_node = _child(system, "TimeCreated")
    timestamp = _parse_timestamp(time_node.attrib.get("SystemTime", "") if time_node is not None else "")
    data = _event_data(_child(element, "EventData"))
    computer = _text(system, "Computer")
    record_id = _text(system, "EventRecordID")
    channel = _text(system, "Channel")

    username = (
        data.get("TargetUserName")
        or data.get("SubjectUserName")
        or data.get("MemberName")
        or ""
    )
    source_ip = data.get("IpAddress", "")
    if source_ip in {"-", "::1", "127.0.0.1"}:
        source_ip = "" if source_ip == "-" else source_ip
    return WindowsEvent(
        event_id=event_id,
        timestamp=timestamp,
        computer=computer,
        record_id=record_id,
        channel=channel,
        username=username,
        source_ip=source_ip,
        logon_type=data.get("LogonType", ""),
        target_username=data.get("TargetUserName", ""),
        member_name=data.get("MemberName", ""),
        raw_xml=ET.tostring(element, encoding="unicode"),
    )


def parse_export(path: Path) -> tuple[list[WindowsEvent], int]:
    """Read an XML export containing an Event root or Events wrapper."""
    root = ET.parse(path).getroot()
    candidates = [root] if _local_name(root.tag) == "Event" else [
        node for node in root.iter() if _local_name(node.tag) == "Event"
    ]
    events: list[WindowsEvent] = []
    unsupported = 0
    for element in candidates:
        event = parse_event(element)
        if event is None:
            unsupported += 1
        else:
            events.append(event)
    return events, unsupported


def _when(event: WindowsEvent) -> datetime:
    return event.timestamp or datetime.min.replace(tzinfo=timezone.utc)


def detect_alerts(
    events: list[WindowsEvent],
    failure_threshold: int = 5,
    window_minutes: int = 10,
) -> list[Alert]:
    if failure_threshold < 1 or window_minutes < 1:
        raise ValueError("Threshold and window must be at least 1.")
    window = timedelta(minutes=window_minutes)
    by_ip: dict[str, list[WindowsEvent]] = defaultdict(list)
    for event in events:
        if event.source_ip and event.event_id in {4624, 4625}:
            by_ip[event.source_ip].append(event)

    alerts: list[Alert] = []
    for source_ip, source_events in by_ip.items():
        ordered = sorted(source_events, key=_when)
        failures = [event for event in ordered if event.event_id == 4625]

        bursts: list[list[WindowsEvent]] = []
        for failure in failures:
            if not bursts or _when(failure) - _when(bursts[-1][-1]) > window:
                bursts.append([failure])
            else:
                bursts[-1].append(failure)

        for burst in bursts:
            left = 0
            evidence: list[WindowsEvent] | None = None
            for right, current in enumerate(burst):
                while left <= right and _when(burst[left]) < _when(current) - window:
                    left += 1
                candidate = burst[left:right + 1]
                if len(candidate) >= failure_threshold:
                    evidence = candidate
                    break
            if evidence:
                users = tuple(sorted({e.username for e in evidence if e.username}))
                alerts.append(Alert(
                    rule_id="WELA-001",
                    severity="HIGH",
                    title="Repeated Windows Failed Logons",
                    description=f"At least {failure_threshold} failed logons from {source_ip} within {window_minutes} minutes.",
                    source_ip=source_ip,
                    username=users[0] if users else "",
                    targeted_users=users,
                    event_ids=(4625,),
                    first_seen=_when(evidence[0]).isoformat(),
                    last_seen=_when(evidence[-1]).isoformat(),
                    event_count=len(evidence),
                    evidence=tuple(e.raw_xml for e in evidence),
                    recommendation="Validate the source host, targeted accounts, logon type, and surrounding endpoint activity.",
                ))

        for success in (e for e in ordered if e.event_id == 4624):
            prior = [e for e in failures if _when(success) - window <= _when(e) < _when(success)]
            if len(prior) < failure_threshold:
                continue
            users = tuple(sorted({e.username for e in prior + [success] if e.username}))
            alerts.append(Alert(
                rule_id="WELA-002",
                severity="CRITICAL",
                title="Successful Logon Following Repeated Failures",
                description=f"Successful logon from {source_ip} followed {len(prior)} failed logons within {window_minutes} minutes.",
                source_ip=source_ip,
                username=success.username,
                targeted_users=users,
                event_ids=(4625, 4624),
                first_seen=_when(prior[0]).isoformat(),
                last_seen=_when(success).isoformat(),
                event_count=len(prior) + 1,
                evidence=tuple(e.raw_xml for e in prior + [success]),
                recommendation="Verify the successful authentication with the account owner and investigate the resulting session.",
            ))

    security_change_events = {4720, 4728, 4732, 1102}
    labels = {
        4720: ("WELA-003", "MEDIUM", "User Account Created"),
        4728: ("WELA-004", "HIGH", "Member Added to Global Security Group"),
        4732: ("WELA-004", "HIGH", "Member Added to Local Security Group"),
        1102: ("WELA-005", "HIGH", "Windows Security Audit Log Cleared"),
    }
    for event in events:
        if event.event_id not in security_change_events:
            continue
        rule_id, severity, title = labels[event.event_id]
        alerts.append(Alert(
            rule_id=rule_id,
            severity=severity,
            title=title,
            description=f"Windows Security event {event.event_id} recorded on {event.computer}.",
            source_ip=event.source_ip,
            username=event.username,
            targeted_users=tuple(filter(None, (event.target_username, event.member_name))),
            event_ids=(event.event_id,),
            first_seen=_when(event).isoformat(),
            last_seen=_when(event).isoformat(),
            event_count=1,
            evidence=(event.raw_xml,),
            recommendation="Confirm the change was authorized and correlate it with the change ticket and administrator activity.",
        ))

    return sorted(alerts, key=lambda a: (a.last_seen, a.rule_id, a.source_ip))


def write_reports(alerts: list[Alert], output_dir: Path) -> tuple[Path, Path]:
    output_dir.mkdir(parents=True, exist_ok=True)
    json_path = output_dir / "windows_security_alerts.json"
    csv_path = output_dir / "windows_security_alerts.csv"
    payload = {
        "tool": "Windows Event Log Analyzer",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "total_alerts": len(alerts),
        "alerts": [asdict(alert) for alert in alerts],
    }
    json_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    fields = list(asdict(alerts[0]).keys()) if alerts else [
        "rule_id", "severity", "title", "description", "source_ip",
        "username", "targeted_users", "event_ids", "first_seen",
        "last_seen", "event_count", "evidence", "recommendation",
    ]
    with csv_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for alert in alerts:
            row = asdict(alert)
            for key in ("targeted_users", "event_ids", "evidence"):
                row[key] = " | ".join(map(str, row[key]))
            writer.writerow(row)
    return json_path, csv_path


def main() -> int:
    parser = argparse.ArgumentParser(description="Analyze exported Windows Security Event XML.")
    sub = parser.add_subparsers(dest="command", required=True)
    analyze = sub.add_parser("analyze", help="Analyze an exported XML file.")
    analyze.add_argument("input", type=Path)
    analyze.add_argument("--output-dir", type=Path, default=Path("reports"))
    analyze.add_argument("--failure-threshold", type=int, default=5)
    analyze.add_argument("--window", type=int, default=10)
    args = parser.parse_args()
    if args.failure_threshold < 1 or args.window < 1:
        parser.error("Threshold and window must be at least 1.")
    if not args.input.is_file():
        print(f"[ERROR] Input file not found: {args.input}", file=sys.stderr)
        return 1
    try:
        events, unsupported = parse_export(args.input)
        alerts = detect_alerts(events, args.failure_threshold, args.window)
        json_path, csv_path = write_reports(alerts, args.output_dir)
    except (OSError, ET.ParseError, ValueError) as exc:
        print(f"[ERROR] Analysis failed: {exc}", file=sys.stderr)
        return 1
    print(f"Parsed events: {len(events)}")
    print(f"Unsupported event records: {unsupported}")
    print(f"Alerts: {len(alerts)}")
    print(f"JSON report: {json_path}")
    print(f"CSV report: {csv_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
