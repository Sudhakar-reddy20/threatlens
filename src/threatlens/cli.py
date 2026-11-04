"""Command-line interface for ThreatLens."""

import argparse
import sys
from pathlib import Path

from threatlens.detector import detect_threats
from threatlens.parser import parse_auth_log_line
from threatlens.reporter import generate_csv_report, generate_json_report


def analyze_file(
    input_path: Path,
    output_dir: Path,
    year: int | None = None,
    failure_threshold: int = 5,
    correlation_threshold: int = 3,
    window_minutes: int = 10,
) -> int:
    """Analyze a Linux SSH authentication log file."""

    if not input_path.is_file():
        print(f"[ERROR] Input file not found: {input_path}", file=sys.stderr)
        return 1

    events = []
    unsupported = 0

    try:
        with input_path.open("r", encoding="utf-8", errors="replace") as file:
            for line in file:
                if not line.strip():
                    continue

                event = parse_auth_log_line(line, year=year)

                if event is None:
                    unsupported += 1
                else:
                    events.append(event)

    except OSError as exc:
        print(f"[ERROR] Could not read input file: {exc}", file=sys.stderr)
        return 1

    alerts = detect_threats(
        events,
        failure_threshold=failure_threshold,
        correlation_threshold=correlation_threshold,
        window_minutes=window_minutes,
    )

    output_dir.mkdir(parents=True, exist_ok=True)

    json_path = generate_json_report(
        alerts,
        output_dir / "threatlens_report.json",
    )

    csv_path = generate_csv_report(
        alerts,
        output_dir / "threatlens_report.csv",
    )

    print("\n" + "=" * 60)
    print("                  THREATLENS SOC ANALYSIS")
    print("=" * 60)

    print(f"Input file          : {input_path}")
    print(f"Parsed SSH events   : {len(events)}")
    print(f"Unsupported entries : {unsupported}")
    print(f"Total alerts        : {len(alerts)}")

    print("\nAUTHENTICATION SUMMARY")
    print("-" * 60)

    failures = sum(event.outcome == "failure" for event in events)
    successes = sum(event.outcome == "success" for event in events)

    print(f"Failed logins       : {failures}")
    print(f"Successful logins   : {successes}")

    print("\nDETECTION RESULTS")
    print("-" * 60)

    if not alerts:
        print("No configured detection rules were triggered.")
    else:
        for index, alert in enumerate(alerts, start=1):
            print(f"\nAlert #{index}")
            print(f"Rule       : {alert.rule_id}")
            print(f"Severity   : {alert.severity}")
            print(f"Title      : {alert.title}")
            print(f"Source IP  : {alert.source_ip}")
            print(f"Username   : {alert.username}")
            print(f"Events     : {alert.event_count}")
            print(f"First seen : {alert.first_seen}")
            print(f"Last seen  : {alert.last_seen}")
            print(f"Evidence   : {len(alert.evidence)} original log entries")
            print(f"Action     : {alert.recommendation}")

    print("\nREPORTS GENERATED")
    print("-" * 60)
    print(f"JSON : {json_path}")
    print(f"CSV  : {csv_path}")
    print("=" * 60 + "\n")

    return 0


def main() -> int:
    """Parse command-line arguments and run ThreatLens."""

    parser = argparse.ArgumentParser(
        prog="threatlens",
        description="Evidence-driven Linux SSH authentication log analysis.",
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    analyze_parser = subparsers.add_parser(
        "analyze",
        help="Analyze an SSH authentication log file.",
    )

    analyze_parser.add_argument(
        "input",
        type=Path,
        help="Path to the authentication log file.",
    )

    analyze_parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("reports"),
        help="Directory for generated reports (default: reports).",
    )

    analyze_parser.add_argument(
        "--year",
        type=int,
        default=None,
        help="Year for traditional syslog timestamps.",
    )

    analyze_parser.add_argument(
        "--failure-threshold",
        type=int,
        default=5,
        help="Failed logins required for TL-SSH-001 (default: 5).",
    )

    analyze_parser.add_argument(
        "--correlation-threshold",
        type=int,
        default=3,
        help="Prior failures required for TL-SSH-002 (default: 3).",
    )

    analyze_parser.add_argument(
        "--window",
        type=int,
        default=10,
        help="Detection window in minutes (default: 10).",
    )

    args = parser.parse_args()

    try:
        if args.failure_threshold < 1:
            parser.error("--failure-threshold must be at least 1.")

        if args.correlation_threshold < 1:
            parser.error("--correlation-threshold must be at least 1.")

        if args.window < 1:
            parser.error("--window must be at least 1.")

        return analyze_file(
            input_path=args.input,
            output_dir=args.output_dir,
            year=args.year,
            failure_threshold=args.failure_threshold,
            correlation_threshold=args.correlation_threshold,
            window_minutes=args.window,
        )

    except ValueError as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
