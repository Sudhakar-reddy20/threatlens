import json
import sys

from threatlens.cli import analyze_file, main


def create_sample_log(path):
    lines = []

    for i in range(5):
        lines.append(
            f"Nov  4 10:0{i}:00 server01 sshd[100{i}]: "
            f"Failed password for admin from 192.0.2.50 "
            f"port 5100{i} ssh2"
        )

    failure_times = [
        ("05", "00"),
        ("05", "30"),
        ("06", "00"),
    ]

    for i, (minute, second) in enumerate(failure_times):
        lines.append(
            f"Nov  4 10:{minute}:{second} server01 sshd[200{i}]: "
            f"Failed password for testuser from 198.51.100.25 "
            f"port 5200{i} ssh2"
        )

    lines.append(
        "Nov  4 10:06:30 server01 sshd[2004]: "
        "Accepted password for testuser from 198.51.100.25 "
        "port 52004 ssh2"
    )

    lines.append(
        "Nov  4 10:07:00 server01 sshd[3001]: "
        "Accepted publickey for sudhakar from 203.0.113.10 "
        "port 53001 ssh2"
    )

    lines.append(
        "Nov  4 10:08:00 server01 sshd[3002]: "
        "Connection closed by authenticating user guest "
        "203.0.113.20 port 53002 [preauth]"
    )

    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def test_cli_analyzes_log_and_generates_reports(tmp_path, monkeypatch, capsys):
    log_file = tmp_path / "auth.log"
    output_dir = tmp_path / "reports"

    create_sample_log(log_file)

    monkeypatch.setattr(
        sys,
        "argv",
        [
            "threatlens",
            "analyze",
            str(log_file),
            "--year",
            "2026",
            "--output-dir",
            str(output_dir),
        ],
    )

    result = main()
    captured = capsys.readouterr()

    assert result == 0

    parsed_line = next(
        line for line in captured.out.splitlines()
        if "Parsed SSH events" in line
    )
    unsupported_line = next(
        line for line in captured.out.splitlines()
        if "Unsupported entries" in line
    )
    alerts_line = next(
        line for line in captured.out.splitlines()
        if "Total alerts" in line
    )

    assert parsed_line.strip().endswith("10")
    assert unsupported_line.strip().endswith("1")
    assert alerts_line.strip().endswith("2")

    json_report = output_dir / "threatlens_report.json"
    csv_report = output_dir / "threatlens_report.csv"

    assert json_report.exists()
    assert csv_report.exists()

    data = json.loads(json_report.read_text(encoding="utf-8"))

    assert data["total_alerts"] == 2
    assert data["alerts"][0]["rule_id"] == "TL-SSH-001"
    assert data["alerts"][1]["rule_id"] == "TL-SSH-002"


def test_cli_handles_missing_input_file(tmp_path, capsys):
    missing_file = tmp_path / "missing.log"

    result = analyze_file(
        input_path=missing_file,
        output_dir=tmp_path / "reports",
        year=2026,
    )

    captured = capsys.readouterr()

    assert result == 1
    assert "[ERROR] Input file not found" in captured.err


def test_cli_rejects_invalid_threshold(monkeypatch):
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "threatlens",
            "analyze",
            "sample_logs/auth.log",
            "--failure-threshold",
            "0",
        ],
    )

    try:
        main()
        assert False, "Expected argparse to reject the invalid threshold."
    except SystemExit as exc:
        assert exc.code == 2
