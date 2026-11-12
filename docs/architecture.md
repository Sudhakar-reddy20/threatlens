# ThreatLens Architecture

## Overview

ThreatLens is a local Python CLI that analyzes supported Linux SSH authentication records and produces evidence-backed alerts.

## Actual repository layout

```text
src/threatlens/
├── parser.py       # Syslog/SSH event parsing and validation
├── detector.py     # TL-SSH-001 and TL-SSH-002
├── reporter.py     # JSON and CSV serialization
└── cli.py          # Arguments, orchestration, and console output
tests/              # pytest coverage
sample_logs/        # Synthetic authentication data
docs/               # Architecture, rules, and investigation notes
```

## Processing pipeline

1. **Input:** Read a local authentication log file.
2. **Parsing:** Extract supported SSH authentication records into immutable `AuthEvent` objects.
3. **Validation:** Validate timestamps, IP addresses, and source ports; count unsupported lines.
4. **Detection:** Apply configurable time-window rules by source IP.
5. **Evidence:** Retain original log lines and targeted usernames.
6. **Reporting:** Write JSON and CSV reports.

## Detection components

- **TL-SSH-001:** Detect a qualifying rolling window of failed SSH logins. Emit one alert for a contiguous failure burst; a quiet gap longer than the configured window begins a new burst.
- **TL-SSH-002:** For each successful login, correlate failures from the same source IP in the preceding configured window.

## Alert data

Each alert includes its rule ID, severity, title, description, source IP, representative username, targeted usernames, first/last timestamps, event count, original evidence lines, and analyst recommendation.

## Reliability and safety

- Malformed or unsupported input records are skipped and counted.
- Invalid detection thresholds are rejected.
- Input and report I/O failures are returned as CLI errors.
- CSV fields are sanitized against common spreadsheet formula-injection prefixes.
- Synthetic examples use documentation-only IP ranges.

## Known limitations

The parser supports a focused subset of SSH syslog messages. Traditional syslog timestamps lack year and timezone; the CLI's `--year` option supplies the year. The tool does not provide live ingestion, automated blocking, or SIEM integration.
