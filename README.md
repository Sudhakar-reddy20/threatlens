# 🛡️ THREATLENS
### SEE THE EVIDENCE. DETECT THE THREAT.

<p align="center">
  <strong>An Evidence-Driven SOC Log Analysis & Threat Detection Platform</strong>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.10%2B-00D26A?style=for-the-badge&logo=python&logoColor=white" />
  <img src="https://img.shields.io/badge/Domain-SOC%20%7C%20Blue%20Team-111111?style=for-the-badge" />
  <img src="https://img.shields.io/badge/Output-JSON%20%7C%20CSV-00D26A?style=for-the-badge" />
  <img src="https://img.shields.io/badge/Tests-Pytest-2ea44f?style=for-the-badge&logo=pytest&logoColor=white" />
</p>

<p align="center">
  <a href="https://github.com/Sudhakar-reddy20/threatlens">Repository</a> •
  <a href="https://github.com/Sudhakar-reddy20/threatlens/issues">Report an Issue</a> •
  <a href="https://github.com/Sudhakar-reddy20">Developer</a>
</p>

---

## `root@threatlens:~$ whoami`

ThreatLens is a Python command-line tool for analyzing Linux SSH authentication logs. It parses supported authentication events, applies configurable detection rules, preserves original log evidence, and exports structured JSON and CSV alerts.

**Workflow:** Log Collection → Parsing → Detection → Evidence → Reporting

> ThreatLens is a local, rule-based prototype. It is not a live monitoring agent, SIEM platform, or automated incident-response system.

## Key capabilities

- Parse supported Linux SSH authentication records, including IPv4 and IPv6 source addresses.
- Detect repeated authentication failures with a rolling time-window check.
- Avoid overlapping duplicate brute-force alerts while allowing later, separate bursts to alert.
- Correlate successful authentication with preceding failures from the same source IP.
- List all usernames observed in the evidence window.
- Preserve original log lines in generated alerts.
- Export JSON and CSV reports, with basic CSV formula-injection mitigation.
- Handle common input and report-generation errors without an unhandled traceback.

## Detection rules

### TL-SSH-001 — Repeated SSH authentication failures

- **Default threshold:** 5 failures.
- **Default window:** 10 minutes.
- **Grouping:** source IP.
- **Deduplication:** one alert per contiguous failure burst; a new burst is eligible after a quiet gap longer than the configured window.
- **Evidence:** first qualifying rolling window, including its original log lines and targeted usernames.

This rule identifies suspicious repeated failures. It does not prove that an attack succeeded.

### TL-SSH-002 — Successful login after repeated failures

- **Default threshold:** 3 preceding failures.
- **Default window:** 10 minutes.
- **Grouping:** source IP.
- **Evidence:** preceding failed events plus the successful event, with usernames involved.

This rule identifies a pattern requiring prompt investigation; it does not independently confirm account compromise.

## Investigation workflow

```text
Linux SSH authentication logs
             |
             v
         Log parser
             |
             v
    Normalized auth events
             |
             v
      Detection engine
        /         \
       v           v
 TL-SSH-001    TL-SSH-002
       \           /
        v         v
       Evidence and context
             |
             v
      JSON and CSV reports
```

## Project structure

```text
threatlens/
├── src/
│   └── threatlens/
│       ├── __init__.py
│       ├── parser.py
│       ├── detector.py
│       ├── reporter.py
│       └── cli.py
├── tests/
│   ├── test_parser.py
│   ├── test_detector.py
│   ├── test_reporter.py
│   └── test_cli.py
├── sample_logs/
│   └── auth.log
├── docs/
│   ├── architecture.md
│   ├── detection-rules.md
│   └── sample-investigation.md
├── pyproject.toml
├── README.md
└── .gitignore
```

## Installation

Requirements: Python 3.10+, Git, and macOS/Linux or another supported Python environment.

```bash
git clone https://github.com/Sudhakar-reddy20/threatlens.git
cd threatlens
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
```

## Quick start

Run the included synthetic log dataset from the repository root:

```bash
threatlens analyze sample_logs/auth.log --year 2026
```

Reports are written to `reports/threatlens_report.json` and `reports/threatlens_report.csv` by default.

Customize thresholds and the report directory:

```bash
threatlens analyze sample_logs/auth.log --year 2026 \
  --failure-threshold 5 \
  --correlation-threshold 3 \
  --window 10 \
  --output-dir reports
```

See all options:

```bash
threatlens analyze --help
```

## Sample dataset and investigation

The file `sample_logs/auth.log` contains synthetic SSH authentication events. The expected analysis includes:
- Five failed attempts from `192.0.2.50`, targeting more than one account.
- Three failed attempts followed by a successful login from `198.51.100.25`.
- A successful public-key login from a separate source.
- One unsupported connection-close record, counted rather than treated as a parsed authentication event.

See [the sample investigation](docs/sample-investigation.md) for the analyst narrative and reproduction steps.

All sample IPs use documentation-only address ranges; they do not identify real attackers or systems.

## Testing

Install development dependencies and run:

```bash
python -m pytest -v
```

The suite covers parsing, detection thresholds, rolling-window boundaries, burst deduplication, targeted-account attribution, evidence preservation, JSON/CSV output, and CLI behavior. Run the command above for the current test result; this README intentionally does not hard-code a test count.

## Technology

- Python 3.10+
- pytest
- Standard library: argparse, dataclasses, datetime, ipaddress, csv, json, pathlib

## Limitations

- Supports a focused subset of Linux SSH authentication log formats.
- Traditional syslog timestamps do not include a year or timezone; use `--year` to set the year.
- Timestamps are currently timezone-naive during parsing.
- Detection is rule-based and depends on configured thresholds.
- No live log ingestion, automatic blocking, threat-intelligence lookup, or external SIEM integration is included.

## Roadmap

- [ ] Additional Linux authentication event formats.
- [ ] Windows Security Event Log support (planned as a separate project).
- [ ] MITRE ATT&CK mapping with documented rule rationale.
- [ ] Optional threat-intelligence enrichment.
- [ ] SIEM integration and dashboard.

## Responsible use

ThreatLens is intended for defensive security education, authorized log analysis, and controlled testing. Analyze only systems and logs you own or are explicitly authorized to investigate.

## Author

**Sudhakar Reddy**  
Computer Science Student | SOC Analyst Aspirant | Blue Team Learner

- GitHub: https://github.com/Sudhakar-reddy20
- LinkedIn: https://www.linkedin.com/in/sudhakar-reddy1920

---

<p align="center">
  <strong>THREATLENS</strong><br/>
  <code>SEE THE EVIDENCE. DETECT THE THREAT.</code>
</p>
