# ThreatLens

### See the evidence. Detect the threat.

**An evidence-driven Python SOC log analysis and threat detection platform.**

ThreatLens analyzes Linux SSH authentication logs, identifies suspicious login patterns, and generates structured security alerts with supporting evidence and investigation recommendations.

## Overview

Security analysts regularly investigate authentication logs to identify brute-force attempts, suspicious login activity, and potentially compromised accounts.

ThreatLens automates part of this investigation process through log parsing, rule-based detection, event correlation, and report generation.

## Key Features

- **SSH log analysis:** Parse Linux SSH authentication records.
- **Threat detection:** Identify repeated failed authentication attempts.
- **Event correlation:** Detect successful logins following repeated failures.
- **Evidence-based alerts:** Preserve relevant original log entries.
- **Severity classification:** Generate HIGH and CRITICAL alerts.
- **JSON reporting:** Export structured investigation results.
- **CSV reporting:** Export alerts for spreadsheet-based analysis.
- **Configurable detection:** Adjust thresholds and time windows.
- **Automated testing:** Validate functionality using pytest.

## Architecture

    Linux SSH Authentication Logs
                 |
                 v
             Log Parser
                 |
                 v
        Authentication Events
                 |
                 v
           Detection Engine
                 |
                 v
            Security Alerts
                 |
                 v
          JSON / CSV Reports

Read the detailed [Architecture Documentation](docs/architecture.md).

## Detection Rules

| Rule ID | Detection | Severity |
|---|---|---|
| TL-SSH-001 | Repeated SSH authentication failures | HIGH |
| TL-SSH-002 | Successful login following repeated failures | CRITICAL |

### TL-SSH-001: Repeated SSH Authentication Failures

Identifies repeated failed SSH authentication attempts from the same source IP within a configurable time window.

Default threshold: 5 failures within 10 minutes.

### TL-SSH-002: Successful Login Following Repeated Failures

Identifies a successful SSH authentication following at least 3 failed attempts from the same source IP within the configured time window.

Default severity: CRITICAL.

See [Detection Rules](docs/detection-rules.md) for the detailed logic.

## Technology Stack

| Technology | Purpose |
|---|---|
| Python 3 | Application development |
| pytest | Automated testing |
| argparse | CLI interface |
| JSON | Structured reports |
| CSV | Investigation exports |
| dataclasses | Event and alert models |
| setuptools | Python package installation |

## Installation

### Requirements

- Python 3.10 or newer
- Git
- macOS, Linux, or another compatible Python environment

### 1. Clone the repository

    git clone https://github.com/Sudhakar-reddy20/threatlens.git

    cd threatlens

### 2. Create a virtual environment

    python3 -m venv .venv

### 3. Activate the environment

macOS / Linux:

    source .venv/bin/activate

### 4. Install ThreatLens

    python -m pip install --upgrade pip

    python -m pip install -e ".[dev]"

## Quick Start

Run ThreatLens against the included synthetic SSH authentication dataset:

    threatlens analyze sample_logs/auth.log --year 2026

ThreatLens will parse the log entries, execute the detection rules, display the findings, and generate JSON and CSV reports.

## Example Results

The included sample dataset produces the following results:

| Metric | Result |
|---|---:|
| Parsed SSH events | 10 |
| Unsupported entries | 1 |
| Failed logins | 8 |
| Successful logins | 2 |
| Alerts generated | 2 |

### Example Findings

**Alert 1 — HIGH**

Repeated SSH Authentication Failures

- Source IP: 192.0.2.50
- Username: admin
- Failed attempts: 5
- Detection: TL-SSH-001

**Alert 2 — CRITICAL**

Successful SSH Login Following Repeated Failures

- Source IP: 198.51.100.25
- Username: testuser
- Related events: 3 failures followed by 1 success
- Detection: TL-SSH-002

These findings demonstrate suspicious authentication patterns, not proof of a successful compromise.

See the complete [Sample Investigation](docs/sample-investigation.md).

## Command-Line Options

    threatlens analyze --help

Available configuration options:

| Option | Purpose |
|---|---|
| `--output-dir` | Select the report output directory |
| `--year` | Set the year for traditional syslog timestamps |
| `--failure-threshold` | Configure the repeated failure threshold |
| `--correlation-threshold` | Configure the preceding failure threshold |
| `--window` | Configure the detection window in minutes |

Example with custom thresholds:

    threatlens analyze sample_logs/auth.log --year 2026 --failure-threshold 5 --correlation-threshold 3 --window 10

## Generated Reports

ThreatLens generates:

    reports/
    ├── threatlens_report.json
    └── threatlens_report.csv

The JSON report contains structured alert information and original log evidence.

The CSV report provides investigation-friendly alert information and basic spreadsheet formula-injection protection.

Generated reports are excluded from Git by default.

## Running Tests

Run the complete automated test suite:

    python -m pytest -v

The project currently includes 29 passing tests covering parsing, detection, reporting, and CLI behavior.

## Project Structure

    threatlens/
    ├── docs/
    │   ├── architecture.md
    │   ├── detection-rules.md
    │   └── sample-investigation.md
    ├── reports/
    ├── sample_logs/
    │   └── auth.log
    ├── src/
    │   └── threatlens/
    │       ├── __init__.py
    │       ├── parser.py
    │       ├── detector.py
    │       ├── reporter.py
    │       └── cli.py
    ├── tests/
    ├── .gitignore
    ├── LICENSE
    ├── pyproject.toml
    └── README.md

## Current Limitations

- Currently focuses on Linux SSH authentication logs.
- Detection is rule-based rather than machine-learning-based.
- Traditional syslog timestamps require a supplied year for accurate interpretation.
- Timezone information is not currently preserved by the parser.
- Live monitoring, automatic blocking, and SIEM integrations are not implemented.

## Roadmap

- [ ] Expand Linux log format support.
- [ ] Add additional authentication detection rules.
- [ ] Improve event correlation and detection performance.
- [ ] Add MITRE ATT&CK mapping.
- [ ] Build an interactive SOC investigation dashboard.
- [ ] Introduce real-time log monitoring.
- [ ] Explore SIEM integrations.

## Responsible Use

ThreatLens is intended for defensive security monitoring, education, and authorized log analysis.

The included sample dataset is synthetic and uses documentation-only IP address ranges.

Alerts should be investigated and validated before drawing conclusions about malicious activity.

## Author

**Sudhakar Reddy**

Cybersecurity | SOC Analysis | Blue Team | Python

GitHub: [Sudhakar-reddy20](https://github.com/Sudhakar-reddy20)

---

*ThreatLens — See the evidence. Detect the threat.*
