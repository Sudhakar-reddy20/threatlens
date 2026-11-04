# 🛡️ THREATLENS
### SEE THE EVIDENCE. DETECT THE THREAT.

<p align="center">
  <strong>An Evidence-Driven SOC Log Analysis & Threat Detection Platform</strong>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.10%2B-00D26A?style=for-the-badge&logo=python&logoColor=white" />
  <img src="https://img.shields.io/badge/Domain-SOC%20%7C%20Blue%20Team-111111?style=for-the-badge" />
  <img src="https://img.shields.io/badge/Output-JSON%20%7C%20CSV-00D26A?style=for-the-badge" />
  <img src="https://img.shields.io/badge/Tests-29%20Passing-success?style=for-the-badge&logo=pytest&logoColor=white" />
</p>

<p align="center">
  <a href="https://github.com/Sudhakar-reddy20/threatlens">Repository</a> •
  <a href="https://github.com/Sudhakar-reddy20/threatlens/issues">Report an Issue</a> •
  <a href="https://github.com/Sudhakar-reddy20">Developer</a>
</p>

---

## `root@threatlens:~$ whoami`

ThreatLens is a Python-based security log analysis tool designed to identify suspicious SSH authentication activity from Linux authentication logs.

It applies rule-based detection logic to authentication events, identifies suspicious patterns, and generates structured alerts with supporting evidence.

The project demonstrates a practical SOC investigation workflow:

**Log Collection → Parsing → Detection → Evidence → Alert Reporting**

> ThreatLens is currently a local, rule-based CLI prototype. It is not a live monitoring agent, SIEM platform, or automated incident response system.

## ⚡ Key Capabilities

| Capability | Description |
|---|---|
| Log Analysis | Parses Linux SSH authentication logs |
| Event Classification | Identifies failed and successful authentication attempts |
| Brute-Force Detection | Detects repeated SSH authentication failures |
| Suspicious Login Detection | Identifies successful authentication following repeated failures |
| Evidence-Based Alerts | Includes relevant events and source IP information |
| JSON Reporting | Generates machine-readable security reports |
| CSV Reporting | Exports alerts for spreadsheet-based investigation |
| Testing | Automated test coverage across core modules |

## 🔍 Detection Engine

ThreatLens currently implements two SSH detection rules.

### TL-SSH-001 — SSH Brute-Force Activity

**Severity:** HIGH

**Detection logic:**
- Monitors failed SSH authentication attempts.
- Groups attempts by source IP.
- Detects 5 or more failures within a rolling 10-minute window.

**SOC investigation questions:**
- Is the source IP associated with known malicious activity?
- Are multiple user accounts being targeted?
- Are authentication attempts occurring repeatedly?
- Is the activity part of a broader attack pattern?

### TL-SSH-002 — Successful Login After Repeated Failures

**Severity:** CRITICAL

**Detection logic:**
- Identifies repeated failed authentication attempts.
- Checks whether a successful authentication follows at least 3 failures from the same source IP within the preceding 10 minutes.

**SOC investigation questions:**
- Was the successful login expected?
- Which account was accessed?
- Did the source IP previously generate suspicious activity?
- Are there additional signs of account compromise?

*Severity labels represent the project's configured detection rules, not a confirmed real-world incident classification.*

## 🧠 Investigation Workflow

```text
          LINUX AUTH LOGS
                 |
                 v
          LOG PARSER
                 |
                 v
         EVENT CLASSIFICATION
                 |
                 v
          DETECTION ENGINE
                 |
          +------+------+
          |             |
          v             v
      TL-SSH-001    TL-SSH-002
          |             |
          +------+------+
                 |
                 v
          EVIDENCE COLLECTION
                 |
                 v
           ALERT GENERATION
                 |
           +-----+-----+
           |           |
           v           v
         JSON         CSV
         REPORT      REPORT
```

## 🏗️ Project Architecture

```text
ThreatLens/
│
├── threatlens/
│   ├── __init__.py
│   ├── parser.py
│   ├── detector.py
│   ├── reporter.py
│   └── cli.py
│
├── tests/
│   ├── test_parser.py
│   ├── test_detector.py
│   ├── test_reporter.py
│   └── test_cli.py
│
├── data/
│   └── sample_auth.log
│
├── docs/
│   ├── architecture.md
│   ├── detection-rules.md
│   └── sample-investigation.md
│
├── reports/
│
├── pyproject.toml
├── README.md
└── .gitignore
```

## 🚀 Installation & Quick Start

### Requirements

- Python 3.10 or later
- Git
- macOS, Linux, or another supported Python environment

### 1. Clone the repository

```bash
git clone https://github.com/Sudhakar-reddy20/threatlens.git
cd threatlens
```

### 2. Create a virtual environment

```bash
python3 -m venv .venv && source .venv/bin/activate
```

### 3. Install ThreatLens

```bash
python -m pip install --upgrade pip && python -m pip install -e .
```

### 4. Run the analysis

```bash
threatlens analyze data/sample_auth.log
```

### 5. Generate reports

```bash
threatlens analyze data/sample_auth.log --json reports/alerts.json --csv reports/alerts.csv
```

For additional CLI options:

```bash
threatlens analyze --help
```

## 📊 Sample Investigation Results

The included synthetic authentication-log dataset produces the following results:

| Metric | Result |
|---|---:|
| Total parsed events | 10 |
| Unsupported events | 1 |
| Failed authentication events | 8 |
| Successful authentication events | 2 |
| Generated alerts | 2 |

### Example Alert — SSH Brute Force

```json
{
  "rule_id": "TL-SSH-001",
  "severity": "HIGH",
  "source_ip": "192.0.2.50",
  "description": "Repeated SSH authentication failures detected"
}
```

*Illustrative alert structure. Actual report fields and values are generated by the application.*

### Example Alert — Suspicious Successful Login

```json
{
  "rule_id": "TL-SSH-002",
  "severity": "CRITICAL",
  "source_ip": "198.51.100.25",
  "description": "Successful SSH authentication following repeated failures"
}
```

*The IP addresses used in sample data are documentation-only addresses.*

## 📁 Generated Reports

ThreatLens supports two report formats:

| Format | Output |
|---|---|
| JSON | `reports/alerts.json` |
| CSV | `reports/alerts.csv` |

These reports can support further investigation, evidence review, and security reporting workflows.

## 🧪 Testing

ThreatLens includes automated tests for its core functionality.

```bash
python -m pytest -v
```

**Current test result: 29 passing tests.**

Test coverage includes:
- Log parsing
- Event classification
- Detection rule evaluation
- Report generation
- CLI behavior
- CSV formula-injection mitigation

## 🛠️ Technology Stack

- **Language:** Python
- **Testing:** Pytest
- **Data Formats:** JSON, CSV
- **Environment:** Python virtual environment
- **Version Control:** Git and GitHub

## ⚠️ Current Limitations

ThreatLens is an early-stage project with a deliberately focused scope.

- Supports a focused subset of Linux SSH authentication log formats.
- Uses predefined rule-based detection rather than machine learning.
- Traditional syslog timestamps require a supplied year.
- Timezone information is not preserved.
- Does not currently provide live log ingestion.
- Does not automatically block IP addresses.
- Does not integrate with external SIEM platforms.

## 🗺️ Roadmap

The following are planned enhancements, not currently implemented features.

- [ ] Interactive SOC dashboard
- [ ] Live log ingestion
- [ ] More SSH and Linux detection rules
- [ ] MITRE ATT&CK mapping
- [ ] Threat intelligence enrichment
- [ ] Splunk and Wazuh integration
- [ ] Alert severity prioritization
- [ ] Investigation timeline visualization

## 🔐 Responsible Use

ThreatLens is intended for educational purposes, defensive security research, and authorized log analysis.

The included sample data uses documentation-only IP addresses. Always analyze logs and systems you own or have explicit authorization to investigate.

## 👨‍💻 Author

**Sudhakar Reddy**

Computer Science Student | SOC Analyst Aspirant | Blue Team & Cybersecurity Learner

- GitHub: https://github.com/Sudhakar-reddy20
- LinkedIn: https://www.linkedin.com/in/sudhakar-reddy1920

---

<p align="center">
  <strong>THREATLENS</strong>
  <br/>
  <code>SEE THE EVIDENCE. DETECT THE THREAT.</code>
  <br/><br/>
  <sub>Built to demonstrate practical security log analysis and evidence-driven threat detection.</sub>
</p>
