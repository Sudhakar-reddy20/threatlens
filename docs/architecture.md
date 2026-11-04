# ThreatLens Architecture

## Overview

ThreatLens is a Python-based security log analysis platform designed to identify suspicious SSH authentication activity and generate evidence-based security alerts.

## Processing Pipeline

    Linux SSH Logs
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
    JSON and CSV Reports

## Core Components

### 1. Log Parser

- Reads Linux SSH authentication logs.
- Extracts timestamps, hostnames, usernames, source IP addresses, ports, and authentication outcomes.
- Supports successful and failed SSH authentication events.
- Skips unsupported or malformed entries safely.

### 2. Detection Engine

Analyzes authentication events using configurable detection thresholds and time windows.

Current detection rules:

- TL-SSH-001: Repeated SSH authentication failures.
- TL-SSH-002: Successful SSH authentication following repeated failures.

### 3. Alert System

Each alert contains a rule ID, severity, description, source IP, username, timestamps, event count, original log evidence, and recommended investigation actions.

### 4. Report Generator

- JSON reports for structured analysis and integrations.
- CSV reports for spreadsheet-based investigations.
- Basic protection against spreadsheet formula injection in CSV values.

### 5. Command-Line Interface

Provides a command-line interface to analyze authentication logs and configure detection thresholds.

## Technology Stack

| Technology | Purpose |
|---|---|
| Python 3 | Core application |
| pytest | Automated testing |
| JSON | Structured reports |
| CSV | Investigation reports |
| argparse | Command-line interface |
| dataclasses | Structured event and alert models |

## Security and Reliability

- Handles malformed log entries without terminating the entire analysis.
- Preserves original log evidence in JSON alerts.
- Supports configurable detection thresholds.
- Uses documentation-only IP addresses in sample logs.

## Current Limitations

- Currently focuses on Linux SSH authentication logs.
- Uses rule-based detection rather than machine learning.
- Traditional syslog timestamps do not contain a year; an explicit year can be supplied.
- Timestamps are currently interpreted without timezone information.
- Does not provide live monitoring or automatic blocking.

## Future Development

- Additional Linux authentication log parsers.
- More detection rules and event correlation.
- Interactive investigation dashboard.
- Real-time log monitoring.
- SIEM integration.
- MITRE ATT&CK technique mapping.
