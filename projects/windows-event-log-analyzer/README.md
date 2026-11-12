# Windows Event Log Analyzer

A defensive Python CLI for triaging **exported Windows Security Event XML**. It parses Windows Event Viewer XML exports, extracts selected Security events, detects suspicious authentication patterns, and writes JSON/CSV investigation reports.

> This project analyzes exported XML files. It does not read live Windows event channels, parse raw EVTX binaries, or perform response actions.

## Supported events

| Event ID | Meaning | Use |
|---|---|---|
| 4624 | Successful logon | Authentication baseline / correlation |
| 4625 | Failed logon | Failed-login detection |
| 4720 | User account created | Account-change triage |
| 4728 | Member added to security-enabled global group | Privilege-change triage |
| 4732 | Member added to security-enabled local group | Privilege-change triage |
| 1102 | Audit log cleared | Audit tampering triage |

Event meanings and field availability depend on Windows version and audit policy. The tool reports the event ID and extracted fields; analysts must validate context.

## Requirements

- Python 3.10+
- No third-party runtime dependencies

## Export Security events on Windows

Run an elevated PowerShell session and export selected Security events as XML:

```powershell
wevtutil qe Security /q:"*[System[(EventID=4624 or EventID=4625 or EventID=4720 or EventID=4728 or EventID=4732 or EventID=1102)]]" /f:xml /e:Events > security-events.xml
```

Copy `security-events.xml` to your analysis machine through an approved evidence-transfer process. Protect the original export and analyze a working copy.

## Run

```bash
python analyzer.py analyze sample_logs/security-events.xml --output-dir reports
```

Optional thresholds:

```bash
python analyzer.py analyze sample_logs/security-events.xml \
  --failure-threshold 5 --window 10 --output-dir reports
```

## Detection rules

- **WELA-001 — Repeated failed logons:** configurable number of 4625 events from the same source IP in a rolling time window. One alert per continuous burst; a quiet gap longer than the window allows a new alert.
- **WELA-002 — Successful logon after failures:** a 4624 event from the same source IP following the configured number of 4625 events within the preceding window.
- **WELA-003 — Security-relevant account or audit changes:** flags 4720, 4728, 4732, and 1102 for analyst review.

Events without a usable source IP remain available for the account/audit-change rule but are not grouped into IP-based authentication detections.

## Sample data

`sample_logs/security-events.xml` is synthetic. Names, hostnames, and IPs are examples only. It is not a real organization's event log.

## Test

```bash
python -m unittest discover -s tests -v
```

## Output

The tool writes:
- `reports/windows_security_alerts.json`
- `reports/windows_security_alerts.csv`

Each alert includes rule ID, severity, event IDs, source IP where applicable, usernames, timestamps, count, and original XML event evidence.

## Limitations and responsible use

- Accepts Windows Event XML exports with one or more `<Event>` elements, including an `<Events>` wrapper.
- Does not parse binary `.evtx` files directly; export to XML first.
- Detection is rule-based and may produce false positives or miss activity outside configured rules.
- Source IP may be absent, represented as `-`, or unavailable depending on event type and audit configuration.
- No automatic account disabling, IP blocking, or other response action is performed.
- Use only logs you own or are authorized to analyze. Preserve originals and follow organizational evidence-handling requirements.
