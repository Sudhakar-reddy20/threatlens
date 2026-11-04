# ThreatLens Sample Investigation

## Case Overview

This investigation demonstrates how ThreatLens identifies suspicious SSH authentication activity using synthetic Linux authentication logs.

## Analysis Environment

- Tool: ThreatLens
- Log source: sample_logs/auth.log
- Operating system: macOS development environment
- Log format: Linux SSH authentication records
- Analysis year: 2026

## Analysis Results

| Metric | Result |
|---|---:|
| Total parsed events | 10 |
| Unsupported entries | 1 |
| Failed logins | 8 |
| Successful logins | 2 |
| Alerts generated | 2 |

## Finding 1: Repeated SSH Authentication Failures

- Rule: TL-SSH-001
- Severity: HIGH
- Source IP: 192.0.2.50
- Username: admin
- Failed attempts: 5
- First observed: 10:00:01
- Last observed: 10:04:30

### Analyst Assessment

Five failed authentication attempts from the same source IP occurred within the configured detection window.

This pattern is consistent with repeated password guessing and requires investigation.

### Recommended Actions

- Review the source IP and targeted account.
- Check for related authentication activity.
- Verify whether the attempts were authorized.
- Review relevant firewall and access controls.

## Finding 2: Successful Login Following Repeated Failures

- Rule: TL-SSH-002
- Severity: CRITICAL
- Source IP: 198.51.100.25
- Username: testuser
- Related events: 3 failures followed by 1 success
- First observed: 10:05:00
- Last observed: 10:06:30

### Analyst Assessment

A successful SSH authentication occurred after three failed attempts from the same source IP within the configured time window.

This pattern deserves urgent investigation because the successful authentication may indicate compromised credentials.

### Recommended Actions

- Verify the login with the account owner.
- Review the resulting session and subsequent activity.
- Check MFA status and account security.
- Investigate related events from the same source.

## Reproduction

Run the following command from the project root:

    threatlens analyze sample_logs/auth.log --year 2026

Generated reports:

- reports/threatlens_report.json
- reports/threatlens_report.csv

## Investigation Conclusion

ThreatLens successfully identified two suspicious SSH authentication patterns from the supplied synthetic dataset.

The alerts provide source information, timestamps, event counts, original evidence, and recommended investigation actions.

These findings are detection leads, not proof of a successful compromise. Further investigation is required before determining whether an actual attack occurred.

## Data Disclaimer

The sample log dataset is synthetic. Its IP addresses belong to documentation-only address ranges and do not identify real attackers or systems.
