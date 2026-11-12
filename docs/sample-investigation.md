# ThreatLens Sample Investigation

## Case overview

This case demonstrates rule-based triage of a synthetic Linux SSH authentication log. The dataset is designed for repeatable learning and does not represent a real incident.

## Environment and reproduction

- Tool: ThreatLens
- Input: `sample_logs/auth.log`
- Log type: Linux SSH syslog-style authentication records
- Sample year: 2026

```bash
python -m pip install -e ".[dev]"
threatlens analyze sample_logs/auth.log --year 2026
```

Generated reports:
- `reports/threatlens_report.json`
- `reports/threatlens_report.csv`

## Dataset observations

The sample contains 11 lines: 10 supported SSH authentication events and one unsupported connection-close event. The supported events include eight failures and two successes.

## Finding 1 — Repeated SSH authentication failures

- Rule: TL-SSH-001
- Severity: HIGH (project-defined)
- Source: `192.0.2.50`
- Qualifying evidence: five failed attempts between 10:00:01 and 10:04:30
- Targeted accounts: `admin` and `root`

**Assessment:** Multiple authentication failures from one source within the configured window are consistent with password guessing. The source and account context require investigation; the pattern alone does not establish malicious intent.

**Recommended analyst actions:**
1. Confirm whether the source is an approved scanner, jump host, or administrator endpoint.
2. Review all targeted accounts and nearby authentication events.
3. Check for related activity on the destination host.
4. Escalate or contain only according to the organization's incident-response procedure.

## Finding 2 — Successful login after repeated failures

- Rule: TL-SSH-002
- Severity: CRITICAL (project-defined)
- Source: `198.51.100.25`
- Evidence: three failed attempts followed by a successful password login at 10:06:30
- Account: `testuser`

**Assessment:** A successful authentication after repeated failures warrants prompt verification. It is not proof of compromise.

**Recommended analyst actions:**
1. Verify the login with the account owner.
2. Review session commands, process activity, and subsequent network connections.
3. Check MFA and credential-reset history where available.
4. Preserve relevant host and network evidence.

## Evidence handling

ThreatLens includes the original matching log lines in each alert's evidence field. The JSON report retains evidence as an array; the CSV report joins evidence lines into a single field. Keep original source logs separately and follow organizational retention and chain-of-custody procedures.

## Conclusion

The synthetic dataset is expected to produce two detection leads: repeated failures from `192.0.2.50` and a successful login following failures from `198.51.100.25`. These are triage findings only. Additional host, identity, and network evidence is required to determine whether either event represents an actual incident.

## Data disclaimer

The dataset uses documentation-only IP ranges and synthetic usernames. No real attacker or production host is represented.
