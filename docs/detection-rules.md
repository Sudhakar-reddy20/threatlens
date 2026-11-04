# ThreatLens Detection Rules

## Overview

ThreatLens currently implements two rule-based detections for Linux SSH authentication logs.

## TL-SSH-001: Repeated SSH Authentication Failures

- **Severity:** HIGH
- **Objective:** Identify repeated failed SSH authentication attempts from one source IP.
- **Default threshold:** 5 failures.
- **Default time window:** 10 minutes.

### Detection Logic

The engine groups failed authentication events by source IP and checks whether the configured number of failures occurs within the rolling time window.

### Example

Five failed login attempts from 192.0.2.50 within 10 minutes trigger an alert.

### Investigation Recommendations

- Review the source IP and targeted accounts.
- Check whether the activity is authorized.
- Review firewall and authentication logs.
- Consider appropriate access restrictions.

## TL-SSH-002: Successful Login Following Repeated Failures

- **Severity:** CRITICAL
- **Objective:** Identify a successful SSH login after repeated authentication failures from the same source IP.
- **Default threshold:** 3 previous failures.
- **Default time window:** 10 minutes.

### Detection Logic

The engine checks successful authentication events for at least the configured number of preceding failures from the same source IP within the configured time window.

### Example

A source IP generates three failed login attempts and then successfully authenticates as testuser. ThreatLens raises a critical alert.

### Investigation Recommendations

- Verify the login with the account owner.
- Review the authenticated session and subsequent activity.
- Check MFA status and account security.
- Investigate related authentication events.

## Configuration

The detection thresholds can be adjusted through CLI options:

- `--failure-threshold`
- `--correlation-threshold`
- `--window`

Example:

    threatlens analyze sample_logs/auth.log --year 2026 --failure-threshold 5 --correlation-threshold 3 --window 10

## Important Notes

These rules identify suspicious patterns, not confirmed attacks. A detection requires investigation and supporting evidence before it can be classified as malicious.
