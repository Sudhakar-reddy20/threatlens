# ThreatLens Detection Rules

ThreatLens currently implements two rule-based detections for Linux SSH authentication logs.

## TL-SSH-001 — Repeated SSH authentication failures

- **Severity:** HIGH (project-defined label)
- **Default threshold:** 5 failures
- **Default window:** 10 minutes
- **Grouping key:** source IP

The detector sorts events by timestamp and looks for a rolling window containing at least the configured number of failures. It emits one alert for the first qualifying window in each contiguous burst. A burst ends when the gap between consecutive failures is greater than the configured window. This suppresses overlapping duplicate alerts while allowing a later burst from the same IP to generate a new alert.

The alert records the original log lines and the unique usernames targeted in the qualifying evidence window.

## TL-SSH-002 — Successful login following repeated failures

- **Severity:** CRITICAL (project-defined label)
- **Default threshold:** 3 preceding failures
- **Default window:** 10 minutes
- **Grouping key:** source IP

For each successful login, the detector checks for the configured number of failures from the same source IP in the preceding window. Evidence includes those failures and the success event. The targeted-user list includes usernames from both failed and successful events.

## Configuration

```bash
threatlens analyze sample_logs/auth.log --year 2026 \
  --failure-threshold 5 \
  --correlation-threshold 3 \
  --window 10 \
  --output-dir reports
```

## Analyst interpretation

These rules identify suspicious authentication patterns, not confirmed attacks or compromise. Analysts should validate account ownership, source context, MFA status, session activity, and surrounding endpoint/network telemetry before drawing conclusions.
