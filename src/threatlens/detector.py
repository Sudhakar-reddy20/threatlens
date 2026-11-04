"""Evidence-based detection rules for SSH authentication events."""

from collections import defaultdict
from dataclasses import dataclass
from datetime import timedelta

from threatlens.parser import AuthEvent


@dataclass(frozen=True)
class Alert:
    """A security alert supported by authentication log evidence."""

    rule_id: str
    severity: str
    title: str
    description: str
    source_ip: str
    username: str
    first_seen: object
    last_seen: object
    event_count: int
    evidence: tuple[str, ...]
    recommendation: str


def detect_threats(
    events: list[AuthEvent],
    failure_threshold: int = 5,
    correlation_threshold: int = 3,
    window_minutes: int = 10,
) -> list[Alert]:
    """
    Detect repeated SSH failures and success following repeated failures.

    TL-SSH-001:
        Detect the first window containing at least failure_threshold
        failures from one source IP.

    TL-SSH-002:
        Detect a successful login when at least correlation_threshold
        failures from the same source IP occurred in the preceding window.

    These rules identify suspicious patterns, not confirmed compromise.
    """
    if failure_threshold < 1 or correlation_threshold < 1:
        raise ValueError("Detection thresholds must be at least 1.")

    if window_minutes < 1:
        raise ValueError("Window must be at least 1 minute.")

    window = timedelta(minutes=window_minutes)

    events_by_ip: dict[str, list[AuthEvent]] = defaultdict(list)

    for event in events:
        events_by_ip[event.source_ip].append(event)

    alerts: list[Alert] = []

    for source_ip, ip_events in events_by_ip.items():
        ordered = sorted(ip_events, key=lambda event: event.timestamp)

        failures = [
            event for event in ordered
            if event.outcome == "failure"
        ]

        # TL-SSH-001: Repeated failed SSH authentication.
        left = 0

        for right, current in enumerate(failures):
            while (
                failures[left].timestamp < current.timestamp - window
            ):
                left += 1

            matching_failures = failures[left:right + 1]

            if len(matching_failures) >= failure_threshold:
                alerts.append(
                    Alert(
                        rule_id="TL-SSH-001",
                        severity="HIGH",
                        title="Repeated SSH Authentication Failures",
                        description=(
                            f"At least {failure_threshold} failed SSH "
                            f"authentication attempts were observed from "
                            f"{source_ip} within {window_minutes} minutes."
                        ),
                        source_ip=source_ip,
                        username=current.username,
                        first_seen=matching_failures[0].timestamp,
                        last_seen=current.timestamp,
                        event_count=len(matching_failures),
                        evidence=tuple(
                            event.raw_line for event in matching_failures
                        ),
                        recommendation=(
                            "Review the source IP, targeted accounts, "
                            "authentication logs, and firewall controls. "
                            "Confirm whether the activity is authorized."
                        ),
                    )
                )
                # Report the first qualifying window for this IP.
                break

        # TL-SSH-002: Successful login after repeated failures.
        for success in ordered:
            if success.outcome != "success":
                continue

            preceding_failures = [
                event for event in failures
                if success.timestamp - window
                <= event.timestamp < success.timestamp
            ]

            if len(preceding_failures) < correlation_threshold:
                continue

            alerts.append(
                Alert(
                    rule_id="TL-SSH-002",
                    severity="CRITICAL",
                    title="Successful SSH Login Following Repeated Failures",
                    description=(
                        f"A successful SSH login from {source_ip} occurred "
                        f"after {len(preceding_failures)} failed attempts "
                        f"within the preceding {window_minutes} minutes. "
                        "This requires analyst investigation."
                    ),
                    source_ip=source_ip,
                    username=success.username,
                    first_seen=preceding_failures[0].timestamp,
                    last_seen=success.timestamp,
                    event_count=len(preceding_failures) + 1,
                    evidence=tuple(
                        event.raw_line for event in preceding_failures
                    ) + (success.raw_line,),
                    recommendation=(
                        "Verify the successful login with the account owner. "
                        "Review session activity, source reputation, MFA "
                        "status, and related authentication events."
                    ),
                )
            )

    return sorted(alerts, key=lambda alert: alert.last_seen)
