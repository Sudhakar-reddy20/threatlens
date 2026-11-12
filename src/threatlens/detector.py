"""Evidence-based detection rules for SSH authentication events."""

from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta

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
    targeted_users: tuple[str, ...]
    first_seen: datetime
    last_seen: datetime
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

    TL-SSH-001 emits one alert for each contiguous failure burst that
    contains a qualifying rolling window. A burst is split when the gap
    between consecutive failures is greater than the configured window.
    This avoids duplicate alerts for every overlapping window while still
    allowing a later, separate burst from the same IP to alert again.

    TL-SSH-002 evaluates every successful login against failures from the
    same source IP in the preceding window.

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
        failures = [event for event in ordered if event.outcome == "failure"]

        # Split failure activity into bursts separated by a quiet period
        # longer than the detection window.
        bursts: list[list[AuthEvent]] = []
        for failure in failures:
            if (
                not bursts
                or failure.timestamp - bursts[-1][-1].timestamp > window
            ):
                bursts.append([failure])
            else:
                bursts[-1].append(failure)

        # TL-SSH-001: one alert per qualifying burst, using the first
        # qualifying rolling window as the alert's evidence.
        for burst in bursts:
            left = 0
            qualifying_window: list[AuthEvent] | None = None

            for right, current in enumerate(burst):
                while (
                    left <= right
                    and burst[left].timestamp < current.timestamp - window
                ):
                    left += 1

                candidate = burst[left:right + 1]
                if len(candidate) >= failure_threshold:
                    qualifying_window = candidate
                    break

            if qualifying_window is None:
                continue

            targeted_users = tuple(sorted({
                event.username for event in qualifying_window
            }))
            alerts.append(
                Alert(
                    rule_id="TL-SSH-001",
                    severity="HIGH",
                    title="Repeated SSH Authentication Failures",
                    description=(
                        f"At least {failure_threshold} failed SSH "
                        f"authentication attempts were observed from "
                        f"{source_ip} within {window_minutes} minutes. "
                        f"Targeted accounts: {', '.join(targeted_users)}."
                    ),
                    source_ip=source_ip,
                    username=targeted_users[0],
                    targeted_users=targeted_users,
                    first_seen=qualifying_window[0].timestamp,
                    last_seen=qualifying_window[-1].timestamp,
                    event_count=len(qualifying_window),
                    evidence=tuple(event.raw_line for event in qualifying_window),
                    recommendation=(
                        "Review the source IP, all targeted accounts, "
                        "authentication logs, and firewall controls. "
                        "Confirm whether the activity is authorized."
                    ),
                )
            )

        # TL-SSH-002: correlate each success with preceding failures.
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

            targeted_users = tuple(sorted({
                event.username for event in preceding_failures
            } | {success.username}))

            alerts.append(
                Alert(
                    rule_id="TL-SSH-002",
                    severity="CRITICAL",
                    title="Successful SSH Login Following Repeated Failures",
                    description=(
                        f"A successful SSH login from {source_ip} occurred "
                        f"after {len(preceding_failures)} failed attempts "
                        f"within the preceding {window_minutes} minutes. "
                        f"Accounts involved: {', '.join(targeted_users)}. "
                        "This requires analyst investigation."
                    ),
                    source_ip=source_ip,
                    username=success.username,
                    targeted_users=targeted_users,
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

    return sorted(
        alerts,
        key=lambda alert: (alert.last_seen, alert.rule_id, alert.source_ip),
    )
