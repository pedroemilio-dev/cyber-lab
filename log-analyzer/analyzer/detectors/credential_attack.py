from collections import defaultdict
from datetime import timedelta

from analyzer.models import LogEntry, Alert

WINDOW = timedelta(seconds=60)
ENUMERATION_THRESHOLD = 3
TOKEN_ABUSE_THRESHOLD = 5


def detect(entries: list[LogEntry]) -> list[Alert]:
    alerts = []

    alerts.extend(_detect_user_enumeration(entries))
    alerts.extend(_detect_token_abuse(entries))

    return alerts


def _detect_user_enumeration(entries: list[LogEntry]) -> list[Alert]:
    alerts = []
    ip_events = defaultdict(list)

    for entry in entries:
        if entry.event_type == "USER_ENUMERATION":
            ip_events[entry.ip].append(entry.time)

    for ip, times in ip_events.items():
        times.sort()
        for i, t in enumerate(times):
            window_hits = [x for x in times[i:] if x - t <= WINDOW]
            if len(window_hits) >= ENUMERATION_THRESHOLD:
                alerts.append(Alert(
                    ip=ip,
                    attack_type="User Enumeration",
                    severity="medium",
                    detail=f"{len(window_hits)} attempts with non-existent emails in 60s",
                    count=len(window_hits)
                ))
                break

    return alerts


def _detect_token_abuse(entries: list[LogEntry]) -> list[Alert]:
    alerts = []
    ip_events = defaultdict(list)

    TOKEN_EVENTS = {"INVALID_TOKEN", "BLACKLISTED_TOKEN", "REFRESH_TOKEN_REUSE", "INVALID_REFRESH_TOKEN"}

    for entry in entries:
        if entry.event_type in TOKEN_EVENTS:
            ip_events[entry.ip].append(entry.time)

    for ip, times in ip_events.items():
        times.sort()
        for i, t in enumerate(times):
            window_hits = [x for x in times[i:] if x - t <= WINDOW]
            if len(window_hits) >= TOKEN_ABUSE_THRESHOLD:
                alerts.append(Alert(
                    ip=ip,
                    attack_type="Token Abuse",
                    severity="high",
                    detail=f"{len(window_hits)} invalid/blacklisted token attempts in 60s",
                    count=len(window_hits)
                ))
                break

    return alerts