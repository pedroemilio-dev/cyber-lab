from collections import defaultdict
from datetime import timedelta

from analyzer.models import LogEntry, Alert

BRUTE_FORCE_EVENTS = {"FAILED_LOGIN", "PASSWORD_CHANGE_FAILED"}
WINDOW = timedelta(seconds=60)
THRESHOLD = 10


def detect(entries: list[LogEntry]) -> list[Alert]:
    alerts = []
    ip_events = defaultdict(list)

    for entry in entries:
        is_apache_match = entry.status in (401, 403) and entry.event_type is None
        is_spring_match = entry.event_type in BRUTE_FORCE_EVENTS

        if is_apache_match or is_spring_match:
            ip_events[entry.ip].append(entry.time)

    for ip, times in ip_events.items():
        times.sort()
        for i, t in enumerate(times):
            window_hits = [x for x in times[i:] if x - t <= WINDOW]
            if len(window_hits) >= THRESHOLD:
                alerts.append(Alert(
                    ip=ip,
                    attack_type="Brute Force",
                    severity="high",
                    detail=f"{len(window_hits)} failed auth attempts in 60s",
                    count=len(window_hits)
                ))
                break

    return alerts