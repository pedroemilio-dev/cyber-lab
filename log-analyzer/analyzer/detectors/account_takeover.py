from collections import defaultdict
from datetime import timedelta

from analyzer.models import LogEntry, Alert

WINDOW = timedelta(seconds=60)
THRESHOLD = 5


def detect(entries: list[LogEntry]) -> list[Alert]:
    alerts = []
    ip_events = defaultdict(list)

    for entry in entries:
        is_apache_match = (
            entry.method in ("PATCH", "POST", "PUT")
            and "/users/me/password" in entry.path
            and entry.status in (400, 401, 403)
        )
        is_spring_match = entry.event_type == "PASSWORD_CHANGE_FAILED"

        if is_apache_match or is_spring_match:
            ip_events[entry.ip].append(entry.time)

    for ip, times in ip_events.items():
        times.sort()
        for i, t in enumerate(times):
            window_hits = [x for x in times[i:] if x - t <= WINDOW]
            if len(window_hits) >= THRESHOLD:
                alerts.append(Alert(
                    ip=ip,
                    attack_type="Account Takeover Attempt",
                    severity="high",
                    detail=f"{len(window_hits)} failed password-change attempts in 60s",
                    count=len(window_hits)
                ))
                break

    return alerts
