from collections import defaultdict
from datetime import timedelta

from analyzer.models import LogEntry, Alert

WINDOW = timedelta(seconds=60)
THRESHOLD = 10


def detect(entries: list[LogEntry]) -> list[Alert]:
    alerts = []
    ip_events = defaultdict(list)
    ip_paths = defaultdict(set)

    for entry in entries:
        is_apache_match = (
            entry.method == "GET" and entry.status == 404 and (
                "/api/tasks/" in entry.path or "/api/projects/" in entry.path
            )
        )
        is_spring_match = entry.event_type == "UNAUTHORIZED_READ"

        if is_apache_match or is_spring_match:
            ip_events[entry.ip].append(entry.time)
            ip_paths[entry.ip].add(entry.path)

    for ip, times in ip_events.items():
        times.sort()
        for i, t in enumerate(times):
            window_hits = [x for x in times[i:] if x - t <= WINDOW]
            if len(window_hits) >= THRESHOLD:
                alerts.append(Alert(
                    ip=ip,
                    attack_type="Resource Enumeration",
                    severity="medium",
                    detail=f"{len(window_hits)} sequential resource access attempts in 60s",
                    count=len(window_hits),
                    paths=sorted(ip_paths[ip])[:10]
                ))
                break

    return alerts