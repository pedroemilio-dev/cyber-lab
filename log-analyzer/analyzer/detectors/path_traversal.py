import re
from collections import defaultdict

from analyzer.models import LogEntry, Alert


TRAVERSAL_PATTERN = re.compile(
    r"(\.\./|\.\.\\|%2e%2e%2f|/etc/passwd|/etc/shadow|/proc/self)",
    re.IGNORECASE
)


def detect(entries: list[LogEntry]) -> list[Alert]:
    alerts = []
    ip_paths = defaultdict(list)

    for entry in entries:
        if TRAVERSAL_PATTERN.search(entry.path):
            ip_paths[entry.ip].append(entry.path)

    for ip, paths in ip_paths.items():
        alerts.append(Alert(
            ip=ip,
            attack_type="Path Traversal",
            severity="high",
            detail=f"{len(paths)} traversal attempts detected",
            count=len(paths),
            paths=paths
        ))

    return alerts