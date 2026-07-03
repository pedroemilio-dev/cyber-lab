import re
from collections import defaultdict

from analyzer.models import LogEntry, Alert


XSS_PATTERN = re.compile(
    r"(<script|</script|javascript:|onerror=|onload=|onclick=|document\.cookie|alert\s*\(|img\s+src=)",
    re.IGNORECASE
)


def detect(entries: list[LogEntry]) -> list[Alert]:
    alerts = []
    ip_paths = defaultdict(list)

    for entry in entries:
        if XSS_PATTERN.search(entry.path):
            ip_paths[entry.ip].append(entry.path)

    for ip, paths in ip_paths.items():
        alerts.append(Alert(
            ip=ip,
            attack_type="Cross-Site Scripting",
            severity="high",
            detail=f"{len(paths)} XSS attempts detected",
            count=len(paths),
            paths=paths
        ))

    return alerts