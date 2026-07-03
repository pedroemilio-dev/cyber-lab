from collections import defaultdict

from analyzer.models import LogEntry, Alert


SUSPICIOUS_METHODS = {"TRACE", "CONNECT", "TRACK"}

REST_METHODS = {"DELETE", "PUT", "PATCH"}


def detect(entries: list[LogEntry]) -> list[Alert]:
    alerts = []
    ip_paths = defaultdict(list)

    for entry in entries:
        method = entry.method.upper()

        if method in SUSPICIOUS_METHODS:
            ip_paths[entry.ip].append(f"{method} {entry.path}")
            continue

        if method in REST_METHODS and not entry.path.startswith("/api/"):
            ip_paths[entry.ip].append(f"{method} {entry.path}")

    for ip, paths in ip_paths.items():
        alerts.append(Alert(
            ip=ip,
            attack_type="HTTP Method Tampering",
            severity="medium",
            detail=f"{len(paths)} suspicious HTTP method requests detected",
            count=len(paths),
            paths=paths
        ))

    return alerts