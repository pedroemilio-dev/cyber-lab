import re
from collections import defaultdict

from analyzer.models import LogEntry, Alert


SQLI_PATTERN = re.compile(
    r"(union(\s|\+)+select"
    r"|drop(\s|\+)+table"
    r"|or(\s|\+)+1(\s|\+)*=(\s|\+)*1"
    r"|sleep\s*\("
    r"|insert(\s|\+)+into"
    r"|admin'--"
    r"|;(\s|\+)*drop"
    r"|and(\s|\+)+sleep)",
    re.IGNORECASE
)


def detect(entries: list[LogEntry]) -> list[Alert]:
    alerts = []
    ip_paths = defaultdict(list)

    for entry in entries:
        if SQLI_PATTERN.search(entry.path):
            ip_paths[entry.ip].append(entry.path)

    for ip, paths in ip_paths.items():
        alerts.append(Alert(
            ip=ip,
            attack_type="SQL Injection",
            severity="critical",
            detail=f"{len(paths)} SQLi attempts detected",
            count=len(paths),
            paths=paths
        ))

    return alerts