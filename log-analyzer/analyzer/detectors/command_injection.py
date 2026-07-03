import re
from collections import defaultdict

from analyzer.models import LogEntry, Alert


COMMAND_INJECTION_PATTERN = re.compile(
    r"(;|\||&&|`|\$\()"
    r"(\s|\+)*(whoami|id|uname|cat|ls|pwd|wget|curl|bash|sh|python|perl|ruby|nc|netcat|chmod|chown|rm\s+-rf)",
    re.IGNORECASE
)


def detect(entries: list[LogEntry]) -> list[Alert]:
    alerts = []
    ip_paths = defaultdict(list)

    for entry in entries:
        if COMMAND_INJECTION_PATTERN.search(entry.path):
            ip_paths[entry.ip].append(entry.path)

    for ip, paths in ip_paths.items():
        alerts.append(Alert(
            ip=ip,
            attack_type="Command Injection",
            severity="critical",
            detail=f"{len(paths)} command injection attempts detected",
            count=len(paths),
            paths=paths
        ))

    return alerts