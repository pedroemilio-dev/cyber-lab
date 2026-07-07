from analyzer.models import LogEntry, Alert

from analyzer.detectors import (
    brute_force,
    sql_injection,
    path_traversal,
    vulnerability_scan,
    xss,
    command_injection,
    http_method_tampering,
    credential_attack,
    resource_enum,
    register_flood,
    account_takeover,
)


def detect(entries: list[LogEntry]) -> list[Alert]:
    alerts = []
    alerts.extend(brute_force.detect(entries))
    alerts.extend(sql_injection.detect(entries))
    alerts.extend(path_traversal.detect(entries))
    alerts.extend(vulnerability_scan.detect(entries))
    alerts.extend(xss.detect(entries))
    alerts.extend(command_injection.detect(entries))
    alerts.extend(http_method_tampering.detect(entries))
    alerts.extend(credential_attack.detect(entries))
    alerts.extend(resource_enum.detect(entries))
    alerts.extend(register_flood.detect(entries))
    alerts.extend(account_takeover.detect(entries))
    return alerts