from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional


@dataclass
class LogEntry:
    ip: str
    time: datetime
    method: str
    path: str
    status: int
    bytes: int
    event_type: Optional[str] = None


@dataclass
class Alert:
    ip: str
    attack_type: str
    severity: str
    detail: str
    count: int
    paths: list[str] = field(default_factory=list)