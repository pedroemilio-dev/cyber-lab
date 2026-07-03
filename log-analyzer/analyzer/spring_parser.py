import json
import re
from datetime import datetime
from urllib.parse import unquote
from analyzer.models import LogEntry

REQUEST_PATTERN = re.compile(
    r'(?P<time>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+[+\-]\d{2}:\d{2})'
    r'.*\[(?P<thread>http-nio-\d+-exec-\d+)\]'
    r'.*DispatcherServlet\s+:\s+'
    r'(?P<method>GET|POST|PUT|PATCH|DELETE)\s+"(?P<path>[^"]+)"'
)

COMPLETED_PATTERN = re.compile(
    r'(?P<time>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+[+\-]\d{2}:\d{2})'
    r'.*\[(?P<thread>http-nio-\d+-exec-\d+)\]'
    r'.*DispatcherServlet\s+:\s+Completed\s+(?P<status>\d{3})'
)

FAILED_PATTERN = re.compile(
    r'(?P<time>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+[+\-]\d{2}:\d{2})'
    r'.*\[(?P<thread>http-nio-\d+-exec-\d+)\]'
    r'.*DispatcherServlet\s+:\s+Failed to complete request:\s+'
    r'[\w.]*\.(?P<exception>\w+Exception[^\n]*)'
)

SECURITY_PATTERN = re.compile(
    r'.*SECURITY.*'
    r'(?P<json>\{.*\})'
)

thread_ips = {}
thread_events = {}


def parse_file(path: str) -> list[LogEntry]:
    pending = {}
    entries = []

    with open(path, "r") as f:
        for line in f:
            sec_match = SECURITY_PATTERN.search(line)
            if sec_match:
                try:
                    event = json.loads(sec_match.group("json"))
                    event_name = event.get("event")
                    thread_match = re.search(r'\[(?P<thread>http-nio-\d+-exec-\d+)\]', line)

                    if event_name in ("INVALID_TOKEN", "BLACKLISTED_TOKEN"):
                        entries.append(LogEntry(
                            ip=event.get("ip", "unknown"),
                            time=datetime.fromisoformat(event["time"].replace("Z", "+00:00")),
                            method="SECURITY",
                            path=f"/{event_name}",
                            status=401,
                            bytes=0,
                            event_type=event_name
                        ))
                    elif thread_match:
                        thread = thread_match.group("thread")
                        thread_ips[thread] = event.get("ip", "unknown")
                        thread_events[thread] = event_name
                except json.JSONDecodeError:
                    pass
                continue

            match = REQUEST_PATTERN.search(line)
            if match:
                pending[match.group("thread")] = {
                    "time": datetime.fromisoformat(match.group("time")),
                    "method": match.group("method"),
                    "path": unquote(match.group("path")),
                }
                continue

            match = COMPLETED_PATTERN.search(line)
            if match:
                thread = match.group("thread")
                if thread in pending:
                    req = pending.pop(thread)
                    ip = thread_ips.pop(thread, "127.0.0.1")
                    event_type = thread_events.pop(thread, None)
                    entries.append(LogEntry(
                        ip=ip,
                        time=req["time"],
                        method=req["method"],
                        path=req["path"],
                        status=int(match.group("status")),
                        bytes=0,
                        event_type=event_type
                    ))
                continue

            match = FAILED_PATTERN.search(line)
            if match:
                thread = match.group("thread")
                if thread in pending:
                    req = pending.pop(thread)
                    ip = thread_ips.pop(thread, "127.0.0.1")
                    event_type = thread_events.pop(thread, None)
                    exception = match.group("exception")
                    status = 401 if "BadCredentials" in exception else 500
                    entries.append(LogEntry(
                        ip=ip,
                        time=req["time"],
                        method=req["method"],
                        path=req["path"],
                        status=status,
                        bytes=0,
                        event_type=event_type
                    ))

    return entries