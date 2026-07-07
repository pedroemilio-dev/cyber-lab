import argparse
import sys
import time

from analyzer.parser import parse_file, parse_line
from analyzer.spring_parser import parse_file as spring_parse_file
from analyzer.detector import detect
from analyzer.reporter import generate

def main():
    sys.stdout.reconfigure(line_buffering=True)
    args = _parse_args()

    if args.live:
        _live_mode(args.log, args.format, args.from_start)
    else:
        _batch_mode(args.log, args.format)


def _batch_mode(log_path: str, fmt: str):
    print(f"\n[*] Reading log file: {log_path}")

    if fmt == "spring":
        entries = spring_parse_file(log_path)
    else:
        entries = parse_file(log_path)

    print(f"[*] Parsed {len(entries)} log entries")
    print(f"[*] Running detection rules...")
    alerts = detect(entries)

    if not alerts:
        print("[+] No attacks detected.")
        sys.exit(0)

    print(f"[!] {len(alerts)} attack(s) detected.")
    print(f"[*] Generating PDF report...")
    report_path = generate(alerts, log_path, len(entries))
    print(f"[+] Report saved to {report_path}")


def _live_mode(log_path: str, fmt: str, from_start: bool = False):
    from datetime import timedelta

    print(f"\n[*] Watching log file: {log_path}")
    if from_start:
        print(f"[*] Analyzing existing content, then following new entries... (Ctrl+C to stop)\n")
    else:
        print(f"[*] Waiting for new entries... (Ctrl+C to stop)\n")

    rolling_window = []
    alerts_by_key  = {}
    WINDOW         = timedelta(minutes=5)

    if fmt == "spring":
        processed = 0
        if not from_start:
            try:
                processed = len(spring_parse_file(log_path))
            except Exception:
                processed = 0
        while True:
            try:
                all_entries = spring_parse_file(log_path)
            except Exception:
                time.sleep(1)
                continue

            new_entries = all_entries[processed:]
            processed = len(all_entries)

            for entry in new_entries:
                _process_entry(entry, rolling_window, alerts_by_key, WINDOW)

            time.sleep(1)
    else:
        with open(log_path, "r") as f:
            if not from_start:
                f.seek(0, 2)
            while True:
                line = f.readline()
                if not line:
                    time.sleep(0.5)
                    continue
                entry = parse_line(line.strip())
                if not entry:
                    continue
                _process_entry(entry, rolling_window, alerts_by_key, WINDOW)


def _process_entry(entry, rolling_window, alerts_by_key, window):
    rolling_window.append(entry)
    cutoff = entry.time - window
    rolling_window[:] = [e for e in rolling_window if e.time >= cutoff]

    for alert in detect(rolling_window):
        key = (alert.attack_type, alert.ip)
        existing = alerts_by_key.get(key)

        if existing is None:
            alerts_by_key[key] = alert
            print(f"  [!] [{alert.severity.upper()}] {alert.attack_type}")
            print(f"      IP     : {alert.ip}")
            print(f"      Detail : {alert.detail}")
            print()
        elif alert.count > existing.count:
            alerts_by_key[key] = alert
            print(f"      ^ {alert.attack_type} from {alert.ip} escalated to {alert.count}")


def _parse_args():
    parser = argparse.ArgumentParser(
        description="Web server log analyzer — detects common attack patterns"
    )
    parser.add_argument(
        "--log",
        required=True,
        help="Path to the log file to analyze"
    )
    parser.add_argument(
        "--format",
        choices=["apache", "spring"],
        default="apache",
        help="Log format: apache (default) or spring"
    )
    parser.add_argument(
        "--live",
        action="store_true",
        help="Live mode — monitor the log file in real time"
    )
    parser.add_argument(
        "--from-start",
        action="store_true",
        help="Live mode: analyze existing file content first, then follow new entries "
             "(default: only new entries appended after startup)"
    )
    return parser.parse_args()


if __name__ == "__main__":
    main()