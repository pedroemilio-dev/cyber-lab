import argparse
import sys
import time

from analyzer.parser import parse_file, parse_line
from analyzer.spring_parser import parse_file as spring_parse_file
from analyzer.detector import detect
from analyzer.reporter import generate

def main():
    args = _parse_args()

    if args.live:
        _live_mode(args.log, args.format)
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


def _live_mode(log_path: str, fmt: str):
    from collections import defaultdict
    from datetime import timedelta
    from analyzer.spring_parser import parse_file as spring_parse_file

    print(f"\n[*] Watching log file: {log_path}")
    print(f"[*] Waiting for new entries... (Ctrl+C to stop)\n")

    auth_failures = defaultdict(list)
    not_found     = defaultdict(list)
    alerted_ips   = set()

    BRUTE_FORCE_THRESHOLD = 10
    SCAN_THRESHOLD        = 20
    WINDOW                = timedelta(seconds=60)

    if fmt == "spring":
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
                _process_entry(entry, auth_failures, not_found, alerted_ips,
                            BRUTE_FORCE_THRESHOLD, SCAN_THRESHOLD, WINDOW)

            time.sleep(1)
    else:
        with open(log_path, "r") as f:
            f.seek(0, 2)
            while True:
                line = f.readline()
                if not line:
                    time.sleep(0.5)
                    continue
                entry = parse_line(line.strip())
                if not entry:
                    continue
                _process_entry(entry, auth_failures, not_found, alerted_ips,
                               BRUTE_FORCE_THRESHOLD, SCAN_THRESHOLD, WINDOW)


def _process_entry(entry, auth_failures, not_found, alerted_ips,
                   brute_threshold, scan_threshold, window):
    alerts = detect([entry])
    for alert in alerts:
        if alert.attack_type not in ("Brute Force", "Vulnerability Scan"):
            print(f"  [!] [{alert.severity.upper()}] {alert.attack_type}")
            print(f"      IP     : {alert.ip}")
            print(f"      Detail : {alert.detail}")
            print()

    if entry.status in (401, 403):
        auth_failures[entry.ip].append(entry.time)
        auth_failures[entry.ip] = [
            t for t in auth_failures[entry.ip]
            if entry.time - t <= window
        ]
        key = f"brute_{entry.ip}"
        if len(auth_failures[entry.ip]) >= brute_threshold:
            alerted_ips.add(key)
            print(f"  [!] [HIGH] Brute Force")
            print(f"      IP     : {entry.ip}")
            print(f"      Detail : {len(auth_failures[entry.ip])} failed auth attempts in 60s")
            print()
            auth_failures[entry.ip] = []  

    if entry.status == 404:
        not_found[entry.ip].append(entry.time)
        not_found[entry.ip] = [
            t for t in not_found[entry.ip]
            if entry.time - t <= window
        ]
        key = f"scan_{entry.ip}"
        if len(not_found[entry.ip]) >= scan_threshold and key not in alerted_ips:
            alerted_ips.add(key)
            print(f"  [!] [MEDIUM] Vulnerability Scan")
            print(f"      IP     : {entry.ip}")
            print(f"      Detail : {len(not_found[entry.ip])} 404s in 60s")
            print()


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
    return parser.parse_args()


if __name__ == "__main__":
    main()