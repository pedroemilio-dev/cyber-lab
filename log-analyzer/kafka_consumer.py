import json
import time
from collections import Counter
from datetime import date, datetime, timedelta
from pathlib import Path
from kafka import KafkaConsumer

from analyzer.detector import detect
from analyzer.reporter import generate
from analyzer.models import LogEntry

REPORT_INTERVAL_SECONDS = 60


def event_to_entry(event: dict) -> LogEntry:
    return LogEntry(
        ip=event.get("ip", "unknown"),
        time=datetime.fromisoformat(event["time"].replace("Z", "+00:00")),
        method="SECURITY",
        path=event.get("resource", "") or f"/{event.get('event', '')}",
        status=0,
        bytes=0,
        event_type=event.get("event")
    )


def _generate_report(entries: list[LogEntry], day: date, alerts_by_key: dict):
    day_dir = Path("reports") / day.isoformat()
    day_dir.mkdir(parents=True, exist_ok=True)

    all_alerts = list(alerts_by_key.values())

    if not entries and not all_alerts:
        print(f"[*] No new events in the last {REPORT_INTERVAL_SECONDS}s — skipping report.")
        return

    counts = Counter(e.event_type for e in entries)
    print(f"\n[*] Buffer summary before report ({len(entries)} events this cycle, "
          f"{len(all_alerts)} unique attack(s) accumulated today):")
    for event_type, count in counts.items():
        print(f"      {event_type}: {count}")

    timestamp = datetime.now().strftime("%H-%M-%S")

    if not all_alerts:
        print(f"[+] {len(entries)} events analyzed, no attacks detected ({timestamp}).")
        return

    log_path = f"kafka-stream-{timestamp}"
    report_path = generate(all_alerts, log_path, len(entries))

    final_path = day_dir / f"{timestamp}.pdf"
    Path(report_path).rename(final_path)

    print(f"[!] {len(all_alerts)} unique attack(s) detected so far today — report saved to {final_path}")

def run_kafka_consumer(bootstrap_servers="localhost:9092", topic="spring-logs"):
    consumer = KafkaConsumer(
        topic,
        bootstrap_servers=bootstrap_servers,
        auto_offset_reset="latest",
        value_deserializer=lambda v: v.decode("utf-8"),
        consumer_timeout_ms=1000
    )

    print(f"\n[*] Connected to Kafka topic '{topic}'")
    print(f"[*] Detecting continuously, reporting every {REPORT_INTERVAL_SECONDS}s into reports/<date>/ (Ctrl+C to stop)\n")

    rolling_window = []
    cycle_buffer = []
    alerts_by_key = {}
    last_report_alert_state = {}
    last_report_time = time.time()
    current_day = date.today()

    try:
        while True:
            for message in consumer:
                try:
                    event = json.loads(message.value)
                except json.JSONDecodeError:
                    print(f"  [x] Failed to parse message: {message.value}")
                    continue

                print(f"  [<] Received: {event.get('event')} from {event.get('ip')} resource={event.get('resource')}")

                entry = event_to_entry(event)
                rolling_window.append(entry)
                cycle_buffer.append(entry)

                cutoff = entry.time - timedelta(minutes=5)
                rolling_window = [e for e in rolling_window if e.time >= cutoff]

                new_alerts = detect(rolling_window)
                for alert in new_alerts:
                    key = (alert.attack_type, alert.ip)
                    existing = alerts_by_key.get(key)

                    if existing is None or alert.count > existing.count:
                        is_new = existing is None
                        alerts_by_key[key] = alert

                        if is_new:
                            print(f"  [!] [{alert.severity.upper()}] {alert.attack_type}")
                            print(f"      IP     : {alert.ip}")
                            print(f"      Detail : {alert.detail}")
                            print()
                        else:
                            print(f"      ↳ {alert.attack_type} from {alert.ip} escalated to {alert.count}")

                if time.time() - last_report_time >= REPORT_INTERVAL_SECONDS:
                    break

            today = date.today()
            if today != current_day:
                if alerts_by_key:
                    _generate_report(cycle_buffer, current_day, alerts_by_key)
                current_day = today
                alerts_by_key = {}
                last_report_alert_state = {}
                cycle_buffer = []
                last_report_time = time.time()
                continue

            if time.time() - last_report_time >= REPORT_INTERVAL_SECONDS:
                current_state = {k: v.count for k, v in alerts_by_key.items()}
                if current_state != last_report_alert_state:
                    _generate_report(cycle_buffer, current_day, alerts_by_key)
                    last_report_alert_state = current_state
                else:
                    print(f"[*] No change in alerts since last report — skipping.")
                cycle_buffer = []
                last_report_time = time.time()

    except KeyboardInterrupt:
        print("\n[*] Shutting down — generating final report with all alerts detected today...")
        current_state = {k: v.count for k, v in alerts_by_key.items()}
        if alerts_by_key and current_state != last_report_alert_state:
            _generate_report(cycle_buffer, current_day, alerts_by_key)
        else:
            print("[*] No new alerts since last report — no final report generated.")
        consumer.close()


if __name__ == "__main__":
    run_kafka_consumer()