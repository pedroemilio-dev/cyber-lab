# Log Analyzer — Web Server Attack Detection

A Python-based security tool that parses Apache/Nginx web server access logs,
detects common attack patterns in real time or in batch mode, and generates
a structured PDF report with findings, recommendations and MITRE ATT&CK references.

---

## Features

- Parses Apache/Nginx Combined Log Format
- Detects 7 attack categories with MITRE ATT&CK references
- Two operating modes: batch analysis and real-time live monitoring
- In-memory buffer for time-based attack detection in live mode
- Configurable log generator for testing with multiple IPs per attack type
- PDF report with executive summary, attack breakdown and recommendations

---

## How It Works

The tool supports two operating modes:

**Batch Mode** — analyzes an entire log file and generates a PDF report:

```
access.log
    │
    ▼
parser.py       → Parses log into structured LogEntry objects
    │
    ▼
detector.py     → Applies 7 attack detection rules
    │
    ▼
reporter.py     → Generates PDF report
```

**Live Mode** — monitors a log file in real time:

```
access.log (new lines only)
    │
    ▼
parser.py       → Parses each new line as it arrives
    │
    ▼
detector.py     → Applies detection rules
                  (in-memory buffer for time-based attacks)
    │
    ▼
Terminal        → Prints alert for each detected attack
```

---

## Setup

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

---

## Usage

**Generate sample log files for testing:**

```bash
# All attack types
python3 sample_logs_generator.py

# Specific attack types
python3 sample_logs_generator.py --attacks brute_force sqli
python3 sample_logs_generator.py --attacks traversal scan xss
```

Available attack types: `brute_force` `sqli` `traversal` `scan` `xss` `cmd_injection` `http_tampering`

**Batch mode — analyze a log file and generate a PDF report:**

```bash
python3 main.py --log logs/all_attacks.log
```

**Live mode — monitor a log file in real time:**

```bash
python3 main.py --log logs/all_attacks.log --live

# Or monitor a real server log
python3 main.py --log /var/log/nginx/access.log --live
```

---

## Detection Engine

The detection engine analyses log entries and applies a set of rules to identify known attack patterns. Pattern-based attacks (SQLi, XSS, etc.) are detected on a single line. Time-based attacks (Brute Force, Vulnerability Scan) use a sliding window algorithm to count events per IP over 60 seconds.

### Brute Force
Brute force is an attack where an automated tool repeatedly tries different credentials until it finds a valid one. It is one of the most common attacks against web applications.

**Rule:** 10+ requests returning status 401 or 403 from the same IP within 60 seconds.

### SQL Injection
SQL Injection (SQLi) is an attack where malicious SQL code is inserted into a query through user input, allowing attackers to read, modify or destroy database data. Consistently ranked in the OWASP Top 10.

**Rule:** Request path matches known SQLi patterns — UNION-based, boolean-based, time-based and stacked queries.

### Path Traversal
Path Traversal is an attack where the attacker manipulates file paths to access files outside the web root, such as `/etc/passwd` or configuration files. Listed in the OWASP Top 10.

**Rule:** Request path contains `../` sequences or direct references to sensitive system files.

### Vulnerability Scan
Vulnerability scanning is an automated attack where a tool probes the server for known vulnerabilities, exposed files and misconfigurations.

**Rule:** 20+ requests returning 404 from the same IP within 60 seconds.

### Cross-Site Scripting (XSS)
XSS is an attack where malicious JavaScript is injected into a web page. When another user visits the page, the script executes in their browser, allowing session hijacking and credential theft. Listed in the OWASP Top 10.

**Rule:** Request path contains known JavaScript injection patterns such as `<script>`, `onerror=` or `document.cookie`.

### Command Injection
Command Injection is an attack where the attacker injects OS commands through application parameters. If the server passes these parameters directly to the system, the commands execute with the web server's permissions. Listed in the OWASP Top 10.

**Rule:** Request path contains command operators (`;`, `|`, `&&`) followed by known system commands (`whoami`, `cat`, `wget`, etc.).

### HTTP Method Tampering
HTTP Method Tampering is an attack where the attacker uses unexpected HTTP methods to probe or exploit endpoints. Methods such as `TRACE`, `DELETE` or `PUT` outside of legitimate REST APIs rarely appear in normal traffic.

**Rule:** Requests using `TRACE`, `CONNECT` or `TRACK` (always suspicious), or `DELETE`, `PUT`, `PATCH` outside of `/api/` endpoints.

---

## Limitations

- **False positives** — legitimate users may trigger brute force or scan rules under certain conditions
- **No persistent storage** — the live mode buffer is lost if the program restarts
- **Pattern-based only** — does not detect zero-day attacks or obfuscated payloads
- **POST-based attacks** — XSS and Command Injection via POST are not logged by Apache/Nginx by default
