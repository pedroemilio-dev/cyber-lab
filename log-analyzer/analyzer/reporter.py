from datetime import datetime
from fpdf import FPDF
import os

from analyzer.models import Alert


SEVERITY_COLORS = {
    "critical": (180, 30,  30),
    "high":     (200, 90,  20),
    "medium":   (170, 130,  0),
    "low":      (50,  140, 70),
}

SEVERITY_BAR = {
    "critical": "||||||||||",
    "high":     "||||||||  ",
    "medium":   "|||||     ",
    "low":      "|||       ",
}

ATTACK_INFO = {
    "Brute Force": {
        "mitre": "T1110 - Brute Force",
        "recommendation": "Implement rate limiting and account lockout policy.",
    },
    "SQL Injection": {
        "mitre": "T1190 - Exploit Public-Facing Application",
        "recommendation": "Use parameterized queries and validate all user input.",
    },
    "Path Traversal": {
        "mitre": "T1083 - File and Directory Discovery",
        "recommendation": "Sanitize file paths and restrict directory access.",
    },
    "Vulnerability Scan": {
        "mitre": "T1595 - Active Scanning",
        "recommendation": "Block IP at firewall level and review exposed endpoints.",
    },
    "Cross-Site Scripting": {
        "mitre": "T1059.007 - JavaScript",
        "recommendation": "Implement Content Security Policy (CSP) and sanitize all user input.",
    },
    "Command Injection": {
        "mitre": "T1059 - Command and Scripting Interpreter",
        "recommendation": "Never pass user input directly to system commands. Use allowlists.",
    },
    "HTTP Method Tampering": {
        "mitre": "T1190 - Exploit Public-Facing Application",
        "recommendation": "Restrict allowed HTTP methods at the web server level.",
    },
    "User Enumeration": {
        "mitre": "T1589.001 - Gather Victim Identity Information: Credentials",
        "recommendation": "Implement consistent error messages for login failures to prevent email discovery. Consider adding CAPTCHA and rate limiting per IP.",
    },
    "Token Abuse": {
        "mitre": "T1528 - Steal Application Access Token",
        "recommendation": "Implement token rotation, short expiration times, and alert on repeated invalid token usage. Consider IP-based token binding.",
    },
    "Account Takeover Attempt": {
        "mitre": "T1110.001 - Password Guessing",
        "recommendation": "Implement account lockout after repeated failed password changes. Alert on suspicious password modification patterns.",
    },
    "Resource Enumeration": {
        "mitre": "T1213 - Data from Information Repositories",
        "recommendation": "Use non-sequential, unpredictable resource identifiers (UUIDs). Implement rate limiting on resource access endpoints.",
    },
    "Registration Abuse": {
        "mitre": "T1585 - Establish Accounts",
        "recommendation": "Implement CAPTCHA on registration, email verification, and rate limiting per IP.",
    },
}


class _PDF(FPDF):
    def header(self):
        self.set_fill_color(40, 40, 40)
        self.rect(0, 0, 210, 2, "F")
        self.set_xy(10, 6)
        self.set_font("Helvetica", "B", 14)
        self.set_text_color(30, 30, 30)
        self.cell(120, 10, "Attack Detection Report", ln=False)
        self.set_font("Helvetica", "", 8)
        self.set_text_color(120, 120, 120)
        self.set_x(130)
        self.cell(70, 5, f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", align="R", ln=True)
        self.set_x(130)
        self.cell(70, 5, "Log Analyzer v1.0", align="R", ln=True)
        self.ln(2)
        self.set_draw_color(200, 200, 200)
        self.set_line_width(0.3)
        self.line(10, self.get_y(), 200, self.get_y())
        self.ln(4)

    def footer(self):
        self.set_y(-12)
        self.set_draw_color(200, 200, 200)
        self.set_line_width(0.3)
        self.line(10, self.get_y(), 200, self.get_y())
        self.ln(2)
        self.set_font("Helvetica", "", 8)
        self.set_text_color(150, 150, 150)
        self.cell(0, 6, f"Page {self.page_no()}", align="C")


def generate(alerts: list[Alert], log_path: str, total_entries: int) -> str:
    pdf = _PDF()
    pdf.set_auto_page_break(auto=True, margin=18)
    pdf.add_page()

    _summary(pdf, log_path, total_entries, alerts)
    _alerts_table(pdf, alerts)
    _recommendations(pdf, alerts)

    log_name = os.path.splitext(os.path.basename(log_path))[0]
    path = f"reports/{log_name}_report.pdf"
    pdf.output(path)
    return path


def _summary(pdf: FPDF, log_path: str, total_entries: int, alerts: list[Alert]):
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for alert in alerts:
        severity_counts[alert.severity.lower()] += 1

    pdf.set_font("Helvetica", "B", 11)
    pdf.set_text_color(30, 30, 30)
    pdf.cell(0, 7, "Executive Summary", ln=True)
    pdf.ln(2)

    left_x = 10
    right_x = 110
    y = pdf.get_y()

    info = [
        ("Log File",         log_path),
        ("Entries Parsed",   str(total_entries)),
        ("Attacks Detected", str(len(alerts))),
        ("Generated At",     datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
    ]

    pdf.set_font("Helvetica", "", 9)
    for label, value in info:
        pdf.set_xy(left_x, pdf.get_y())
        pdf.set_text_color(100, 100, 100)
        pdf.cell(40, 6, label + ":", border=0)
        pdf.set_text_color(30, 30, 30)
        pdf.set_font("Helvetica", "B", 9)
        pdf.cell(0, 6, value, ln=True, border=0)
        pdf.set_font("Helvetica", "", 9)

    pdf.set_xy(right_x, y)
    pdf.set_font("Helvetica", "B", 9)
    pdf.set_text_color(30, 30, 30)
    pdf.cell(0, 6, "Severity Breakdown", ln=True)

    for severity, color in SEVERITY_COLORS.items():
        count = severity_counts[severity]
        bar = SEVERITY_BAR[severity]
        pdf.set_xy(right_x, pdf.get_y())
        pdf.set_font("Helvetica", "", 8)
        pdf.set_text_color(80, 80, 80)
        pdf.cell(22, 6, severity.upper(), border=0)
        pdf.set_text_color(*color)
        pdf.cell(30, 6, bar, border=0)
        pdf.set_text_color(30, 30, 30)
        pdf.set_font("Helvetica", "B", 8)
        pdf.cell(10, 6, str(count), border=0, ln=True)

    pdf.ln(6)
    pdf.set_draw_color(220, 220, 220)
    pdf.line(10, pdf.get_y(), 200, pdf.get_y())
    pdf.ln(6)


def _alerts_table(pdf: FPDF, alerts: list[Alert]):
    grouped = {}
    for alert in alerts:
        if alert.attack_type not in grouped:
            grouped[alert.attack_type] = []
        grouped[alert.attack_type].append(alert)

    for attack_type, attack_alerts in grouped.items():
        color = SEVERITY_COLORS.get(attack_alerts[0].severity.lower(), (100, 100, 100))

        pdf.set_font("Helvetica", "B", 10)
        pdf.set_text_color(*color)
        pdf.cell(0, 7, attack_type, ln=True)
        pdf.set_text_color(40, 40, 40)
        pdf.ln(1)

        pdf.set_font("Helvetica", "B", 8)
        pdf.set_fill_color(50, 50, 50)
        pdf.set_text_color(255, 255, 255)
        pdf.set_draw_color(50, 50, 50)
        pdf.cell(40, 6, "IP Address", fill=True, border=1)
        pdf.cell(22, 6, "Severity",   fill=True, border=1)
        pdf.cell(15, 6, "Count",      fill=True, border=1)
        pdf.cell(0,  6, "Detail",     fill=True, border=1, ln=True)

        for i, alert in enumerate(attack_alerts):
            fill = (248, 248, 248) if i % 2 == 0 else (255, 255, 255)
            pdf.set_fill_color(*fill)
            pdf.set_draw_color(200, 200, 200)
            pdf.set_font("Helvetica", "", 8)
            pdf.set_text_color(*color)
            pdf.cell(40, 6, alert.ip,               fill=True, border=1)
            pdf.set_text_color(40, 40, 40)
            pdf.cell(22, 6, alert.severity.upper(),  fill=True, border=1)
            pdf.cell(15, 6, str(alert.count),        fill=True, border=1)
            pdf.cell(0,  6, alert.detail,            fill=True, border=1, ln=True)

            if alert.paths:
                pdf.set_font("Helvetica", "B", 7)
                pdf.set_fill_color(*fill)
                pdf.set_text_color(80, 80, 80)
                pdf.cell(0, 5, "  Paths detected:", fill=True, border=0, ln=True)
                pdf.set_font("Helvetica", "", 7)
                for path in alert.paths:
                    pdf.set_text_color(100, 100, 100)
                    pdf.cell(10, 5, "", fill=True, border=0)
                    pdf.cell(0,  5, path[:95], fill=True, border=0, ln=True)

        pdf.ln(6)
        pdf.set_draw_color(220, 220, 220)
        pdf.line(10, pdf.get_y(), 200, pdf.get_y())
        pdf.ln(4)


def _recommendations(pdf: FPDF, alerts: list[Alert]):
    detected_types = {alert.attack_type for alert in alerts}

    pdf.set_font("Helvetica", "B", 11)
    pdf.set_text_color(30, 30, 30)
    pdf.cell(0, 7, "Recommendations", ln=True)
    pdf.ln(2)

    for attack_type, info in ATTACK_INFO.items():
        if attack_type not in detected_types:
            continue

        pdf.set_font("Helvetica", "B", 9)
        pdf.set_text_color(30, 30, 30)
        pdf.cell(0, 6, attack_type, ln=True)

        pdf.set_font("Helvetica", "", 8)
        pdf.set_text_color(100, 100, 100)
        pdf.cell(25, 6, "MITRE:", border=0)
        pdf.set_text_color(50, 50, 150)
        pdf.cell(0, 6, info["mitre"], ln=True, border=0)

        pdf.set_text_color(100, 100, 100)
        pdf.cell(25, 6, "Action:", border=0)
        pdf.set_text_color(40, 40, 40)
        pdf.cell(0, 6, info["recommendation"], ln=True, border=0)

        pdf.ln(3)