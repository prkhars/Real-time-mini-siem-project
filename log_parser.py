import sqlite3
import re
import time
import smtplib
import json
import threading
import requests
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime, timedelta
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from collections import defaultdict

# ─────────────────────────────────────────────
#  ALERT CONFIG — edit these before running
# ─────────────────────────────────────────────

ALERT_CONFIG = {
    # ── Thresholds ──────────────────────────
    "failed_login_threshold": 5,
    "failed_login_window_secs": 60,

    "invalid_user_threshold": 3,
    "invalid_user_window_secs": 60,

    # ── Email alerts ────────────────────────
    "email_enabled": True,
    "smtp_host": "smtp.gmail.com",
    "smtp_port": 587,
    "smtp_user": "SENDERMAIL@gmail.com",
    "smtp_password": "YOUR PASSWORD",
    "alert_recipient": "RECEIVERMAIL@gmail.com",

    # ── Slack alerts ────────────────────────
    "slack_enabled": True,
    "slack_webhook_url": "SLACKWEBHOOKURL",

    # ── Cooldown ────────────────────────────
    "alert_cooldown_secs": 300,}


DB = "siem.db"
LOG_FILE = "test.log"

# ─────────────────────────────────────────────
#  Database setup
# ─────────────────────────────────────────────

def init_db():
    conn = sqlite3.connect(DB)
    conn.execute('''CREATE TABLE IF NOT EXISTS logs (
        id        INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT,
        host      TEXT,
        program   TEXT,
        message   TEXT,
        tag       TEXT,
        src_ip    TEXT
    )''')
    conn.execute('''CREATE TABLE IF NOT EXISTS alerts (
        id         INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp  TEXT,
        alert_type TEXT,
        detail     TEXT,
        sent_via   TEXT
    )''')
    conn.commit()
    conn.close()
    print("[DB] Initialised siem.db")

def insert_log(entry):
    conn = sqlite3.connect(DB)
    conn.execute(
        "INSERT INTO logs (timestamp, host, program, message, tag, src_ip) VALUES (?,?,?,?,?,?)",
        (entry["timestamp"], entry["host"], entry["program"],
         entry["message"], entry["tag"], entry.get("src_ip", ""))
    )
    conn.commit()
    conn.close()

def insert_alert(alert_type, detail, sent_via):
    conn = sqlite3.connect(DB)
    conn.execute(
        "INSERT INTO alerts (timestamp, alert_type, detail, sent_via) VALUES (?,?,?,?)",
        (str(datetime.now()), alert_type, detail, sent_via)
    )
    conn.commit()
    conn.close()

# ─────────────────────────────────────────────
#  Log parsing
# ─────────────────────────────────────────────

# Regex patterns for extracting IPs from auth messages
IP_PATTERN = re.compile(r'(\d{1,3}(?:\.\d{1,3}){3})')
SYSLOG_PATTERN = re.compile(
    r'(\w+\s+\d+\s+[\d:]+)\s+(\S+)\s+([^\[:\s]+)(?:\[\d+\])?\s*:\s+(.*)'
)

TAG_RULES = [
    ("Failed password",         "failed_login"),
    ("Accepted password",       "successful_login"),
    ("Accepted publickey",      "successful_login"),
    ("Invalid user",            "invalid_user"),
    ("Connection closed",       "connection_closed"),
    ("Disconnected from",       "disconnected"),
    ("session opened",          "session_opened"),
    ("session closed",          "session_closed"),
    ("sudo:",                   "sudo"),
    ("CRON",                    "cron"),
]

def parse_line(line):
    match = SYSLOG_PATTERN.match(line.strip())
    if not match:
        return None

    timestamp_raw, host, program, message = match.groups()

    tag = "normal"
    for keyword, t in TAG_RULES:
        if keyword in message:
            tag = t
            break

    ip_match = IP_PATTERN.search(message)
    src_ip = ip_match.group(1) if ip_match else ""

    return {
        "timestamp": str(datetime.now()),
        "host": host,
        "program": program,
        "message": message,
        "tag": tag,
        "src_ip": src_ip,
    }

# ─────────────────────────────────────────────
#  Alerting engine
# ─────────────────────────────────────────────

# Track recent event timestamps per tag for threshold checks
event_windows = defaultdict(list)
last_alert_time = {}   # tag -> datetime of last alert sent


def send_email(subject, body):
    if not ALERT_CONFIG["email_enabled"]:
        return False
    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = ALERT_CONFIG["smtp_user"]
        msg["To"] = ALERT_CONFIG["alert_recipient"]
        msg.attach(MIMEText(body, "plain"))

        with smtplib.SMTP(ALERT_CONFIG["smtp_host"], ALERT_CONFIG["smtp_port"]) as s:
            s.starttls()
            s.login(ALERT_CONFIG["smtp_user"], ALERT_CONFIG["smtp_password"])
            s.sendmail(ALERT_CONFIG["smtp_user"], ALERT_CONFIG["alert_recipient"], msg.as_string())
        print(f"[EMAIL] Alert sent: {subject}")
        return True
    except Exception as e:
        print(f"[EMAIL ERROR] {e}")
        return False


def send_slack(message):
    if not ALERT_CONFIG["slack_enabled"]:
        return False
    try:
        payload = {
		"text": f"🚨 *SIEM ALERT*\n```{message}```",
		"username": "SIEM Bot",
		"icon_emoji": ":warning:",
        }
        resp = requests.post(
            ALERT_CONFIG["slack_webhook_url"],
            data=json.dumps(payload),
            headers={"Content-Type": "application/json"},
            timeout=5,
        )
        if resp.status_code == 200:
            print("[SLACK] Alert sent")
            return True
        else:
            print(f"[SLACK ERROR] status {resp.status_code}")
            return False
    except Exception as e:
        print(f"[SLACK ERROR] {e}")
        return False


def fire_alert(alert_type, detail):
    """Send alert via configured channels and log it to DB."""
    now = datetime.now()

    # Cooldown check
    if alert_type in last_alert_time:
        elapsed = (now - last_alert_time[alert_type]).total_seconds()
        if elapsed < ALERT_CONFIG["alert_cooldown_secs"]:
            print(f"[ALERT] Suppressed '{alert_type}' (cooldown {int(elapsed)}s / {ALERT_CONFIG['alert_cooldown_secs']}s)")
            return

    last_alert_time[alert_type] = now

    subject = f"🚨 SIEM Alert: {alert_type.replace('_', ' ').title()}"
    body = f"{subject}\n\nTime: {now}\nDetail: {detail}\n\nCheck your dashboard at http://localhost:8050"

    print(f"\n{'='*50}")
    print(f"  ⚠  ALERT FIRED: {alert_type}")
    print(f"  {detail}")
    print(f"{'='*50}\n")

    channels = []
    if send_email(subject, body):
        channels.append("email")
    if send_slack(body):
        channels.append("slack")
    if not channels:
        channels.append("console")

    insert_alert(alert_type, detail, ", ".join(channels))


def check_thresholds(entry):
    """Sliding-window threshold checker run after every event insert."""
    tag = entry["tag"]
    now = datetime.now()

    # Threshold rules: (tag, threshold, window_secs, alert_type, detail_template)
    rules = [
        (
            "failed_login",
            ALERT_CONFIG["failed_login_threshold"],
            ALERT_CONFIG["failed_login_window_secs"],
            "brute_force_detected",
            lambda count, ip: f"{count} failed logins in {ALERT_CONFIG['failed_login_window_secs']}s"
                              + (f" from {ip}" if ip else ""),
        ),
        (
            "invalid_user",
            ALERT_CONFIG["invalid_user_threshold"],
            ALERT_CONFIG["invalid_user_window_secs"],
            "invalid_user_probe",
            lambda count, ip: f"{count} invalid user attempts in {ALERT_CONFIG['invalid_user_window_secs']}s"
                              + (f" from {ip}" if ip else ""),
        ),
    ]

    for rule_tag, threshold, window, alert_type, detail_fn in rules:
        if tag != rule_tag:
            continue

        event_windows[rule_tag].append(now)

        # Drop events outside the window
        cutoff = now - timedelta(seconds=window)
        event_windows[rule_tag] = [t for t in event_windows[rule_tag] if t > cutoff]

        count = len(event_windows[rule_tag])
        if count >= threshold:
            fire_alert(alert_type, detail_fn(count, entry.get("src_ip", "")))

# ─────────────────────────────────────────────
#  Live log polling watcher
# ─────────────────────────────────────────────

def watch_log():

    print(f"[SIEM] Watching {LOG_FILE} — Ctrl+C to stop")

    with open(LOG_FILE, "r") as file:

        # Start at end of file
        file.seek(0, 2)

        while True:

            line = file.readline()

            if not line:
                time.sleep(1)
                continue

            entry = parse_line(line)

            if not entry:
                continue

            insert_log(entry)

            tag_display = entry["tag"].upper().ljust(18)

            ip_display = (
                f" ip={entry['src_ip']}"
                if entry["src_ip"]
                else ""
            )

            print(
                f"[{tag_display}] "
                f"{entry['message'][:72]}"
                f"{ip_display}"
            )

            # Threshold detection
            threading.Thread(
                target=check_thresholds,
                args=(entry,),
                daemon=True
            ).start()
# ───────────────────────────────────────────
#  Entry point
# ─────────────────────────────────────────────
if __name__ == "__main__":

    init_db()

    print(f"[SIEM] Alert thresholds:")

    print(
        f"       Failed logins : "
        f"{ALERT_CONFIG['failed_login_threshold']} "
        f"in {ALERT_CONFIG['failed_login_window_secs']}s"
    )

    print(
        f"       Invalid users : "
        f"{ALERT_CONFIG['invalid_user_threshold']} "
        f"in {ALERT_CONFIG['invalid_user_window_secs']}s"
    )

    print(
        f"       Email alerts  : "
        f"{'ON' if ALERT_CONFIG['email_enabled'] else 'OFF'}"
    )

    print(
        f"       Slack alerts  : "
        f"{'ON' if ALERT_CONFIG['slack_enabled'] else 'OFF'}\n"
    )

    try:

        watch_log()

    except KeyboardInterrupt:

        print("\n[SIEM] Shutting down...")
    # ── Start file watcher ───────────────

    handler = LogHandler(LOG_FILE)

    observer = Observer()

    observer.schedule(
        handler,
        path=".",
        recursive=False
    )

    observer.start()

    # ── Keep running ─────────────────────

    try:

        while True:
            time.sleep(1)

    except KeyboardInterrupt:

        print("\n[SIEM] Shutting down...")

        observer.stop()

    observer.join()
