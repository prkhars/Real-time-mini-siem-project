# Real-Time MINI-SIEM Dashboard using Python

A lightweight Security Information and Event Management (SIEM) platform built using Python, SQLite, Dash, and Plotly for real-time log monitoring, attack detection, alerting, and visualization.

---

## Features

* Real-time log monitoring
* Brute-force attack detection
* Invalid user detection
* Sliding-window threshold correlation
* SQLite-based log storage
* Interactive SOC-style dashboard
* Slack alert integration
* Email alert integration
* Top attacker IP tracking
* Live event timeline visualization
* Auto-refreshing dashboard
* Dark-themed SOC interface

---

## Technologies Used

* Python
* SQLite
* Dash
* Plotly
* Pandas
* Watchdog
* Slack Webhooks
* SMTP (Gmail)

---

## Dashboard Preview

Add screenshots inside the `screenshots/` folder.

Example screenshots:

* Dashboard UI
* Alert Feed
* Slack Alerts
* Email Alerts
* Terminal Monitoring

---

## Installation

Clone repository:

```bash
git clone https://github.com/YOUR_USERNAME/python-mini-siem.git
cd python-mini-siem
```

Install dependencies:

```bash
pip install -r requirements.txt
```

---

## Running the Project

### Terminal 1 — Start Log Parser

```bash
python3 log_parser.py
```

### Terminal 2 — Start Dashboard

```bash
python3 dashboard.py
```

Open browser:

```text
http://localhost:8050
```

---

## Simulating Attacks

### Brute Force Simulation

```bash
for i in {1..10}; do echo "May 28 10:20:00 kali sshd: Failed password for invalid user attacker$i from 192.168.1.50" >> test.log; sleep 1; done
```

### Invalid User Probe

```bash
for i in {1..5}; do echo "May 28 10:25:00 kali sshd: Invalid user admin$i from 10.0.0.5" >> test.log; sleep 1; done
```

---

## Alerting System

### Email Alerts

* Gmail SMTP integration
* Uses App Passwords
* Configurable recipients

### Slack Alerts

* Slack Incoming Webhooks
* Real-time SOC notifications

---

## Detection Logic

The SIEM uses a sliding-window threshold mechanism:

* 5 failed logins within 60 seconds → Brute-force alert
* 3 invalid-user attempts within 60 seconds → Invalid-user alert

---

## Dashboard Components

* KPI Cards
* Event Timeline
* Event Type Donut Chart
* Top Source IP Visualization
* Live Alert Feed
* Live Log Tail

---

## Future Improvements

* Machine learning anomaly detection
* Elasticsearch integration
* Docker deployment
* Multi-host monitoring
* Threat intelligence feeds
* Role-based authentication

---

## Author

Prkhar Sharma

Cyber Security Enthusiast | SOC & SIEM Projects | Python Security Automation
