"""
Alerting & Notifications
Reads the local config.json (SMTP + webhook settings) and sends a
summarized notification for newly generated HIGH RISK alerts. Both
channels are independently optional - if neither is enabled, notify()
is a no-op. Uses only the standard library (smtplib, urllib) so no new
dependency is required.

config.json lives next to app.py (NOT inside the SQLite database) so
credentials never end up mixed into the analytics data the pipeline
resets on every run. See config.example.json for the expected shape.
"""
import json
import os
import smtplib
import ssl
import urllib.request
from email.message import EmailMessage

CONFIG_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "config.json")
CONFIG_PATH = os.path.abspath(CONFIG_PATH)

DEFAULT_CONFIG = {
    "smtp": {
        "enabled": False,
        "host": "",
        "port": 587,
        "username": "",
        "password": "",
        "from_addr": "",
        "to_addr": "",
        "use_tls": True,
    },
    "webhook": {
        "enabled": False,
        "url": "",
    },
}


def load_config() -> dict:
    merged = json.loads(json.dumps(DEFAULT_CONFIG))
    if not os.path.exists(CONFIG_PATH):
        return merged
    try:
        with open(CONFIG_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (json.JSONDecodeError, OSError):
        return merged
    merged["smtp"].update(data.get("smtp", {}))
    merged["webhook"].update(data.get("webhook", {}))
    return merged


def save_config(config: dict):
    with open(CONFIG_PATH, "w", encoding="utf-8") as f:
        json.dump(config, f, indent=2)


def _format_message(alert_rows: list) -> str:
    lines = [f"CyberTrace-Lite: {len(alert_rows)} new HIGH RISK alert(s)", ""]
    for row in alert_rows:
        lines.append(f"- {row['username']} ({row['date']}): {row['message']}")
    return "\n".join(lines)


def _send_email(cfg: dict, subject: str, body: str):
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = cfg.get("from_addr") or cfg.get("username")
    msg["To"] = cfg.get("to_addr")
    msg.set_content(body)

    with smtplib.SMTP(cfg["host"], int(cfg["port"]), timeout=10) as server:
        if cfg.get("use_tls", True):
            server.starttls(context=ssl.create_default_context())
        if cfg.get("username"):
            server.login(cfg["username"], cfg["password"])
        server.send_message(msg)


def _send_webhook(url: str, text: str):
    payload = json.dumps({"text": text}).encode("utf-8")
    req = urllib.request.Request(
        url, data=payload, headers={"Content-Type": "application/json"}, method="POST",
    )
    urllib.request.urlopen(req, timeout=10)  # nosec - user-provided local webhook, not user input from the web


def notify(alert_rows: list) -> dict:
    """Send one summarized notification for a batch of new HIGH RISK
    alerts (dicts with username/date/message keys). Returns a status
    dict and never raises - a bad SMTP/webhook config should not break
    a pipeline run.
    """
    result = {"email_sent": False, "webhook_sent": False, "errors": []}
    if not alert_rows:
        return result

    cfg = load_config()
    body = _format_message(alert_rows)

    if cfg["smtp"].get("enabled"):
        try:
            _send_email(cfg["smtp"], "CyberTrace-Lite security alert", body)
            result["email_sent"] = True
        except Exception as e:
            result["errors"].append(f"email: {e}")

    if cfg["webhook"].get("enabled") and cfg["webhook"].get("url"):
        try:
            _send_webhook(cfg["webhook"]["url"], body)
            result["webhook_sent"] = True
        except Exception as e:
            result["errors"].append(f"webhook: {e}")

    return result
