"""
SentinelX - Email Alert Notifier
FR-06: Real-time Alert Generation — email delivery channel

Sends an email when a Medium or Critical alert fires. Configured entirely
via environment variables so credentials never sit in source code.
Uses Python's built-in smtplib — no extra dependency needed.

Required env vars:
  SMTP_HOST       e.g. smtp.gmail.com
  SMTP_PORT       e.g. 587
  SMTP_USER       sending account email address
  SMTP_PASSWORD   app password / SMTP password
  ALERT_EMAIL_TO  recipient address (security team inbox)

If any of these are missing, email sending is silently disabled —
the dashboard and audit log channels keep working regardless.
"""
import os
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

SMTP_HOST      = os.getenv("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT      = int(os.getenv("SMTP_PORT", "587"))
SMTP_USER      = os.getenv("SMTP_USER", "sentinelxalerts0@gmail.com")
SMTP_PASSWORD  = os.getenv("SMTP_PASSWORD", "jmmejkyzjbygrriv")
ALERT_EMAIL_TO = os.getenv("ALERT_EMAIL_TO", "sentinelxalerts0@gmail.com")

EMAIL_ENABLED = bool(SMTP_HOST and SMTP_USER and SMTP_PASSWORD and ALERT_EMAIL_TO)

if not EMAIL_ENABLED:
    print("[EmailNotifier] Email alerts disabled — SMTP env vars not fully set.")


def send_alert_email(alert):
    """
    Send a formatted email for a single alert dict.
    Returns True on success, False otherwise. Never raises —
    a failed email must never break the alert pipeline.
    """
    if not EMAIL_ENABLED:
        return False

    subject = f"[SentinelX] {alert['risk_label']} alert — {alert['attack_type']}"

    body = f"""SentinelX Security Alert

Severity:     {alert['risk_label']}
Attack type:  {alert['attack_type']}
Source IP:    {alert['source_ip']}
Target URL:   {alert['target_url']}
Risk score:   {alert['risk_score']}
CVE:          {alert.get('cve_id') or 'N/A'}
CVSS:         {alert.get('cvss_score') or 'N/A'}
Time:         {alert['timestamp']}
Alert ID:     {alert['id']}

View this alert in the Command Center dashboard.
"""

    msg            = MIMEMultipart()
    msg["From"]    = SMTP_USER
    msg["To"]      = ALERT_EMAIL_TO
    msg["Subject"] = subject
    msg.attach(MIMEText(body, "plain"))

    try:
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=10) as server:
            server.starttls()
            server.login(SMTP_USER, SMTP_PASSWORD)
            server.sendmail(SMTP_USER, ALERT_EMAIL_TO, msg.as_string())
        return True
    except Exception as e:
        print(f"[EmailNotifier] Failed to send alert email: {e}")
        return False
