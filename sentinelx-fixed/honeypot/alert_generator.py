"""
SentinelX - Alert Generator
Developer : Janith Warawita (Alerts and QA)
FR-06     : Real-time Alert Generation

FIX v2:
  - Alert threshold lowered from 5.0 to 3.5 to match RiskScorer label logic:
      RiskScorer labels Medium when score > 3.5
      AlertGenerator previously only fired at score >= 5.0, silently dropping
      all Medium-labeled events (scores 3.5–5.0) from the alerts list.
  - MEDIUM_RISK_THRESHOLD renamed to ALERT_THRESHOLD for clarity."""

import os
import json
import uuid
import threading
import fcntl
from datetime import datetime, timezone
from . import email_notifier

ALERT_THRESHOLD = 3.5   # fire alert for anything labeled Medium or Critical
ALERTS_FILE     = os.path.join(os.path.dirname(__file__), "alerts.json")


class AlertGenerator:

    def __init__(self):
        self._alerts = self._load_alerts()

    def evaluate(self, log_entry):
        risk_score = log_entry.get("risk_score", 0)
        risk_label = log_entry.get("risk_label", "Low")

        if risk_score <= ALERT_THRESHOLD:
            return None

        alert = {
            "id":          f"ALT-{uuid.uuid4().hex[:8].upper()}",
            "timestamp":   datetime.now(timezone.utc).isoformat(),
            "risk_score":  risk_score,
            "risk_label":  risk_label,
            "attack_type": log_entry.get("attack_type", "Unknown"),
            "source_ip":   log_entry.get("source_ip", "?"),
            "target_url":  log_entry.get("target_url", "/"),
            "cve_id":      log_entry.get("cve_id"),
            "cvss_score":  log_entry.get("cvss_score"),
            "status":      "open",
            "channel":     ["dashboard"],
        }

        self._alerts.append(alert)
        self._save_alerts()

        print(
            f"\n🚨 ALERT [{alert['id']}] {risk_label} | "
            f"{alert['attack_type']} from {alert['source_ip']} | "
            f"CVE: {alert['cve_id'] or 'N/A'} | "
            f"CVSS: {alert['cvss_score'] or 'N/A'}"
        )
        threading.Thread(
            target=self._send_email_and_record,
            args=(alert,),
            daemon=True
        ).start()

        return alert

    def _send_email_and_record(self, alert):
        """
        Sends the alert email on a background thread so the honeypot's
        request/response cycle is never blocked by a slow SMTP call.
        NFR-01: request processing latency must stay under 50ms — a
        synchronous SMTP send (often 1-3+ seconds) would violate that
        on every Medium/Critical event.
        """
        if email_notifier.send_alert_email(alert):
            for a in self._alerts:
                if a["id"] == alert["id"]:
                    if "email" not in a["channel"]:
                        a["channel"].append("email")
                    break
            self._save_alerts()

    def get_alerts(self, status=None, limit=50):
        alerts = self._alerts
        if status:
            alerts = [a for a in alerts if a.get("status") == status]
        return list(reversed(alerts))[:limit]

    def acknowledge(self, alert_id):
        for alert in self._alerts:
            if alert["id"] == alert_id:
                alert["status"]   = "acknowledged"
                alert["acked_at"] = datetime.now(timezone.utc).isoformat()
                self._save_alerts()
                return True
        return False

    def _load_alerts(self):
        if os.path.exists(ALERTS_FILE):
            try:
                import encryption  # NFR-06: AES-256 at rest
                with open(ALERTS_FILE, "r") as f:
                    content = f.read().strip()
                if content:
                    try:
                        content = encryption.decrypt(content)
                    except Exception:
                        pass  # graceful fallback for pre-encryption data
                    return json.loads(content)
            except (json.JSONDecodeError, ValueError):
                print("[AlertGenerator] alerts.json unreadable on startup, starting with empty list")
        return []

    def _save_alerts(self):
        """
        Write alerts to disk with an exclusive file lock so concurrent
        Gunicorn worker processes cannot corrupt the JSON by writing
        simultaneously. Uses a separate .lock file to avoid truncating
        alerts.json while it is being locked.
        """
        lock_path = ALERTS_FILE + ".lock"
        try:
            with open(lock_path, "w") as lock_file:
                fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)
                try:
                    # Re-read current disk state inside the lock
                    current = []
                    if os.path.exists(ALERTS_FILE):
                        try:
                            import encryption  # NFR-06
                            with open(ALERTS_FILE, "r") as f:
                                content = f.read().strip()
                            if content:
                                try:
                                    content = encryption.decrypt(content)
                                except Exception:
                                    pass
                                current = json.loads(content)
                        except (json.JSONDecodeError, ValueError):
                            print("[AlertGenerator] alerts.json corrupt, resetting to clean state")
                            current = []

                    # Preserve ack status for any alerts acknowledged
                    # via the dashboard while we were running
                    existing = {a["id"]: a for a in current}
                    for alert in self._alerts:
                        aid = alert["id"]
                        if aid in existing and existing[aid].get("status") == "acknowledged":
                            alert["status"]   = existing[aid]["status"]
                            alert["acked_at"] = existing[aid].get("acked_at", "")

                    import encryption  # NFR-06: AES-256 at rest
                    json_str = json.dumps(self._alerts, indent=2, default=str)
                    with open(ALERTS_FILE, "w") as f:
                        f.write(encryption.encrypt(json_str))
                finally:
                    fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)
        except Exception as e:
            print(f"[AlertGenerator] Save error: {e}")
