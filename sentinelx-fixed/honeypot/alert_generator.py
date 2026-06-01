"""
SentinelX - Alert Generator
Developer : Janith Warawita (Alerts and QA)
FR-06     : Real-time Alert Generation

FIX v2:
  - Alert threshold lowered from 5.0 to 2.5 to match RiskScorer label logic:
      RiskScorer labels Medium when score > 2.5
      AlertGenerator previously only fired at score >= 5.0, silently dropping
      all Medium-labeled events (scores 2.5–5.0) from the alerts list.
  - MEDIUM_RISK_THRESHOLD renamed to ALERT_THRESHOLD for clarity.
"""

import os
import json
import uuid
from datetime import datetime, timezone

ALERT_THRESHOLD = 2.5   # fire alert for anything labeled Medium or Critical
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

        return alert

    def get_alerts(self, status=None, limit=50):
        alerts = self._alerts
        if status:
            alerts = [a for a in alerts if a.get("status") == status]
        return list(reversed(alerts))[:limit]

    def acknowledge(self, alert_id):
        for alert in self._alerts:
            if alert["id"] == alert_id:
                alert["status"] = "acknowledged"
                self._save_alerts()
                return True
        return False

    def _load_alerts(self):
        if os.path.exists(ALERTS_FILE):
            try:
                with open(ALERTS_FILE, "r") as f:
                    return json.load(f)
            except Exception:
                pass
        return []

    def _save_alerts(self):
        try:
            with open(ALERTS_FILE, "w") as f:
                json.dump(self._alerts, f, indent=2, default=str)
        except Exception as e:
            print(f"[AlertGenerator] Save error: {e}")
