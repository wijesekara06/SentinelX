"""
SentinelX - Activity Logging Module
Developer : Pawani Wijesekara (Honeypot Engineer)
FR-02     : Continuous Activity Logging
Algorithm 01: Activity Logging Algorithm (Fig. 5)

Pawani's Deliverables:
- Capture Source IP, Timestamp, HTTP Method
- Capture Payload and Target Resource
- Store to MongoDB or flat file fallback
- Color-coded real-time console output

WHILE honeypot is active:
    WAIT for incoming request
    CAPTURE: Source IP, Timestamp, Request type,
             Payload, Target resource
    STORE captured data in Log Database
END WHILE
"""

import json
import logging
import os
from datetime import datetime, timezone
from colorama import Fore, Style, init

init(autoreset=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
console_log = logging.getLogger("SentinelX-Honeypot")

LOG_FILE = os.path.join(os.path.dirname(__file__), "honeypot_activity.log")


class ActivityLogger:
    """
    Pawani Wijesekara - Honeypot Engineer
    Implements Algorithm 01 - Activity Logging Algorithm
    """

    def __init__(self, mongo_collection=None):
        self.collection = mongo_collection
        self._ensure_log_file()

    def _ensure_log_file(self):
        if not os.path.exists(LOG_FILE):
            with open(LOG_FILE, "w") as f:
                f.write("")

    def capture(self, request, extra=None):
        source_ip    = request.remote_addr
        timestamp    = datetime.now(timezone.utc).isoformat()
        http_method  = request.method
        target_url   = request.path
        query_str    = request.query_string.decode("utf-8", errors="replace")
        user_agent   = request.headers.get("User-Agent", "Unknown")
        content_type = request.headers.get("Content-Type", "")

        try:
            if request.is_json:
                payload = request.get_json(silent=True) or {}
            else:
                payload = request.form.to_dict() or {}
        except Exception:
            payload = {}

        raw_payload = request.get_data(as_text=True)[:2000]

        log_entry = {
            "source_ip":    source_ip,
            "timestamp":    timestamp,
            "http_method":  http_method,
            "target_url":   target_url,
            "query_string": query_str,
            "headers": {
                "user_agent":   user_agent,
                "content_type": content_type,
                "referer":      request.headers.get("Referer", ""),
                "accept":       request.headers.get("Accept", ""),
            },
            "payload":     payload,
            "raw_payload": raw_payload,
            "attack_type": (extra or {}).get("attack_type", "Unknown"),
            "risk_score":  (extra or {}).get("risk_score", 0),
            "risk_label":  (extra or {}).get("risk_label", "Low"),
            "cve_id":      (extra or {}).get("cve_id", None),
            "cvss_score":  (extra or {}).get("cvss_score", None),
        }

        self._store(log_entry)
        self._console_print(log_entry)
        return log_entry

    def _store(self, entry):
        if self.collection is not None:
            try:
                self.collection.insert_one(entry)
                return
            except Exception as e:
                console_log.warning(f"MongoDB write failed: {e}")

        try:
            with open(LOG_FILE, "a") as f:
                f.write(json.dumps(entry, default=str) + "\n")
        except Exception as e:
            console_log.error(f"File logging failed: {e}")

    def _console_print(self, entry):
        label = entry.get("risk_label", "Low")
        color_map = {
            "Critical": Fore.RED,
            "Medium":   Fore.YELLOW,
            "Low":      Fore.CYAN,
        }
        color  = color_map.get(label, Fore.WHITE)
        attack = entry.get("attack_type", "Unknown")
        ip     = entry.get("source_ip", "?")
        url    = entry.get("target_url", "/")
        method = entry.get("http_method", "GET")
        ts     = entry.get("timestamp", "")[:19]

        print(
            f"{color}[{label}] {ts} | "
            f"{method} {url} | "
            f"IP: {ip} | "
            f"Attack: {attack}{Style.RESET_ALL}"
        )

    
