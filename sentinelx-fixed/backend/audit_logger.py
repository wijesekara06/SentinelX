"""
SentinelX - Centralized Admin Audit Logger
NFR-07: All administrative actions shall be logged and retained to ensure
        accountability and forensic traceability.

This module is intentionally separate from config_manager.py's honeypot-only
audit trail (honeypot_audit.log). This one captures EVERY admin-privileged
action across the whole system: logins, alert acknowledgement, honeypot
CRUD, and report exports — giving a single forensic timeline.
"""
import os
import json
import time

AUDIT_FILE = os.path.join(os.path.dirname(__file__), "admin_audit.log")

MAX_AUDIT_ENTRIES = 50000  # safety cap so the file can't grow forever


def log_action(actor, action, details=None, ip=None, success=True):
    """
    Append one structured audit entry to admin_audit.log.

    actor   - username performing the action (or "unknown" if not yet authenticated)
    action  - short machine-readable action name, e.g. "login", "alert_ack"
    details - optional dict with extra context (alert_id, honeypot url, etc.)
    ip      - source IP of the request, if available
    success - whether the action succeeded (False for failed logins, denied actions)
    """
    entry = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "actor":     actor or "unknown",
        "action":    action,
        "success":   success,
        "ip":        ip or "unknown",
        "details":   details or {},
    }
    try:
        with open(AUDIT_FILE, "a") as f:
            f.write(json.dumps(entry, default=str) + "\n")
    except Exception as e:
        # Never let audit logging crash the request it's logging
        print(f"[AuditLogger] Failed to write audit entry: {e}")


def get_audit_log(limit=100, actor=None, action=None):
    """
    Read the most recent audit entries, newest first.
    Optional filters by actor or action type.
    """
    if not os.path.exists(AUDIT_FILE):
        return []

    entries = []
    try:
        with open(AUDIT_FILE, "r") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    entries.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    except Exception as e:
        print(f"[AuditLogger] Failed to read audit log: {e}")
        return []

    if actor:
        entries = [e for e in entries if e.get("actor") == actor]
    if action:
        entries = [e for e in entries if e.get("action") == action]

    entries.reverse()  # newest first
    return entries[:limit]
