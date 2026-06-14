"""
SentinelX - Honeypot Configuration Manager
Developer : Pawani Wijesekara (Honeypot Engineer)
FR-01     : Honeypot Deployment and Configuration

Implements UC-04: Administrator Configures Honeypot Endpoint
  - List / create / update / delete honeypot decoy endpoints
  - Enable / disable toggling (FR-01: "enabling or disabling honeypots")
  - Interaction level control: "passive" (log only) or "active"
    (log + return the full decoy response) — FR-01: "defining
    interaction levels"
  - Duplicate endpoint URL conflict detection (UC-04, Alternate Flow AF1:
    "Endpoint already in use")
  - Every configuration change is written to honeypot_audit.log with a
    timestamp, the action taken, and the admin who performed it
    (UC-04 post-conditions: "An audit entry records who made the change
    and when")

Storage:
  The configuration is persisted as a flat JSON file
  (honeypot_config.json). Every read re-loads from disk and every write
  re-saves the full file. This keeps the honeypot process (port 5001)
  and the backend/dashboard process (port 5000) in sync without needing
  a shared database connection — a config change made via the dashboard
  takes effect on the honeypot's very next request.
"""

import json
import os
import uuid
from datetime import datetime, timezone

CONFIG_FILE = os.path.join(os.path.dirname(__file__), "honeypot_config.json")
AUDIT_FILE  = os.path.join(os.path.dirname(__file__), "honeypot_audit.log")

VALID_INTERACTION_LEVELS = {"passive", "active"}


class HoneypotConfigManager:
    """
    Stateless-per-call configuration manager.

    No in-memory caching is used deliberately: the honeypot server and
    the backend/dashboard server run as separate Flask processes, so
    every call re-reads the JSON file from disk to guarantee both
    processes always see the latest configuration.
    """

    def __init__(self):
        if not os.path.exists(CONFIG_FILE):
            self._save([])

    # ── persistence ─────────────────────────────────────────────────────

    def _load(self):
        try:
            with open(CONFIG_FILE, "r") as f:
                return json.load(f)
        except Exception:
            return []

    def _save(self, config):
        try:
            with open(CONFIG_FILE, "w") as f:
                json.dump(config, f, indent=2, default=str)
        except Exception as e:
            print(f"[ConfigManager] Save error: {e}")

    def _audit(self, action, honeypot_id, actor, details=None):
        entry = {
            "timestamp":    datetime.now(timezone.utc).isoformat(),
            "action":       action,
            "honeypot_id":  honeypot_id,
            "actor":        actor or "unknown",
            "details":      details or {},
        }
        try:
            with open(AUDIT_FILE, "a") as f:
                f.write(json.dumps(entry, default=str) + "\n")
        except Exception as e:
            print(f"[ConfigManager] Audit log error: {e}")

    # ── reads ───────────────────────────────────────────────────────────

    def get_all(self):
        return self._load()

    def get_by_id(self, hp_id):
        for hp in self._load():
            if hp["id"] == hp_id:
                return hp
        return None

    def get_by_url(self, url):
        for hp in self._load():
            if hp["url"] == url:
                return hp
        return None

    def find_config(self, path):
        """
        Resolve an incoming request path to its honeypot configuration
        entry, used by the honeypot's process_request() pipeline.

        Matching order:
          1. Exact match on `url`
          2. Exact match on one of `aliases`
          3. Prefix match — e.g. /internal-docs/secret matches the
             /internal-docs entry so that parametrized sub-routes
             inherit their parent's configuration.
        """
        config = self._load()

        for entry in config:
            if path == entry.get("url") or path in entry.get("aliases", []):
                return entry

        for entry in config:
            base = entry.get("url", "").rstrip("/")
            if base and path.startswith(base + "/"):
                return entry

        return None

    # ── writes ──────────────────────────────────────────────────────────

    def create(self, url, service_type, interaction_level, actor):
        if not url.startswith("/"):
            raise ValueError("url must start with '/'")
        if interaction_level not in VALID_INTERACTION_LEVELS:
            raise ValueError("interaction_level must be 'passive' or 'active'")

        config = self._load()
        if any(hp.get("url") == url for hp in config):
            # UC-04 Alternate Flow AF1: Duplicate endpoint URL conflict
            raise ValueError("Endpoint already in use")

        hp = {
            "id":                f"hp-{uuid.uuid4().hex[:8]}",
            "url":               url,
            "aliases":           [],
            "service_type":      service_type,
            "interaction_level": interaction_level,
            "enabled":           True,
            "created_at":        datetime.now(timezone.utc).isoformat(),
            "created_by":        actor or "unknown",
        }
        config.append(hp)
        self._save(config)
        self._audit("created", hp["id"], actor, {"url": url, "service_type": service_type})
        return hp

    def update(self, hp_id, actor, **fields):
        config = self._load()
        hp = next((h for h in config if h["id"] == hp_id), None)
        if not hp:
            return None

        if "url" in fields and fields["url"] != hp["url"]:
            if not str(fields["url"]).startswith("/"):
                raise ValueError("url must start with '/'")
            if any(h["url"] == fields["url"] for h in config if h["id"] != hp_id):
                raise ValueError("Endpoint already in use")

        if "interaction_level" in fields and \
                fields["interaction_level"] not in VALID_INTERACTION_LEVELS:
            raise ValueError("interaction_level must be 'passive' or 'active'")

        before = dict(hp)
        for key in ("url", "service_type", "interaction_level", "enabled"):
            if key in fields:
                hp[key] = fields[key]

        self._save(config)
        self._audit("updated", hp_id, actor, {"before": before, "after": dict(hp)})
        return hp

    def delete(self, hp_id, actor):
        config = self._load()
        hp = next((h for h in config if h["id"] == hp_id), None)
        if not hp:
            return False

        config = [h for h in config if h["id"] != hp_id]
        self._save(config)
        self._audit("deleted", hp_id, actor, {"url": hp["url"]})
        return True

    def toggle(self, hp_id, actor):
        config = self._load()
        hp = next((h for h in config if h["id"] == hp_id), None)
        if not hp:
            return None

        hp["enabled"] = not hp["enabled"]
        self._save(config)
        self._audit("toggled", hp_id, actor, {"enabled": hp["enabled"]})
        return hp

    # ── audit retrieval (for dashboard) ────────────────────────────────

    def get_audit_log(self, limit=100):
        entries = []
        if not os.path.exists(AUDIT_FILE):
            return entries
        try:
            with open(AUDIT_FILE, "r") as f:
                lines = f.readlines()
            for line in reversed(lines):
                if len(entries) >= limit:
                    break
                line = line.strip()
                if not line:
                    continue
                try:
                    entries.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
        except Exception:
            pass
        return entries
