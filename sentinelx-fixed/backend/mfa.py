"""
SentinelX - TOTP Multi-Factor Authentication
=============================================
NFR-05: The system shall enforce multi-factor authentication (MFA)
        for administrative users.

How it works:
  1. Admin calls /api/auth/mfa/setup  → gets a secret + provisioning URI
  2. Admin scans the URI with Google Authenticator or enters the secret manually
  3. Admin calls /api/auth/mfa/confirm with the first 6-digit code
     → MFA is now active for that account
  4. Every login after that requires a second step:
       POST /api/auth/login    → returns mfa_token (5 min, not a real JWT)
       POST /api/auth/mfa/verify with {mfa_token, code} → returns real JWT

Backup codes: 8 single-use codes generated at setup time.
Each one is consumed when used. They allow recovery if the phone is lost.

Author: Naveesha Pathirathna (CVE Analyst / Security)
"""

import os
import json
import time
import secrets
import pyotp

# MFA data is stored in a hidden JSON file next to this module.
# In production this would live in a database, but a local file
# is sufficient for the capstone and keeps the system self-contained.
_MFA_STORE = os.path.join(os.path.dirname(__file__), ".mfa_store.json")


# ── Internal helpers ──────────────────────────────────────────────────────────

def _load() -> dict:
    """Read the MFA store from disk. Returns empty dict if not found."""
    if os.path.exists(_MFA_STORE):
        try:
            with open(_MFA_STORE) as f:
                return json.load(f)
        except Exception:
            pass
    return {}


def _save(store: dict) -> None:
    """Write the MFA store back to disk."""
    with open(_MFA_STORE, "w") as f:
        json.dump(store, f, indent=2)


# ── Public API ────────────────────────────────────────────────────────────────

def setup_mfa(username: str) -> dict:
    """
    Generate a new TOTP secret for this user.
    MFA is NOT active yet — the user must call confirm_mfa() first
    with the code from their authenticator app to prove the app is working.

    Returns: { secret, uri, backup_codes }
      secret       - the raw base32 secret (can be typed into the app manually)
      uri          - otpauth:// URI (scan as QR code or paste into app)
      backup_codes - 8 single-use recovery codes
    """
    secret = pyotp.random_base32()
    uri    = pyotp.TOTP(secret).provisioning_uri(
        name=username,
        issuer_name="SentinelX Command Center",
    )
    backup_codes = [secrets.token_hex(4).upper() for _ in range(8)]

    store = _load()
    store[username] = {
        "secret":       secret,
        "enabled":      False,   # becomes True after confirm_mfa() succeeds
        "backup_codes": backup_codes,
        "created_at":   time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    _save(store)

    return {"secret": secret, "uri": uri, "backup_codes": backup_codes}


def confirm_mfa(username: str, code: str) -> bool:
    """
    Verify the first TOTP code and activate MFA for this user.
    valid_window=1 means we accept one 30-second step in either direction
    to handle minor clock skew between the server and the phone.
    """
    store = _load()
    entry = store.get(username)
    if not entry:
        return False

    if pyotp.TOTP(entry["secret"]).verify(code, valid_window=1):
        entry["enabled"] = True
        store[username]  = entry
        _save(store)
        return True
    return False


def verify_mfa(username: str, code: str) -> bool:
    """
    Verify a TOTP code (or backup code) during login.

    Returns True in three cases:
      1. The code is a valid TOTP for this user
      2. The code matches one of the remaining backup codes
      3. MFA has not been set up yet for this user (allows login to proceed
         so they can set up MFA from the dashboard)

    Backup codes are case-insensitive and consumed on use (single-use).
    """
    store = _load()
    entry = store.get(username)

    # MFA not set up yet — let the user through so they can configure it
    if not entry or not entry.get("enabled", False):
        return True

    # Standard TOTP check — valid_window=1 allows ±30 seconds clock skew
    if pyotp.TOTP(entry["secret"]).verify(code, valid_window=1):
        return True

    # Backup code check (case-insensitive, single-use)
    upper = (code or "").strip().upper()
    if upper in entry.get("backup_codes", []):
        entry["backup_codes"].remove(upper)
        store[username] = entry
        _save(store)
        return True

    return False


def is_mfa_enabled(username: str) -> bool:
    """Returns True only if MFA has been set up and confirmed."""
    store = _load()
    entry = store.get(username, {})
    return bool(entry.get("enabled", False))


def get_status(username: str) -> dict:
    """Return MFA status info for the dashboard settings panel."""
    store = _load()
    entry = store.get(username, {})
    return {
        "enabled":                entry.get("enabled", False),
        "created_at":             entry.get("created_at"),
        "backup_codes_remaining": len(entry.get("backup_codes", [])),
    }


def disable_mfa(username: str) -> bool:
    """Remove MFA entirely for this user (admin recovery operation)."""
    store = _load()
    if username in store:
        del store[username]
        _save(store)
        return True
    return False
