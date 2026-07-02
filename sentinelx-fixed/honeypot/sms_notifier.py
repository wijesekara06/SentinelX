"""
SentinelX - SMS Alert Notifier
FR-06: Real-time Alert Generation — SMS delivery channel
NFR-02 ties SMS specifically to Critical-risk delivery ("Email and SMS
notifications shall be dispatched within 30 seconds" in the context of
critical-risk alerts), so unlike email (which fires on Medium+Critical),
SMS is reserved for Critical alerts only — Medium-risk already gets
dashboard + email, and SMS has a real per-message cost.

Sends via Text.lk's REST API (https://text.lk), a Sri Lanka-based SMS
gateway with direct local carrier interconnects (Dialog, Mobitel, Hutch,
Airtel Lanka). A prior implementation against Twilio was verified working
end-to-end (Twilio accepted every request with HTTP 201) but consistently
failed at actual delivery to Sri Lankan numbers with Twilio error 30008 —
a generic carrier-level delivery failure. That's consistent with a known,
common pattern: international carriers routinely filter or drop SMS
originating from foreign long-code numbers as an anti-spam measure, which
a US-based Twilio trial number sending into Sri Lanka runs straight into.
A local gateway sends as domestic Sri Lankan traffic, avoiding that
failure mode entirely rather than working around it.

Uses `requests` directly (already a project dependency), matching the
same no-extra-SDK convention as email_notifier.py and the prior Twilio
implementation.

Configured entirely via environment variables so credentials never sit
in source code — same convention as email_notifier.py.

Required env vars:
  TEXTLK_API_KEY     from your Text.lk dashboard (Bearer token)
  ALERT_SMS_TO       recipient number — either format works, e.g.
                     +94771234567 or 94771234567 (leading + is stripped)

Optional:
  TEXTLK_SENDER_ID   defaults to "TextLKDemo" (Text.lk's shared testing
                     sender name — fine for verification and demos, but
                     their own docs say not to rely on it for anything
                     you'd consider production use). Register your own
                     sender ID in the Text.lk dashboard and set this to
                     switch — no code change needed.

If any required var is missing, SMS sending is silently disabled — the
dashboard and email channels keep working regardless.
"""
import os
import time
import requests

TEXTLK_API_KEY   = os.getenv("TEXTLK_API_KEY", "5746|OjilDcp4G6diDrbuArmnNUyA5XErGDlGQAKypjbVe2796821")
TEXTLK_SENDER_ID = os.getenv("TEXTLK_SENDER_ID", "TextLKDemo")
ALERT_SMS_TO     = os.getenv("ALERT_SMS_TO", "").lstrip("+")

SMS_ENABLED = bool(TEXTLK_API_KEY and ALERT_SMS_TO)

TEXTLK_URL = "https://app.text.lk/api/v3/sms/send"

if not SMS_ENABLED:
    print("[SmsNotifier] SMS alerts disabled — Text.lk env vars not fully set.")


def send_alert_sms(alert):
    """
    Send a short SMS for a single Critical alert dict.
    Returns True on success, False otherwise. Never raises —
    a failed SMS must never break the alert pipeline.
    """
    if not SMS_ENABLED:
        return False

    body = (
        f"SentinelX CRITICAL: {alert['attack_type']} from {alert['source_ip']} "
        f"on {alert['target_url']} (score {alert['risk_score']}, "
        f"CVE {alert.get('cve_id') or 'N/A'}). Alert {alert['id']}."
    )

    headers = {
        "Authorization": f"Bearer {TEXTLK_API_KEY}",
        "Content-Type":  "application/json",
        "Accept":        "application/json",
    }
    payload = {
        "recipient": ALERT_SMS_TO,
        "sender_id": TEXTLK_SENDER_ID,
        "type":      "plain",
        "message":   body,
    }

    for attempt in range(3):
        try:
            r = requests.post(TEXTLK_URL, headers=headers, json=payload, timeout=10)

            if r.status_code == 429 and attempt < 2:
                # Rate limited — wait and retry
                time.sleep(2 ** attempt)
                continue

            try:
                resp_json = r.json()
            except ValueError:
                print(f"[SmsNotifier] Failed to send alert SMS: HTTP {r.status_code} — non-JSON response: {r.text[:200]}")
                return False

            if r.status_code == 200 and resp_json.get("status") == "success":
                return True

            print(f"[SmsNotifier] Failed to send alert SMS: HTTP {r.status_code} — {resp_json.get('message', r.text[:200])}")
            return False

        except requests.exceptions.RequestException as e:
            print(f"[SmsNotifier] Failed to send alert SMS: {e}")
            return False
    return False
