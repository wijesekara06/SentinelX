"""
SentinelX - FR-01 Honeypot Configuration Test Suite
Developer : Pawani Wijesekara (Honeypot Engineer)
FR-01     : Honeypot Deployment and Configuration
UC-04     : Administrator Configures Honeypot Endpoint

Run this AFTER run_all.py is up:
    python tests/test_honeypot_config.py

Covers:
  - GET  /api/honeypots               (list, requires auth)
  - POST /api/honeypots               (create, admin only)
  - UC-04 AF1: duplicate endpoint URL conflict -> 409
  - POST /api/honeypots/<id>/toggle   (disable)
  - Honeypot returns 404 once disabled (process_request short-circuit)
  - PUT  /api/honeypots/<id>          (set interaction_level=passive)
  - Honeypot returns 200 with minimal body when passive
  - DELETE /api/honeypots/<id>        (cleanup)
  - GET  /api/honeypots/audit         (audit trail recorded all changes)
  - Analyst role: read allowed, write forbidden (403)
"""

import requests
from colorama import Fore, Style, init

init(autoreset=True)

HP_URL  = "http://localhost:5001"
BE_URL  = "http://localhost:5000"


def section(title):
    print(f"\n{Fore.CYAN}{'='*55}")
    print(f"  {title}")
    print(f"{'='*55}{Style.RESET_ALL}")


def check(label, condition):
    color = Fore.GREEN if condition else Fore.RED
    status = "PASS" if condition else "FAIL"
    print(f"  {color}[{status}]{Style.RESET_ALL} {label}")
    return condition


def login(username, password):
    r = requests.post(f"{BE_URL}/api/auth/login",
                       json={"username": username, "password": password},
                       timeout=5)
    return r.json().get("token")


def auth(token):
    return {"Authorization": f"Bearer {token}"}


# ── Setup ────────────────────────────────────────────────────────────────
section("SETUP — Authenticate")
admin_token   = login("admin",   "SentinelX@2026")
analyst_token = login("analyst", "Analyst@2026")
check("Admin token obtained",   bool(admin_token))
check("Analyst token obtained", bool(analyst_token))


# ── 1. List existing honeypots ──────────────────────────────────────────
section("TEST 1 — List Honeypots (FR-01)")
r = requests.get(f"{BE_URL}/api/honeypots", headers=auth(admin_token), timeout=5)
data = r.json()
check("GET /api/honeypots returns 200", r.status_code == 200)
check("Seeded honeypots present (>=8)", len(data.get("honeypots", [])) >= 8)
for hp in data.get("honeypots", []):
    print(f"    {hp['id']:20s} {hp['url']:24s} {hp['service_type']:18s} "
          f"{hp['interaction_level']:8s} enabled={hp['enabled']}")


# ── 2. Analyst cannot create honeypots ──────────────────────────────────
section("TEST 2 — RBAC: Analyst cannot create honeypots")
r = requests.post(f"{BE_URL}/api/honeypots", headers=auth(analyst_token),
                   json={"url": "/fake-test", "service_type": "test",
                         "interaction_level": "active"}, timeout=5)
check("Analyst create -> 403 Forbidden", r.status_code == 403)


# ── 3. Admin creates a new honeypot ─────────────────────────────────────
section("TEST 3 — Admin creates a new honeypot")
r = requests.post(f"{BE_URL}/api/honeypots", headers=auth(admin_token),
                   json={"url": "/fake-test-endpoint",
                         "service_type": "test_service",
                         "interaction_level": "active"}, timeout=5)
check("Create honeypot -> 201", r.status_code == 201)
new_hp = r.json().get("honeypot", {})
new_id = new_hp.get("id")
check("New honeypot has an id", bool(new_id))
check("New honeypot enabled by default", new_hp.get("enabled") is True)


# ── 4. UC-04 AF1: Duplicate endpoint URL conflict ───────────────────────
section("TEST 4 — UC-04 AF1: Duplicate URL conflict")
r = requests.post(f"{BE_URL}/api/honeypots", headers=auth(admin_token),
                   json={"url": "/fake-test-endpoint",
                         "service_type": "test_service",
                         "interaction_level": "active"}, timeout=5)
check("Duplicate URL -> 409 Conflict", r.status_code == 409)
check('Error message mentions "already in use"',
      "already in use" in r.json().get("error", "").lower())


# ── 5. New honeypot is live on the honeypot server ──────────────────────
section("TEST 5 — New honeypot is live (active)")
r = requests.get(f"{HP_URL}/fake-test-endpoint", timeout=5)
check("Active honeypot returns 200", r.status_code == 200)


# ── 6. Disable the honeypot -> 404 on honeypot server ───────────────────
section("TEST 6 — Disable honeypot -> 404")
r = requests.post(f"{BE_URL}/api/honeypots/{new_id}/toggle",
                   headers=auth(admin_token), timeout=5)
check("Toggle -> 200", r.status_code == 200)
check("Honeypot now disabled", r.json().get("honeypot", {}).get("enabled") is False)

r = requests.get(f"{HP_URL}/fake-test-endpoint", timeout=5)
check("Disabled honeypot returns 404", r.status_code == 404)


# ── 7. Re-enable and set to passive ─────────────────────────────────────
section("TEST 7 — Re-enable + set interaction_level=passive")
r = requests.put(f"{BE_URL}/api/honeypots/{new_id}", headers=auth(admin_token),
                  json={"enabled": True, "interaction_level": "passive"}, timeout=5)
check("Update -> 200", r.status_code == 200)
hp = r.json().get("honeypot", {})
check("Honeypot re-enabled", hp.get("enabled") is True)
check("Interaction level = passive", hp.get("interaction_level") == "passive")

r = requests.get(f"{HP_URL}/fake-test-endpoint", timeout=5)
check("Passive honeypot returns 200", r.status_code == 200)
check("Passive honeypot returns minimal (empty) body", r.text == "")


# ── 8. Audit log recorded all changes ───────────────────────────────────
section("TEST 8 — Audit log (UC-04 post-conditions)")
r = requests.get(f"{BE_URL}/api/honeypots/audit", headers=auth(admin_token), timeout=5)
check("GET /api/honeypots/audit -> 200", r.status_code == 200)
audit = r.json().get("audit", [])
actions_for_new = [a["action"] for a in audit if a.get("honeypot_id") == new_id]
check("Audit contains 'created'", "created" in actions_for_new)
check("Audit contains 'toggled'", "toggled" in actions_for_new)
check("Audit contains 'updated'", "updated" in actions_for_new)
check("Audit entries record actor='admin'",
      all(a.get("actor") == "admin" for a in audit if a.get("honeypot_id") == new_id))


# ── 9. Cleanup — delete test honeypot ───────────────────────────────────
section("TEST 9 — Delete honeypot (cleanup)")
r = requests.delete(f"{BE_URL}/api/honeypots/{new_id}", headers=auth(admin_token), timeout=5)
check("Delete -> 200", r.status_code == 200)

r = requests.get(f"{HP_URL}/fake-test-endpoint", timeout=5)
check("Deleted honeypot route falls through to catch-all (404)", r.status_code == 404)


# ── 10. Analyst can read but not write ──────────────────────────────────
section("TEST 10 — RBAC: Analyst read-only access")
r = requests.get(f"{BE_URL}/api/honeypots", headers=auth(analyst_token), timeout=5)
check("Analyst GET /api/honeypots -> 200", r.status_code == 200)

r = requests.delete(f"{BE_URL}/api/honeypots/hp-admin-login", headers=auth(analyst_token), timeout=5)
check("Analyst DELETE -> 403 Forbidden", r.status_code == 403)

print(f"\n{Fore.GREEN}  FR-01 / UC-04 test suite complete.{Style.RESET_ALL}\n")
