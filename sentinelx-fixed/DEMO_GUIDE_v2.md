# SentinelX v2 — Demo Guide (Fixed)

## Changes in v2 (Bug Fixes)

| # | File | Fix |
|---|------|-----|
| 1 | `honeypot/endpoints.py` | Removed unreachable dead-code block after `return log_entry` |
| 2 | `honeypot/pattern_detector.py` | Removed `python-requests`/`Go-http-client` from recon patterns — they matched the test suite's own UA |
| 3 | `honeypot/pattern_detector.py` | Formula docstring corrected to match actual normalization in code |
| 4 | `honeypot/alert_generator.py` | Alert threshold corrected from 5.0 → 2.5 to match `RiskScorer` label boundary |
| 5 | `backend/app.py` | `require_auth()` applied to `/api/logs`, `/api/stats`, `/api/alerts`, `/api/alerts/summary`, `/api/alerts/<id>/ack` |
| 6 | `backend/app.py` | JWT_SECRET and passwords now load from environment variables |
| 7 | `backend/app.py` | Added `/api/auth/me` endpoint |
| 8 | `tests/test_honeypot.py` | Auth header sent to backend API calls; encoded URL paths for directory traversal |

---

## Start — Two Terminals

**Terminal 1 — Honeypot (port 5001):**
```bash
cd /home/kali/Desktop/sentinalx-honepot
source venv/bin/activate
rm -f honeypot/honeypot_activity.log honeypot/alerts.json
python run.py
```

**Terminal 2 — Backend (port 5000):**
```bash
cd /home/kali/Desktop/sentinalx-honepot
source venv/bin/activate
python backend/app.py
```

**Dashboard:**
```
http://127.0.0.1:5000/dashboard
```
Login: `admin` / `SentinelX@2026`

---

## PART 1 — Attacker's View (Fake Pages)

Tab 1 — Fake admin portal:
```
http://localhost:5001/admin-login
```

Tab 2 — Fake database panel:
```
http://localhost:5001/phpmyadmin
```

Tab 3 — Fake config file:
```
http://localhost:5001/.env
```

Tab 4 — Fake robots.txt:
```
http://localhost:5001/robots.txt
```

---

## PART 2 — Live Attack Simulation

Open **Terminal 3:**
```bash
cd /home/kali/Desktop/sentinalx-honepot
source venv/bin/activate
```

---

### Attack 1 — SQL Injection (CRITICAL)

```bash
curl -X POST http://localhost:5001/admin-login \
  -d "username=' OR 1=1--&password=anything"
```

**Expected Terminal 1:**
```
[Critical] POST /admin-login | IP: 127.0.0.1 | Attack: SQL Injection
```

**Dashboard shows:**
- SQL Injection detected
- CVE: CVE-2019-9081, CVSS: 9.8, Risk: Critical

**Risk score calculation (actual formula):**
```
norm_freq = min(1 × 2.0, 10.0) = 2.0
score = (2.0 × 0.4) + (9.8 × 0.4) + (0 × 0.2)
      = 0.8 + 3.92 + 0 = 4.72 → CRITICAL
```

---

### Attack 2 — XSS Attack (MEDIUM → may show as Critical with persistence)

```bash
curl -X POST http://localhost:5001/admin-login \
  -d "username=<script>alert('XSS')</script>&password=x"
```

**Expected:**
```
[Medium/Critical] POST /admin-login | IP: 127.0.0.1 | Attack: XSS Attack
```

> Note: XSS has CVSS 6.1. A single fresh request scores ~3.24 → Medium.
> After several requests, persistence raises the score into Critical.
> CVE-2021-34429 identified.

---

### Attack 3 — Command Injection (CRITICAL)

```bash
curl -X POST http://localhost:5001/api/v1/users \
  -d "query=; whoami"

curl -X POST http://localhost:5001/api/v1/users \
  -d "query=| cat /etc/passwd"
```

**Expected:**
```
[Critical] POST /api/v1/users | IP: 127.0.0.1 | Attack: Command Injection
```

CVE-2021-42013 identified, CVSS 9.8.

---

### Attack 4 — Directory Traversal (MEDIUM)

> **Important:** Use URL-encoded paths. Literal `../../` is normalised by
> the HTTP stack before the request is sent, so the honeypot never sees it.
> Use `--path-as-is` OR the percent-encoded form below:

```bash
curl "http://localhost:5001/%2e%2e%2f%2e%2e%2fetc%2fpasswd"

curl "http://localhost:5001/api/v1/users?file=../../../etc/hosts"
```

**Expected:**
```
[Medium] GET /%2e%2e%2f... | IP: 127.0.0.1 | Attack: Directory Traversal
```

CVE-2021-41773 identified, CVSS 7.5.

---

### Attack 5 — Brute Force (MEDIUM)

Fire 6 attempts rapidly:
```bash
curl -X POST http://localhost:5001/admin-login \
  -d "username=admin&password=password"
curl -X POST http://localhost:5001/admin-login \
  -d "username=admin&password=123456"
curl -X POST http://localhost:5001/admin-login \
  -d "username=admin&password=admin"
curl -X POST http://localhost:5001/admin-login \
  -d "username=admin&password=letmein"
curl -X POST http://localhost:5001/admin-login \
  -d "username=admin&password=qwerty"
curl -X POST http://localhost:5001/admin-login \
  -d "username=admin&password=password123"
```

After 5 failed attempts within 60 seconds → **Brute Force** detected.
CVE-2022-0778 identified.

---

### Attack 6 — Reconnaissance (LOW)

```bash
curl http://localhost:5001/robots.txt
curl http://localhost:5001/.git/config
curl http://localhost:5001/phpinfo.php
curl http://localhost:5001/wp-admin
```

CVE-2017-9798 identified.

---

### Attack 7 — Sensitive File Access

```bash
curl http://localhost:5001/.env
curl http://localhost:5001/backup.zip
curl http://localhost:5001/internal-docs
```

Honeypot returns convincing fake data — attacker gets fake credentials/ZIP.

---

## PART 3 — Dashboard

```
http://127.0.0.1:5000/dashboard
```

Shows: total threats, critical/medium/low counts, attack breakdown, live feed.

---

## PART 4 — API Data (requires auth token)

Get token first:
```bash
TOKEN=$(curl -s -X POST http://localhost:5000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"SentinelX@2026"}' \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['token'])")
```

Full stats:
```bash
curl -H "Authorization: Bearer $TOKEN" http://localhost:5000/api/stats
```

CVE details:
```bash
curl -H "Authorization: Bearer $TOKEN" \
  "http://localhost:5000/api/logs?limit=5" \
  | python3 -m json.tool | grep -E "attack_type|cve_id|cvss_score|risk_label|source_ip"
```

---

## PART 5 — All Attacks at Once

```bash
python tests/test_honeypot.py
```

Wait for completion, then refresh dashboard.

---

## CVE Reference Table

| Attack | CVE | CVSS | Label (single hit, no persistence) |
|---|---|---|---|
| SQL Injection | CVE-2019-9081 | 9.8 | Critical (score 4.72) |
| Command Injection | CVE-2021-42013 | 9.8 | Critical (score 4.72) |
| Directory Traversal | CVE-2021-41773 | 7.5 | Critical (score 3.8) |
| Brute Force | CVE-2022-0778 | 7.5 | Medium (score 3.8) |
| XSS Attack | CVE-2021-34429 | 6.1 | Medium (score 3.24) |
| Reconnaissance | CVE-2017-9798 | 5.3 | Medium (score 3.04) |

> XSS and Reconnaissance are listed as "Critical" in some earlier materials —
> that label applies after multiple hits increase the persistence component.
> A single isolated hit scores Medium. Both are correct depending on context.

---

## Risk Score Formula (Exact)

```
norm_freq        = min(frequency × 2.0, 10.0)
norm_persistence = min(duration_minutes / 6.0, 10.0)

score = (norm_freq × 0.4) + (CVSS × 0.4) + (norm_persistence × 0.2)
```

**SQL Injection example (freq=1, CVSS=9.8, persistence=0 min):**
```
norm_freq = min(1 × 2.0, 10.0) = 2.0
score     = (2.0 × 0.4) + (9.8 × 0.4) + (0 × 0.2)
          = 0.8 + 3.92 + 0.0
          = 4.72 → CRITICAL
```

Labels: Critical > 4.5 | Medium > 2.5 | Low ≤ 2.5

---

## Viva — Key Q&A

**Q: Why is CVE-2022-0778 mapped to Brute Force?**
A: It's the closest match in the offline CVE map for authentication-related
vulnerabilities. In a production system the CVE correlator queries the live
NVD API to find a more precise match. For demo purposes, the offline map
is used as a guaranteed-available fallback.

**Q: Why does XSS have a lower CVSS than SQL Injection?**
A: XSS is client-side — the attacker must trick a victim into visiting the
page. SQL Injection directly affects the server database. NIST scores
server-side RCE/data-breach vectors higher (9.8) than client-side script
injection (6.1).

**Q: How does the CVE fallback chain work?**
A: Cache → live NVD API (5 s timeout) → offline map. Results are written
to `.cve_cache.json` so repeated lookups are instant.

**Q: Why does the honeypot always return HTTP 200?**
A: Intentional deception. A real login page returns 200. If the honeypot
returned 403/404 on attack detection, the attacker would know they've been
spotted and stop — defeating the purpose.

**Q: Are the passwords in the .env file real?**
A: No — they are entirely fictional credentials designed to look convincing.
AWS example keys are from Amazon's own documentation examples.
