import os

BASE = "os.path.dirname(os.path.abspath(__file__))"
	
print("Updating all team files...")

# ── FILE 1: run.py ─────────────────────────────────────────────
run_py = '''import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from honeypot.app import create_honeypot_app

if __name__ == "__main__":
    app  = create_honeypot_app()
    port = int(os.getenv("PORT", 5001))

    print("""
╔══════════════════════════════════════════════════════════╗
║              SentinelX — Team A                          ║
╠══════════════════════════════════════════════════════════╣
║  Pawani Wijesekara    — Honeypot Engineer                ║
║    FR-01  Honeypot Endpoints         Active              ║
║    FR-02  Activity Logger            Running             ║
║    FR-03  Pattern Detector           Running             ║
║    FR-05  Risk Scorer                Active              ║
╠══════════════════════════════════════════════════════════╣
║  Naveesha Pathirathna — CVE Analyst                      ║
║    FR-04  CVE Correlator (NVD API)   Ready               ║
║    FR-04  CVSS Risk Scoring          Active              ║
╠══════════════════════════════════════════════════════════╣
║  Janith Warawita      — Alerts and QA                    ║
║    FR-06  Alert Generator            Armed               ║
║    FR-07  Backend API                Active              ║
║    FR-08  JWT Authentication         Active              ║
╠══════════════════════════════════════════════════════════╣
║  Gimashi Gimhara      — Frontend Developer               ║
║    FR-07  Command Center Dashboard   Active              ║
║    FR-07  Live Threat Feed           Active              ║
║    FR-07  Attack Vector Analysis     Active              ║
╠══════════════════════════════════════════════════════════╣
║  Decoy Endpoints (Pawani + Naveesha):                    ║
║    /admin-login   /phpmyadmin   /wp-admin                ║
║    /.env          /backup.zip   /internal-docs           ║
╠══════════════════════════════════════════════════════════╣
║  CVE Mappings (Naveesha):                                ║
║    SQL Injection       -> CVE-2019-9081  CVSS: 9.8       ║
║    Command Injection   -> CVE-2021-42013 CVSS: 9.8       ║
║    Directory Traversal -> CVE-2021-41773 CVSS: 7.5       ║
║    Brute Force         -> CVE-2022-0778  CVSS: 7.5       ║
║    XSS Attack          -> CVE-2021-34429 CVSS: 6.1       ║
║    Reconnaissance      -> CVE-2017-9798  CVSS: 5.3       ║
╚══════════════════════════════════════════════════════════╝
""")
    print(f"  Running on : http://localhost:{port}")
    print(f"  Logs API   : http://localhost:{port}/api/logs")
    print(f"  Stats API  : http://localhost:{port}/api/stats\\n")

    app.run(host="0.0.0.0", port=port, debug=False)
'''

with open(os.path.join(BASE, "run.py"), "w") as f:
    f.write(run_py)
print("  run.py updated")

# ── FILE 2: backend/app.py ─────────────────────────────────────
backend_py = '''"""
SentinelX - Backend Intelligence API
Developer : Janith Warawita (Alerts and QA)
FR-07     : Web-Based Dashboard and Reporting
FR-08     : Secure Authentication and Access Control

Janith\'s Deliverables:
- JWT Authentication system
- Role-Based Access Control (RBAC)
- REST API endpoints for logs and stats
- Alert management API
- CSV report export
- Three-tier architecture implementation
- System architecture and database schema
"""

import os
import json
import hmac
import hashlib
import base64
import time
from functools import wraps
from flask import Flask, request, jsonify, Response, send_from_directory
from flask_cors import CORS

JWT_SECRET = os.getenv("JWT_SECRET", "sentinelx-dev-secret")
JWT_EXPIRY = 8 * 3600

USERS = {
    "admin": {
        "password_hash": hashlib.sha256(os.getenv("ADMIN_PASSWORD", "SentinelX@2026").encode()).hexdigest(),
        "role": "admin",
        "name": "System Administrator"
    },
    "analyst": {
        "password_hash": hashlib.sha256(b"Analyst@2026").hexdigest(),
        "role": "analyst",
        "name": "Security Analyst"
    },
}

def _b64(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

def _b64d(s):
    s += "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s)

def create_token(username, role):
    header  = _b64(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    payload = _b64(json.dumps({
        "sub":  username,
        "role": role,
        "iat":  int(time.time()),
        "exp":  int(time.time()) + JWT_EXPIRY,
    }).encode())
    sig_input = f"{header}.{payload}".encode()
    sig = _b64(hmac.new(JWT_SECRET.encode(), sig_input, hashlib.sha256).digest())
    return f"{header}.{payload}.{sig}"

def verify_token(token):
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None
        header, payload, sig = parts
        expected_sig = _b64(
            hmac.new(
                JWT_SECRET.encode(),
                f"{header}.{payload}".encode(),
                hashlib.sha256
            ).digest()
        )
        if not hmac.compare_digest(sig, expected_sig):
            return None
        data = json.loads(_b64d(payload))
        if data.get("exp", 0) < int(time.time()):
            return None
        return data
    except Exception:
        return None

def require_auth(roles=None):
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            auth_header = request.headers.get("Authorization", "")
            if not auth_header.startswith("Bearer "):
                return jsonify({"error": "Missing token"}), 401
            token  = auth_header[7:]
            claims = verify_token(token)
            if not claims:
                return jsonify({"error": "Token invalid or expired"}), 401
            if roles and claims.get("role") not in roles:
                return jsonify({"error": "Insufficient permissions"}), 403
            request.user = claims
            return f(*args, **kwargs)
        return wrapper
    return decorator

LOG_FILE    = os.path.join(
    os.path.dirname(__file__), "../honeypot/honeypot_activity.log"
)
ALERTS_FILE = os.path.join(
    os.path.dirname(__file__), "../honeypot/alerts.json"
)

def read_logs(limit=500, filters=None):
    entries = []
    try:
        with open(LOG_FILE, "r") as f:
            lines = f.readlines()
        for i, line in enumerate(reversed(lines)):
            if len(entries) >= limit:
                break
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
                entry["_id"] = str(len(lines) - i)
                if filters:
                    if filters.get("risk_label") and \\
                       entry.get("risk_label") != filters["risk_label"]:
                        continue
                    if filters.get("attack_type") and \\
                       entry.get("attack_type") != filters["attack_type"]:
                        continue
                entries.append(entry)
            except json.JSONDecodeError:
                pass
    except FileNotFoundError:
        pass
    return entries

def load_alerts():
    if os.path.exists(ALERTS_FILE):
        try:
            with open(ALERTS_FILE, "r") as f:
                return json.load(f)
        except Exception:
            pass
    return []

def save_alerts(alerts):
    with open(ALERTS_FILE, "w") as f:
        json.dump(alerts, f, indent=2, default=str)

def create_backend_app():
    app = Flask(__name__)
    CORS(app, resources={r"/api/*": {"origins": "*"}})

    @app.route("/")
    @app.route("/dashboard")
    def dashboard():
        frontend = os.path.join(
            os.path.dirname(os.path.abspath(__file__)),
            "..", "frontend"
        )
        return send_from_directory(frontend, "dashboard.html")

    @app.route("/api/auth/login", methods=["POST"])
    def login():
        data     = request.get_json() or {}
        username = data.get("username", "").strip()
        password = data.get("password", "")
        user     = USERS.get(username)
        if not user:
            return jsonify({"error": "Invalid credentials"}), 401
        pwd_hash = hashlib.sha256(password.encode()).hexdigest()
        if not hmac.compare_digest(pwd_hash, user["password_hash"]):
            return jsonify({"error": "Invalid credentials"}), 401
        token = create_token(username, user["role"])
        return jsonify({
            "token":      token,
            "role":       user["role"],
            "name":       user["name"],
            "expires_in": JWT_EXPIRY,
        })

    @app.route("/api/logs", methods=["GET"])
    def get_logs():
        limit  = min(int(request.args.get("limit", 100)), 500)
        label  = request.args.get("label")
        attack = request.args.get("attack")
        filters = {}
        if label:  filters["risk_label"]  = label
        if attack: filters["attack_type"] = attack
        logs = read_logs(limit=limit, filters=filters)
        return jsonify({"status": "ok", "count": len(logs), "logs": logs})

    @app.route("/api/stats", methods=["GET"])
    def get_stats():
        from collections import defaultdict
        all_logs         = read_logs(limit=10000)
        attack_breakdown = defaultdict(int)
        risk_breakdown   = defaultdict(int)
        ip_counts        = defaultdict(int)
        for log in all_logs:
            attack_breakdown[log.get("attack_type", "Unknown")] += 1
            risk_breakdown[log.get("risk_label", "Low")]        += 1
            ip_counts[log.get("source_ip", "?")]                += 1
        top_ips = dict(
            sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:10]
        )
        return jsonify({
            "total_events":     len(all_logs),
            "critical_count":   risk_breakdown.get("Critical", 0),
            "medium_count":     risk_breakdown.get("Medium", 0),
            "low_count":        risk_breakdown.get("Low", 0),
            "attack_breakdown": dict(attack_breakdown),
            "top_ips":          top_ips,
        })

    @app.route("/api/alerts", methods=["GET"])
    def get_alerts():
        status = request.args.get("status")
        limit  = int(request.args.get("limit", 50))
        alerts = load_alerts()
        if status:
            alerts = [a for a in alerts if a.get("status") == status]
        alerts = list(reversed(alerts))[:limit]
        return jsonify({"status": "ok", "count": len(alerts), "alerts": alerts})

    @app.route("/api/alerts/<alert_id>/ack", methods=["POST"])
    def acknowledge_alert(alert_id):
        alerts = load_alerts()
        for alert in alerts:
            if alert["id"] == alert_id:
                alert["status"]   = "acknowledged"
                alert["acked_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ")
                save_alerts(alerts)
                return jsonify({"status": "ok", "alert_id": alert_id})
        return jsonify({"error": "Alert not found"}), 404

    @app.route("/api/alerts/summary", methods=["GET"])
    def alerts_summary():
        alerts  = load_alerts()
        summary = {"open": 0, "acknowledged": 0, "critical": 0, "medium": 0}
        for a in alerts:
            s = a.get("status", "open")
            l = a.get("risk_label", "Low")
            if s in summary: summary[s] += 1
            if l == "Critical": summary["critical"] += 1
            elif l == "Medium":  summary["medium"]   += 1
        return jsonify({"status": "ok", "summary": summary})

    @app.route("/api/report/csv", methods=["GET"])
    @require_auth()
    def export_csv():
        import csv, io
        logs   = read_logs(limit=1000)
        output = io.StringIO()
        writer = csv.DictWriter(output, fieldnames=[
            "timestamp", "source_ip", "http_method", "target_url",
            "attack_type", "risk_score", "risk_label", "cve_id", "cvss_score"
        ])
        writer.writeheader()
        for log in logs:
            writer.writerow({
                "timestamp":   log.get("timestamp", ""),
                "source_ip":   log.get("source_ip", ""),
                "http_method": log.get("http_method", ""),
                "target_url":  log.get("target_url", ""),
                "attack_type": log.get("attack_type", ""),
                "risk_score":  log.get("risk_score", ""),
                "risk_label":  log.get("risk_label", ""),
                "cve_id":      log.get("cve_id", ""),
                "cvss_score":  log.get("cvss_score", ""),
            })
        return Response(
            output.getvalue(),
            mimetype="text/csv",
            headers={
                "Content-Disposition": "attachment;filename=sentinelx_report.csv"
            }
        )

    @app.route("/api/health", methods=["GET"])
    def health():
        return jsonify({
            "status":    "backend_active",
            "version":   "1.0.0",
            "honeypot":  "http://localhost:5001",
            "dashboard": "http://localhost:5000/dashboard",
        })

    return app


if __name__ == "__main__":
    import sys
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    app  = create_backend_app()
    port = int(os.getenv("BACKEND_PORT", 5000))
    print("""
╔══════════════════════════════════════════════════════╗
║            SentinelX — Team A                        ║
╠══════════════════════════════════════════════════════╣
║  Pawani Wijesekara   — Honeypot Engineer             ║
║  Naveesha Pathirathna — CVE Analyst                  ║
║  Janith Warawita     — Alerts and QA                 ║
║  Gimashi Gimhara     — Frontend Developer            ║
╠══════════════════════════════════════════════════════╣
║  POST /api/auth/login   — get JWT token              ║
║  GET  /api/logs         — attack log list            ║
║  GET  /api/stats        — aggregated statistics      ║
║  GET  /api/alerts       — alert list                 ║
║  GET  /api/report/csv   — export CSV report          ║
╠══════════════════════════════════════════════════════╣
║  Credentials:                                        ║
║    admin   / SentinelX@2026                          ║
║    analyst / Analyst@2026                            ║
╚══════════════════════════════════════════════════════╝
""")
    print(f"  Running on: http://localhost:{port}")
    print(f"  Dashboard:  http://localhost:{port}/dashboard\\n")
    app.run(host="0.0.0.0", port=port, debug=False)
'''

with open(os.path.join(BASE, "backend", "app.py"), "w") as f:
    f.write(backend_py)
print("  backend/app.py updated")

# ── FILE 3: frontend/dashboard.html topbar update ─────────────
html_path = os.path.join(BASE, "frontend", "dashboard.html")
with open(html_path, "r") as f:
    content = f.read()

old = '<div class="topbar-tag">COMMAND CENTER</div>'
new = '''<div class="topbar-tag">COMMAND CENTER</div>
      <div class="topbar-tag" style="color:#a78bfa;border-color:rgba(167,139,250,0.4)">UI: GIMASHI GIMHARA</div>'''

if old in content:
    content = content.replace(old, new)
    with open(html_path, "w") as f:
        f.write(content)
    print("  frontend/dashboard.html updated")
else:
    print("  frontend/dashboard.html — already updated or tag not found")

print()
print("=" * 45)
print("  All files updated successfully!")
print("=" * 45)
print()
print("  Now run:")
print("  Terminal 1: python run.py")
print("  Terminal 2: python backend/app.py")
print("  Firefox:    http://127.0.0.1:5000/dashboard")
print()
