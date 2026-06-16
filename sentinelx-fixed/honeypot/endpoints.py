"""
SentinelX - Honeypot Decoy Endpoints
Developer : Pawani Wijesekara (Honeypot Engineer)
FR-01     : Honeypot Endpoint Simulation & Configuration
FR-02     : Continuous Activity Logging

FIX v2:
  - Removed unreachable dead-code block after first return in process_request()
  - Directory traversal curl note: use --path-as-is or encoded URLs

FIX v3 (FR-01):
  - process_request() now consults HoneypotConfigManager (UC-04):
      * If the matching honeypot is disabled, the request is NOT
        logged and the route returns a plain 404.
      * If the matching honeypot's interaction_level is "passive",
        the request IS logged (for FR-02 / pattern detection / risk
        scoring) but the route returns a minimal response instead of
        the full decoy page — avoiding tipping off automated scanners
        while still capturing telemetry.
  - Configurable routes now check process_request()'s return value
    before rendering their decoy response.
"""

from flask import Blueprint, request, jsonify, render_template_string, make_response
from .logger import ActivityLogger
from .pattern_detector import PatternDetector, RiskScorer
from .cve_correlator import CVECorrelator
from .alert_generator import AlertGenerator
from .config_manager import HoneypotConfigManager

logger         = ActivityLogger()
detector       = PatternDetector()
scorer         = RiskScorer()
correlator     = CVECorrelator()
alerter        = AlertGenerator()
config_manager = HoneypotConfigManager()

honeypot_bp = Blueprint("honeypot", __name__)


def process_request(is_login_fail=False):
    """
    Core request pipeline:
      0. Resolve honeypot configuration for this path (FR-01)
      1. Collect payload from all sources (raw body, form fields, query string)
      2. Run pattern detection
      3. Correlate CVE
      4. Score risk
      5. Log and raise alert

    Returns:
      None -> matching honeypot is disabled; caller returns 404, no logging.
      dict -> log entry with an extra "_interaction_level" key
              ("active" or "passive").
    """
    ip         = request.remote_addr
    target_url = request.path

    # ── FR-01: honeypot configuration check ────────────────────────────
    hp_config = config_manager.find_config(target_url)
    if hp_config is not None and not hp_config.get("enabled", True):
        return None

    

    # Read raw bytes first — must happen before form parsing touches the stream
    raw_bytes   = request.get_data()
    raw_payload = raw_bytes.decode("utf-8", errors="replace")

    # Form fields
    form_str = ""
    try:
        for key, val in request.form.items():
            form_str += f"{key}={val} "
    except Exception:
        pass

    # Query string
    query_str = ""
    try:
        for key, val in request.args.items():
            query_str += f"{key}={val} "
    except Exception:
        pass

    combined_payload = raw_payload + " " + form_str + " " + query_str

    detection   = detector.analyze(ip, target_url, combined_payload, is_login_fail)
    attack_type = detection["attack_type"]
    base_cvss   = detection["base_cvss"]
    cve_hint    = detection.get("cve_hint")
    freq        = detection.get("attempt_count", 1)

    cve_info   = correlator.correlate(attack_type, cve_hint)
    cvss_score = max(base_cvss, cve_info.get("cvss_score", 0.0))

    persistence = detector.get_persistence(ip)
    risk        = scorer.calculate(freq, cvss_score, persistence)

    extra = {
        "attack_type": attack_type,
        "risk_score":  risk["risk_score"],
        "risk_label":  risk["risk_label"],
        "cve_id":      cve_info.get("cve_id"),
        "cvss_score":  cvss_score,
    }

    log_entry = logger.capture(request, extra)
    alerter.evaluate(log_entry)

    # ── FR-01: attach interaction level for the calling route ──────────
    log_entry["_interaction_level"] = (
        hp_config.get("interaction_level", "active") if hp_config else "active"
    )
    return log_entry


# ── Decoy HTML templates ──────────────────────────────────────────────────────

ADMIN_LOGIN_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Admin Portal — Vertex Global Networks</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { background: #1a1a2e; font-family: 'Segoe UI', sans-serif;
         display: flex; justify-content: center; align-items: center; min-height: 100vh; }
  .card { background: #16213e; border: 1px solid #0f3460;
          border-radius: 8px; padding: 40px; width: 360px; }
  .logo { text-align: center; margin-bottom: 30px; }
  .logo h2 { color: #e94560; font-size: 1.4rem; }
  .logo p  { color: #a0aec0; font-size: .8rem; margin-top: 4px; }
  label { display: block; color: #a0aec0; font-size: .85rem; margin-bottom: 6px; }
  input { width: 100%; padding: 10px 14px; background: #0f3460;
          border: 1px solid #e94560; border-radius: 4px;
          color: #fff; font-size: .9rem; margin-bottom: 18px; }
  button { width: 100%; padding: 12px; background: #e94560; border: none;
           border-radius: 4px; color: #fff; font-weight: 600;
           cursor: pointer; font-size: .95rem; }
  button:hover { background: #c73652; }
  .error { color: #e94560; font-size: .8rem; text-align: center; margin-top: 12px; }
  .badge { color: #4a5568; font-size: .7rem; text-align: center; margin-top: 20px; }
</style>
</head>
<body>
<div class="card">
  <div class="logo">
    <h2>VERTEX GLOBAL</h2>
    <p>Internal Administration Portal</p>
  </div>
  <form method="POST">
    <label>Administrator Email</label>
    <input type="email" name="username" placeholder="admin@vertexglobal.net">
    <label>Password</label>
    <input type="password" name="password" placeholder="Password">
    <button type="submit">Authenticate</button>
    {% if error %}<p class="error">{{ error }}</p>{% endif %}
  </form>
  <p class="badge">Restricted Access — Vertex Global Networks 2026</p>
</div>
</body>
</html>
"""

PHPMYADMIN_HTML = """<!DOCTYPE html>
<html>
<head><title>phpMyAdmin</title>
<style>
  body { background:#f5f5f5; font-family: Arial, sans-serif; }
  .header { background:#3e4e5e; color:#fff; padding:10px 20px; }
  .box { background:#fff; margin:60px auto; padding:30px; width:380px;
         border:1px solid #ddd; border-radius:4px; }
  h2 { color:#3e4e5e; margin-bottom:20px; }
  input { width:100%; padding:8px; margin-bottom:14px;
          border:1px solid #ccc; border-radius:3px; }
  button { background:#4e6e8e; color:#fff; border:none;
           padding:9px 24px; border-radius:3px; cursor:pointer; }
</style>
</head>
<body>
<div class="header"><strong>phpMyAdmin 5.2.1</strong></div>
<div class="box">
  <h2>Welcome to phpMyAdmin</h2>
  <form method="POST">
    <input name="pma_username" placeholder="Username" />
    <input name="pma_password" type="password" placeholder="Password" />
    <button type="submit">Go</button>
  </form>
</div>
</body>
</html>
"""

ENV_CONTENT = """# Vertex Global Networks - Production Config
APP_ENV=production
DEBUG=false
SECRET_KEY=vgn-secret-XK92mP3nQr8s
DATABASE_URL=mongodb://admin:Vrt3xDB!2026@db.vertexglobal.internal:27017/production
JWT_SECRET=jwt-hs256-VgN!8xKp3mR
SMTP_HOST=smtp.vertexglobal.net
SMTP_USER=noreply@vertexglobal.net
SMTP_PASSWORD=SMTPvgn2026!
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
"""


# ── Honeypot routes ───────────────────────────────────────────────────────────

@honeypot_bp.route("/admin-login", methods=["GET", "POST"])
def admin_login():
    is_fail = False
    error   = None
    if request.method == "POST":
        is_fail = True
        error = "Invalid credentials. Please try again."
    else:
        # GET = fresh page load, treat as a "successful" session start
        detector.brute_tracker.reset(request.remote_addr)
    log_entry = process_request(is_login_fail=is_fail)
    if log_entry is None:
        return "", 404
    if log_entry["_interaction_level"] == "passive":
        return "", 200
    return render_template_string(ADMIN_LOGIN_HTML, error=error), 200


@honeypot_bp.route("/phpmyadmin", methods=["GET", "POST"])
@honeypot_bp.route("/phpmyadmin/index.php", methods=["GET", "POST"])
def phpmyadmin():
    log_entry = process_request(is_login_fail=(request.method == "POST"))
    if log_entry is None:
        return "", 404
    if log_entry["_interaction_level"] == "passive":
        return "", 200
    return render_template_string(PHPMYADMIN_HTML), 200

@honeypot_bp.route("/wp-admin", methods=["GET", "POST"])
@honeypot_bp.route("/wp-login.php", methods=["GET", "POST"])
def wp_admin():
    log_entry = process_request(is_login_fail=(request.method == "POST"))
    if log_entry is None:
        return "", 404
    if log_entry["_interaction_level"] == "passive":
        return "", 200
    return (
        "<html><head><title>WordPress Login</title></head>"
        "<body><form method='POST'>"
        "<input name='log' placeholder='Username'/>"
        "<input name='pwd' type='password' placeholder='Password'/>"
        "<input type='submit' value='Log In'/>"
        "</form></body></html>"
    ), 200


@honeypot_bp.route("/.env", methods=["GET"])
def env_file():
    log_entry = process_request()
    if log_entry is None:
        return "", 404
    if log_entry["_interaction_level"] == "passive":
        return "", 200
    response = make_response(ENV_CONTENT, 200)
    response.headers["Content-Type"] = "text/plain"
    return response


@honeypot_bp.route("/backup.zip", methods=["GET"])
@honeypot_bp.route("/db_backup.sql", methods=["GET"])
def fake_backup():
    log_entry = process_request()
    if log_entry is None:
        return "", 404
    if log_entry["_interaction_level"] == "passive":
        return "", 200
    fake_zip = b"PK\x03\x04" + b"\x00" * 20 + b"FAKE_BACKUP_SENTINELX"
    response = make_response(fake_zip, 200)
    response.headers["Content-Type"] = "application/zip"
    return response


@honeypot_bp.route("/api/v1/users", methods=["GET", "POST", "PUT", "DELETE"])
def api_users():
    log_entry = process_request()
    if log_entry is None:
        return "", 404
    if log_entry["_interaction_level"] == "passive":
        return "", 200
    return jsonify({
        "status": "success",
        "data": [
            {"id": 1, "email": "admin@vertexglobal.net",     "role": "superadmin"},
            {"id": 2, "email": "john.doe@vertexglobal.net",  "role": "user"},
            {"id": 3, "email": "jane.smith@vertexglobal.net","role": "manager"},
        ]
    }), 200


@honeypot_bp.route("/api/v1/admin/config", methods=["GET", "POST"])
def api_admin_config():
    log_entry = process_request()
    if log_entry is None:
        return "", 404
    if log_entry["_interaction_level"] == "passive":
        return "", 200
    return jsonify({
        "environment": "production",
        "db_host":     "db.vertexglobal.internal",
        "debug_mode":  False,
        "version":     "4.2.1",
    }), 200


@honeypot_bp.route("/internal-docs", methods=["GET"])
@honeypot_bp.route("/internal-docs/<path:subpath>", methods=["GET"])
def internal_docs(subpath=""):
    log_entry = process_request()
    if log_entry is None:
        return "", 404
    if log_entry["_interaction_level"] == "passive":
        return "", 200
    return (
        "<html><body>"
        "<h1>Internal Security Guidelines — Employee Only</h1>"
        "<p>[RESTRICTED] This document contains confidential network architecture details.</p>"
        "</body></html>"
    ), 200


@honeypot_bp.route("/robots.txt", methods=["GET"])
def robots():
    log_entry = process_request()
    if log_entry is None:
        return "", 404
    if log_entry["_interaction_level"] == "passive":
        return "", 200
    return (
        "User-agent: *\n"
        "Disallow: /admin/\n"
        "Disallow: /internal/\n"
        "Disallow: /.env\n"
        "Disallow: /backup/\n"
    ), 200, {"Content-Type": "text/plain"}


@honeypot_bp.route("/", methods=["GET"])
def index():
    log_entry = process_request()
    if log_entry is None:
        return "", 404
    return (
        "<html><head><title>Vertex Global Networks</title></head>"
        "<body><h1>Vertex Global Networks</h1>"
        "<p>Enterprise Digital Infrastructure</p>"
        "<a href='/admin-login'>Staff Portal</a></body></html>"
    ), 200


@honeypot_bp.route("/<path:path>", methods=["GET", "POST", "PUT", "DELETE", "PATCH"])
def catch_all(path):
    log_entry = process_request()
    if log_entry is None:
        return "", 404

    # FR-01: honeypots created via the Configuration API may not have a
    # dedicated Flask route. If this path matches a configured, enabled
    # honeypot, serve a generic decoy instead of the default 404.
    hp_config = config_manager.find_config(request.path)
    if hp_config is not None:
        if log_entry["_interaction_level"] == "passive":
            return "", 200
        return jsonify({
            "status":  "ok",
            "service": hp_config.get("service_type", "service"),
            "message": "Service temporarily unavailable. Please try again later.",
        }), 200

    return "", 404
