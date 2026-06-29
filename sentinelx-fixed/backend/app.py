"""
SentinelX - Backend Intelligence API
Developer : Janith Warawita (Alerts and QA)
FR-07     : Web-Based Dashboard and Reporting
FR-08     : Secure Authentication and Access Control

FIX v2:
  - require_auth() now applied to /api/logs, /api/stats, /api/alerts,
    /api/alerts/summary, and /api/alerts/<id>/ack — all were previously
    unauthenticated despite the dashboard requiring a login.
  - JWT_SECRET loaded from environment variable JWT_SECRET with dev fallback.
  - Password hashes loaded from env vars ADMIN_PASSWORD / ANALYST_PASSWORD
    with dev-password fallbacks (prints a warning if defaults are used).
  - Added /api/auth/me endpoint so the dashboard can validate a stored token.

IMPROVEMENT:
  - /api/logs and /api/stats accept an analyst role as well as admin, so a
    read-only analyst account can use the dashboard without full admin rights.
"""
import sys
import os
import json
import hmac
import hashlib
import base64
import time
from functools import wraps
from collections import defaultdict
from flask import Flask, request, jsonify, Response, send_from_directory
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from honeypot.config_manager import HoneypotConfigManager, VALID_INTERACTION_LEVELS
import audit_logger
import security as sec
import mfa as mfa_module

config_manager = HoneypotConfigManager()

# ── Secrets — load from env in production, fall back to dev defaults ──────────
JWT_SECRET = os.getenv("JWT_SECRET", "sentinelx-dev-secret")
JWT_EXPIRY = 8 * 3600

_admin_pwd    = os.getenv("ADMIN_PASSWORD",   "SentinelX@2026")
_analyst_pwd  = os.getenv("ANALYST_PASSWORD", "Analyst@2026")

if JWT_SECRET == "sentinelx-dev-secret":
    print("[WARNING] JWT_SECRET is using the default dev value. "
          "Set the JWT_SECRET environment variable in production.")

USERS = {
    "admin": {
        "password_hash": generate_password_hash(_admin_pwd),
        "role":          "admin",
        "name":          "System Administrator",
    },
    "analyst": {
        "password_hash": generate_password_hash(_analyst_pwd),
        "role":          "analyst",
        "name":          "Security Analyst",
    },
}

_failed_attempts  = defaultdict(int)
_lockout_until    = {}
LOCKOUT_THRESHOLD = 3
LOCKOUT_SECONDS   = 300


# ── JWT helpers ───────────────────────────────────────────────────────────────

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
    if sec.token_blacklist.is_revoked(token):
        return None
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

def create_mfa_token(username, role):
    """
    Create a short-lived (5 minute) token used only during the MFA step.
    It has mfa_pending=True so require_auth() will reject it everywhere
    except /api/auth/mfa/verify, which checks for that flag explicitly.
    This means a stolen mfa_token cannot be used to access the dashboard.
    """
    header  = _b64(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    payload = _b64(json.dumps({
        "sub":         username,
        "role":        role,
        "iat":         int(time.time()),
        "exp":         int(time.time()) + 300,  # 5 minutes only
        "mfa_pending": True,
    }).encode())
    sig_input = f"{header}.{payload}".encode()
    sig = _b64(hmac.new(JWT_SECRET.encode(), sig_input, hashlib.sha256).digest())
    return f"{header}.{payload}.{sig}"


def require_auth(roles=None):
    """Decorator that enforces JWT authentication and optional role check."""
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
            # Reject MFA pending tokens — they can only be used with
            # /api/auth/mfa/verify, not with any protected endpoint
            if claims.get("mfa_pending"):
                return jsonify({"error": "MFA verification required"}), 401
            if roles and claims.get("role") not in roles:
                return jsonify({"error": "Insufficient permissions"}), 403
            request.user = claims
            return f(*args, **kwargs)
        return wrapper
    return decorator

# ── File helpers ──────────────────────────────────────────────────────────────

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
                import encryption  # NFR-06: AES-256 at rest
                try:
                    line = encryption.decrypt(line)
                except Exception:
                    pass  # graceful fallback for pre-encryption lines
                entry = json.loads(line)
                entry["_id"] = str(len(lines) - i)
                if filters:
                    if filters.get("risk_label") and \
                       entry.get("risk_label") != filters["risk_label"]:
                        continue
                    if filters.get("attack_type") and \
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
            import encryption  # NFR-06: AES-256 at rest
            with open(ALERTS_FILE, "r") as f:
                content = f.read().strip()
            if content:
                try:
                    content = encryption.decrypt(content)
                except Exception:
                    pass  # graceful fallback for pre-encryption data
                return json.loads(content)
        except Exception:
            pass
    return []

def save_alerts(alerts):
    import fcntl
    import encryption  # NFR-06: AES-256 at rest
    lock_path = ALERTS_FILE + ".lock"
    with open(lock_path, "w") as lock_file:
        fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)
        try:
            json_str = json.dumps(alerts, indent=2, default=str)
            with open(ALERTS_FILE, "w") as f:
                f.write(encryption.encrypt(json_str))
        finally:
            fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)


# ── App factory ───────────────────────────────────────────────────────────────

def create_backend_app():
    app = Flask(__name__)
    CORS(app, resources={
        r"/api/*": {
            "origins": "*",
            "methods": ["GET", "POST", "OPTIONS"],
            "allow_headers": ["Content-Type", "Authorization"]
        }
    })

    # ── Security: inject headers into every response ──────────────────────────
    app.after_request(sec.apply_security_headers)

    # ── Security: per-IP rate limiting ────────────────────────────────────────
    @app.before_request
    def enforce_rate_limit():
        ip = request.remote_addr or "unknown"
        if request.path.startswith("/api/auth"):
            if not sec.auth_limiter.is_allowed(ip):
                retry = sec.auth_limiter.retry_after(ip)
                return jsonify({
                    "error": f"Too many requests. Retry after {retry} seconds."
                }), 429
        elif request.path.startswith("/api/"):
            if not sec.api_limiter.is_allowed(ip):
                retry = sec.api_limiter.retry_after(ip)
                return jsonify({
                    "error": f"Rate limit exceeded. Retry after {retry} seconds."
                }), 429

    # ── Dashboard (public) ────────────────────────────────────────────────────

    @app.route("/")
    @app.route("/dashboard")
    def dashboard():
        frontend = os.path.join(
            os.path.dirname(os.path.abspath(__file__)),
            "..", "frontend"
        )
        return send_from_directory(frontend, "dashboard.html")

    # ── Auth ──────────────────────────────────────────────────────────────────

    @app.route("/api/auth/login", methods=["POST"])
    def login():
        data = request.get_json() or {}

        # Sanitize first — strip non-printables and validate format
        username = sec.sanitize(data.get("username", "").strip(), max_len=64)
        password = data.get("password", "")

        if not sec.is_safe_username(username):
            audit_logger.log_action(
                "unknown", "login",
                ip=request.remote_addr,
                success=False,
                details={"reason": "invalid_username_format"},
            )
            return jsonify({"error": "Invalid credentials"}), 401

        if not isinstance(password, str) or len(password) > 256:
            return jsonify({"error": "Invalid credentials"}), 401
        now = time.time()

        if username in _lockout_until:
            if now < _lockout_until[username]:
                remaining = int(_lockout_until[username] - now)

                audit_logger.log_action(
                    username,
                    "login",
                    ip=request.remote_addr,
                    success=False,
                    details={"reason": "locked_out"}
                )

                return jsonify({
                    "error": f"Account locked. Try again in {remaining} seconds."
                }), 429
            else:
                del _lockout_until[username]
                _failed_attempts[username] = 0

        user = USERS.get(username)

        if not user:
            _failed_attempts[username] += 1
            attempts_left = LOCKOUT_THRESHOLD - _failed_attempts[username]

            if _failed_attempts[username] >= LOCKOUT_THRESHOLD:
                _lockout_until[username] = now + LOCKOUT_SECONDS
                _failed_attempts[username] = 0

                audit_logger.log_action(
                    username,
                    "login",
                    ip=request.remote_addr,
                    success=False,
                    details={"reason": "lockout_triggered"}
                )

                return jsonify({
                    "error": "Too many failed attempts. Account locked for 5 minutes."
                }), 429

            audit_logger.log_action(
                username,
                "login",
                ip=request.remote_addr,
                success=False,
                details={"reason": "unknown_user"}
            )

            return jsonify({
                "error": f"Invalid credentials. {attempts_left} attempt(s) remaining."
            }), 401

        if not check_password_hash(user["password_hash"], password):
            _failed_attempts[username] += 1
            attempts_left = LOCKOUT_THRESHOLD - _failed_attempts[username]

            if _failed_attempts[username] >= LOCKOUT_THRESHOLD:
                _lockout_until[username] = now + LOCKOUT_SECONDS
                _failed_attempts[username] = 0

                audit_logger.log_action(
                    username,
                    "login",
                    ip=request.remote_addr,
                    success=False,
                    details={"reason": "lockout_triggered"}
                )

                return jsonify({
                    "error": "Too many failed attempts. Account locked for 5 minutes."
                }), 429

            audit_logger.log_action(
                username,
                "login",
                ip=request.remote_addr,
                success=False,
                details={"reason": "wrong_password"}
            )

            return jsonify({
                "error": f"Invalid credentials. {attempts_left} attempt(s) remaining."
            }), 401

        _failed_attempts[username] = 0

        # If MFA is enabled for this user, don't issue the real JWT yet.
        # Return a short-lived mfa_token and let the frontend handle step 2.
        if mfa_module.is_mfa_enabled(username):
            mfa_tok = create_mfa_token(username, user["role"])
            audit_logger.log_action(
                username, "login_mfa_required",
                ip=request.remote_addr, success=True,
            )
            return jsonify({
                "mfa_required": True,
                "mfa_token":    mfa_tok,
            })

        # MFA not set up — issue the full JWT immediately
        token = create_token(username, user["role"])

        audit_logger.log_action(
            username,
            "login",
            ip=request.remote_addr,
            success=True
        )

        return jsonify({
            "token": token,
            "role": user["role"],
            "name": user["name"],
            "expires_in": JWT_EXPIRY
        })


    @app.route("/api/auth/me", methods=["GET"])
    @require_auth()
    def me():
        """Validate a stored token and return the current user info."""
        return jsonify({
            "username": request.user.get("sub"),
            "role":     request.user.get("role"),
        })

    @app.route("/api/auth/logout", methods=["POST"])
    @require_auth()
    def logout():
        """
        Revoke the current JWT so it cannot be reused after logout.
        The token signature is added to the blacklist until its natural expiry.
        """
        auth_header = request.headers.get("Authorization", "")
        token       = auth_header[7:] if auth_header.startswith("Bearer ") else ""
        exp         = request.user.get("exp", time.time())
        if token:
            sec.token_blacklist.revoke(token, exp)
        audit_logger.log_action(
            request.user.get("sub"), "logout",
            ip=request.remote_addr, success=True,
        )
        return jsonify({"status": "ok", "message": "Logged out successfully"})

    # ── MFA endpoints ─────────────────────────────────────────────────────────

    @app.route("/api/auth/mfa/verify", methods=["POST"])
    def mfa_verify():
        """
        Step 2 of login when MFA is enabled.
        Accepts the short-lived mfa_token from /api/auth/login plus the
        6-digit TOTP code. Returns a full JWT on success.
        """
        data      = request.get_json() or {}
        mfa_token = data.get("mfa_token", "")
        code      = str(data.get("code", "")).strip()

        # Verify the MFA pending token (must be signed and not expired)
        claims = verify_token(mfa_token)
        if not claims or not claims.get("mfa_pending"):
            return jsonify({"error": "Invalid or expired MFA session"}), 401

        username = claims.get("sub")

        if not mfa_module.verify_mfa(username, code):
            audit_logger.log_action(
                username, "mfa_verify",
                ip=request.remote_addr, success=False,
                details={"reason": "wrong_code"},
            )
            return jsonify({"error": "Invalid MFA code"}), 401

        # Code is correct — issue the real JWT
        role  = claims.get("role")
        token = create_token(username, role)

        audit_logger.log_action(
            username, "login",
            ip=request.remote_addr, success=True,
            details={"mfa": "verified"},
        )

        user = USERS.get(username, {})
        return jsonify({
            "token":      token,
            "role":       role,
            "name":       user.get("name", username),
            "expires_in": JWT_EXPIRY,
        })

    @app.route("/api/auth/mfa/setup", methods=["POST"])
    @require_auth(roles=["admin"])
    def mfa_setup():
        """
        Generate a TOTP secret for the current admin.
        MFA is NOT active until /api/auth/mfa/confirm is called.
        """
        username = request.user.get("sub")
        result   = mfa_module.setup_mfa(username)
        audit_logger.log_action(
            username, "mfa_setup",
            ip=request.remote_addr, success=True,
        )
        return jsonify({
            "status":       "ok",
            "secret":       result["secret"],
            "uri":          result["uri"],
            "backup_codes": result["backup_codes"],
        })

    @app.route("/api/auth/mfa/confirm", methods=["POST"])
    @require_auth(roles=["admin"])
    def mfa_confirm():
        """Activate MFA by verifying the first code from the authenticator app."""
        data     = request.get_json() or {}
        code     = str(data.get("code", "")).strip()
        username = request.user.get("sub")

        if not mfa_module.confirm_mfa(username, code):
            return jsonify({
                "error": "Invalid code. Make sure your authenticator app is set up correctly."
            }), 400

        audit_logger.log_action(
            username, "mfa_enabled",
            ip=request.remote_addr, success=True,
        )
        return jsonify({"status": "ok", "message": "MFA enabled successfully"})

    @app.route("/api/auth/mfa/status", methods=["GET"])
    @require_auth()
    def mfa_status():
        """Return the MFA status for the currently logged-in user."""
        username = request.user.get("sub")
        return jsonify({
            "status": "ok",
            **mfa_module.get_status(username),
        })

    @app.route("/api/auth/mfa/disable", methods=["POST"])
    @require_auth(roles=["admin"])
    def mfa_disable():
        """Remove MFA for the current admin (recovery operation)."""
        username = request.user.get("sub")
        mfa_module.disable_mfa(username)
        audit_logger.log_action(
            username, "mfa_disabled",
            ip=request.remote_addr, success=True,
        )
        return jsonify({"status": "ok", "message": "MFA disabled"})


    # ── Logs — requires auth (admin or analyst) ───────────────────────────────

    @app.route("/api/logs", methods=["GET"])
    @require_auth(roles=["admin", "analyst"])
    def get_logs():
        limit  = min(int(request.args.get("limit", 100)), 500)
        label  = request.args.get("label")
        attack = request.args.get("attack")
        filters = {}
        if label:  filters["risk_label"]  = label
        if attack: filters["attack_type"] = attack
        logs = read_logs(limit=limit, filters=filters)
        return jsonify({"status": "ok", "count": len(logs), "logs": logs})

    # ── Stats — requires auth ─────────────────────────────────────────────────

    @app.route("/api/stats", methods=["GET"])
    @require_auth(roles=["admin", "analyst"])
    def get_stats():
        from collections import defaultdict
        from datetime import datetime, timezone, timedelta
        all_logs         = read_logs(limit=10000)
        attack_breakdown = defaultdict(int)
        risk_breakdown   = defaultdict(int)
        ip_counts        = defaultdict(int)
        cutoff           = datetime.now(timezone.utc) - timedelta(hours=24)
        recent_24h       = 0
        for log in all_logs:
            attack_breakdown[log.get("attack_type", "Unknown")] += 1
            risk_breakdown[log.get("risk_label", "Low")]        += 1
            ip_counts[log.get("source_ip", "?")]                += 1
            try:
                ts = datetime.fromisoformat(log.get("timestamp", ""))
                if ts.tzinfo is None:
                    ts = ts.replace(tzinfo=timezone.utc)
                if ts > cutoff:
                    recent_24h += 1
            except (ValueError, TypeError):
                pass
        top_ips = dict(sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:10])
        by_type = dict(attack_breakdown)
        return jsonify({
            "total_events":     len(all_logs),
            "total_alerts":     len(all_logs),
            "critical_count":   risk_breakdown.get("Critical", 0),
            "medium_count":     risk_breakdown.get("Medium", 0),
            "low_count":        risk_breakdown.get("Low", 0),
            "attack_breakdown": by_type,
            "by_type":          by_type,
            "recent_24h":       recent_24h,
            "top_ips":          top_ips,
        })

    # ── Alerts — requires auth ────────────────────────────────────────────────

    @app.route("/api/alerts", methods=["GET"])
    @require_auth(roles=["admin", "analyst"])
    def get_alerts():
        status = request.args.get("status")
        limit  = min(int(request.args.get("limit", 50)), 500)
        alerts = load_alerts()
        if status:
            alerts = [a for a in alerts if a.get("status") == status]
        alerts = list(reversed(alerts))[:limit]
        return jsonify({"status": "ok", "count": len(alerts), "alerts": alerts})

    @app.route("/api/alerts/<alert_id>/ack", methods=["POST"])
    @require_auth(roles=["admin"])
    def acknowledge_alert(alert_id):
        alerts = load_alerts()
        for alert in alerts:
            if alert["id"] == alert_id:
                alert["status"]   = "acknowledged"
                alert["acked_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ")
                save_alerts(alerts)
                audit_logger.log_action(
                    request.user.get("sub"), "alert_ack",
                    details={"alert_id": alert_id}, ip=request.remote_addr
                )
                return jsonify({"status": "ok", "alert_id": alert_id})
        return jsonify({"error": "Alert not found"}), 404

    @app.route("/api/alerts/summary", methods=["GET"])
    @require_auth(roles=["admin", "analyst"])
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

    # ── Honeypot Configuration (FR-01 / UC-04) — admin manages, ──────────────
    #    analysts get read-only visibility ────────────────────────────────────

    @app.route("/api/honeypots", methods=["GET"])
    @require_auth(roles=["admin", "analyst"])
    def list_honeypots():
        return jsonify({
            "status":    "ok",
            "honeypots": config_manager.get_all(),
        })

    @app.route("/api/honeypots", methods=["POST"])
    @require_auth(roles=["admin"])
    def create_honeypot():
        data              = request.get_json() or {}
        url               = (data.get("url") or "").strip()
        service_type      = (data.get("service_type") or "").strip()
        interaction_level = (data.get("interaction_level") or "active").strip()

        if not url or not service_type:
            return jsonify({"error": "url and service_type are required"}), 400
        if not url.startswith("/"):
            return jsonify({"error": "url must start with '/'"}), 400
        if interaction_level not in VALID_INTERACTION_LEVELS:
            return jsonify({"error": "interaction_level must be 'passive' or 'active'"}), 400

        try:
            hp = config_manager.create(
                url, service_type, interaction_level,
                actor=request.user.get("sub"),
            )
        except ValueError as e:
            return jsonify({"error": str(e)}), 409
        audit_logger.log_action(
            request.user.get("sub"), "honeypot_create",
            details={"url": url, "service_type": service_type}, ip=request.remote_addr
        )
        return jsonify({"status": "ok", "honeypot": hp}), 201

    @app.route("/api/honeypots/<hp_id>", methods=["PUT"])
    @require_auth(roles=["admin"])
    def update_honeypot(hp_id):
        data    = request.get_json() or {}
        allowed = {}
        for key in ("url", "service_type", "interaction_level", "enabled"):
            if key in data:
                allowed[key] = data[key]

        if "url" in allowed and not str(allowed["url"]).startswith("/"):
            return jsonify({"error": "url must start with '/'"}), 400
        if "interaction_level" in allowed and \
                allowed["interaction_level"] not in VALID_INTERACTION_LEVELS:
            return jsonify({"error": "interaction_level must be 'passive' or 'active'"}), 400

        try:
            hp = config_manager.update(hp_id, actor=request.user.get("sub"), **allowed)
        except ValueError as e:
            return jsonify({"error": str(e)}), 409

        if hp is None:
            return jsonify({"error": "Honeypot not found"}), 404
        audit_logger.log_action(
            request.user.get("sub"), "honeypot_update",
            details={"hp_id": hp_id, "changes": allowed}, ip=request.remote_addr
        )
        return jsonify({"status": "ok", "honeypot": hp})

    @app.route("/api/honeypots/<hp_id>", methods=["DELETE"])
    @require_auth(roles=["admin"])
    def delete_honeypot(hp_id):
        ok = config_manager.delete(hp_id, actor=request.user.get("sub"))
        if not ok:
            return jsonify({"error": "Honeypot not found"}), 404
        audit_logger.log_action(
            request.user.get("sub"), "honeypot_delete",
            details={"hp_id": hp_id}, ip=request.remote_addr
        )
        return jsonify({"status": "ok", "deleted": hp_id})

    @app.route("/api/honeypots/<hp_id>/toggle", methods=["POST"])
    @require_auth(roles=["admin"])
    def toggle_honeypot(hp_id):
        hp = config_manager.toggle(hp_id, actor=request.user.get("sub"))
        if hp is None:
            return jsonify({"error": "Honeypot not found"}), 404
        audit_logger.log_action(
            request.user.get("sub"), "honeypot_toggle",
            details={"hp_id": hp_id}, ip=request.remote_addr
        )
        return jsonify({"status": "ok", "honeypot": hp})

    @app.route("/api/audit", methods=["GET"])
    @require_auth(roles=["admin"])
    def admin_audit_log():
        limit  = min(int(request.args.get("limit", 100)), 500)
        actor  = request.args.get("actor")
        action = request.args.get("action")
        return jsonify({
            "status": "ok",
            "entries":  audit_logger.get_audit_log(limit=limit, actor=actor, action=action),
        })
    @app.route("/api/honeypots/audit", methods=["GET"])
    @require_auth(roles=["admin"])
    def honeypot_audit_log():
        """
        Returns the honeypot configuration audit trail — who created,
        updated, toggled, or deleted each honeypot endpoint and when.
        Separate from /api/audit which covers all admin actions system-wide.
        """
        limit = min(int(request.args.get("limit", 50)), 500)
        return jsonify({
            "status": "ok",
            "audit":  config_manager.get_audit_log(limit=limit),
        })
    # ── CSV export — admin only ───────────────────────────────────────────────

    @app.route("/api/report/csv", methods=["GET"])
    @require_auth(roles=["admin"])
    def export_csv():
        import csv, io
        logs   = read_logs(limit=1000)
        audit_logger.log_action(
        request.user.get("sub"), "csv_export",
        details={"row_count": len(logs)}, ip=request.remote_addr)
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
    @app.route("/api/report/pdf", methods=["GET"])
    @require_auth(roles=["admin"])
    def export_pdf():
        import io
        from collections import defaultdict
        from reportlab.lib.pagesizes import letter
        from reportlab.lib import colors
        from reportlab.lib.units import inch
        from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle

        limit = min(int(request.args.get("limit", 50)), 500)
        logs  = read_logs(limit=limit)

        risk_breakdown = defaultdict(int)
        for log in read_logs(limit=10000):
            risk_breakdown[log.get("risk_label", "Low")] += 1

        audit_logger.log_action(
            request.user.get("sub"), "pdf_export",
            details={"row_count": len(logs)}, ip=request.remote_addr
        )

        buf = io.BytesIO()
        doc = SimpleDocTemplate(
            buf, pagesize=letter,
            topMargin=0.6 * inch, bottomMargin=0.6 * inch,
            leftMargin=0.6 * inch, rightMargin=0.6 * inch,
        )
        styles      = getSampleStyleSheet()
        title_style = ParagraphStyle("TitleX", parent=styles["Title"], fontSize=18, spaceAfter=4)
        meta_style  = ParagraphStyle("Meta", parent=styles["Normal"], fontSize=9, textColor=colors.grey)

        elements = []
        elements.append(Paragraph("SentinelX — Incident Report", title_style))
        elements.append(Paragraph(
            f"Generated {time.strftime('%Y-%m-%d %H:%M UTC', time.gmtime())} "
            f"by {request.user.get('sub')}",
            meta_style
        ))
        elements.append(Spacer(1, 16))

        summary_data = [
            ["Total events", "Critical", "Medium", "Low"],
            [
                str(sum(risk_breakdown.values())),
                str(risk_breakdown.get("Critical", 0)),
                str(risk_breakdown.get("Medium", 0)),
                str(risk_breakdown.get("Low", 0)),
            ],
        ]
        summary_table = Table(summary_data, colWidths=[1.6 * inch] * 4)
        summary_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1f2937")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTSIZE", (0, 0), (-1, -1), 10),
            ("ALIGN", (0, 0), (-1, -1), "CENTER"),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#d1d5db")),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
            ("TOPPADDING", (0, 0), (-1, -1), 8),
        ]))
        elements.append(summary_table)
        elements.append(Spacer(1, 20))

        elements.append(Paragraph("Recent activity", styles["Heading2"]))
        elements.append(Spacer(1, 8))

        table_data = [["Time", "Source IP", "Attack type", "Risk", "Score", "CVE"]]
        for log in logs:
            table_data.append([
                (log.get("timestamp") or "")[:19],
                log.get("source_ip", ""),
                log.get("attack_type", ""),
                log.get("risk_label", ""),
                str(log.get("risk_score", "")),
                log.get("cve_id") or "N/A",
            ])

        log_table = Table(
            table_data,
            colWidths=[1.2 * inch, 0.9 * inch, 1.3 * inch, 0.7 * inch, 0.6 * inch, 1.1 * inch],
            repeatRows=1,
        )
        log_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#374151")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#d1d5db")),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f9fafb")]),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ("TOPPADDING", (0, 0), (-1, -1), 5),
        ]))
        elements.append(log_table)

        doc.build(elements)
        buf.seek(0)

        return Response(
            buf.read(),
            mimetype="application/pdf",
            headers={
                "Content-Disposition": "attachment;filename=sentinelx_report.pdf"
            }
        )
    # ── Health (public) ───────────────────────────────────────────────────────

    @app.route("/api/health", methods=["GET"])
    def health():
        host = request.host.split(":")[0]
        return jsonify({
            "status":    "backend_active",
            "version":   "2.0.0",
            "honeypot":  f"https://{host}:5001",
            "dashboard": f"https://{host}:5000/dashboard",
        })

    return app


if __name__ == "__main__":
    import sys
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    app  = create_backend_app()
    port = int(os.getenv("BACKEND_PORT", 5000))
    print("""
╔═══════════════════════════════════════════════════════════╗
║            SentinelX — Team A  (v2.0)                     ║
╠═══════════════════════════════════════════════════════════╣
║  Pawani Wijesekara   — Honeypot Engineer                  ║
║  Naveesha Pathirathna — CVE Analyst                       ║
║  Janith Warawita     — Alerts and QA                      ║
║  Gimashi Gimhara     — Frontend Developer                 ║
╠═══════════════════════════════════════════════════════════╣
║  POST /api/auth/login   — get JWT token                   ║
║  GET  /api/auth/me      — validate token                  ║
║  GET  /api/logs         — attack log list   [auth]        ║
║  GET  /api/stats        — aggregated stats  [auth]        ║
║  GET  /api/alerts       — alert list        [auth]        ║
║  GET  /api/alerts/summary — alert summary   [auth]        ║
║  GET  /api/honeypots    — list honeypots    [auth]        ║
║  POST /api/honeypots    — create honeypot   [admin]       ║
║  PUT  /api/honeypots/<id>      — update     [admin]       ║
║  DEL  /api/honeypots/<id>      — delete     [admin]       ║
║  POST /api/honeypots/<id>/toggle — enable/disable [admin] ║
║  GET  /api/honeypots/audit     — config audit log [admin] ║
║  GET  /api/report/csv   — export CSV        [admin]       ║
║  GET  /api/report/pdf   — export PDF        [admin]       ║
╠═══════════════════════════════════════════════════════════╣
║  Credentials:                                             ║
║    admin   / SentinelX@2026  (or env ADMIN_PASSWORD)      ║
║    analyst / Analyst@2026    (or env ANALYST_PASSWORD)    ║
╚═══════════════════════════════════════════════════════════╝
""")
    CERT_FILE = os.path.join(BASE_DIR, "cert.pem")
    KEY_FILE  = os.path.join(BASE_DIR, "key.pem")
    ssl_ctx   = (CERT_FILE, KEY_FILE) if os.path.exists(CERT_FILE) else None
    scheme    = "https" if ssl_ctx else "http"

    print(f"  Running on: {scheme}://localhost:{port}")
    print(f"  Dashboard:  {scheme}://localhost:{port}/dashboard\n")
    app.run(host="0.0.0.0", port=port, debug=False, ssl_context=ssl_ctx)
