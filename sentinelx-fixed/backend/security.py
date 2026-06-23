"""
SentinelX - Security Utilities
================================
NFR-05 / NFR-06 supporting module.

Contains four things:
  1. HTTP Security Headers  - added to every response automatically
  2. Per-IP Rate Limiting   - stops brute-force abuse of any API endpoint
  3. JWT Token Blacklist    - makes logout actually work server-side
  4. Input Sanitization     - prevents log-injection via crafted usernames

Author: Naveesha Pathirathna (CVE Analyst / Security)
"""

import re
import time
from collections import defaultdict, deque


# ─────────────────────────────────────────────────────────────────────────────
# 1. HTTP SECURITY HEADERS
# ─────────────────────────────────────────────────────────────────────────────
# These headers tell the browser how to behave when displaying your dashboard.
# Without them, attackers can embed your page in an iframe (clickjacking),
# run scripts from other origins (XSS), or sniff the content type.

_SECURITY_HEADERS = {
    "X-Content-Type-Options":  "nosniff",
    "X-Frame-Options":         "DENY",
    "X-XSS-Protection":        "1; mode=block",
    "Referrer-Policy":         "strict-origin-when-cross-origin",
    "Permissions-Policy":      "geolocation=(), microphone=(), camera=()",
    "Content-Security-Policy": (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; "
        "connect-src 'self' http://localhost:5001 http://localhost:5000 "
        "http://127.0.0.1:5001 http://127.0.0.1:5000;"
    ),
}


def apply_security_headers(response):
    """
    This function runs after EVERY response the backend sends.
    It injects the security headers above into that response.
    We register it with:  app.after_request(sec.apply_security_headers)
    """
    for name, value in _SECURITY_HEADERS.items():
        response.headers.setdefault(name, value)
    return response


# ─────────────────────────────────────────────────────────────────────────────
# 2. PER-IP RATE LIMITER
# ─────────────────────────────────────────────────────────────────────────────
# A sliding window means we track WHEN each request arrived, not just how many.
# Example: if max_requests=10 and window=60s, a user can make 10 requests in
# any rolling 60-second period — not 10 at second 0 and 10 more at second 1.
# This prevents abuse at window boundaries.

class SlidingWindowRateLimiter:

    _MAX_KEYS = 50_000   # never track more than 50k IPs at once

    def __init__(self, max_requests: int, window_seconds: int):
        self.max_requests = max_requests
        self.window       = window_seconds
        self._buckets: dict[str, deque] = defaultdict(deque)

    def is_allowed(self, key: str) -> bool:
        """Returns True if this IP is within its limit, False if blocked."""
        now = time.time()
        q   = self._buckets[key]
        # Remove timestamps older than the window
        while q and (now - q[0]) > self.window:
            q.popleft()
        if len(q) >= self.max_requests:
            return False
        if len(self._buckets) < self._MAX_KEYS or key in self._buckets:
            q.append(now)
        return True

    def retry_after(self, key: str) -> int:
        """How many seconds until this IP can try again."""
        q = self._buckets.get(key)
        if not q:
            return 0
        return max(0, int(self.window - (time.time() - q[0])) + 1)


# Two separate limiters with different thresholds:
# - Auth endpoints (login/logout): strict — 10 requests per minute
# - All other API endpoints: relaxed — 120 requests per minute
auth_limiter = SlidingWindowRateLimiter(max_requests=10,  window_seconds=60)
api_limiter  = SlidingWindowRateLimiter(max_requests=120, window_seconds=60)


# ─────────────────────────────────────────────────────────────────────────────
# 3. JWT TOKEN BLACKLIST
# ─────────────────────────────────────────────────────────────────────────────
# The problem with JWTs is they're stateless — once issued, the server has
# no way to cancel them until they expire (8 hours in your case).
# If someone logs out, their token is still technically valid.
#
# The fix: store the token's unique signature in a blacklist on logout.
# verify_token() checks this list first. Blacklisted tokens are rejected
# even though their cryptographic signature is still valid.
#
# Entries auto-expire when the token's own exp time passes, so the list
# doesn't grow forever.

class TokenBlacklist:

    def __init__(self):
        self._store: dict[str, float] = {}   # signature -> expiry timestamp

    def revoke(self, token: str, exp: float) -> None:
        """Add this token to the blacklist until its expiry time."""
        # We only store the signature (3rd segment) — much smaller than
        # storing the whole token string
        sig = token.split(".")[-1] if "." in token else token
        self._store[sig] = float(exp)
        self._purge()

    def is_revoked(self, token: str) -> bool:
        """Returns True if this token was explicitly revoked."""
        self._purge()
        sig = token.split(".")[-1] if "." in token else token
        return sig in self._store

    def _purge(self) -> None:
        """Remove entries for tokens that have naturally expired."""
        now     = time.time()
        expired = [s for s, e in self._store.items() if e < now]
        for s in expired:
            del self._store[s]


token_blacklist = TokenBlacklist()


# ─────────────────────────────────────────────────────────────────────────────
# 4. INPUT SANITIZATION
# ─────────────────────────────────────────────────────────────────────────────
# Your audit log is a file of JSON lines. If an attacker sends a username like:
#   {"actor":"admin"}\n{"actor":"
# ...that string gets written into admin_audit.log and corrupts the JSON.
# This is called log injection.
#
# sanitize() strips anything that isn't a normal printable character.
# is_safe_username() goes further — only a-z, A-Z, 0-9, underscore, hyphen.
# Both "admin" and "analyst" pass. "../../etc/passwd" does not.

_PRINTABLE_RE = re.compile(r"[^\x20-\x7E\t\n\r]")


def sanitize(value: str, max_len: int = 512) -> str:
    """Strip non-printable chars and truncate."""
    if not isinstance(value, str):
        value = str(value)
    return _PRINTABLE_RE.sub("", value)[:max_len]


def is_safe_username(username: str) -> bool:
    """Only allow alphanumeric + underscore/hyphen, 1 to 64 chars."""
    return bool(re.fullmatch(r"[a-zA-Z0-9_\-]{1,64}", username or ""))
