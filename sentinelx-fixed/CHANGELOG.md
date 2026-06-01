# SentinelX Changelog

## v2.0.0 — Bug Fixes & Security Improvements

### Bug Fixes

**1. Dead code removed — `honeypot/endpoints.py`**
- `process_request()` had an entire duplicate payload-parsing and detection
  block after the first `return log_entry` statement, making it completely
  unreachable. Removed cleanly.

**2. Recon false-positive on test suite — `honeypot/pattern_detector.py`**
- `python-requests` and `Go-http-client` were listed in `RECON_PATTERNS`.
  Since `test_honeypot.py` uses the `requests` library, every simulated
  attack also generated a spurious Reconnaissance event, inflating counts.
  Both entries removed from the pattern list.

**3. Alert threshold mismatch — `honeypot/alert_generator.py`**
- `MEDIUM_RISK_THRESHOLD = 5.0` meant alerts were silently dropped for all
  events with risk scores between 2.5 and 5.0, even though `RiskScorer`
  labels those as Medium. Threshold corrected to 2.5 (matches label boundary).
  Constant renamed to `ALERT_THRESHOLD` for clarity.

**4. Unauthenticated API endpoints — `backend/app.py`**
- `/api/logs`, `/api/stats`, `/api/alerts`, `/api/alerts/summary`, and
  `/api/alerts/<id>/ack` were all publicly accessible without a token,
  despite the dashboard requiring login. `require_auth()` applied to all.

**5. Formula docstring mismatch — `honeypot/pattern_detector.py`**
- The module docstring stated `Risk = (Freq × 0.4) + (CVSS × 0.4) + (Pers × 0.2)`
  but the actual code normalizes inputs before applying weights. Docstring
  updated to show the true formula including normalization steps.

**6. Directory traversal test paths — `tests/test_honeypot.py`**
- Literal `../../` paths are normalized by the HTTP client stack before the
  request is sent; the honeypot never saw them. Tests now use
  percent-encoded equivalents (`%2e%2e%2f`) which survive transport.

**7. Test suite missing auth headers — `tests/test_honeypot.py`**
- Backend API calls in the test suite now obtain a JWT token via
  `/api/auth/login` and include `Authorization: Bearer <token>` on all
  requests to authenticated endpoints.

### Improvements

- `backend/app.py`: JWT secret and user passwords are now loaded from
  environment variables (`JWT_SECRET`, `ADMIN_PASSWORD`, `ANALYST_PASSWORD`)
  with dev-mode fallbacks and a printed warning when defaults are used.
- `backend/app.py`: New `/api/auth/me` endpoint — validates a stored token
  and returns the current user's username and role.
- `backend/app.py`: `analyst` role can now access `/api/logs`, `/api/stats`,
  `/api/alerts`, and `/api/alerts/summary` (read-only). Only `admin` can
  acknowledge alerts or export CSV.
- `DEMO_GUIDE_v2.md`: Corrected CVE table labels, risk score examples,
  directory traversal curl commands, and API auth flow.
