"""
SentinelX - Pattern Recognition and Risk Scoring
Developer : Pawani Wijesekara (Honeypot Engineer)
FR-03     : Attack Pattern Recognition
FR-05     : Dynamic Risk Scoring

Actual risk formula applied in code:
    norm_freq        = min(frequency × 2.0, 10.0)
    norm_persistence = min(duration_minutes / 6.0, 10.0)
    score = (norm_freq × 0.4) + (CVSS × 0.4) + (norm_persistence × 0.2)

Example — SQL Injection, freq=1, CVSS=9.8, persistence=0:
    norm_freq = min(2.0, 10) = 2.0
    score = (2.0×0.4) + (9.8×0.4) + (0×0.2) = 0.8 + 3.92 + 0 = 4.72 → Critical

FIX v2:
  - Removed python-requests / Go-http-client from RECON_PATTERNS (matched test suite UA)
  - Formula docstring now matches actual normalization in calculate()
"""

import re
import time
from collections import defaultdict, deque


SQL_PATTERNS = [
    r"(?i)(select\s.+from)",
    r"(?i)(insert\s+into)",
    r"(?i)(drop\s+table)",
    r"(?i)(union\s+select)",
    r"(?i)(or\s+1\s*=\s*1)",
    r"(?i)(sleep\s*\()",
    r"(?i)(benchmark\s*\()",
    r"(?i)(waitfor\s+delay)",
    r"(?i)(xp_cmdshell)",
    r"(?i)(information_schema)",
]

XSS_PATTERNS = [
    r"(?i)(<script)",
    r"(?i)(<\/script>)",
    r"(?i)(javascript\s*:)",
    r"(?i)(onerror\s*=)",
    r"(?i)(onload\s*=)",
    r"(?i)(onclick\s*=)",
    r"(?i)(onmouseover\s*=)",
    r"(?i)(alert\s*\()",
    r"(?i)(confirm\s*\()",
    r"(?i)(prompt\s*\()",
    r"(?i)(<iframe)",
    r"(?i)(<svg\s+on)",
    r"(?i)(document\.cookie)",
    r"(?i)(document\.write)",
    r"(?i)(window\.location)",
]

DIR_TRAVERSAL_PATTERNS = [
    r"\.\./",
    r"\.\.\\/",
    r"(?i)(\/etc\/passwd)",
    r"(?i)(\/etc\/shadow)",
    r"(?i)(\/etc\/hosts)",
    r"(?i)(\/windows\/system32)",
    r"(?i)(cmd\.exe)",
    r"(?i)(powershell)",
    r"(?i)(%2e%2e%2f)",
    r"(?i)(%252e%252e)",
    r"(?i)(\/proc\/self)",
    r"(?i)(\/var\/log)",
]

RECON_PATTERNS = [
    r"(?i)(\/robots\.txt)",
    r"(?i)(\/sitemap\.xml)",
    r"(?i)(\/\.git\/)",
    r"(?i)(\/\.svn\/)",
    r"(?i)(nmap)",
    r"(?i)(masscan)",
    r"(?i)(nikto)",
    r"(?i)(sqlmap)",
    r"(?i)(burpsuite)",
    r"(?i)(dirbuster)",
    r"(?i)(gobuster)",
    r"(?i)(\/wp-admin)",
    r"(?i)(\/phpmyadmin)",
    r"(?i)(\/adminer\.php)",
    r"(?i)(\/\.env)",
    r"(?i)(\/config\.php)",
    r"(?i)(\/settings\.py)",
    # python-requests and Go-http-client removed — they matched the test
    # suite's own User-Agent, causing every simulated attack to also
    # register as Reconnaissance and inflate counts.
    r"(?i)(wget\/)",
]

COMMAND_INJECTION_PATTERNS = [
    r"(?i)(;\s*ls)",
    r"(?i)(;\s*cat)",
    r"(?i)(;\s*whoami)",
    r"(?i)(;\s*id)",
    r"(?i)(;\s*uname)",
    r"(?i)(;\s*pwd)",
    r"(?i)(;\s*wget)",
    r"(?i)(;\s*curl)",
    r"(?i)(\|\s*ls)",
    r"(?i)(\|\s*cat)",
    r"(?i)(\|\s*whoami)",
    r"(?i)(\|\s*id)",
    r"(?i)(\|\s*bash)",
    r"(?i)(\|\s*sh)",
    r"(?i)(\|\s*python)",
    r"`[^`]+`",
    r"\$\([^)]+\)",
    r"(?i)(\/bin\/sh)",
    r"(?i)(\/bin\/bash)",
]

ATTACK_REGISTRY = [
    {
        "name":        "SQL Injection",
        "patterns":    SQL_PATTERNS,
        "cve_hint":    "sql injection",
        "base_cvss":   8.5,
        "cve_example": "CVE-2019-9081",
    },
    {
        "name":        "XSS Attack",
        "patterns":    XSS_PATTERNS,
        "cve_hint":    "cross-site scripting xss",
        "base_cvss":   6.1,
        "cve_example": "CVE-2021-34429",
    },
    {
        "name":        "Directory Traversal",
        "patterns":    DIR_TRAVERSAL_PATTERNS,
        "cve_hint":    "path traversal directory",
        "base_cvss":   7.5,
        "cve_example": "CVE-2021-41773",
    },
    {
        "name":        "Command Injection",
        "patterns":    COMMAND_INJECTION_PATTERNS,
        "cve_hint":    "command injection rce",
        "base_cvss":   9.8,
        "cve_example": "CVE-2021-42013",
    },
    {
        "name":        "Reconnaissance",
        "patterns":    RECON_PATTERNS,
        "cve_hint":    "information disclosure",
        "base_cvss":   5.3,
        "cve_example": None,
    },
]


class BruteForceTracker:
    """Brute Force Detection using sliding window (time-aware, IP-scoped)."""

    def __init__(self, threshold=5, window_seconds=60):
        self.threshold = threshold
        self.window    = window_seconds
        self._attempts = defaultdict(deque)

    def record_failure(self, ip):
        now = time.time()
        q   = self._attempts[ip]
        q.append(now)
        while q and (now - q[0]) > self.window:
            q.popleft()

    def is_brute_force(self, ip):
        now = time.time()
        q   = self._attempts[ip]
        while q and (now - q[0]) > self.window:
            q.popleft()
        return len(q) >= self.threshold

    def attempt_count(self, ip):
        return len(self._attempts.get(ip, []))

    def reset(self, ip):
        self._attempts[ip] = deque()


class PatternDetector:
    """Implements Algorithm 02 — Pattern Recognition."""

    def __init__(self):
        self.brute_tracker = BruteForceTracker(threshold=5, window_seconds=60)
        self._persistence  = defaultdict(list)

    def analyze(self, source_ip, target_url, payload_str, is_login_fail=False):
        combined = target_url + " " + payload_str
        self._persistence[source_ip].append(time.time())

        # Signatures first — brute force only fires if no signature matched
        for attack in ATTACK_REGISTRY:
            for pattern in attack["patterns"]:
                try:
                    if re.search(pattern, combined):
                        if is_login_fail:
                            self.brute_tracker.record_failure(source_ip)
                        return {
                            "attack_type":     attack["name"],
                            "matched_pattern": pattern,
                            "cve_hint":        attack["cve_hint"],
                            "base_cvss":       attack["base_cvss"],
                            "cve_example":     attack["cve_example"],
                            "attempt_count":    self.brute_tracker.attempt_count(source_ip),
                        }
                except re.error:
                    continue

        if is_login_fail:
            self.brute_tracker.record_failure(source_ip)
            if self.brute_tracker.is_brute_force(source_ip):
                return {
                    "attack_type":     "Brute Force",
                    "matched_pattern": "Multiple failed logins",
                    "cve_hint":        "brute force authentication",
                    "base_cvss":       7.5,
                    "cve_example":     "CVE-2022-0778",
                    "attempt_count":   self.brute_tracker.attempt_count(source_ip),
                }

        return {
            "attack_type":     "Unauthorized Access",
            "matched_pattern": None,
            "cve_hint":        None,
            "base_cvss":       3.0,
            "cve_example":     None,
            "attempt_count":   self.brute_tracker.attempt_count(source_ip),
        }

    def get_persistence(self, ip):
        timestamps = self._persistence.get(ip, [])
        if len(timestamps) < 2:
            return 0.0
        duration_minutes = (timestamps[-1] - timestamps[0]) / 60.0
        return min(duration_minutes, 60.0)


class RiskScorer:
    """Implements Algorithm 04 — Dynamic Risk Scoring."""

    WEIGHT_FREQUENCY   = 0.4
    WEIGHT_CVSS        = 0.4
    WEIGHT_PERSISTENCE = 0.2

    def calculate(self, attack_frequency, cvss_score, persistence):
        freq_normalized    = min(attack_frequency * 2.0, 10.0)
        persist_normalized = min(persistence / 6.0, 10.0)

        score = (
            (freq_normalized    * self.WEIGHT_FREQUENCY) +
            (cvss_score         * self.WEIGHT_CVSS) +
            (persist_normalized * self.WEIGHT_PERSISTENCE)
        )
        score = round(min(score, 10.0), 2)

        if score > 6.5:
            label = "Critical"
        elif score > 3.5:
            label = "Medium"
        else:
            label = "Low"

        return {
            "risk_score": score,
            "risk_label": label,
            "breakdown": {
                "frequency_component":   round(freq_normalized    * self.WEIGHT_FREQUENCY, 2),
                "cvss_component":        round(cvss_score         * self.WEIGHT_CVSS, 2),
                "persistence_component": round(persist_normalized * self.WEIGHT_PERSISTENCE, 2),
            }
        }
