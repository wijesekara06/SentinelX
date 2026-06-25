"""
SentinelX - CVE Correlation Module
Developer : Naveesha Pathirathna (CVE Analyst)
FR-04     : Automated CVE Correlation
Algorithm 03: CVE Correlation Algorithm (Fig. 7)

Naveesha's Deliverables:
- NVD API integration (NIST National Vulnerability Database)
- CVE ID mapping for each attack type
- CVSS severity score retrieval
- Offline CVE fallback map
- Local cache system for performance

FOR each detected attack:
    EXTRACT service name and exploit signature
    SEARCH CVE database for matching vulnerability
    IF match found:
        RETRIEVE CVE ID
        RETRIEVE CVSS score
    ELSE:
        LABEL as Unknown Exploit
END FOR
STORE CVE mapping results
"""

import requests
import json
import os
import time

NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_API_KEY  = os.getenv("NVD_API_KEY", "")
CACHE_FILE   = os.path.join(os.path.dirname(__file__), ".cve_cache.json")

OFFLINE_CVE_MAP = {
    "SQL Injection": {
        "cve_id":      "CVE-2019-9081",
        "cvss_score":  9.8,
        "description": "SQL Injection vulnerability allowing remote code execution.",
        "severity":    "CRITICAL",
    },
    "XSS Attack": {
        "cve_id":      "CVE-2021-34429",
        "cvss_score":  6.1,
        "description": "Cross-Site Scripting vulnerability allows injection of JavaScript.",
        "severity":    "MEDIUM",
    },
    "Directory Traversal": {
        "cve_id":      "CVE-2021-41773",
        "cvss_score":  7.5,
        "description": "Path traversal vulnerability in Apache HTTP Server 2.4.49.",
        "severity":    "HIGH",
    },
    "Command Injection": {
        "cve_id":      "CVE-2021-42013",
        "cvss_score":  9.8,
        "description": "Command injection leading to remote code execution.",
        "severity":    "CRITICAL",
    },
    "Brute Force": {
        "cve_id":      "CVE-2022-0778",
        "cvss_score":  7.5,
        "description": "Infinite loop in OpenSSL exploitable via brute-force.",
        "severity":    "HIGH",
    },
    "Reconnaissance": {
        "cve_id":      "CVE-2017-9798",
        "cvss_score":  5.3,
        "description": "Apache OPTIONS method information disclosure.",
        "severity":    "MEDIUM",
    },
    "Unauthorized Access": {
        "cve_id":      None,
        "cvss_score":  3.0,
        "description": "No specific CVE matched. Unknown exploit attempt.",
        "severity":    "LOW",
    },
}


class CVECorrelator:
    """
    Naveesha Pathirathna - CVE Analyst
    Implements Algorithm 03 - CVE Correlation Algorithm.
    Attempts live NVD API lookup first.
    Falls back to local cache then offline map.
    """
    RETRY_AFTER = 300 #retry the NVD API after 5 minutes
    
    def __init__(self):
        self._cache         = self._load_cache()
        self._api_failed_at = 0


    def correlate(self, attack_type, cve_hint=None):
        """
        Map an attack type to a CVE entry.
        Step 1 - Check local cache
        Step 2 - Try live NVD API
        Step 3 - Use offline map as fallback
        """
        # Step 1 - Check local cache first
        if attack_type in self._cache:
            cached = self._cache[attack_type]
            cached["source"] = "cache"
            return cached

        # Step 2 - Try live NVD API
        if cve_hint and (time.time() - self._api_failed_at > self.RETRY_AFTER):
            result = self._query_nvd(cve_hint)
            if result:
                result["source"] = "nvd_api"
                self._cache[attack_type] = result
                self._save_cache()
                return result
            else:
                self._api_failed_at = time.time()
        # Step 3 - Offline fallback
        offline = OFFLINE_CVE_MAP.get(
            attack_type,
            OFFLINE_CVE_MAP["Unauthorized Access"]
        )
        result = dict(offline)
        result["source"] = "offline_map"
        return result

    def _query_nvd(self, keyword, max_results=1):
        """
        Query NIST NVD API for CVE data.
        Naveesha - NVD API Integration
        """
        params  = {
            "keywordSearch":  keyword,
            "resultsPerPage": max_results,
            "startIndex":     0
        }
        headers = {}
        if NVD_API_KEY:
            headers["apiKey"] = NVD_API_KEY

        try:
            response = requests.get(
                NVD_API_BASE,
                params=params,
                headers=headers,
                timeout=5
            )
            if response.status_code != 200:
                return None

            data  = response.json()
            vulns = data.get("vulnerabilities", [])
            if not vulns:
                return None

            cve_data    = vulns[0].get("cve", {})
            cve_id      = cve_data.get("id", "Unknown")
            desc_list   = cve_data.get("descriptions", [])
            description = next(
                (d["value"] for d in desc_list if d.get("lang") == "en"),
                "No description available."
            )

            metrics    = cve_data.get("metrics", {})
            cvss_score = 0.0
            severity   = "UNKNOWN"

            for metric_key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                metric_list = metrics.get(metric_key, [])
                if metric_list:
                    cvss_data  = metric_list[0].get("cvssData", {})
                    cvss_score = cvss_data.get("baseScore", 0.0)
                    severity   = cvss_data.get("baseSeverity", "UNKNOWN")
                    break

            return {
                "cve_id":      cve_id,
                "cvss_score":  float(cvss_score),
                "description": description[:500],
                "severity":    severity,
            }

        except requests.exceptions.Timeout:
            print("[CVECorrelator] NVD API timeout — using offline fallback")
            return None
        except Exception as e:
            print(f"[CVECorrelator] NVD API error: {e}")
            return None

    def _load_cache(self):
        """Load previously fetched CVE results from disk."""
        if os.path.exists(CACHE_FILE):
            try:
                with open(CACHE_FILE, "r") as f:
                    return json.load(f)
            except Exception:
                pass
        return {}

    def _save_cache(self):
        """Save CVE results to disk cache."""
        try:
            with open(CACHE_FILE, "w") as f:
                json.dump(self._cache, f, indent=2)
        except Exception as e:
            print(f"[CVECorrelator] Cache save error: {e}")
