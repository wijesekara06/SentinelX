import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from honeypot.app import create_honeypot_app

if __name__ == "__main__":
    app  = create_honeypot_app()
    port = int(os.getenv("HONEYPOT_PORT", 5001))

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
    print(f"  Health API : http://localhost:{port}/api/health\n")

    app.run(host="0.0.0.0", port=port, debug=False)
