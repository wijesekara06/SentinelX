import os
import sys
import socket
import threading
import time
import webbrowser
import subprocess

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

PRODUCTION = "--production" in sys.argv

BASE_DIR  = os.path.dirname(os.path.abspath(__file__))
CERT_FILE = os.path.join(BASE_DIR, "cert.pem")
KEY_FILE  = os.path.join(BASE_DIR, "key.pem")


def get_local_ip():
    """Detect the machine's LAN IP for the certificate SAN field."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def ensure_certificates():
    """
    Generate a self-signed TLS certificate if one doesn't already exist.
    Covers localhost and the machine's LAN IP via Subject Alternative Names
    so the dashboard works both locally and over the network.
    NFR-06: The system shall use TLS/SSL for all communications.
    """
    if os.path.exists(CERT_FILE) and os.path.exists(KEY_FILE):
        print("  🔒 TLS         → Certificate found (cert.pem / key.pem)")
        return

    local_ip = get_local_ip()
    san = f"subjectAltName=IP:127.0.0.1,IP:{local_ip},DNS:localhost"

    result = subprocess.run([
        "openssl", "req", "-x509",
        "-newkey", "rsa:2048",
        "-keyout", KEY_FILE,
        "-out",    CERT_FILE,
        "-days",   "365",
        "-nodes",
        "-subj",   "/C=LK/ST=Western/L=Colombo/O=SentinelX/OU=Security/CN=localhost",
        "-addext", san,
    ], capture_output=True, text=True)

    if result.returncode == 0:
        print(f"  🔒 TLS         → Certificate generated (localhost + {local_ip}, 365 days)")
    else:
        print(f"  ⚠️  TLS         → Certificate generation FAILED:\n{result.stderr}")
        print("                    Ensure openssl is installed and re-run.")


def run_honeypot():
    from honeypot.app import create_honeypot_app
    app = create_honeypot_app()
    app.run(host="0.0.0.0", port=5001, debug=False, use_reloader=False,
            threaded=True, ssl_context=(CERT_FILE, KEY_FILE))


def run_backend():
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), "backend"))
    from backend.app import create_backend_app
    app = create_backend_app()
    app.run(host="0.0.0.0", port=5000, debug=False, use_reloader=False,
            threaded=True, ssl_context=(CERT_FILE, KEY_FILE))


def start_dev_mode():
    t1 = threading.Thread(target=run_honeypot, daemon=True)
    t1.start()
    time.sleep(2)
    print("  ✅ Honeypot   → https://localhost:5001  (Flask dev server, TLS)")

    t2 = threading.Thread(target=run_backend, daemon=True)
    t2.start()
    time.sleep(2)
    print("  ✅ Backend    → https://localhost:5000  (Flask dev server, TLS)")
    return []


def start_production_mode():
    """
    Launches both services under Gunicorn with TLS enabled.
    NFR-01: Performance under load. NFR-06: TLS on all connections.
    """
    procs = []

    honeypot_proc = subprocess.Popen([
        "gunicorn", "-w", "4", "-b", "0.0.0.0:5001", "wsgi_honeypot:app",
        "--certfile", CERT_FILE, "--keyfile", KEY_FILE,
        "--access-logfile", "honeypot_gunicorn_access.log",
        "--error-logfile",  "honeypot_gunicorn_error.log",
    ])
    procs.append(honeypot_proc)
    time.sleep(2)
    print("  ✅ Honeypot   → https://localhost:5001  (Gunicorn, 4 workers, TLS)")

    backend_proc = subprocess.Popen([
        "gunicorn", "-w", "4", "-b", "0.0.0.0:5000", "wsgi_backend:app",
        "--certfile", CERT_FILE, "--keyfile", KEY_FILE,
        "--access-logfile", "backend_gunicorn_access.log",
        "--error-logfile",  "backend_gunicorn_error.log",
    ])
    procs.append(backend_proc)
    time.sleep(2)
    print("  ✅ Backend    → https://localhost:5000  (Gunicorn, 4 workers, TLS)")

    return procs


if __name__ == "__main__":
    print("""
╔══════════════════════════════════════════════════════╗
║           SentinelX — Full System Startup            ║
║                    Team A                            ║
╠══════════════════════════════════════════════════════╣
║  Starting all services...                            ║
╚══════════════════════════════════════════════════════╝
""")
    print(f"  Mode: {'PRODUCTION (Gunicorn, multi-worker)' if PRODUCTION else 'DEVELOPMENT (Flask dev server, threaded)'}\n")

    ensure_certificates()

    production_procs = start_production_mode() if PRODUCTION else start_dev_mode()

    print("""
  ─────────────────────────────────────────
  NFR-06: TLS/SSL active on all services.

  FIRST-TIME SETUP (self-signed cert):
    1. Open Firefox → https://localhost:5001
       Click Advanced → Accept the Risk
    2. Open Firefox → https://localhost:5000/dashboard
       Click Advanced → Accept the Risk
    You only need to do this once per browser.

  Login with your configured credentials.
  ─────────────────────────────────────────
  Press Ctrl+C to stop all services.
    """)

    webbrowser.open("https://localhost:5000/dashboard")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n  Stopping SentinelX...")
        for p in production_procs:
            p.terminate()
        for p in production_procs:
            p.wait()
        print("  SentinelX stopped.")
