import os
import sys
import threading
import time
import webbrowser
import subprocess

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

PRODUCTION = "--production" in sys.argv


def run_honeypot():
    from honeypot.app import create_honeypot_app
    app = create_honeypot_app()
    app.run(host="0.0.0.0", port=5001, debug=False, use_reloader=False, threaded=True)


def run_backend():
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), "backend"))
    from backend.app import create_backend_app
    app = create_backend_app()
    app.run(host="0.0.0.0", port=5000, debug=False, use_reloader=False, threaded=True)


def start_dev_mode():
    t1 = threading.Thread(target=run_honeypot, daemon=True)
    t1.start()
    time.sleep(2)
    print("  ✅ Honeypot   → http://localhost:5001  (Flask dev server, threaded)")

    t2 = threading.Thread(target=run_backend, daemon=True)
    t2.start()
    time.sleep(2)
    print("  ✅ Backend    → http://localhost:5000  (Flask dev server, threaded)")
    return []


def start_production_mode():
    """
    Launches both services under Gunicorn with 4 worker processes each,
    instead of Flask's single-process development server. This is what
    NFR-01/NFR-08 load testing should run against, since Flask's own
    dev server explicitly warns it is not meant for production use.
    """
    procs = []

    honeypot_proc = subprocess.Popen([
        "gunicorn", "-w", "4", "-b", "0.0.0.0:5001", "wsgi_honeypot:app",
        "--access-logfile", "honeypot_gunicorn_access.log",
        "--error-logfile", "honeypot_gunicorn_error.log",
    ])
    procs.append(honeypot_proc)
    time.sleep(2)
    print("  ✅ Honeypot   → http://localhost:5001  (Gunicorn, 4 workers)")

    backend_proc = subprocess.Popen([
        "gunicorn", "-w", "4", "-b", "0.0.0.0:5000", "wsgi_backend:app",
        "--access-logfile", "backend_gunicorn_access.log",
        "--error-logfile", "backend_gunicorn_error.log",
    ])
    procs.append(backend_proc)
    time.sleep(2)
    print("  ✅ Backend    → http://localhost:5000  (Gunicorn, 4 workers)")

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

    production_procs = start_production_mode() if PRODUCTION else start_dev_mode()

    print("""  
  ─────────────────────────────────────────
  Open Firefox and go to:
  http://localhost:5000/dashboard

  Login:
    Login with your configured credentials.
  
  ─────────────────────────────────────────
  Press Ctrl+C to stop all services.
    """)

    webbrowser.open("http://localhost:5000/dashboard")

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
