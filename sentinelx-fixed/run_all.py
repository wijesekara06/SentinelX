import os
import sys
import threading
import time
import webbrowser

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def run_honeypot():
    from honeypot.app import create_honeypot_app
    app = create_honeypot_app()
    app.run(host="0.0.0.0", port=5001, debug=False, use_reloader=False)

def run_backend():
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), "backend"))
    from backend.app import create_backend_app
    app = create_backend_app()
    app.run(host="0.0.0.0", port=5000, debug=False, use_reloader=False)


if __name__ == "__main__":
    print("""
╔══════════════════════════════════════════════════════╗
║           SentinelX — Full System Startup            ║
║                    Team A                            ║
╠══════════════════════════════════════════════════════╣
║  Starting all services...                            ║
╚══════════════════════════════════════════════════════╝
""")

    t1 = threading.Thread(target=run_honeypot, daemon=True)
    t1.start()
    time.sleep(2)
    print("  ✅ Honeypot   → http://localhost:5001")

    t2 = threading.Thread(target=run_backend, daemon=True)
    t2.start()
    time.sleep(2)
    print("  ✅ Backend    → http://localhost:5000")

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
        print("\n  SentinelX stopped.")
