"""
SentinelX - Production WSGI entry point (Backend service)

Run with Gunicorn instead of the Flask development server:
    gunicorn -w 4 -b 0.0.0.0:5000 wsgi_backend:app

-w 4   number of worker processes (tune to vCPU count; 2-4x cores is typical)
-b     bind address:port
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "backend"))

from backend.app import create_backend_app

app = create_backend_app()
