"""
SentinelX - Production WSGI entry point (Honeypot service)

Run with Gunicorn instead of the Flask development server:
    gunicorn -w 4 -b 0.0.0.0:5001 wsgi_honeypot:app
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from honeypot.app import create_honeypot_app

app = create_honeypot_app()
