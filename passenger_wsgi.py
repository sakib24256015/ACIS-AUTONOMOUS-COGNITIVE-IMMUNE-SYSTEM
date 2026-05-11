"""
passenger_wsgi.py — cPanel Phusion Passenger entry point
Upload this entire 'acis' folder to your cPanel Python app directory.

Setup Steps on cPanel:
1. Go to cPanel → Setup Python App
2. Python version: 3.9+ (3.11 preferred)
3. Application root: /home/yourusername/acis  (or wherever you uploaded)
4. Application URL: your domain or subdomain
5. Application startup file: passenger_wsgi.py
6. Application entry point: application
7. Click CREATE, then open the virtual environment terminal
8. Run: pip install -r requirements.txt
9. Click RESTART

The app will be live at your configured URL.
"""

import sys
import os

# Add app directory to Python path
APP_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, APP_DIR)

from app import app as application

# Initialize DB on startup
try:
    from modules.database import Database
    db = Database()
    db.init_db()
    db.log_event("SYSTEM", "ACIS boot via Passenger WSGI", "INFO", "server")
except Exception as e:
    pass  # Non-fatal
