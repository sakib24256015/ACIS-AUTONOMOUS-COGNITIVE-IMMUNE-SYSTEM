#!/home/purefitb/virtualenv/24256015.purefitbd.com/3.11/bin/python3
"""CGI WSGI entrypoint for LiteSpeed/cPanel fallback hosting."""

import os
import sys
from wsgiref.handlers import CGIHandler

APP_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, APP_DIR)
os.environ["SCRIPT_NAME"] = ""

from app import app

CGIHandler().run(app)
