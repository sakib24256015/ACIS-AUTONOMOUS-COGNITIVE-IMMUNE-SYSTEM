"""
ACIS: Autonomous Cognitive Immune System for Cyber Defense
Real-time Security Operations Dashboard
Daffodil International University - Department of Cyber Security
"""

import os
import json
import time
import hashlib
from datetime import datetime, timedelta
from functools import wraps
from flask import (Flask, render_template, redirect, url_for,
                   request, session, jsonify, flash)

from modules.monitor import SystemMonitor
from modules.threat_analyzer import ThreatAnalyzer
from modules.web_pentest import WebPentestScanner
from modules.database import Database

app = Flask(__name__)
app.secret_key = os.environ.get("ACIS_SECRET_KEY", hashlib.sha256(b"ACIS-242-56-015").hexdigest())
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("ACIS_COOKIE_SECURE", "1").lower() not in {"0", "false", "no"},
)
app.permanent_session_lifetime = timedelta(hours=8)

monitor = SystemMonitor()
analyzer = ThreatAnalyzer()
web_pentest = WebPentestScanner(
    allow_private_targets=os.environ.get("ACIS_ALLOW_PRIVATE_TARGETS", "").lower() in {"1", "true", "yes"}
)
db = Database()

# ── Auth credentials (also saved in credentials.txt) ─────────────────────────
USERS = {
    "admin":    hashlib.sha256(b"ACIS@2024!").hexdigest(),
    "sakib":    hashlib.sha256(b"DIU@242-56-015").hexdigest(),
    "analyst":  hashlib.sha256(b"analyst123").hexdigest(),
}

STUDENT_INFO = {
    "submitted_by": "MD RAFSHAN RAHMAN SAKIB",
    "id":           "242-56-015",
    "department":   "DEPARTMENT OF CYBER SECURITY",
    "submitted_to": "DR MD FAZLA ELAHE",
    "supervisor_dept": "DEPARTMENT OF SOFTWARE ENGINEERING",
    "university":   "DAFFODIL INTERNATIONAL UNIVERSITY",
}

# ── Login required decorator ──────────────────────────────────────────────────
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user" not in session:
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated

# ── Context processor — inject student info & time into every template ────────
@app.context_processor
def inject_globals():
    return {
        "student_info": STUDENT_INFO,
        "now": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
        "current_user": session.get("user", ""),
    }

# ═════════════════════════════════════════════════════════════════════════════
# AUTH ROUTES
# ═════════════════════════════════════════════════════════════════════════════

@app.route("/", methods=["GET", "POST"])
@app.route("/login", methods=["GET", "POST"])
def login():
    if "user" in session:
        return redirect(url_for("dashboard"))

    error = None
    if request.method == "POST":
        username = request.form.get("username", "").strip().lower()
        password = request.form.get("password", "")
        pw_hash  = hashlib.sha256(password.encode()).hexdigest()

        if username in USERS and USERS[username] == pw_hash:
            session.permanent = True
            session["user"] = username
            db.log_event("AUTH", f"Successful login: {username}", "INFO", request.remote_addr)
            return redirect(url_for("dashboard"))
        else:
            error = "AUTHENTICATION FAILED — INVALID CREDENTIALS"
            db.log_event("AUTH", f"Failed login attempt: {username}", "WARNING", request.remote_addr)

    return render_template("login.html", error=error)

@app.route("/logout")
def logout():
    user = session.pop("user", None)
    if user:
        db.log_event("AUTH", f"User logged out: {user}", "INFO", request.remote_addr)
    return redirect(url_for("login"))

# ═════════════════════════════════════════════════════════════════════════════
# MAIN PAGES
# ═════════════════════════════════════════════════════════════════════════════

@app.route("/dashboard")
@login_required
def dashboard():
    metrics    = monitor.get_system_metrics()
    alerts     = db.get_recent_alerts(10)
    stats      = db.get_alert_stats()
    top_procs  = monitor.get_top_processes(5)
    connections = monitor.get_connections()
    flagged    = [c for c in connections if c.get("flagged")]
    return render_template("dashboard.html",
                           metrics=metrics,
                           alerts=alerts,
                           stats=stats,
                           top_procs=top_procs,
                           flagged_count=len(flagged))

@app.route("/network")
@login_required
def network():
    interfaces  = monitor.get_interfaces()
    connections = monitor.get_connections()
    metrics     = monitor.get_system_metrics()
    host_info   = monitor.get_host_info()
    flagged_count = len([c for c in connections if c.get("flagged")])
    return render_template("network.html",
                           interfaces=interfaces,
                           connections=connections,
                           metrics=metrics,
                           host_info=host_info,
                           flagged_count=flagged_count)

@app.route("/processes")
@login_required
def processes():
    procs   = monitor.get_all_processes()
    metrics = monitor.get_system_metrics()
    return render_template("processes.html", processes=procs, metrics=metrics)

@app.route("/alerts")
@login_required
def alerts():
    all_alerts = db.get_recent_alerts(200)
    stats      = db.get_alert_stats()
    return render_template("alerts.html", alerts=all_alerts, stats=stats)

@app.route("/pentest", methods=["GET", "POST"])
@login_required
def pentest():
    stats = db.get_alert_stats()
    reports = db.get_recent_pentest_reports(25)
    error = None

    if request.method == "POST":
        target = request.form.get("target", "").strip()
        authorized = request.form.get("authorized") == "on"
        if not authorized:
            error = "AUTHORIZATION REQUIRED — CONFIRM YOU OWN OR HAVE WRITTEN PERMISSION TO TEST THIS TARGET"
            db.log_event("PENTEST", f"Pentest blocked without authorization confirmation: {target}", "WARNING", request.remote_addr)
        elif not target:
            error = "TARGET URL IS REQUIRED"
        else:
            db.log_event("PENTEST", f"Authorized web pentest started for {target}", "INFO", request.remote_addr)
            report = web_pentest.run(target, requestor=session.get("user", ""))
            report_id = db.save_pentest_report(report)
            db.log_event(
                "PENTEST",
                f"Web pentest completed for {report.get('normalized_url') or target} with risk score {report['risk_score']} (report #{report_id})",
                "HIGH" if report["risk_score"] >= 50 else "MEDIUM" if report["risk_score"] >= 25 else "INFO",
                report.get("host", target),
            )
            return redirect(url_for("pentest_report", report_id=report_id))

    return render_template("pentest.html", reports=reports, stats=stats, error=error)

@app.route("/pentest/report/<int:report_id>")
@login_required
def pentest_report(report_id):
    report = db.get_pentest_report(report_id)
    if not report:
        return render_template("404.html"), 404
    report["checks"] = json.loads(report.get("checks_json") or "[]")
    report["findings"] = json.loads(report.get("findings_json") or "[]")
    stats = db.get_alert_stats()
    db.log_event("PENTEST", f"Pentest report viewed: #{report_id}", "INFO", request.remote_addr)
    return render_template("pentest_report.html", report=report, stats=stats)

@app.route("/system")
@login_required
def system_info():
    host    = monitor.get_host_info()
    metrics = monitor.get_system_metrics()
    disks   = monitor.get_disk_info()
    temps   = monitor.get_temperatures()
    return render_template("system.html",
                           host=host,
                           metrics=metrics,
                           disks=disks,
                           temps=temps)

# ═════════════════════════════════════════════════════════════════════════════
# API — REAL-TIME DATA ENDPOINTS
# ═════════════════════════════════════════════════════════════════════════════

@app.route("/api/metrics")
@login_required
def api_metrics():
    return jsonify(monitor.get_system_metrics())

@app.route("/api/connections")
@login_required
def api_connections():
    conns = monitor.get_connections()
    # Run threat analysis and log any new alerts
    for conn in conns:
        if conn.get("flagged"):
            db.log_event(
                "NETWORK",
                f"Suspicious connection: {conn['local_addr']} → {conn['remote_addr']} [{conn.get('flag_reason','')}]",
                "HIGH",
                conn.get("remote_addr", ""),
            )
    return jsonify(conns)

@app.route("/api/processes")
@login_required
def api_processes():
    return jsonify(monitor.get_top_processes(20))

@app.route("/api/alerts")
@login_required
def api_alerts():
    return jsonify(db.get_recent_alerts(50))

@app.route("/api/scan")
@login_required
def api_scan():
    """Trigger a full system threat scan and store results."""
    results = analyzer.full_scan(monitor)
    for r in results:
        db.log_event(r["category"], r["message"], r["severity"], r.get("source", ""))
    return jsonify({"scanned": len(results), "results": results})

@app.route("/api/network_traffic")
@login_required
def api_network_traffic():
    return jsonify(monitor.get_traffic_delta())

@app.route("/api/dismiss_alert/<int:alert_id>", methods=["POST"])
@login_required
def dismiss_alert(alert_id):
    db.dismiss_alert(alert_id)
    return jsonify({"ok": True})

# ═════════════════════════════════════════════════════════════════════════════
# ERROR HANDLERS
# ═════════════════════════════════════════════════════════════════════════════

@app.errorhandler(404)
def not_found(e):
    return render_template("404.html"), 404

@app.errorhandler(500)
def server_error(e):
    return jsonify({"error": str(e)}), 500

# ═════════════════════════════════════════════════════════════════════════════
if __name__ == "__main__":
    db.init_db()
    db.log_event("SYSTEM", "ACIS initialized — monitoring active", "INFO", "localhost")
    app.run(host="0.0.0.0", port=5000, debug=False)
