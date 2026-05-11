"""
modules/database.py
SQLite-based persistent storage for alerts, events, login logs
"""

import sqlite3
import os
import datetime
from typing import Optional

DB_PATH = os.path.join(os.path.dirname(__file__), "..", "acis.db")

SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4, "WARNING": 5}


class Database:

    def __init__(self):
        self.db_path = os.path.abspath(DB_PATH)
        self.init_db()

    def _conn(self):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def init_db(self):
        with self._conn() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS events (
                    id        INTEGER PRIMARY KEY AUTOINCREMENT,
                    ts        TEXT    NOT NULL,
                    category  TEXT    NOT NULL,
                    message   TEXT    NOT NULL,
                    severity  TEXT    NOT NULL DEFAULT 'INFO',
                    source    TEXT    DEFAULT '',
                    dismissed INTEGER DEFAULT 0
                )
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts)
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_events_sev ON events(severity)
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS pentest_reports (
                    id            INTEGER PRIMARY KEY AUTOINCREMENT,
                    ts            TEXT    NOT NULL,
                    target        TEXT    NOT NULL,
                    normalized_url TEXT   NOT NULL,
                    host          TEXT    NOT NULL,
                    target_ip     TEXT    DEFAULT '',
                    status        TEXT    NOT NULL,
                    risk_score    INTEGER NOT NULL DEFAULT 0,
                    summary       TEXT    DEFAULT '',
                    duration_ms   INTEGER NOT NULL DEFAULT 0,
                    checks_json   TEXT    NOT NULL,
                    findings_json TEXT    NOT NULL,
                    requestor     TEXT    DEFAULT ''
                )
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_pentest_ts ON pentest_reports(ts)
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_pentest_risk ON pentest_reports(risk_score)
            """)
            conn.commit()

    def log_event(self, category: str, message: str,
                  severity: str = "INFO", source: str = "") -> int:
        ts = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
        with self._conn() as conn:
            cur = conn.execute(
                "INSERT INTO events (ts, category, message, severity, source) VALUES (?,?,?,?,?)",
                (ts, category, message, severity, source)
            )
            conn.commit()
            return cur.lastrowid

    def get_recent_alerts(self, limit: int = 100) -> list:
        with self._conn() as conn:
            rows = conn.execute(
                """SELECT id, ts, category, message, severity, source, dismissed
                   FROM events
                   ORDER BY id DESC
                   LIMIT ?""",
                (limit,)
            ).fetchall()
        return [dict(r) for r in rows]

    def get_alert_stats(self) -> dict:
        with self._conn() as conn:
            total    = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
            critical = conn.execute("SELECT COUNT(*) FROM events WHERE severity='CRITICAL'").fetchone()[0]
            high     = conn.execute("SELECT COUNT(*) FROM events WHERE severity='HIGH'").fetchone()[0]
            medium   = conn.execute("SELECT COUNT(*) FROM events WHERE severity='MEDIUM'").fetchone()[0]
            info     = conn.execute("SELECT COUNT(*) FROM events WHERE severity='INFO'").fetchone()[0]
            today    = conn.execute(
                "SELECT COUNT(*) FROM events WHERE ts >= date('now')"
            ).fetchone()[0]
        return {
            "total": total, "critical": critical, "high": high,
            "medium": medium, "info": info, "today": today,
        }

    def dismiss_alert(self, alert_id: int):
        with self._conn() as conn:
            conn.execute("UPDATE events SET dismissed=1 WHERE id=?", (alert_id,))
            conn.commit()

    def clear_old_events(self, days: int = 30):
        cutoff = (datetime.datetime.utcnow() - datetime.timedelta(days=days)).strftime("%Y-%m-%d")
        with self._conn() as conn:
            conn.execute("DELETE FROM events WHERE ts < ?", (cutoff,))
            conn.commit()

    def save_pentest_report(self, report: dict) -> int:
        with self._conn() as conn:
            cur = conn.execute(
                """INSERT INTO pentest_reports
                   (ts, target, normalized_url, host, target_ip, status, risk_score,
                    summary, duration_ms, checks_json, findings_json, requestor)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    report.get("ts", ""),
                    report.get("target", ""),
                    report.get("normalized_url", ""),
                    report.get("host", ""),
                    report.get("target_ip", ""),
                    report.get("status", "UNKNOWN"),
                    int(report.get("risk_score", 0)),
                    report.get("summary", ""),
                    int(report.get("duration_ms", 0)),
                    report.get("checks_json", "[]"),
                    report.get("findings_json", "[]"),
                    report.get("requestor", ""),
                )
            )
            conn.commit()
            return cur.lastrowid

    def get_pentest_report(self, report_id: int) -> Optional[dict]:
        with self._conn() as conn:
            row = conn.execute(
                """SELECT id, ts, target, normalized_url, host, target_ip, status,
                          risk_score, summary, duration_ms, checks_json,
                          findings_json, requestor
                   FROM pentest_reports WHERE id=?""",
                (report_id,)
            ).fetchone()
        return dict(row) if row else None

    def get_recent_pentest_reports(self, limit: int = 25) -> list:
        with self._conn() as conn:
            rows = conn.execute(
                """SELECT id, ts, target, normalized_url, host, target_ip, status,
                          risk_score, summary, duration_ms, requestor
                   FROM pentest_reports
                   ORDER BY id DESC
                   LIMIT ?""",
                (limit,)
            ).fetchall()
        return [dict(r) for r in rows]
