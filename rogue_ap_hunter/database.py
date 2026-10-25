"""SQLite storage for trusted APs, detection history and alerts."""

from __future__ import annotations

import csv
import io
import os
import sqlite3
import threading
import time
from typing import Any

from .config import DB_PATH, DATA_DIR


class RogueHunterDB:
    """Thin wrapper around the SQLite database.

    All methods are safe to call repeatedly; the schema is created idempotently
    on first use.  The connection is opened with ``check_same_thread=False``
    and guarded by a lock so it can be used from the scan worker thread as well
    as the main UI thread.  Scans are exclusive, so the lock serializes access
    and keeps SQLite happy.
    """

    def __init__(self, db_path: str | None = None) -> None:
        self.db_path = db_path or DB_PATH
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        self.conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA foreign_keys = ON")
        self._lock = threading.Lock()
        self._init_schema()

    # ------------------------------------------------------------------ #
    # Low-level, thread-safe helpers
    # ------------------------------------------------------------------ #
    def _execute(self, sql: str, params=()) -> sqlite3.Cursor:
        with self._lock:
            return self.conn.execute(sql, params)

    def _executemany(self, sql: str, params=()) -> sqlite3.Cursor:
        with self._lock:
            return self.conn.executemany(sql, params)

    def _executescript(self, sql: str) -> None:
        with self._lock:
            self.conn.executescript(sql)

    def _commit(self) -> None:
        with self._lock:
            self.conn.commit()

    # ------------------------------------------------------------------ #
    # Schema
    # ------------------------------------------------------------------ #
    def _init_schema(self) -> None:
        self._executescript(
            """
            CREATE TABLE IF NOT EXISTS trusted_aps (
                bssid        TEXT PRIMARY KEY,
                ssid         TEXT NOT NULL,
                channel      INTEGER,
                security     TEXT,
                vendor       TEXT,
                first_seen   REAL NOT NULL,
                last_seen    REAL NOT NULL,
                notes        TEXT
            );

            CREATE TABLE IF NOT EXISTS detection_history (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp    REAL NOT NULL,
                bssid        TEXT NOT NULL,
                ssid         TEXT NOT NULL,
                channel      INTEGER,
                signal_dbm   REAL,
                security     TEXT,
                vendor       TEXT,
                risk_score   INTEGER NOT NULL,
                severity     TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS alerts (
                id             INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp      REAL NOT NULL,
                rule           TEXT NOT NULL,
                bssid          TEXT NOT NULL,
                ssid           TEXT NOT NULL,
                channel        INTEGER,
                signal_dbm     REAL,
                security       TEXT,
                vendor         TEXT,
                risk_score     INTEGER NOT NULL,
                severity       TEXT NOT NULL,
                explanation    TEXT NOT NULL,
                acknowledged   INTEGER NOT NULL DEFAULT 0
            );

            CREATE INDEX IF NOT EXISTS idx_history_bssid
                ON detection_history(bssid);
            CREATE INDEX IF NOT EXISTS idx_history_ts
                ON detection_history(timestamp);
            CREATE INDEX IF NOT EXISTS idx_alerts_ts
                ON alerts(timestamp);
            CREATE INDEX IF NOT EXISTS idx_alerts_bssid
                ON alerts(bssid);
            """
        )
        self._commit()

    # ------------------------------------------------------------------ #
    # Trusted AP management
    # ------------------------------------------------------------------ #
    def add_trusted_ap(
        self,
        bssid: str,
        ssid: str,
        channel: int | None,
        security: str,
        vendor: str,
        notes: str = "",
    ) -> None:
        now = time.time()
        with self._lock:
            self.conn.execute(
                """
                INSERT INTO trusted_aps
                    (bssid, ssid, channel, security, vendor, first_seen, last_seen, notes)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(bssid) DO UPDATE SET
                    ssid       = excluded.ssid,
                    channel    = excluded.channel,
                    security   = excluded.security,
                    vendor     = excluded.vendor,
                    last_seen  = excluded.last_seen,
                    notes      = excluded.notes
                """,
                (bssid, ssid, channel, security, vendor, now, now, notes),
            )
            self.conn.commit()

    def remove_trusted_ap(self, bssid: str) -> bool:
        with self._lock:
            cur = self.conn.execute("DELETE FROM trusted_aps WHERE bssid = ?", (bssid,))
            self.conn.commit()
            return cur.rowcount > 0

    def list_trusted_aps(self) -> list[sqlite3.Row]:
        with self._lock:
            return self.conn.execute(
                "SELECT * FROM trusted_aps ORDER BY ssid, bssid"
            ).fetchall()

    def get_trusted_ap(self, bssid: str) -> sqlite3.Row | None:
        with self._lock:
            return self.conn.execute(
                "SELECT * FROM trusted_aps WHERE bssid = ?", (bssid,)
            ).fetchone()

    def is_trusted_bssid(self, bssid: str) -> bool:
        with self._lock:
            row = self.conn.execute(
                "SELECT 1 FROM trusted_aps WHERE bssid = ?", (bssid,)
            ).fetchone()
            return row is not None

    def get_trusted_by_ssid(self, ssid: str) -> list[sqlite3.Row]:
        with self._lock:
            return self.conn.execute(
                "SELECT * FROM trusted_aps WHERE ssid = ? ORDER BY bssid", (ssid,)
            ).fetchall()

    # ------------------------------------------------------------------ #
    # Detection history
    # ------------------------------------------------------------------ #
    def log_detection(
        self,
        bssid: str,
        ssid: str,
        channel: int | None,
        signal_dbm: float | None,
        security: str,
        vendor: str,
        risk_score: int,
        severity: str,
    ) -> int:
        return self.log_detections_batch([(
            time.time(), bssid, ssid, channel, signal_dbm, security, vendor,
            risk_score, severity,
        )])

    def log_detections_batch(
        self,
        rows: list[tuple[float, str, str, int | None, float | None, str, str, int, str]],
    ) -> int:
        """Batch-insert multiple detection_history rows in one transaction."""
        with self._lock:
            cur = self.conn.executemany(
                """
                INSERT INTO detection_history
                    (timestamp, bssid, ssid, channel, signal_dbm, security, vendor,
                     risk_score, severity)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                rows,
            )
            self.conn.commit()
            return cur.rowcount

    def get_recent_detections(self, limit: int = 200) -> list[sqlite3.Row]:
        with self._lock:
            return self.conn.execute(
                """
                SELECT * FROM detection_history
                ORDER BY timestamp DESC LIMIT ?
                """,
                (limit,),
            ).fetchall()

    # ------------------------------------------------------------------ #
    # Alerts
    # ------------------------------------------------------------------ #
    def log_alert(
        self,
        rule: str,
        bssid: str,
        ssid: str,
        channel: int | None,
        signal_dbm: float | None,
        security: str,
        vendor: str,
        risk_score: int,
        severity: str,
        explanation: str,
    ) -> int:
        with self._lock:
            cur = self.conn.execute(
                """
                INSERT INTO alerts
                    (timestamp, rule, bssid, ssid, channel, signal_dbm, security,
                     vendor, risk_score, severity, explanation, acknowledged)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0)
                """,
                (time.time(), rule, bssid, ssid, channel, signal_dbm, security,
                 vendor, risk_score, severity, explanation),
            )
            self.conn.commit()
            return cur.lastrowid

    def get_alerts(self, acknowledged: bool | None = None, limit: int = 500
                   ) -> list[sqlite3.Row]:
        with self._lock:
            if acknowledged is None:
                return self.conn.execute(
                    "SELECT * FROM alerts ORDER BY timestamp DESC LIMIT ?",
                    (limit,),
                ).fetchall()
            return self.conn.execute(
                """
                SELECT * FROM alerts
                WHERE acknowledged = ?
                ORDER BY timestamp DESC LIMIT ?
                """,
                (1 if acknowledged else 0, limit),
            ).fetchall()

    def acknowledge_alert(self, alert_id: int) -> bool:
        with self._lock:
            cur = self.conn.execute(
                "UPDATE alerts SET acknowledged = 1 WHERE id = ?", (alert_id,)
            )
            self.conn.commit()
            return cur.rowcount > 0

    def clear_alerts(self, acknowledged_only: bool = True) -> int:
        with self._lock:
            if acknowledged_only:
                cur = self.conn.execute(
                    "DELETE FROM alerts WHERE acknowledged = 1"
                )
            else:
                cur = self.conn.execute("DELETE FROM alerts")
            self.conn.commit()
            return cur.rowcount

    # ------------------------------------------------------------------ #
    # Export helpers
    # ------------------------------------------------------------------ #
    def export_alerts_json(self) -> list[dict[str, Any]]:
        with self._lock:
            rows = self.conn.execute(
                "SELECT * FROM alerts ORDER BY timestamp DESC"
            ).fetchall()
            return [dict(r) for r in rows]

    def export_alerts_csv(self) -> str:
        rows = self.get_alerts()
        output = io.StringIO()
        fields = [
            "timestamp", "rule", "bssid", "ssid", "channel", "signal_dbm",
            "security", "vendor", "risk_score", "severity", "explanation",
            "acknowledged",
        ]
        writer = csv.DictWriter(output, fieldnames=fields)
        writer.writeheader()
        for row in rows:
            writer.writerow({k: row[k] for k in fields})
        return output.getvalue()

    def export_detections_json(self) -> list[dict[str, Any]]:
        """Export every scanned AP from detection_history (all APs seen)."""
        with self._lock:
            rows = self.conn.execute(
                "SELECT * FROM detection_history ORDER BY timestamp DESC"
            ).fetchall()
            return [dict(r) for r in rows]

    def export_detections_csv(self) -> str:
        """Export every scanned AP from detection_history to CSV string."""
        with self._lock:
            rows = self.conn.execute(
                "SELECT * FROM detection_history ORDER BY timestamp DESC"
            ).fetchall()
        output = io.StringIO()
        fields = [
            "timestamp", "bssid", "ssid", "channel", "signal_dbm",
            "security", "vendor", "risk_score", "severity",
        ]
        writer = csv.DictWriter(output, fieldnames=fields)
        writer.writeheader()
        for row in rows:
            writer.writerow({k: row[k] for k in fields})
        return output.getvalue()

    def close(self) -> None:
        with self._lock:
            if self.conn is not None:
                self.conn.close()
                self.conn = None

    def __enter__(self) -> "RogueHunterDB":
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()
