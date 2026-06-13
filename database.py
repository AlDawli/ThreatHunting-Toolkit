"""
core/database.py
─────────────────
SQLite persistence layer.

Tables
------
searches  — every IOC lookup (query, type, verdict, stats, raw JSON)
iocs      — user-managed watchlist of IOCs with tags and notes
"""
import json
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Optional

from config.settings import DB_PATH


# ── Schema ────────────────────────────────────────────────────────────────────
_SCHEMA = """
CREATE TABLE IF NOT EXISTS searches (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp        TEXT    NOT NULL,
    query            TEXT    NOT NULL,
    ioc_type         TEXT    NOT NULL,
    verdict          TEXT    DEFAULT 'UNKNOWN',
    malicious_count  INTEGER DEFAULT 0,
    suspicious_count INTEGER DEFAULT 0,
    undetected_count INTEGER DEFAULT 0,
    harmless_count   INTEGER DEFAULT 0,
    full_result      TEXT
);

CREATE TABLE IF NOT EXISTS iocs (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    ioc          TEXT    NOT NULL UNIQUE,
    ioc_type     TEXT    NOT NULL,
    tags         TEXT    DEFAULT '',
    notes        TEXT    DEFAULT '',
    added_at     TEXT    NOT NULL,
    last_checked TEXT
);
"""


class Database:
    """Thin wrapper around SQLite for the Threat Hunting Toolkit."""

    def __init__(self, db_path: Path = DB_PATH):
        self.db_path = db_path
        self._init_db()

    # ── Internal helpers ──────────────────────────────────────────────────────

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        with self._connect() as conn:
            conn.executescript(_SCHEMA)

    @staticmethod
    def _extract_stats(result: dict) -> dict:
        """Pull detection counts + verdict out of a raw VT response."""
        try:
            attrs = result.get("data", {}).get("attributes", {})
            s = attrs.get("last_analysis_stats", {})
            malicious  = s.get("malicious",  0)
            suspicious = s.get("suspicious", 0)
            undetected = s.get("undetected", 0)
            harmless   = s.get("harmless",   0)

            if malicious > 0:
                verdict = "MALICIOUS"
            elif suspicious > 0:
                verdict = "SUSPICIOUS"
            elif (undetected + harmless) > 0:
                verdict = "CLEAN"
            else:
                verdict = "UNKNOWN"

            return dict(malicious=malicious, suspicious=suspicious,
                        undetected=undetected, harmless=harmless,
                        verdict=verdict)
        except Exception:
            return dict(malicious=0, suspicious=0, undetected=0,
                        harmless=0, verdict="UNKNOWN")

    # ── Searches ──────────────────────────────────────────────────────────────

    def log_search(self, query: str, ioc_type: str, result: dict) -> int:
        """Persist a VT lookup; returns the new row id."""
        s = self._extract_stats(result)
        with self._connect() as conn:
            cur = conn.execute(
                """INSERT INTO searches
                   (timestamp, query, ioc_type, verdict,
                    malicious_count, suspicious_count,
                    undetected_count, harmless_count, full_result)
                   VALUES (?,?,?,?,?,?,?,?,?)""",
                (
                    datetime.utcnow().isoformat(timespec="seconds") + "Z",
                    query, ioc_type, s["verdict"],
                    s["malicious"], s["suspicious"],
                    s["undetected"], s["harmless"],
                    json.dumps(result),
                ),
            )
            return cur.lastrowid

    def get_history(self, limit: int = 100) -> list[dict]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM searches ORDER BY timestamp DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [dict(r) for r in rows]

    def clear_history(self) -> None:
        with self._connect() as conn:
            conn.execute("DELETE FROM searches")

    # ── IOC Watchlist ─────────────────────────────────────────────────────────

    def add_ioc(self, ioc: str, ioc_type: str,
                tags: str = "", notes: str = "") -> bool:
        """Returns True on success, False if the IOC already exists."""
        try:
            with self._connect() as conn:
                conn.execute(
                    """INSERT INTO iocs (ioc, ioc_type, tags, notes, added_at)
                       VALUES (?,?,?,?,?)""",
                    (ioc, ioc_type, tags, notes,
                     datetime.utcnow().isoformat(timespec="seconds") + "Z"),
                )
            return True
        except sqlite3.IntegrityError:
            return False

    def get_iocs(self) -> list[dict]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM iocs ORDER BY added_at DESC"
            ).fetchall()
        return [dict(r) for r in rows]

    def delete_ioc(self, ioc_id: int) -> None:
        with self._connect() as conn:
            conn.execute("DELETE FROM iocs WHERE id = ?", (ioc_id,))

    def update_ioc(self, ioc_id: int, tags: str, notes: str) -> None:
        with self._connect() as conn:
            conn.execute(
                "UPDATE iocs SET tags=?, notes=? WHERE id=?",
                (tags, notes, ioc_id),
            )

    def search_watchlist(self, query: str) -> list[dict]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM iocs WHERE ioc LIKE ? OR tags LIKE ?",
                (f"%{query}%", f"%{query}%"),
            ).fetchall()
        return [dict(r) for r in rows]

    def mark_checked(self, ioc: str) -> None:
        with self._connect() as conn:
            conn.execute(
                "UPDATE iocs SET last_checked=? WHERE ioc=?",
                (datetime.utcnow().isoformat(timespec="seconds") + "Z", ioc),
            )
