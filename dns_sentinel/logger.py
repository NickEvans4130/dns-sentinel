"""
SQLite-backed query logger for dns-sentinel.

Records every DNS query (blocked or allowed) and provides statistical
queries for the reporter and batch notifier.
"""

import logging
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Generator, Optional

log = logging.getLogger(__name__)


SCHEMA = """
CREATE TABLE IF NOT EXISTS queries (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp   TEXT    NOT NULL,
    domain      TEXT    NOT NULL,
    client_ip   TEXT,
    blocked     INTEGER NOT NULL DEFAULT 0,
    category    TEXT
);

CREATE TABLE IF NOT EXISTS daily_stats (
    date             TEXT PRIMARY KEY,
    total_queries    INTEGER DEFAULT 0,
    blocked_queries  INTEGER DEFAULT 0,
    top_blocked      TEXT
);

CREATE INDEX IF NOT EXISTS idx_queries_timestamp ON queries(timestamp);
CREATE INDEX IF NOT EXISTS idx_queries_domain    ON queries(domain);
CREATE INDEX IF NOT EXISTS idx_queries_blocked   ON queries(blocked);
"""


class QueryLogger:
    """Logs DNS queries to SQLite and provides statistical methods."""

    def __init__(self, db_path: str) -> None:
        """
        Initialize the query logger and create the database schema if needed.

        Args:
            db_path: Path to the SQLite database file.
        """
        self.db_path = db_path
        self._init_db()

    @contextmanager
    def _connect(self) -> Generator[sqlite3.Connection, None, None]:
        """Yield a database connection with WAL mode enabled."""
        conn = sqlite3.connect(self.db_path, check_same_thread=False)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def _init_db(self) -> None:
        """Create tables and indexes if they do not exist."""
        with self._connect() as conn:
            conn.executescript(SCHEMA)
        log.debug("Database initialised at %s", self.db_path)

    def log_query(
        self,
        domain: str,
        client_ip: Optional[str],
        blocked: bool,
        category: Optional[str] = None,
    ) -> None:
        """
        Record a single DNS query.

        Args:
            domain:    The queried domain name.
            client_ip: IP address of the requesting client.
            blocked:   Whether the query was blocked.
            category:  Optional tracker category label.
        """
        ts = datetime.now(timezone.utc).isoformat()
        with self._connect() as conn:
            conn.execute(
                "INSERT INTO queries (timestamp, domain, client_ip, blocked, category) "
                "VALUES (?, ?, ?, ?, ?)",
                (ts, domain.lower(), client_ip, int(blocked), category),
            )

    def get_stats(self, since: datetime) -> dict:
        """
        Return aggregate statistics since a given datetime.

        Args:
            since: Only include queries at or after this timestamp.

        Returns:
            dict with keys: total, blocked, allowed, block_rate, top_domains
        """
        since_str = since.isoformat()
        with self._connect() as conn:
            row = conn.execute(
                "SELECT COUNT(*) AS total, SUM(blocked) AS blocked "
                "FROM queries WHERE timestamp >= ?",
                (since_str,),
            ).fetchone()
            total = row["total"] or 0
            blocked = int(row["blocked"] or 0)

            top = conn.execute(
                "SELECT domain, COUNT(*) AS cnt FROM queries "
                "WHERE timestamp >= ? AND blocked = 1 "
                "GROUP BY domain ORDER BY cnt DESC LIMIT 10",
                (since_str,),
            ).fetchall()

        top_domains = [{"domain": r["domain"], "count": r["cnt"]} for r in top]
        block_rate = round((blocked / total * 100), 1) if total else 0.0

        return {
            "total": total,
            "blocked": blocked,
            "allowed": total - blocked,
            "block_rate": block_rate,
            "top_domains": top_domains,
        }

    def get_hourly_breakdown(self, date: str) -> list[dict]:
        """
        Return per-hour blocked query counts for a given date.

        Args:
            date: Date string in YYYY-MM-DD format.

        Returns:
            List of dicts with keys: hour (int 0-23), blocked_count.
        """
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT CAST(strftime('%H', timestamp) AS INTEGER) AS hour, "
                "COUNT(*) AS cnt "
                "FROM queries "
                "WHERE date(timestamp) = ? AND blocked = 1 "
                "GROUP BY hour ORDER BY hour",
                (date,),
            ).fetchall()

        hourly = {r["hour"]: r["cnt"] for r in rows}
        return [
            {"hour": h, "blocked_count": hourly.get(h, 0)} for h in range(24)
        ]
