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

CREATE TABLE IF NOT EXISTS domain_scores (
    domain      TEXT PRIMARY KEY,
    score       INTEGER NOT NULL,
    category    TEXT    NOT NULL,
    company     TEXT,
    reason      TEXT    NOT NULL,
    source      TEXT    NOT NULL,
    scored_at   TEXT    NOT NULL
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

    def get_score(self, domain: str) -> dict | None:
        """
        Return the cached threat score for a domain, or None if not yet scored.

        Args:
            domain: The domain name to look up.

        Returns:
            Score dict with keys (score, category, company, reason, source),
            or None if no cached entry exists.
        """
        with self._connect() as conn:
            row = conn.execute(
                "SELECT score, category, company, reason, source "
                "FROM domain_scores WHERE domain = ?",
                (domain.lower(),),
            ).fetchone()
        if row is None:
            return None
        return {
            "score": row["score"],
            "category": row["category"],
            "company": row["company"],
            "reason": row["reason"],
            "source": row["source"],
        }

    def cache_score(self, domain: str, score_data: dict) -> None:
        """
        Persist a threat score result for a domain.

        Uses INSERT OR REPLACE so repeated calls safely update stale entries.

        Args:
            domain:     The domain name being scored.
            score_data: Dict with keys: score, category, company, reason, source.
        """
        ts = datetime.now(timezone.utc).isoformat()
        with self._connect() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO domain_scores "
                "(domain, score, category, company, reason, source, scored_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    domain.lower(),
                    int(score_data["score"]),
                    score_data["category"],
                    score_data.get("company"),
                    score_data["reason"],
                    score_data["source"],
                    ts,
                ),
            )

    def get_score_stats(self, since: datetime) -> dict:
        """
        Return score distribution and per-domain average scores for blocked queries.

        Args:
            since: Only include queries at or after this timestamp.

        Returns:
            Dict with keys: avg_score, low, medium, high, critical, top_domains.
            top_domains is a list of dicts with keys: domain, count, avg_score.
        """
        since_str = since.isoformat()
        with self._connect() as conn:
            row = conn.execute(
                "SELECT ROUND(AVG(ds.score), 1) AS avg_score, "
                "SUM(CASE WHEN ds.score BETWEEN 1 AND 3 THEN 1 ELSE 0 END) AS low, "
                "SUM(CASE WHEN ds.score BETWEEN 4 AND 6 THEN 1 ELSE 0 END) AS medium, "
                "SUM(CASE WHEN ds.score BETWEEN 7 AND 8 THEN 1 ELSE 0 END) AS high, "
                "SUM(CASE WHEN ds.score BETWEEN 9 AND 10 THEN 1 ELSE 0 END) AS critical "
                "FROM queries q "
                "LEFT JOIN domain_scores ds ON q.domain = ds.domain "
                "WHERE q.timestamp >= ? AND q.blocked = 1",
                (since_str,),
            ).fetchone()

            top = conn.execute(
                "SELECT q.domain, COUNT(*) AS cnt, "
                "ROUND(AVG(ds.score), 1) AS avg_score "
                "FROM queries q "
                "LEFT JOIN domain_scores ds ON q.domain = ds.domain "
                "WHERE q.timestamp >= ? AND q.blocked = 1 "
                "GROUP BY q.domain ORDER BY cnt DESC LIMIT 10",
                (since_str,),
            ).fetchall()

        return {
            "avg_score": float(row["avg_score"] or 0),
            "low": int(row["low"] or 0),
            "medium": int(row["medium"] or 0),
            "high": int(row["high"] or 0),
            "critical": int(row["critical"] or 0),
            "top_domains": [
                {
                    "domain": r["domain"],
                    "count": r["cnt"],
                    "avg_score": r["avg_score"],
                }
                for r in top
            ],
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
