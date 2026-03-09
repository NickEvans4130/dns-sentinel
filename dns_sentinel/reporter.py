"""
Reporting tool for dns-sentinel.

Queries the SQLite database and produces human-readable summaries,
ASCII bar charts, and pre-formatted social media snippets.

Usage:
    python -m dns_sentinel.reporter --period today
    python -m dns_sentinel.reporter --period yesterday
    python -m dns_sentinel.reporter --period week
"""

import argparse
import logging
import os
from datetime import datetime, timedelta, timezone

log = logging.getLogger(__name__)

BAR_WIDTH = 30


def _load_config(path: str = "config.toml") -> dict:
    """Load TOML config, falling back to config.example.toml."""
    try:
        import tomllib
    except ImportError:
        import tomli as tomllib  # type: ignore[no-redef]

    if not os.path.exists(path):
        path = "config.example.toml"

    with open(path, "rb") as fh:
        return tomllib.load(fh)


def _period_since(period: str) -> tuple[datetime, str]:
    """
    Return (since_datetime, label) for a named period.

    Args:
        period: One of "today", "yesterday", "week".

    Returns:
        Tuple of (start datetime in UTC, human-readable label).
    """
    now = datetime.now(timezone.utc)
    today = now.replace(hour=0, minute=0, second=0, microsecond=0)
    if period == "today":
        return today, "Today"
    if period == "yesterday":
        return today - timedelta(days=1), "Yesterday"
    if period == "week":
        return today - timedelta(days=7), "Last 7 days"
    raise ValueError(f"Unknown period: {period!r}. Choose: today, yesterday, week")


def _bar(count: int, max_count: int) -> str:
    """Render a proportional ASCII bar."""
    if max_count == 0:
        return ""
    filled = round(BAR_WIDTH * count / max_count)
    return "█" * filled + "░" * (BAR_WIDTH - filled)


def print_report(period: str, db_path: str) -> None:
    """
    Generate and print a full report for the given period.

    Outputs:
    - Summary statistics (total, blocked, allowed, block rate)
    - Top 10 blocked domains with ASCII bar chart
    - Hourly breakdown (for today/yesterday)
    - Pre-formatted blog/LinkedIn snippet

    Args:
        period: One of "today", "yesterday", "week".
        db_path: Path to the SQLite database file.
    """
    from .logger import QueryLogger

    since, label = _period_since(period)
    ql = QueryLogger(db_path)
    stats = ql.get_stats(since)

    total = stats["total"]
    blocked = stats["blocked"]
    allowed = stats["allowed"]
    rate = stats["block_rate"]
    top = stats["top_domains"]

    sep = "=" * 50

    print(f"\n{sep}")
    print(f"  DNS Sentinel Report — {label}")
    print(sep)
    print(f"  Total queries : {total:,}")
    print(f"  Allowed       : {allowed:,}")
    print(f"  Blocked       : {blocked:,}  ({rate}%)")
    print(sep)

    if top:
        print("\n  Top 10 Blocked Domains:")
        max_count = top[0]["count"]
        for i, entry in enumerate(top, 1):
            bar = _bar(entry["count"], max_count)
            print(f"  {i:>2}. {entry['domain']:<40} {entry['count']:>6}  {bar}")

    if period in ("today", "yesterday"):
        date_str = since.strftime("%Y-%m-%d")
        hourly = ql.get_hourly_breakdown(date_str)
        max_h = max((h["blocked_count"] for h in hourly), default=0)
        if max_h > 0:
            print(f"\n  Hourly breakdown ({date_str}):")
            for h in hourly:
                if h["blocked_count"] > 0:
                    bar = _bar(h["blocked_count"], max_h)
                    print(f"  {h['hour']:>02d}:00  {bar}  {h['blocked_count']}")

    print(f"\n{sep}")
    print("  Blog / LinkedIn snippet:")
    print(sep)

    tracker_lines = ""
    if top:
        for entry in top[:3]:
            tracker_lines += f"   * {entry['domain']}: {entry['count']} attempts\n"

    snippet = (
        f"Today I monitored my DNS traffic and found:\n"
        f"  {allowed:,} legitimate requests\n"
        f"  {blocked:,} tracker requests blocked ({rate}%)\n"
    )
    if tracker_lines:
        snippet += f"\nTop trackers encountered:\n{tracker_lines}"
    snippet += (
        "\nThis is what your browser does without a DNS blocker.\n"
        "#Privacy #DNS #CyberSecurity"
    )

    for line in snippet.splitlines():
        print(f"  {line}")

    print(f"{sep}\n")


def main() -> None:
    """CLI entry point for the reporter."""
    logging.basicConfig(level=logging.WARNING)
    parser = argparse.ArgumentParser(
        description="DNS Sentinel reporter — generate DNS query statistics."
    )
    parser.add_argument(
        "--period",
        choices=["today", "yesterday", "week"],
        default="today",
        help="Reporting period (default: today)",
    )
    parser.add_argument(
        "--config",
        default="config.toml",
        help="Path to config TOML file (default: config.toml)",
    )
    args = parser.parse_args()

    config = _load_config(args.config)
    db_path = config["database"]["path"]
    print_report(args.period, db_path)


if __name__ == "__main__":
    main()
