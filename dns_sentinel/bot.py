"""
Discord slash-command bot for dns-sentinel.

Provides interactive commands for querying reports, domain scores, live stats,
and triggering blocklist refreshes. Runs as a background daemon thread
alongside the DNS server and never touches the webhook notifier.

Commands:
    /report  [period]        — full report embed + .txt download
    /top     [period] [limit]— top N blocked domains
    /score   <domain>        — on-demand threat score lookup
    /stats                   — live server statistics
    /blocklist refresh       — re-download all blocklists (role-restricted)
"""

import asyncio
import functools
import logging
import sqlite3
from datetime import datetime, timedelta, timezone
from io import BytesIO
from typing import Optional

import discord
from discord import app_commands

log = logging.getLogger(__name__)

# ── Constants ──────────────────────────────────────────────────────────────────

_EIGHTH_BLOCKS = " ▏▎▍▌▋▊▉█"

_CATEGORY_LABELS: dict[str, str] = {
    "ad_network": "Ad network",
    "analytics": "Analytics",
    "fingerprinting": "Fingerprinting",
    "cross_site_tracking": "Cross-site tracking",
    "data_broker": "Data broker",
    "malware_c2": "Malware / C2",
    "telemetry": "Telemetry",
    "unknown": "Unknown",
}

# ── Pure helper functions ──────────────────────────────────────────────────────

def _score_emoji(score: int) -> str:
    """Return the coloured indicator emoji for a numeric score 1–10."""
    if score <= 3:
        return "🟢"
    if score <= 6:
        return "🟡"
    if score <= 8:
        return "🔴"
    return "☠️"


def _embed_colour(block_rate: float) -> int:
    """Return a Discord sidebar colour int based on block rate percentage."""
    if block_rate < 10:
        return 0x57F287
    if block_rate < 25:
        return 0xFEE75C
    return 0xED4245


def _period_since(period: str) -> tuple[datetime, str]:
    """Return (start_datetime_utc, human_label) for a named period."""
    now = datetime.now(timezone.utc)
    today = now.replace(hour=0, minute=0, second=0, microsecond=0)
    mapping = {
        "today":     (today,                        "Today"),
        "yesterday": (today - timedelta(days=1),    "Yesterday"),
        "week":      (today - timedelta(days=7),    "Last 7 days"),
        "month":     (today - timedelta(days=30),   "Last 30 days"),
    }
    return mapping.get(period, (today, "Today"))


def _fmt_uptime(start: datetime) -> str:
    """Format a timedelta since start as '3d 14h 22m'."""
    delta = datetime.now(timezone.utc) - start
    days = delta.days
    hours = delta.seconds // 3600
    minutes = (delta.seconds % 3600) // 60
    parts: list[str] = []
    if days:
        parts.append(f"{days}d")
    if hours:
        parts.append(f"{hours}h")
    parts.append(f"{minutes}m")
    return " ".join(parts)


def _fmt_time_ago(ts_str: str) -> str:
    """Format an ISO timestamp as a human-readable 'X ago' string."""
    try:
        ts = datetime.fromisoformat(ts_str)
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)
        diff = int((datetime.now(timezone.utc) - ts).total_seconds())
        if diff < 60:
            return f"{diff}s ago"
        if diff < 3600:
            return f"{diff // 60}m ago"
        if diff < 86400:
            return f"{diff // 3600}h ago"
        return f"{diff // 86400}d ago"
    except Exception:
        return "unknown"


def _hourly_bar(count: int, max_count: int, width: int = 12) -> str:
    """
    Render a proportional bar using Unicode block elements.

    Uses sub-character precision (▏▎▍▌▋▊▉█) for smooth scaling.
    Returns a string of exactly `width` characters.
    """
    if max_count == 0 or count == 0:
        return " " * width
    total_eighths = round((count / max_count) * width * 8)
    full = min(total_eighths // 8, width)
    remainder = total_eighths % 8
    bar = "█" * full
    if remainder and full < width:
        bar += _EIGHTH_BLOCKS[remainder]
    return bar.ljust(width)


def _get_last_blocked(db_path: str) -> Optional[dict]:
    """Return the most recently blocked query row from the database."""
    try:
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
        row = conn.execute(
            "SELECT domain, timestamp FROM queries "
            "WHERE blocked = 1 ORDER BY timestamp DESC LIMIT 1"
        ).fetchone()
        conn.close()
        if row:
            return {"domain": row["domain"], "timestamp": row["timestamp"]}
        return None
    except Exception:
        return None


def _build_share_snippet(stats: dict, score_stats: dict) -> str:
    """Return the pre-formatted LinkedIn / blog text snippet."""
    allowed = stats["allowed"]
    blocked = stats["blocked"]
    rate = stats["block_rate"]
    avg = score_stats.get("avg_score", 0)
    top = score_stats.get("top_domains", [])

    lines = [
        "Today I monitored my DNS traffic and found:",
        f"  {allowed:,} legitimate requests",
        f"  {blocked:,} tracker requests blocked ({rate}%)",
    ]
    if avg:
        lines.append(f"  Average threat score of blocked trackers: {avg:.1f}/10")
    if top:
        lines.append("")
        lines.append("Top trackers encountered:")
        for entry in top[:3]:
            lines.append(f"   * {entry['domain']}: {entry['count']} attempts")
    lines += [
        "",
        "This is what your browser does without a DNS blocker.",
        "#Privacy #DNS #CyberSecurity",
    ]
    return "\n".join(lines)


def _build_report_embed(
    stats: dict,
    score_stats: dict,
    hourly: list[dict],
    label: str,
    period: str,
) -> discord.Embed:
    """Build the rich Discord embed for /report."""
    block_rate = stats["block_rate"]
    top = score_stats["top_domains"]
    avg = score_stats.get("avg_score", 0)
    unique = len(top)

    embed = discord.Embed(
        title=f"📊 dns-sentinel Report — {label}",
        colour=_embed_colour(block_rate),
        timestamp=datetime.now(timezone.utc),
    )
    embed.set_footer(text="Generated by dns-sentinel")

    # Overview
    embed.add_field(
        name="📈 Overview",
        value=(
            f"Total queries:   **{stats['total']:,}**\n"
            f"Blocked:         **{stats['blocked']:,}** ({block_rate}%)\n"
            f"Avg score:       **{avg:.1f}** / 10\n"
            f"Unique trackers: **{unique}** distinct domains"
        ),
        inline=False,
    )

    # Top blockers (up to 5 + overflow count)
    if top:
        lines: list[str] = []
        for entry in top[:5]:
            score = entry.get("avg_score")
            if score is not None:
                emoji = _score_emoji(round(score))
                score_str = f" · {score:.0f}/10"
            else:
                emoji = "⚪"
                score_str = ""
            lines.append(f"{emoji} `{entry['domain']}` — {entry['count']}{score_str}")
        remaining = unique - 5
        if remaining > 0:
            lines.append(f"… and {remaining} more")
        embed.add_field(name="🏆 Top Blockers", value="\n".join(lines), inline=False)

    # Score breakdown
    low = score_stats["low"]
    medium = score_stats["medium"]
    high = score_stats["high"]
    critical = score_stats["critical"]
    embed.add_field(
        name="📊 Score Breakdown",
        value=(
            f"🟢 Low       {low:>5}\n"
            f"🟡 Medium   {medium:>5}\n"
            f"🔴 High      {high:>5}\n"
            f"☠️  Critical  {critical:>5}"
        ),
        inline=True,
    )

    # Hourly chart — only for single-day periods
    if period in ("today", "yesterday") and hourly:
        max_h = max((h["blocked_count"] for h in hourly), default=0)
        if max_h > 0:
            chart_lines = [
                f"{h['hour']:02d} {_hourly_bar(h['blocked_count'], max_h)} {h['blocked_count']}"
                for h in hourly
                if h["blocked_count"] > 0
            ]
            embed.add_field(
                name="⏰ Hourly Activity",
                value="```\n" + "\n".join(chart_lines) + "\n```",
                inline=False,
            )

    # Share snippet
    snippet = _build_share_snippet(stats, score_stats)
    embed.add_field(
        name="📝 Share Snippet",
        value="```\n" + snippet + "\n```",
        inline=False,
    )

    return embed


def _build_txt_report(
    period_label: str,
    date_str: str,
    stats: dict,
    score_stats: dict,
    hourly: list[dict],
    period: str,
) -> str:
    """
    Build the full plain-text report returned as a .txt file attachment.

    Generated entirely in memory — no disk writes.
    """
    sep = "=" * 50
    thin = "-" * 50
    top = score_stats["top_domains"]
    avg = score_stats.get("avg_score", 0)
    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")

    lines: list[str] = [
        sep,
        f"dns-sentinel Privacy Report — {period_label}",
        f"Generated: {now_str} UTC",
        sep,
        "",
        "OVERVIEW",
        thin,
        f"Total DNS queries:      {stats['total']:>8,}",
        f"Blocked (trackers):     {stats['blocked']:>8,}  ({stats['block_rate']}%)",
        f"Allowed:                {stats['allowed']:>8,}",
        f"Unique tracker domains: {len(top):>8}",
        f"Average threat score:   {avg:>8.1f} / 10",
        "",
        "SCORE DISTRIBUTION",
        thin,
        f"🟢 Low concern    (1-3):  {score_stats['low']:>5} blocks",
        f"🟡 Medium concern (4-6):  {score_stats['medium']:>5} blocks",
        f"🔴 High concern   (7-8):  {score_stats['high']:>5} blocks",
        f"☠️  Critical       (9-10): {score_stats['critical']:>5} blocks",
        "",
        "TOP 20 BLOCKED DOMAINS",
        thin,
        f" {'#':<4} {'Domain':<35} {'Blocks':>7}  Score",
        f" {'---':<4} {'---':<35} {'---':>7}  -----",
    ]

    for i, entry in enumerate(top[:20], 1):
        score = entry.get("avg_score")
        score_str = f"{score:.0f}/10" if score is not None else "—"
        lines.append(f" {i:<4} {entry['domain']:<35} {entry['count']:>7}  {score_str}")

    if period in ("today", "yesterday") and hourly:
        max_h = max((h["blocked_count"] for h in hourly), default=0)
        lines += ["", "HOURLY BREAKDOWN", thin]
        for h in hourly:
            bar = _hourly_bar(h["blocked_count"], max_h, width=12)
            lines.append(f"{h['hour']:02d}:00  {bar}  {h['blocked_count']}")

    snippet = _build_share_snippet(stats, score_stats)
    lines += [
        "",
        sep,
        "SHARE SNIPPET (LinkedIn / Blog)",
        sep,
        snippet,
        "",
        sep,
        "dns-sentinel — github.com/yourname/dns-sentinel",
        sep,
    ]

    return "\n".join(lines)


# ── Access control ─────────────────────────────────────────────────────────────

async def _check_access(
    interaction: discord.Interaction,
    bot_config: dict,
) -> bool:
    """
    Validate channel and role access for a slash command interaction.

    Sends an ephemeral denial message and returns False if access is denied.
    Must be called before interaction.response.defer().
    """
    allowed_channels = [int(c) for c in bot_config.get("allowed_channel_ids", [])]
    if allowed_channels and interaction.channel_id not in allowed_channels:
        await interaction.response.send_message(
            "⛔ This command is not available in this channel.", ephemeral=True
        )
        return False

    allowed_roles = [int(r) for r in bot_config.get("allowed_role_ids", [])]
    if allowed_roles:
        user_roles = [r.id for r in getattr(interaction.user, "roles", [])]
        if not any(r in user_roles for r in allowed_roles):
            await interaction.response.send_message(
                "⛔ You don't have permission to use this command.", ephemeral=True
            )
            return False

    return True


def _error_embed(detail: str) -> discord.Embed:
    """Return a standardised error embed that never exposes raw tracebacks."""
    return discord.Embed(
        title="❌ Something went wrong",
        description=f"{detail}\n\nCheck server logs for details.",
        colour=0xFF0000,
    )


# ── Bot class ──────────────────────────────────────────────────────────────────

class SentinelBot(discord.Client):
    """
    Discord client for dns-sentinel.

    Registers slash commands on an app_commands.CommandTree and syncs them
    to the configured guild on login. Receives logger, scorer, and blocklist
    as constructor arguments to avoid importing from server.py.
    """

    def __init__(
        self,
        config: dict,
        db_logger,
        scorer,
        blocklist,
        start_time: datetime,
    ) -> None:
        """
        Initialise the bot.

        Args:
            config:     Full application config dict.
            db_logger:  QueryLogger instance for database reads.
            scorer:     Scorer instance for on-demand domain scoring.
            blocklist:  BlocklistLoader instance for stats and refresh.
            start_time: Server startup time used to compute uptime in /stats.
        """
        intents = discord.Intents.default()
        super().__init__(intents=intents)
        self.config = config
        self.bot_config = config.get("bot", {})
        self.db_path: str = config["database"]["path"]
        self.db_logger = db_logger
        self.scorer = scorer
        self.blocklist = blocklist
        self.start_time = start_time
        self.tree = app_commands.CommandTree(self)
        self._register_commands()

    async def on_ready(self) -> None:
        """Sync slash commands on login."""
        guild_id = self.bot_config.get("guild_id")
        if guild_id:
            guild = discord.Object(id=int(guild_id))
            self.tree.copy_global_to(guild=guild)
            await self.tree.sync(guild=guild)
            log.info("Slash commands synced to guild %s", guild_id)
        else:
            await self.tree.sync()
            log.info("Slash commands synced globally (up to 1h propagation)")
        log.info("Discord bot ready: %s", self.user)

    def _register_commands(self) -> None:
        """
        Register all slash commands on the CommandTree.

        Commands are defined as closures so they can reference `bot` (self)
        without requiring a Cog.
        """
        bot = self

        # ── /report ───────────────────────────────────────────────────────────

        @self.tree.command(name="report", description="Generate a DNS block report")
        @app_commands.describe(period="Time period to report on")
        @app_commands.choices(period=[
            app_commands.Choice(name="Today",        value="today"),
            app_commands.Choice(name="Yesterday",    value="yesterday"),
            app_commands.Choice(name="Last 7 days",  value="week"),
            app_commands.Choice(name="Last 30 days", value="month"),
        ])
        async def cmd_report(
            interaction: discord.Interaction,
            period: str = "today",
        ) -> None:
            if not await _check_access(interaction, bot.bot_config):
                return
            await interaction.response.defer()
            try:
                loop = asyncio.get_event_loop()
                since, label = _period_since(period)

                stats = await loop.run_in_executor(
                    None, functools.partial(bot.db_logger.get_stats, since)
                )
                score_stats = await loop.run_in_executor(
                    None, functools.partial(bot.db_logger.get_score_stats, since)
                )

                hourly: list[dict] = []
                if period in ("today", "yesterday"):
                    date_str = since.strftime("%Y-%m-%d")
                    hourly = await loop.run_in_executor(
                        None,
                        functools.partial(bot.db_logger.get_hourly_breakdown, date_str),
                    )

                embed = _build_report_embed(stats, score_stats, hourly, label, period)

                date_file = datetime.now(timezone.utc).strftime("%Y-%m-%d")
                txt_content = _build_txt_report(
                    label, date_file, stats, score_stats, hourly, period
                )
                txt_file = discord.File(
                    fp=BytesIO(txt_content.encode("utf-8")),
                    filename=f"sentinel-report-{date_file}.txt",
                )

                await interaction.followup.send(embed=embed, file=txt_file)

            except Exception as exc:
                log.error("Error in /report: %s", exc, exc_info=True)
                await interaction.followup.send(
                    embed=_error_embed(str(exc)), ephemeral=True
                )

        # ── /top ──────────────────────────────────────────────────────────────

        @self.tree.command(name="top", description="Show the top blocked domains")
        @app_commands.describe(
            period="Time period",
            limit="Number of domains to show (5–25)",
        )
        @app_commands.choices(period=[
            app_commands.Choice(name="Today",       value="today"),
            app_commands.Choice(name="Yesterday",   value="yesterday"),
            app_commands.Choice(name="Last 7 days", value="week"),
        ])
        async def cmd_top(
            interaction: discord.Interaction,
            period: str = "today",
            limit: app_commands.Range[int, 5, 25] = 10,
        ) -> None:
            if not await _check_access(interaction, bot.bot_config):
                return
            await interaction.response.defer()
            try:
                loop = asyncio.get_event_loop()
                since, label = _period_since(period)

                score_stats = await loop.run_in_executor(
                    None, functools.partial(bot.db_logger.get_score_stats, since)
                )
                top = score_stats["top_domains"][:limit]

                medals = ["🥇", "🥈", "🥉"]
                lines: list[str] = []
                for i, entry in enumerate(top):
                    pos = medals[i] if i < 3 else f"{i + 1}."
                    score = entry.get("avg_score")
                    if score is not None:
                        score_str = f"{_score_emoji(round(score))} {score:.0f}/10"
                    else:
                        score_str = "—"
                    domain = entry["domain"]
                    dashes = "—" * max(1, 30 - len(domain))
                    lines.append(
                        f"{pos} `{domain}` {dashes} "
                        f"**{entry['count']}** blocks  {score_str}"
                    )

                embed = discord.Embed(
                    title=f"🏆 Top {limit} Blocked Domains — {label}",
                    description="\n".join(lines) or "No blocked domains in this period.",
                    colour=0xE74C3C,
                )
                embed.set_footer(
                    text=f"dns-sentinel · "
                    f"{datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}"
                )
                await interaction.followup.send(embed=embed)

            except Exception as exc:
                log.error("Error in /top: %s", exc, exc_info=True)
                await interaction.followup.send(
                    embed=_error_embed(str(exc)), ephemeral=True
                )

        # ── /score ────────────────────────────────────────────────────────────

        @self.tree.command(
            name="score",
            description="Look up the threat score for a domain",
        )
        @app_commands.describe(domain="Domain to score (e.g. doubleclick.net)")
        async def cmd_score(
            interaction: discord.Interaction,
            domain: str,
        ) -> None:
            if not await _check_access(interaction, bot.bot_config):
                return
            await interaction.response.defer()
            try:
                loop = asyncio.get_event_loop()
                clean = domain.lower().strip()

                result = await loop.run_in_executor(
                    None, functools.partial(bot.scorer.score, clean)
                )

                score = result["score"]
                emoji = _score_emoji(score)
                category_key = result.get("category", "unknown")
                category_label = _CATEGORY_LABELS.get(
                    category_key, category_key.replace("_", " ").title()
                )
                source_label = "Groq AI" if result.get("source") == "llm" else "rules"

                colour = (
                    0x57F287 if score <= 3
                    else 0xFEE75C if score <= 6
                    else 0xED4245 if score <= 8
                    else 0x2C2F33
                )
                embed = discord.Embed(
                    title=f"🔍 Domain Score: {clean}",
                    colour=colour,
                )
                embed.add_field(name="Score",    value=f"{emoji} {score}/10", inline=True)
                embed.add_field(name="Category", value=category_label,         inline=True)
                if result.get("company"):
                    embed.add_field(name="Company", value=result["company"], inline=True)
                if result.get("reason"):
                    embed.add_field(name="Why", value=result["reason"], inline=False)
                embed.add_field(name="Classified by", value=source_label, inline=True)
                embed.set_footer(
                    text=f"dns-sentinel · "
                    f"{datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}"
                )
                await interaction.followup.send(embed=embed)

            except Exception as exc:
                log.error("Error in /score: %s", exc, exc_info=True)
                await interaction.followup.send(
                    embed=_error_embed(str(exc)), ephemeral=True
                )

        # ── /stats ────────────────────────────────────────────────────────────

        @self.tree.command(name="stats", description="Show live dns-sentinel statistics")
        async def cmd_stats(interaction: discord.Interaction) -> None:
            if not await _check_access(interaction, bot.bot_config):
                return
            await interaction.response.defer()
            try:
                loop = asyncio.get_event_loop()
                today_start = datetime.now(timezone.utc).replace(
                    hour=0, minute=0, second=0, microsecond=0
                )

                stats = await loop.run_in_executor(
                    None, functools.partial(bot.db_logger.get_stats, today_start)
                )
                score_stats = await loop.run_in_executor(
                    None, functools.partial(bot.db_logger.get_score_stats, today_start)
                )
                last_blocked = await loop.run_in_executor(
                    None, functools.partial(_get_last_blocked, bot.db_path)
                )

                avg = score_stats.get("avg_score", 0)
                last_str = (
                    f"`{last_blocked['domain']}` — "
                    f"{_fmt_time_ago(last_blocked['timestamp'])}"
                    if last_blocked
                    else "None yet"
                )

                embed = discord.Embed(title="📡 dns-sentinel — Live Stats", colour=0x5865F2)
                embed.add_field(name="Uptime",             value=_fmt_uptime(bot.start_time),    inline=True)
                embed.add_field(name="Blocklist size",     value=f"{bot.blocklist.domain_count():,} domains", inline=True)
                embed.add_field(name="Total queries today",value=f"{stats['total']:,}",           inline=True)
                embed.add_field(name="Blocked today",      value=f"{stats['blocked']:,} ({stats['block_rate']}%)", inline=True)
                embed.add_field(name="Avg threat score",   value=f"{avg:.1f}/10" if avg else "—", inline=True)
                embed.add_field(name="Last block",         value=last_str,                        inline=False)
                embed.set_footer(
                    text=f"dns-sentinel · "
                    f"{datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}"
                )
                await interaction.followup.send(embed=embed)

            except Exception as exc:
                log.error("Error in /stats: %s", exc, exc_info=True)
                await interaction.followup.send(
                    embed=_error_embed(str(exc)), ephemeral=True
                )

        # ── /blocklist refresh ────────────────────────────────────────────────

        blocklist_group = app_commands.Group(
            name="blocklist", description="Blocklist management"
        )

        @blocklist_group.command(
            name="refresh", description="Re-download all blocklists from source URLs"
        )
        async def cmd_blocklist_refresh(interaction: discord.Interaction) -> None:
            if not await _check_access(interaction, bot.bot_config):
                return
            await interaction.response.defer()
            try:
                loop = asyncio.get_event_loop()
                t0 = loop.time()
                await loop.run_in_executor(None, bot.blocklist.refresh)
                duration = loop.time() - t0

                count = bot.blocklist.domain_count()
                sources = len(bot.blocklist.sources)

                embed = discord.Embed(title="✅ Blocklists refreshed", colour=0x57F287)
                embed.add_field(
                    name="Domains loaded",
                    value=f"{count:,} from {sources} source{'s' if sources != 1 else ''}",
                    inline=True,
                )
                embed.add_field(name="Duration", value=f"{duration:.1f}s", inline=True)
                embed.set_footer(
                    text=f"dns-sentinel · "
                    f"{datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}"
                )
                await interaction.followup.send(embed=embed)

            except Exception as exc:
                log.error("Error in /blocklist refresh: %s", exc, exc_info=True)
                await interaction.followup.send(
                    embed=_error_embed(str(exc)), ephemeral=True
                )

        self.tree.add_command(blocklist_group)


# ── Entry point called from server.py ─────────────────────────────────────────

def run_bot(bot: SentinelBot, token: str) -> None:
    """
    Start the bot's asyncio event loop in the calling thread.

    Designed to be called inside a daemon threading.Thread. Any exception
    is caught and logged so the DNS server is not affected.
    """
    try:
        asyncio.run(bot.start(token))
    except Exception as exc:
        log.error("Discord bot crashed: %s", exc, exc_info=True)
