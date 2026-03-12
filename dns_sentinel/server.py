"""
UDP DNS proxy server for dns-sentinel.

Listens for DNS queries, checks each domain against the blocklist,
returns NXDOMAIN for blocked domains, and forwards legitimate queries
to the configured upstream resolver.

Run with: python -m dns_sentinel.server
"""

import logging
import os
import signal
import socket
import sys
import threading
from datetime import datetime, timezone
from typing import Optional

from dnslib import DNSRecord, RCODE
from dnslib.server import DNSServer, BaseResolver
from dnslib.server import DNSLogger as DnsLibLogger

from .blocklist import BlocklistLoader
from .logger import QueryLogger
from .notifier import DiscordNotifier
from .scorer import Scorer

log = logging.getLogger(__name__)


class SentinelResolver(BaseResolver):
    """
    dnslib resolver that enforces the blocklist and proxies allowed queries.
    """

    def __init__(
        self,
        blocklist: BlocklistLoader,
        db_logger: QueryLogger,
        notifier: DiscordNotifier,
        scorer: Scorer,
        upstream_host: str,
        upstream_port: int,
    ) -> None:
        """
        Initialise the resolver.

        Args:
            blocklist:     Loaded BlocklistLoader instance.
            db_logger:     QueryLogger for persisting query records.
            notifier:      DiscordNotifier for sending block alerts.
            scorer:        Scorer for computing domain threat scores.
            upstream_host: IP of the upstream DNS resolver.
            upstream_port: Port of the upstream DNS resolver.
        """
        self.blocklist = blocklist
        self.db_logger = db_logger
        self.notifier = notifier
        self.scorer = scorer
        self.upstream_host = upstream_host
        self.upstream_port = upstream_port

    def resolve(self, request: DNSRecord, handler) -> DNSRecord:
        """
        Handle an incoming DNS query.

        Returns NXDOMAIN for blocked domains; forwards to upstream otherwise.
        Malformed packets are caught by dnslib before reaching this method.
        """
        reply = request.reply()
        qname = str(request.q.qname).rstrip(".")
        client_ip: Optional[str] = getattr(handler, "client_address", (None,))[0]

        if self.blocklist.is_blocked(qname):
            log.info("BLOCKED  %s (client: %s)", qname, client_ip)
            reply.header.rcode = RCODE.NXDOMAIN
            self._record_async(qname, client_ip, blocked=True)
            return reply

        try:
            upstream_reply = self._forward(request)
            if upstream_reply:
                log.debug("ALLOWED  %s", qname)
                self._record_async(qname, client_ip, blocked=False)
                return upstream_reply
        except Exception as exc:
            log.error("Upstream query failed for %s: %s", qname, exc)

        reply.header.rcode = RCODE.SERVFAIL
        return reply

    def _forward(self, request: DNSRecord) -> Optional[DNSRecord]:
        """Send the query to the upstream DNS server and return the response."""
        raw = request.pack()
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(5.0)
            sock.sendto(raw, (self.upstream_host, self.upstream_port))
            data, _ = sock.recvfrom(4096)
        return DNSRecord.parse(data)

    def _record_async(
        self, domain: str, client_ip: Optional[str], blocked: bool
    ) -> None:
        """Log, score, and notify in a background thread to keep the DNS hot path fast."""

        def _work() -> None:
            try:
                self.db_logger.log_query(domain, client_ip, blocked)
                if blocked:
                    sources = self.blocklist.get_sources(domain)
                    score_data = self.scorer.score(domain, blocklist_sources=sources)
                    self.notifier.notify(domain, client_ip, score_data=score_data)
            except Exception as exc:
                log.error("Background record error: %s", exc)

        threading.Thread(target=_work, daemon=True).start()


class SentinelServer:
    """
    Wraps dnslib's DNSServer with graceful startup/shutdown and config loading.
    """

    def __init__(self, config: dict) -> None:
        """
        Initialise the server from a loaded config dict.

        Args:
            config: Full application config (all sections).
        """
        self._config = config
        self.start_time = datetime.now(timezone.utc)

        dns_cfg = config["dns"]
        self.host: str = dns_cfg.get("listen_host", "0.0.0.0")
        self.port: int = int(dns_cfg.get("listen_port", 5353))

        self.blocklist = BlocklistLoader(config["blocklist"])
        self.db_logger = QueryLogger(config["database"]["path"])
        self.notifier = DiscordNotifier(config["discord"], db_logger=self.db_logger)
        self.scorer = Scorer(config, self.db_logger)

        self.resolver = SentinelResolver(
            blocklist=self.blocklist,
            db_logger=self.db_logger,
            notifier=self.notifier,
            scorer=self.scorer,
            upstream_host=dns_cfg.get("upstream_dns", "1.1.1.1"),
            upstream_port=int(dns_cfg.get("upstream_port", 53)),
        )

        self._dns_server: Optional[DNSServer] = None

    def start(self) -> None:
        """Load blocklists, start the DNS server, and block until shutdown."""
        log.info("Loading blocklists...")
        self.blocklist.load()
        log.info("Blocklist ready: %d domains", self.blocklist.domain_count())

        self._dns_server = DNSServer(
            self.resolver,
            port=self.port,
            address=self.host,
            logger=DnsLibLogger(prefix=False),
        )

        signal.signal(signal.SIGINT, self._handle_shutdown)
        signal.signal(signal.SIGTERM, self._handle_shutdown)

        log.info("DNS Sentinel listening on %s:%d", self.host, self.port)
        self._dns_server.start_thread()

        self._start_bot()

        # Block the main thread until a signal arrives
        try:
            signal.pause()
        except AttributeError:
            # signal.pause() not available on Windows
            import time
            while True:
                time.sleep(1)

    def _start_bot(self) -> None:
        """Start the Discord bot in a background thread if configured and enabled."""
        bot_cfg = self._config.get("bot", {})
        if not bot_cfg.get("enabled", False):
            return

        token = bot_cfg.get("token", "")
        if not token or token == "YOUR_DISCORD_BOT_TOKEN_HERE":
            log.warning("Discord bot enabled but no token configured — skipping")
            return

        try:
            from .bot import SentinelBot, run_bot

            bot = SentinelBot(
                config=self._config,
                db_logger=self.db_logger,
                scorer=self.scorer,
                blocklist=self.blocklist,
                start_time=self.start_time,
            )
            bot_thread = threading.Thread(
                target=run_bot,
                args=(bot, token),
                daemon=True,
                name="discord-bot",
            )
            bot_thread.start()
            log.info("Discord bot thread started")
        except Exception as exc:
            log.error("Failed to start Discord bot: %s", exc)

    def stop(self) -> None:
        """Gracefully stop the server and background threads."""
        log.info("Shutting down DNS Sentinel...")
        if self._dns_server:
            self._dns_server.stop()
        self.notifier.stop()
        log.info("Shutdown complete.")

    def _handle_shutdown(self, signum, frame) -> None:
        """Signal handler for SIGINT/SIGTERM."""
        self.stop()
        sys.exit(0)


def _load_config(path: str = "config.toml") -> dict:
    """
    Load TOML config from disk.

    Falls back to config.example.toml if config.toml is not found.
    """
    try:
        import tomllib
    except ImportError:
        import tomli as tomllib  # type: ignore[no-redef]

    if not os.path.exists(path):
        fallback = "config.example.toml"
        log.warning("Config %s not found, using %s", path, fallback)
        path = fallback

    with open(path, "rb") as fh:
        return tomllib.load(fh)


def main() -> None:
    """Configure logging, load config, and start the DNS server."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)-8s %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    config = _load_config()
    server = SentinelServer(config)
    server.start()


if __name__ == "__main__":
    main()
