"""
Blocklist loader and domain matcher for dns-sentinel.

Downloads hosts-format blocklists from configured URLs, caches them locally,
and provides O(1) domain lookup with subdomain matching.
"""

import logging
import re
from pathlib import Path
from typing import Optional

import requests

logger = logging.getLogger(__name__)


class BlocklistLoader:
    """
    Loads and manages DNS blocklists from remote hosts-format files.

    Supports subdomain matching: blocking 'doubleclick.net' also blocks
    'ad.doubleclick.net', 'track.doubleclick.net', etc.
    """

    def __init__(self, config: dict, cache_dir: str = "blocklists") -> None:
        """
        Initialize the blocklist loader.

        Args:
            config: The [blocklist] section of the application config.
            cache_dir: Directory to cache downloaded blocklist files.
        """
        self.sources: list[str] = config.get("sources", [])
        self.custom: list[str] = config.get("custom", [])
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self._blocked: set[str] = set()
        self._domain_sources: dict[str, list[str]] = {}

    def load(self) -> None:
        """Load all blocklists. Uses cached files if available, otherwise downloads."""
        for url in self.sources:
            cache_file = self._cache_path(url)
            if cache_file.exists():
                logger.info("Loading cached blocklist: %s", cache_file.name)
                self._parse_file(cache_file, source_url=url)
            else:
                self._download_and_parse(url)

        self._add_custom()
        logger.info("Blocklist loaded: %d blocked domains total", len(self._blocked))

    def refresh(self) -> None:
        """Re-download all blocklist sources and rebuild the blocked domain set."""
        logger.info("Refreshing blocklists from %d sources...", len(self.sources))
        self._blocked.clear()
        self._domain_sources.clear()

        for url in self.sources:
            self._download_and_parse(url)

        self._add_custom()
        logger.info("Blocklist refreshed: %d blocked domains total", len(self._blocked))

    def is_blocked(self, domain: str) -> bool:
        """
        Check if a domain (or any of its parents) is blocked.

        Args:
            domain: The fully-qualified domain name to check.

        Returns:
            True if the domain or a parent domain is in the blocklist.
        """
        domain = domain.rstrip(".").lower()
        parts = domain.split(".")
        for i in range(len(parts) - 1):
            candidate = ".".join(parts[i:])
            if candidate in self._blocked:
                return True
        return False

    def domain_count(self) -> int:
        """Return the number of blocked domains currently loaded."""
        return len(self._blocked)

    def _download_and_parse(self, url: str) -> None:
        """Download a blocklist from a URL and parse it."""
        logger.info("Downloading blocklist: %s", url)
        try:
            response = requests.get(url, timeout=30)
            response.raise_for_status()
            cache_file = self._cache_path(url)
            cache_file.write_text(response.text, encoding="utf-8")
            count_before = len(self._blocked)
            self._parse_file(cache_file, source_url=url)
            added = len(self._blocked) - count_before
            logger.info("Loaded %d domains from %s", added, url)
        except requests.RequestException as exc:
            logger.error("Failed to download blocklist %s: %s", url, exc)

    def _parse_file(self, path: Path, source_url: str = "") -> None:
        """
        Parse a hosts-format file and add domains to the blocked set.

        Handles lines like:
            0.0.0.0 ad.example.com
            127.0.0.1 tracker.example.com

        Args:
            path:       Path to the cached hosts file.
            source_url: The URL this file was downloaded from, used to track
                        which lists each domain appears on.
        """
        hosts_pattern = re.compile(
            r"^(?:0\.0\.0\.0|127\.0\.0\.1)\s+([a-zA-Z0-9._-]+)"
        )
        try:
            with path.open("r", encoding="utf-8", errors="ignore") as fh:
                for line in fh:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    match = hosts_pattern.match(line)
                    if match:
                        domain = match.group(1).lower()
                        if domain not in ("localhost", "localhost.localdomain", "broadcasthost"):
                            self._blocked.add(domain)
                            if source_url:
                                sources = self._domain_sources.setdefault(domain, [])
                                if source_url not in sources:
                                    sources.append(source_url)
        except OSError as exc:
            logger.error("Failed to read blocklist file %s: %s", path, exc)

    def get_sources(self, domain: str) -> list[str]:
        """
        Return the source URLs that contain this domain or any parent domain.

        Mirrors the subdomain matching logic of is_blocked().

        Args:
            domain: The queried domain name.

        Returns:
            List of source URLs; empty list if the domain source is untracked.
        """
        domain = domain.rstrip(".").lower()
        parts = domain.split(".")
        for i in range(len(parts) - 1):
            candidate = ".".join(parts[i:])
            if candidate in self._domain_sources:
                return list(self._domain_sources[candidate])
        return []

    def _add_custom(self) -> None:
        """Add custom domains from config to the blocked set."""
        for domain in self.custom:
            d = domain.lower().strip()
            self._blocked.add(d)
            sources = self._domain_sources.setdefault(d, [])
            if "custom" not in sources:
                sources.append("custom")
        if self.custom:
            logger.info("Added %d custom blocked domains", len(self.custom))

    def _cache_path(self, url: str) -> Path:
        """Convert a URL to a safe local cache filename."""
        safe_name = re.sub(r"[^a-zA-Z0-9._-]", "_", url)[:100] + ".txt"
        return self.cache_dir / safe_name
