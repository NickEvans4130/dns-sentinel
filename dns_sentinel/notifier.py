"""
Discord webhook notifier for dns-sentinel.

Supports two alert modes:
  - realtime: fires an embed immediately for every blocked domain
  - batch:    collects blocks and sends a summary on a configurable interval
"""

import logging
import queue
import threading
import time
from collections import Counter
from datetime import datetime, timezone
from typing import Optional

import requests

log = logging.getLogger(__name__)

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

_SCORE_STYLES: list[tuple[int, str, int]] = [
    # (max_score, emoji, hex_color)
    (3,  "🟢", 0x57F287),
    (6,  "🟡", 0xFEE75C),
    (8,  "🔴", 0xED4245),
    (10, "☠️",  0x2C2F33),
]


def _score_style(score: int) -> tuple[str, int]:
    """Return (emoji, hex_color) for a numeric score 1-10."""
    for max_score, emoji, color in _SCORE_STYLES:
        if score <= max_score:
            return emoji, color
    return "☠️", 0x2C2F33


class DiscordNotifier:
    """
    Sends DNS block notifications to a Discord webhook.

    In realtime mode each block triggers an immediate webhook POST.
    In batch mode blocks are collected and a summary is sent on an interval.
    """

    def __init__(self, config: dict, db_logger=None) -> None:
        """
        Initialise the notifier.

        Args:
            config:    The [discord] section of the application config.
            db_logger: Optional QueryLogger used to enrich batch summaries.
        """
        self.webhook_url: str = config.get("webhook_url", "")
        self.alert_mode: str = config.get("alert_mode", "realtime")
        self.batch_interval: int = int(config.get("batch_interval_minutes", 60)) * 60

        self._db_logger = db_logger
        self._batch: list[str] = []
        self._batch_lock = threading.Lock()
        self._notify_queue: queue.Queue = queue.Queue(maxsize=500)
        self._stop_event = threading.Event()

        self._worker = threading.Thread(
            target=self._queue_worker, daemon=True, name="notifier-worker"
        )
        self._worker.start()

        if self.alert_mode in ("hourly", "daily", "batch"):
            self._batch_thread = threading.Thread(
                target=self._batch_loop, daemon=True, name="notifier-batch"
            )
            self._batch_thread.start()

    def notify(
        self,
        domain: str,
        client_ip: Optional[str] = None,
        score_data: Optional[dict] = None,
    ) -> None:
        """
        Schedule a notification for a blocked domain.

        This method returns immediately; delivery is handled by a background thread.

        Args:
            domain:     The blocked domain name.
            client_ip:  Optional client IP address (for context).
            score_data: Optional threat score dict from the Scorer.
        """
        if not self.webhook_url or self.webhook_url == "YOUR_DISCORD_WEBHOOK_URL_HERE":
            return

        if self.alert_mode == "realtime":
            try:
                self._notify_queue.put_nowait(("realtime", domain, client_ip, score_data))
            except queue.Full:
                log.warning("Notification queue full — dropping alert for %s", domain)
        else:
            with self._batch_lock:
                self._batch.append(domain)

    def stop(self) -> None:
        """Signal background threads to stop gracefully."""
        self._stop_event.set()

    def _queue_worker(self) -> None:
        """Consume the notification queue and deliver webhooks."""
        while not self._stop_event.is_set():
            try:
                item = self._notify_queue.get(timeout=1.0)
                mode, domain, client_ip, score_data = item
                self._send_realtime(domain, client_ip, score_data)
                self._notify_queue.task_done()
            except queue.Empty:
                continue

    def _batch_loop(self) -> None:
        """Sleep for the batch interval then send a summary."""
        while not self._stop_event.is_set():
            self._stop_event.wait(timeout=self.batch_interval)
            if self._stop_event.is_set():
                break
            self._flush_batch()

    def _flush_batch(self) -> None:
        """Send a batch summary and clear the in-memory buffer."""
        with self._batch_lock:
            batch = list(self._batch)
            self._batch.clear()

        if not batch:
            return

        label = "Hourly" if self.alert_mode == "hourly" else "Batch"
        counter = Counter(batch)
        top = counter.most_common(5)

        lines = [
            f"{i+1}. `{domain}` — {count} block{'s' if count != 1 else ''}"
            for i, (domain, count) in enumerate(top)
        ]

        description = (
            f"Blocked **{len(batch)} tracker{'s' if len(batch) != 1 else ''}** "
            f"in the last {self.batch_interval // 60} minute(s)\n\n"
            f"**Top offenders:**\n" + "\n".join(lines)
        )

        payload = {
            "embeds": [
                {
                    "title": f"Tracker Report — {label}",
                    "description": description,
                    "color": 0xE74C3C,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                }
            ]
        }
        self._post_webhook(payload)

    def _send_realtime(
        self,
        domain: str,
        client_ip: Optional[str],
        score_data: Optional[dict],
    ) -> None:
        """Build and send a realtime block embed, enriched with score data if available."""
        ts = datetime.now(timezone.utc).isoformat()

        if score_data:
            score = int(score_data.get("score", 5))
            category_key = score_data.get("category", "unknown")
            company = score_data.get("company")
            reason = score_data.get("reason", "")
            source = score_data.get("source", "rules")

            emoji, color = _score_style(score)
            category_label = _CATEGORY_LABELS.get(category_key, category_key.replace("_", " ").title())
            source_label = "ai-classified" if source == "llm" else "rules"

            fields = [
                {"name": "Domain", "value": f"`{domain}`", "inline": True},
                {
                    "name": "Score",
                    "value": f"{emoji} {score}/10 — {category_label}",
                    "inline": True,
                },
            ]
            if company:
                fields.append({"name": "Company", "value": company, "inline": True})
            if reason:
                fields.append({"name": "Why", "value": reason, "inline": False})
            fields.append({"name": "Source", "value": source_label, "inline": True})
            if client_ip:
                fields.append({"name": "Client", "value": f"`{client_ip}`", "inline": True})

            embed: dict = {
                "title": "🚫 Tracker Blocked",
                "color": color,
                "fields": fields,
                "timestamp": ts,
            }
        else:
            # Fallback: plain embed when no score data is available
            now = datetime.now(timezone.utc).strftime("%H:%M:%S UTC")
            description = f"`{domain}`\nBlocked at {now}"
            if client_ip:
                description += f"\nClient: `{client_ip}`"
            embed = {
                "title": "🚫 Tracker Blocked",
                "description": description,
                "color": 0xFF4444,
                "timestamp": ts,
            }

        self._post_webhook({"embeds": [embed]})

    def _post_webhook(self, payload: dict, retry: bool = True) -> None:
        """
        POST a payload to the Discord webhook URL.

        Retries once on failure. Logs to stderr on second failure but never
        raises — the DNS server must not crash due to notification issues.
        """
        try:
            resp = requests.post(self.webhook_url, json=payload, timeout=10)
            resp.raise_for_status()
        except requests.RequestException as exc:
            if retry:
                log.warning("Webhook delivery failed (%s), retrying in 2s...", exc)
                time.sleep(2)
                self._post_webhook(payload, retry=False)
            else:
                log.error("Webhook delivery failed permanently: %s", exc)
