"""
Domain threat scorer for dns-sentinel.

Classifies blocked domains in three layers:
  1. Known-company map  — instant O(1) lookup for ~60 high-traffic trackers
  2. Rule-based heuristics — pattern signals + blocklist source weighting
  3. Groq LLM fallback — called only for novel unknown domains when configured

The public API is a single score() method that is always safe to call:
it catches every exception internally and returns a safe default.
"""

import json
import logging
from datetime import datetime, timezone
from typing import Optional

import requests

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Layer 1 — Known-company map
# ---------------------------------------------------------------------------

_KNOWN_DOMAINS: dict[str, dict] = {
    # Google — ad_network
    "doubleclick.net": {
        "score": 6, "category": "ad_network", "company": "Google",
        "reason": "Google's primary ad delivery and cross-site tracking network.",
    },
    "google-analytics.com": {
        "score": 6, "category": "ad_network", "company": "Google",
        "reason": "Google Analytics collects detailed user behaviour data across all sites.",
    },
    "googletagmanager.com": {
        "score": 6, "category": "ad_network", "company": "Google",
        "reason": "Google Tag Manager loads third-party tracking scripts on publisher sites.",
    },
    "googlesyndication.com": {
        "score": 6, "category": "ad_network", "company": "Google",
        "reason": "Google AdSense ad delivery network embedded in millions of websites.",
    },
    "googleadservices.com": {
        "score": 6, "category": "ad_network", "company": "Google",
        "reason": "Google ad click tracking and conversion measurement service.",
    },
    "googletagservices.com": {
        "score": 6, "category": "ad_network", "company": "Google",
        "reason": "Google Tag Services hosts ad tag scripts for publisher monetisation.",
    },
    "gstatic.com": {
        "score": 4, "category": "ad_network", "company": "Google",
        "reason": "Google static content CDN; also serves ad resources and tracking pixels.",
    },
    # Meta — cross_site_tracking / fingerprinting
    "facebook.net": {
        "score": 8, "category": "cross_site_tracking", "company": "Meta Platforms",
        "reason": "Meta's ad network tracks users across all sites with the Facebook pixel.",
    },
    "pixel.facebook.com": {
        "score": 9, "category": "fingerprinting", "company": "Meta Platforms",
        "reason": "Facebook pixel beacon records every page view and action for ad targeting.",
    },
    "connect.facebook.net": {
        "score": 8, "category": "cross_site_tracking", "company": "Meta Platforms",
        "reason": "Loads Facebook SDK including Like buttons and cross-site tracking scripts.",
    },
    "fbcdn.net": {
        "score": 4, "category": "analytics", "company": "Meta Platforms",
        "reason": "Facebook CDN for serving assets; also used to track media engagement.",
    },
    # Data brokers — data_broker
    "acxiom.com": {
        "score": 9, "category": "data_broker", "company": "Acxiom",
        "reason": "Major data broker aggregating offline and online consumer profiles.",
    },
    "datalogix.com": {
        "score": 9, "category": "data_broker", "company": "Oracle",
        "reason": "Oracle Data Cloud bridges offline purchase data with online ad targeting.",
    },
    "liveramp.com": {
        "score": 9, "category": "data_broker", "company": "LiveRamp",
        "reason": "Identity resolution platform links fragmented user data across advertisers.",
    },
    "bluekai.com": {
        "score": 9, "category": "data_broker", "company": "Oracle",
        "reason": "Oracle BlueKai data marketplace sells audience segments for ad targeting.",
    },
    "krxd.net": {
        "score": 9, "category": "data_broker", "company": "Salesforce",
        "reason": "Salesforce Krux DMP collects and sells audience data across publisher networks.",
    },
    "demdex.net": {
        "score": 8, "category": "data_broker", "company": "Adobe",
        "reason": "Adobe Audience Manager syncs user IDs across data partners for ad targeting.",
    },
    # Amazon — ad_network
    "amazon-adsystem.com": {
        "score": 5, "category": "ad_network", "company": "Amazon",
        "reason": "Amazon's ad delivery network tracking purchases and serving retargeted ads.",
    },
    "assoc-amazon.com": {
        "score": 5, "category": "ad_network", "company": "Amazon",
        "reason": "Amazon Associates affiliate link tracking domain.",
    },
    # Microsoft — telemetry / analytics
    "bat.bing.com": {
        "score": 5, "category": "telemetry", "company": "Microsoft",
        "reason": "Bing Ads Universal Event Tracking pixel collects ad conversion data.",
    },
    "clarity.ms": {
        "score": 5, "category": "analytics", "company": "Microsoft",
        "reason": "Microsoft Clarity records session replays and heatmaps of user interactions.",
    },
    "c.bing.com": {
        "score": 4, "category": "telemetry", "company": "Microsoft",
        "reason": "Bing telemetry and ad click tracking endpoint.",
    },
    # TikTok — cross_site_tracking
    "analytics.tiktok.com": {
        "score": 7, "category": "cross_site_tracking", "company": "ByteDance",
        "reason": "TikTok Pixel tracks user actions on third-party sites for ad optimisation.",
    },
    "ads.tiktok.com": {
        "score": 7, "category": "ad_network", "company": "ByteDance",
        "reason": "TikTok ad delivery and conversion tracking infrastructure.",
    },
    # Basic analytics
    "hotjar.com": {
        "score": 4, "category": "analytics", "company": "Hotjar",
        "reason": "Session recording and heatmap analytics tool embedded on commercial sites.",
    },
    "mixpanel.com": {
        "score": 4, "category": "analytics", "company": "Mixpanel",
        "reason": "Product analytics platform tracking user events and conversion funnels.",
    },
    "segment.io": {
        "score": 4, "category": "analytics", "company": "Twilio Segment",
        "reason": "Customer data platform routing user events to dozens of analytics services.",
    },
    "amplitude.com": {
        "score": 4, "category": "analytics", "company": "Amplitude",
        "reason": "Product analytics tracking user journeys across web and mobile apps.",
    },
    "heap.io": {
        "score": 4, "category": "analytics", "company": "Heap",
        "reason": "Auto-captures all user interactions for retroactive product analytics.",
    },
    "fullstory.com": {
        "score": 5, "category": "fingerprinting", "company": "FullStory",
        "reason": "Records complete session replays including keypresses and mouse movements.",
    },
    "logrocket.com": {
        "score": 4, "category": "analytics", "company": "LogRocket",
        "reason": "Frontend monitoring with full session replay capabilities.",
    },
    # CDN / performance telemetry — low threat
    "newrelic.com": {
        "score": 2, "category": "telemetry", "company": "New Relic",
        "reason": "Application performance monitoring; primarily server-side telemetry.",
    },
    "nr-data.net": {
        "score": 2, "category": "telemetry", "company": "New Relic",
        "reason": "New Relic browser agent data collection endpoint.",
    },
    "datadog-browser-agent.com": {
        "score": 2, "category": "telemetry", "company": "Datadog",
        "reason": "Datadog RUM browser agent for frontend performance monitoring.",
    },
    "sentry.io": {
        "score": 2, "category": "telemetry", "company": "Sentry",
        "reason": "Error tracking and performance monitoring; collects stack traces.",
    },
    "datadoghq.com": {
        "score": 2, "category": "telemetry", "company": "Datadog",
        "reason": "Datadog infrastructure and application monitoring platform.",
    },
    # Ad networks — ad_network / cross_site_tracking
    "outbrain.com": {
        "score": 6, "category": "ad_network", "company": "Outbrain",
        "reason": "Native content recommendation network with cross-site browsing tracking.",
    },
    "taboola.com": {
        "score": 6, "category": "ad_network", "company": "Taboola",
        "reason": "Sponsored content recommendation network with persistent cross-site cookies.",
    },
    "criteo.com": {
        "score": 7, "category": "ad_network", "company": "Criteo",
        "reason": "Retargeting network tracking shopping behaviour across e-commerce sites.",
    },
    "criteo.net": {
        "score": 7, "category": "ad_network", "company": "Criteo",
        "reason": "Criteo retargeting infrastructure and ad delivery network.",
    },
    "adsrvr.org": {
        "score": 7, "category": "ad_network", "company": "The Trade Desk",
        "reason": "The Trade Desk programmatic ad platform with extensive cross-site tracking.",
    },
    "rubiconproject.com": {
        "score": 6, "category": "ad_network", "company": "Magnite",
        "reason": "Programmatic advertising exchange collecting bidstream user signals.",
    },
    "openx.net": {
        "score": 6, "category": "ad_network", "company": "OpenX",
        "reason": "Programmatic ad exchange collecting bid request data with user identifiers.",
    },
    "pubmatic.com": {
        "score": 6, "category": "ad_network", "company": "PubMatic",
        "reason": "Supply-side ad platform tracking users across publisher inventory.",
    },
    "scorecardresearch.com": {
        "score": 6, "category": "analytics", "company": "Comscore",
        "reason": "Comscore audience measurement beacons embedded across news and media sites.",
    },
    "moatads.com": {
        "score": 6, "category": "analytics", "company": "Oracle Moat",
        "reason": "Oracle Moat ad viewability and brand measurement tracking pixels.",
    },
    "adnxs.com": {
        "score": 7, "category": "ad_network", "company": "Xandr (Microsoft)",
        "reason": "Xandr/AppNexus programmatic advertising platform with bidstream tracking.",
    },
    "advertising.com": {
        "score": 7, "category": "ad_network", "company": "Yahoo",
        "reason": "Yahoo advertising network tracking users for targeted ad delivery.",
    },
    "quantserve.com": {
        "score": 6, "category": "analytics", "company": "Quantcast",
        "reason": "Quantcast audience measurement and programmatic advertising cookies.",
    },
    "chartbeat.com": {
        "score": 3, "category": "analytics", "company": "Chartbeat",
        "reason": "Real-time editorial analytics tracking content engagement on news sites.",
    },
    # Attribution / fingerprinting
    "branch.io": {
        "score": 6, "category": "fingerprinting", "company": "Branch Metrics",
        "reason": "Mobile deep linking with device fingerprinting for cross-device tracking.",
    },
    "adjust.com": {
        "score": 6, "category": "cross_site_tracking", "company": "Adjust GmbH",
        "reason": "Mobile app attribution tracking installs, events and user journeys.",
    },
    "appsflyer.com": {
        "score": 6, "category": "cross_site_tracking", "company": "AppsFlyer",
        "reason": "Mobile attribution and marketing analytics with device fingerprinting.",
    },
}

# ---------------------------------------------------------------------------
# Layer 2 helpers
# ---------------------------------------------------------------------------

_MALICIOUS_TLDS = {"xyz", "top", "tk", "click", "bid", "loan", "work", "date"}

_SOURCE_BASE_SCORES: list[tuple[str, int]] = [
    ("fakenews", 3),
    ("gambling", 3),
    ("porn", 3),
    ("adware", 3),
    ("adaway", 2),
    ("stevenblack", 1),
    ("hosts", 1),
]


def _source_base_score(source_url: str) -> int:
    """Return the threat base score for a blocklist source URL."""
    url_lower = source_url.lower()
    for keyword, score in _SOURCE_BASE_SCORES:
        if keyword in url_lower:
            return score
    return 1  # generic blocklist


def _rule_score(domain: str, blocklist_sources: list[str]) -> dict:
    """
    Compute a rule-based threat score from domain patterns and source lists.

    Args:
        domain:           The blocked domain (lowercased).
        blocklist_sources: Source URLs that contained this domain.

    Returns:
        Score dict with keys: score, category, company, reason, source.
    """
    score = 0
    category = "unknown"
    signals: list[str] = []

    # Source-based score: max per-source base * min(distinct_count, 3)
    if blocklist_sources:
        max_base = max(_source_base_score(s) for s in blocklist_sources)
        multiplier = min(len(set(blocklist_sources)), 3)
        source_contribution = max_base * multiplier
        score += source_contribution
        count = len(set(blocklist_sources))
        signals.append(f"on {count} blocklist{'s' if count != 1 else ''}")

    # Isolate subdomain portion for keyword matching
    parts = domain.split(".")
    # subdomain is everything except the last two labels (registrable domain)
    subdomain = ".".join(parts[:-2]) if len(parts) > 2 else ""
    tld = parts[-1] if parts else ""

    # Fingerprinting/tracking keywords (+3)
    fp_keywords = ["pixel", "beacon", "track", "telemetry", "spy", "fingerprint"]
    if any(kw in subdomain for kw in fp_keywords):
        score += 3
        matched = next(kw for kw in fp_keywords if kw in subdomain)
        if matched in ("pixel", "beacon", "fingerprint"):
            category = "fingerprinting"
        else:
            category = "cross_site_tracking"
        signals.append(f'"{matched}" subdomain')

    # Ad keywords (+2)
    ad_keywords = ["ad", "ads", "advert", "banner"]
    if any(kw in subdomain.split(".") for kw in ad_keywords):
        score += 2
        if category == "unknown":
            category = "ad_network"
        signals.append("ad subdomain")

    # Analytics keywords (+1)
    analytics_keywords = ["analytics", "metrics", "stats", "log", "logs"]
    if any(kw in subdomain for kw in analytics_keywords):
        score += 1
        if category == "unknown":
            category = "analytics"
        signals.append("analytics subdomain")

    # "track" anywhere in domain (+implicit category)
    if "track" in domain and "track" not in subdomain:
        if category == "unknown":
            category = "cross_site_tracking"

    # Suspicious TLD (+2)
    if tld in _MALICIOUS_TLDS:
        score += 2
        if category == "unknown":
            category = "malware_c2"
        signals.append(f"suspicious .{tld} TLD")

    score = max(1, min(score, 10))

    if signals:
        reason = ", ".join(s.capitalize() for s in signals)
    else:
        reason = "Blocked domain with no additional pattern signals"

    return {
        "score": score,
        "category": category,
        "company": None,
        "reason": reason,
        "source": "rules",
    }


# ---------------------------------------------------------------------------
# Scorer class
# ---------------------------------------------------------------------------

class Scorer:
    """
    Classifies blocked domains with a privacy threat score (1-10).

    Layer 1: Instant lookup in the known-company map.
    Layer 2: Rule-based heuristics from domain patterns and blocklist sources.
    Layer 3: Groq LLM for novel domains of unknown category (optional).

    All results are cached in SQLite via QueryLogger so each domain is only
    classified once.
    """

    _SAFE_DEFAULT: dict = {
        "score": 5,
        "category": "unknown",
        "company": None,
        "reason": "Score unavailable.",
        "source": "rules",
    }

    def __init__(self, config: dict, logger) -> None:
        """
        Initialise the scorer.

        Args:
            config: Full application config dict; reads the [scoring] section.
            logger: QueryLogger instance used for cache reads and writes.
        """
        scoring_cfg = config.get("scoring", {})
        self._api_key: str = scoring_cfg.get("groq_api_key", "")
        self._model: str = scoring_cfg.get("groq_model", "llama-3.1-8b-instant")
        self._logger = logger

    def score(
        self,
        domain: str,
        blocklist_sources: Optional[list[str]] = None,
    ) -> dict:
        """
        Return a threat score dict for the given domain.

        Tries the cache first, then layer 1, layer 2, and layer 3 in order.
        Always returns a valid dict; never raises.

        Args:
            domain:           The blocked domain name.
            blocklist_sources: Source URLs the domain was found on (for layer 2).

        Returns:
            Dict with keys: score (int 1-10), category, company, reason, source.
        """
        try:
            domain = domain.lower().rstrip(".")
            sources = blocklist_sources or []

            # Cache check
            cached = self._logger.get_score(domain)
            if cached is not None:
                return cached

            result = self._classify(domain, sources)
            self._logger.cache_score(domain, result)
            return result

        except Exception as exc:
            log.error("Scorer error for %s: %s", domain, exc)
            return dict(self._SAFE_DEFAULT)

    def _classify(self, domain: str, sources: list[str]) -> dict:
        """Run layers 1-3 and return the best available result."""
        # Layer 1: exact match or suffix match in known map
        result = self._layer1(domain)
        if result is not None:
            return result

        # Layer 2: rule-based
        result = _rule_score(domain, sources)

        # Layer 3: LLM only when category is still unknown and key is configured
        if result["category"] == "unknown" and self._api_key:
            llm_result = self._layer3(domain)
            if llm_result is not None:
                return llm_result

        return result

    def _layer1(self, domain: str) -> dict | None:
        """Check the known-company map with suffix matching."""
        # Exact match first
        if domain in _KNOWN_DOMAINS:
            entry = _KNOWN_DOMAINS[domain]
            return {**entry, "source": "rules"}

        # Suffix match: check if any known domain is a suffix of the queried domain
        parts = domain.split(".")
        for i in range(1, len(parts) - 1):
            candidate = ".".join(parts[i:])
            if candidate in _KNOWN_DOMAINS:
                entry = _KNOWN_DOMAINS[candidate]
                return {**entry, "source": "rules"}

        return None

    def _layer3(self, domain: str) -> dict | None:
        """
        Call the Groq API to classify an unknown domain.

        Returns a score dict on success, or None if the call fails or
        returns an unparseable response.
        """
        url = "https://api.groq.com/openai/v1/chat/completions"
        headers = {
            "Authorization": f"Bearer {self._api_key}",
            "Content-Type": "application/json",
        }
        user_prompt = (
            f"Classify this blocked domain and rate its privacy threat.\n"
            f"Domain: {domain}\n"
            "Respond ONLY with valid JSON, no other text:\n"
            '{"score": <1-10>, "category": '
            '"<ad_network|analytics|fingerprinting|cross_site_tracking|'
            'data_broker|malware_c2|telemetry|unknown>", '
            '"company": "<company name or null>", '
            '"reason": "<one sentence>"}'
        )
        payload = {
            "model": self._model,
            "messages": [
                {
                    "role": "system",
                    "content": "You are a DNS privacy analyst. Respond only in JSON.",
                },
                {"role": "user", "content": user_prompt},
            ],
            "temperature": 0,
            "max_tokens": 150,
        }

        try:
            resp = requests.post(url, headers=headers, json=payload, timeout=3)
            resp.raise_for_status()
            content = resp.json()["choices"][0]["message"]["content"].strip()
            data = json.loads(content)

            score = int(data.get("score", 5))
            if not (1 <= score <= 10):
                score = 5

            return {
                "score": score,
                "category": data.get("category", "unknown"),
                "company": data.get("company") or None,
                "reason": str(data.get("reason", "LLM classification.")),
                "source": "llm",
            }
        except Exception as exc:
            log.warning("Groq LLM classification failed for %s: %s", domain, exc)
            return None
