# Groq API Setup (Optional)

DNS Sentinel's threat scorer works entirely offline for the vast majority of
domains. The Groq LLM integration is an optional enhancement that classifies
novel domains that fall outside the built-in rules — think obscure third-party
SDKs, new ad-tech startups, or one-off tracking pixels.

## Getting a free API key

1. Go to [console.groq.com](https://console.groq.com) and create an account.
2. Navigate to **API Keys** in the left sidebar.
3. Click **Create API Key**, give it a name (e.g. `dns-sentinel`), and copy the key.
4. Paste it into `config.toml`:

```toml
[scoring]
groq_api_key = "gsk_your_key_here"
groq_model   = "llama-3.1-8b-instant"
```

## Which model and why

`llama-3.1-8b-instant` is the default. It is:

- **Fast** — typical response under 300ms, well within the 3-second timeout.
- **Free** — included in Groq's free tier at no cost.
- **Sufficient** — the classification task (output a small JSON object) is
  well within the capability of an 8B model; a larger model adds no value here.

If you want more accurate classifications you can switch to `llama-3.3-70b-versatile`,
but it is slower and consumes more of your daily quota.

## Offline-only mode

Leaving `groq_api_key` empty (the default) disables Layer 3 entirely. The scorer
falls back to Layer 2 rule-based heuristics, which cover:

- All domains in the 60-entry known-company map (Layer 1).
- Any domain with ad/tracking/analytics keywords in subdomain labels.
- Domains on blocklists with a high-confidence source (e.g. AdAway).
- Suspicious TLDs (`.xyz`, `.top`, `.tk`, `.click`, `.bid`).

For a typical home network this covers 90%+ of real traffic with no API calls at all.

## Rate limits and caching

Groq's free tier allows **6,000 requests per day**.

In practice this limit is effectively unlimited for this use case because:

- The LLM is **only called for novel unknown domains** — Layer 1 and Layer 2
  handle everything they can first.
- Every result is **cached permanently in SQLite** (`domain_scores` table).
  A domain is only ever sent to the LLM once; all subsequent blocks hit the cache.
- Most networks see the same ~200 tracking domains repeatedly. After the first
  day the LLM call rate drops close to zero.

Even on a very active network with many novel domains, hitting 6,000 genuinely
unknown new domains in a single day would be extraordinary.
