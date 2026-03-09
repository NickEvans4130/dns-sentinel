# DNS Sentinel

A self-hosted DNS proxy that blocks tracker domains and fires real-time Discord alerts.
Run it on a Raspberry Pi or VPS, point your router's DNS at it, and get notified every
time an ad network or tracker is intercepted.

## Architecture

```
Client device
     |  UDP DNS query
     v
+---------------------+
|   DNS Sentinel      |  (Python / dnslib)
|                     |
|  +--------------+   |
|  |  Blocklist   |   |<-- hosts files (StevenBlack, AdAway, custom)
|  | (set lookup) |   |
|  +--------------+   |
|         |           |
|    blocked?         |
|    +-- YES --> NXDOMAIN response
|    |           + Discord webhook alert
|    |           + SQLite log entry
|    |                |
|    +-- NO  --> Forward to 1.1.1.1
|                + SQLite log entry
+---------------------+
         |
         v
   Discord webhook  /  SQLite database  /  CLI reporter
```

## Features

- Blocks tracker and ad domains using community-maintained blocklists
- Returns NXDOMAIN immediately — no browser latency
- Subdomain matching: blocking `doubleclick.net` covers `ad.doubleclick.net`, etc.
- Real-time Discord alerts with auto-detected tracker category
- Hourly or daily batch summaries with top offenders
- SQLite query log with per-domain and per-hour statistics
- ASCII bar chart reporter with copy-paste blog snippet generator
- systemd service file for production deployment
- Idempotent install script

## Prerequisites

- Python 3.10 or newer
- Linux server or Raspberry Pi (Raspberry Pi OS / Ubuntu / Debian)
- A Discord server where you can create webhooks

## Quick Start (local testing, no root required)

```bash
git clone https://github.com/yourname/dns-sentinel.git
cd dns-sentinel

python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

cp config.example.toml config.toml
# Edit config.toml — paste your Discord webhook URL

python -m dns_sentinel.server
```

Test it in a second terminal:

```bash
# Should resolve normally
dig @127.0.0.1 -p 5353 google.com

# Should return NXDOMAIN (blocked tracker)
dig @127.0.0.1 -p 5353 doubleclick.net
```

## Production Deployment

```bash
sudo bash scripts/install.sh
```

The script:
1. Creates a `dns-sentinel` system user
2. Copies files to `/opt/dns-sentinel`
3. Creates a Python virtualenv and installs dependencies
4. Downloads blocklists
5. Installs and starts the systemd service

Monitor:

```bash
systemctl status dns-sentinel
journalctl -u dns-sentinel -f
```

## Discord Webhook Setup

1. Open Discord server **Settings → Integrations → Webhooks**
2. Click **New Webhook**, choose a channel (e.g. `#dns-alerts`)
3. Copy the webhook URL
4. Paste it into `config.toml` under `[discord] webhook_url`

> Screenshot: add `docs/discord-webhook-setup.png` here

## Pointing Your Router at DNS Sentinel

In your router admin panel, find **LAN / DHCP Settings** and set:

- **Primary DNS**: IP address of the machine running DNS Sentinel
- **Port**: 5353 (or 53 if you configured it that way)

All devices on the network will then route DNS through DNS Sentinel automatically.

## Alert Modes

| Mode       | Behaviour                                             |
|------------|-------------------------------------------------------|
| `realtime` | One Discord message per blocked domain (default)      |
| `hourly`   | Digest every hour listing top blocked domains         |
| `daily`    | Digest once per day                                   |

Set `alert_mode` in `config.toml`. For high-traffic networks, `hourly` is recommended
to avoid webhook rate limits.

## Reporter

```bash
# Stats and snippet for today
python -m dns_sentinel.reporter --period today

# Yesterday
python -m dns_sentinel.reporter --period yesterday

# Last 7 days
python -m dns_sentinel.reporter --period week
```

Example output:

```
==================================================
  DNS Sentinel Report — Today
==================================================
  Total queries : 1,491
  Allowed       : 1,204
  Blocked       :   287  (19.3%)
==================================================

  Top 10 Blocked Domains:
   1. doubleclick.net                                    89  ██████████████████████████████
   2. google-analytics.com                               43  ██████████████
   3. facebook.net                                       38  ████████████

  Hourly breakdown (2026-03-09):
  09:00  ████████░░░░░░░░░░░░░░░░░░░░░░  12
  14:00  ██████████████████████████████  41
  ...

==================================================
  Blog / LinkedIn snippet:
==================================================
  Today I monitored my DNS traffic and found:
    1,204 legitimate requests
    287 tracker requests blocked (19.3%)

  Top trackers encountered:
   * doubleclick.net: 89 attempts
   * google-analytics.com: 43 attempts
   * facebook.net: 38 attempts

  This is what your browser does without a DNS blocker.
  #Privacy #DNS #CyberSecurity
==================================================
```

## Configuration Reference

All settings live in `config.toml` (never committed — see `.gitignore`).
Use `config.example.toml` as a template.

| Key                               | Description                              | Default                    |
|-----------------------------------|------------------------------------------|----------------------------|
| `dns.listen_host`                 | Interface to bind                        | `0.0.0.0`                  |
| `dns.listen_port`                 | UDP port to listen on                    | `5353`                     |
| `dns.upstream_dns`                | Upstream resolver IP                     | `1.1.1.1`                  |
| `dns.upstream_port`               | Upstream resolver port                   | `53`                       |
| `discord.webhook_url`             | Discord webhook URL                      | *(required)*               |
| `discord.alert_mode`              | `realtime`, `hourly`, or `daily`         | `realtime`                 |
| `discord.batch_interval_minutes`  | Interval for batch summaries             | `60`                       |
| `blocklist.sources`               | URLs of hosts-format blocklists          | StevenBlack + AdAway       |
| `blocklist.custom`                | Extra domains to always block            | `[]`                       |
| `database.path`                   | SQLite file path                         | `dns_sentinel.db`          |

## Running on Port 53

Binding to port 53 requires either running as root or setting the `CAP_NET_BIND_SERVICE`
capability. On Ubuntu/Debian, `systemd-resolved` occupies port 53 by default.
See the comment block at the top of `scripts/install.sh` for step-by-step instructions
on disabling it — read those carefully before proceeding, as it temporarily breaks DNS.

## License

MIT
