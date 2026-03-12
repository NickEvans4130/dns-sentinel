# Discord Bot Setup

dns-sentinel includes an optional Discord bot that lets you query reports,
scores, and live stats via slash commands directly from your Discord server.

## 1 — Create the Discord application

1. Go to [discord.com/developers/applications](https://discord.com/developers/applications).
2. Click **New Application**, give it a name (e.g. `dns-sentinel`), and confirm.
3. Navigate to the **Bot** tab in the left sidebar.
4. Click **Reset Token**, confirm, and copy the token.
5. Paste the token into `config.toml`:

```toml
[bot]
enabled = true
token   = "your_token_here"
```

**Keep your token secret.** Anyone with it can control the bot. `config.toml`
is gitignored — never commit it.

## 2 — Required bot permissions and scopes

In the **OAuth2 → URL Generator** section, tick these **scopes**:

- `bot`
- `applications.commands`

Tick these **Bot Permissions**:

- Send Messages
- Embed Links
- Attach Files
- Use Slash Commands

Copy the generated URL and open it in your browser to invite the bot to
your server.

## 3 — Get your guild (server) ID

Guild ID is required for instant slash command registration. Without it,
commands register globally and can take up to 1 hour to appear.

1. In Discord, open **User Settings → Advanced** and enable **Developer Mode**.
2. Right-click your server name in the left sidebar.
3. Click **Copy Server ID**.
4. Paste the integer into `config.toml`:

```toml
[bot]
guild_id = 987654321098765432
```

## 4 — Channel and role restrictions (optional)

By default all commands are available to everyone in any channel.
To restrict them:

**Limit to specific channels:**

1. Right-click the channel → **Copy Channel ID** (requires Developer Mode).
2. Add to config:

```toml
[bot]
allowed_channel_ids = [1234567890, 9876543210]
```

**Limit to specific roles:**

1. Server Settings → Roles → right-click a role → **Copy Role ID**.
2. Add to config:

```toml
[bot]
allowed_role_ids = [1111111111, 2222222222]
```

When `allowed_role_ids` is set, only members with one of those roles can
run any slash command. The `/blocklist refresh` command always enforces
role restrictions if configured.

## 5 — How slash commands register

Slash commands are synced automatically when the bot starts:

- **Guild commands** (when `guild_id` is set): appear **instantly**.
- **Global commands** (no `guild_id`): may take **up to 1 hour** to propagate
  to all servers. Use guild mode during development.

If commands don't appear after a restart, check the bot logs:

```bash
journalctl -u dns-sentinel | grep -i bot
```

## 6 — Available commands

| Command                 | Description                                      |
|-------------------------|--------------------------------------------------|
| `/report [period]`      | Full report embed + `.txt` file download         |
| `/top [period] [limit]` | Ranked table of top N blocked domains            |
| `/score <domain>`       | On-demand threat score for any domain            |
| `/stats`                | Live uptime, block rate, and last blocked domain |
| `/blocklist refresh`    | Re-download all blocklists (role-restricted)     |

`period` choices: `today` · `yesterday` · `week` · `month`

## 7 — Verifying the setup

Once invited and configured, restart dns-sentinel:

```bash
sudo systemctl restart dns-sentinel
```

Then in Discord, type `/` in any allowed channel — you should see the
dns-sentinel commands appear in the autocomplete menu.

If the bot is online (green dot) but commands don't appear, wait a few
minutes or check that `guild_id` matches the server you invited the bot to.
