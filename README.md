# /gg.all.4u — Discord protection bot (MAXIMUM preset)

Python 3.11+ / discord.py 2.x / FastAPI / PostgreSQL / Railway. Multi-server configuration. This is an **initial deployable security foundation**, not a guarantee of perfect protection. Review and test in a private server before production use.

## Included
- Anti-Nuke: audit-log attribution for channel/role deletions, permission changes, mass bans and kicks; threshold-based containment with role hierarchy checks and trusted IDs.
- Anti-Raid: join burst detection; temporary timeout of joining accounts during bursts, optional timeout of accounts under 24 hours.
- Anti-Spam: message flood, duplicates, mass mentions, links; delete and 10-minute timeout.
- Recovery: PostgreSQL structural backups every 30 minutes by default; preview; **additive** recovery of missing roles/channels, with no privileged permissions restored. Cannot restore deleted messages, memberships, integrations, or exact original IDs.
- Slash commands: security_status, security_set, security_logs, trusted_add/remove, backup_create, recovery_preview/full, lockdown, ban, kick, timeout, purge, warn, warnings, incidents, ping, dashboard.
- Web dashboard: Discord OAuth2 identify, session signature, CSRF, owner/admin authorization on every API call, configuration toggles and incident list.

## Discord Developer Portal
1. Create a **new** application at https://discord.com/developers/applications and create its Bot. Never commit the token.
2. Under Bot, enable **Server Members Intent** and **Message Content Intent** (if available and approved; some verified bots require approval). If message content is unavailable, set ENABLE_MESSAGE_CONTENT=false; anti-spam content checks will be limited.
3. OAuth2 URL Generator: scopes `bot` and `applications.commands`; permissions: View Audit Log, View Channels, Send Messages, Manage Messages, Manage Roles, Manage Channels, Moderate Members, Kick Members, Ban Members, Read Message History. Grant only necessary permissions; Administrator is NOT required. Bot role must be above roles it is meant to manage, but below trusted administrators.
4. Under OAuth2 Redirects, add exactly `https://YOUR-SERVICE.up.railway.app/callback`. For Dashboard, the bot uses `identify` scope and only shows guilds where the signed-in member is server owner or administrator.
5. Invite to each server with the generated install URL. Commands are registered **globally**, so no single GUILD_ID is needed. Global command availability may take time.

## Automatic backup interval
Set `BACKUP_INTERVAL_MINUTES=30` in Railway Variables. The scheduler checks every 5 minutes and stores a new structural snapshot once the latest snapshot is at least 30 minutes old. It runs while the service is online; actual timing can drift due to restart, rate limits, or API errors. This is not a backup of deleted messages.

## Railway deployment
1. Create a private GitHub repository containing these files (not .env), then create a Railway project **Deploy from GitHub**.
2. Add Railway **PostgreSQL** database in the same project. Reference its `DATABASE_URL` in the bot service variables (Railway variable reference, e.g. `${{Postgres.DATABASE_URL}}`, using your actual database service name).
3. Add bot variables from `.env.example` to Railway service variables. `DISCORD_TOKEN` and `DISCORD_CLIENT_SECRET` are secret values. Generate `SESSION_SECRET` using `python -c "import secrets; print(secrets.token_urlsafe(48))"`.
4. Generate a public Railway domain for the bot service. Set `DASHBOARD_URL` to its HTTPS URL without a trailing slash; set the Discord OAuth2 redirect URL to `DASHBOARD_URL/callback`.
5. Deploy with `python main.py`. Check Railway logs for `Ready as ...`. Visit `/health` and `/` on the generated HTTPS domain.
6. Install the bot on each server; use `/security_logs` and `/backup_create` first. Verify backups and permissions before enabling the bot in a live server.

## Local run
```bash
python -m venv .venv
# activate venv, then
pip install -r requirements.txt
# export/set environment variables from .env.example (this app does not automatically load .env)
python main.py
```
Local dashboard OAuth requires a public HTTPS callback URL configured in Discord. Do not use a public shared computer to store tokens.

## Safety and operational limitations
- Default detection thresholds: 2 destructive events per actor per 30 seconds (3 bans/kicks), 8 joins per 30 seconds, 6 messages per 8 seconds, 4 duplicate messages, 4 links, or 6 mentions. These are intentionally aggressive and may produce false positives.
- Audit log entries are eventually consistent and attribution is best-effort; a late or incorrect match is possible. Review logs after incidents. Discord API permissions and role hierarchy limit intervention.
- Containment removes manageable roles and times out suspicious members; it can disrupt legitimate moderators. Server owner is exempt. Add other trusted admins via `/trusted_add`.
- A `lockdown` command denies @everyone send_messages in text channels; **there is no automatic unlock** because pre-existing overwrites are not snapshotted for rollback. Review permissions manually. Use only for emergencies.
- Backup data includes role permissions and channel overwrites but automatic restore intentionally does **not** reapply privileged permissions or overwrites. Manually inspect before applying them. Duplicate names may prevent precise matching; IDs of restored entities will differ.
- Database must have durable storage and backups. Railway service storage is ephemeral; PostgreSQL holds snapshots, incidents, warnings and configuration. Consider independent off-platform backups and encryption/retention policies for production.
- This implementation does not include a full configurable AutoMod rule manager, invite/URL reputation intelligence, full webhook audit attribution, member verification challenges, disaster recovery of all server settings, Redis distributed rate limits, or guaranteed multi-instance-safe scheduled jobs. Avoid running multiple replicas without a leader election mechanism.
- OAuth dashboard requires a correctly configured HTTPS URL and secure cookies. Rotate compromised secrets immediately. Set a restrictive Discord bot install policy.
- Never expose a bot token or client secret in GitHub, Discord chat, or screenshots.

## Command reference
`/security_status`, `/security_set`, `/security_logs`, `/trusted_add`, `/trusted_remove`, `/backup_create`, `/recovery_preview`, `/recovery_full`, `/lockdown`, `/ban`, `/kick`, `/timeout`, `/purge`, `/warn`, `/warnings`, `/incidents`, `/ping`, `/dashboard`.

## Incident response
Immediately revoke stolen tokens, remove malicious roles and integrations, check audit logs, isolate the server, and take a new backup after remediation. Do not assume bot-based recovery is complete.

## Bot name and maximum-security deployment
- In Discord Developer Portal > Bot, set the bot username/display name to `/gg.all.4u` if Discord accepts it. The code cannot change the application username; alternatively set a server nickname.
- MAXIMUM is an aggressive policy target, not a guarantee against every attack. The current thresholds are described above. Review incidents and test on a staging guild first.
- In Discord Developer Portal > Bot, enable **Server Members Intent** and **Message Content Intent** (where permitted), and grant only necessary bot permissions; role hierarchy still applies.
- Turn on Discord native AutoMod, verification, and 2FA requirement for moderator actions separately.
- Never grant a bot owner permissions it does not need. Configure PostgreSQL backup retention and keep credentials in Railway variables.
