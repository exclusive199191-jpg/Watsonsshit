# Discord Anti-Nuke Bot

Enterprise-grade Discord bot that protects servers from nuke attacks with real-time detection, automatic punishment, server snapshot/restore, and per-action toggles.

## Run & Operate

- `pnpm --filter @workspace/api-server run dev` — build + run the bot (port 8080)
- `pnpm run typecheck` — full typecheck across all packages
- Required env: `DATABASE_URL` — Postgres connection string (Railway provides this)
- Required env: `DISCORD_BOT_TOKEN` — Discord bot token

## Stack

- pnpm workspaces, Node.js 24, TypeScript 5.9
- API: Express 5 (health check endpoint only)
- DB: PostgreSQL + Drizzle ORM (raw migrations in `migrate.ts`)
- Discord: discord.js v14, prefix commands (`-antinuke`)
- Build: esbuild (single CJS bundle)

## Where things live

- `artifacts/api-server/src/antinuke.ts` — all anti-nuke logic (detection, punishment, snapshot/restore, commands)
- `artifacts/api-server/src/bot.ts` — bot startup, event router, role-audit commands (`,` prefix)
- `artifacts/api-server/src/migrate.ts` — raw SQL migrations (`CREATE TABLE IF NOT EXISTS` + `ALTER TABLE ADD COLUMN IF NOT EXISTS`)
- `lib/db/src/schema/antinuke.ts` — Drizzle schema (source of truth for DB shape)
- `lib/db/src/schema/index.ts` — schema barrel export

## Architecture decisions

- **Sliding-window rate tracker** (`timestamps` map): per-action timestamp queues (not reset-window) to defeat async/delayed burst attacks.
- **Migrations via raw SQL**: `migrate.ts` uses `CREATE TABLE IF NOT EXISTS` + `ALTER TABLE ADD COLUMN IF NOT EXISTS` — fully idempotent, safe to re-run on every boot.
- **Incident log ring buffer**: in-memory only (max 25), resets on restart — intentional (no DB writes on hot path).
- **Toggle keys default ON**: `checkToggle()` returns `true` if key absent from toggles JSON — new detections are auto-enabled for existing servers.
- **Per-guild snapshot schedule**: `scheduleGuildSnapshot` runs every 5 min per guild; `GuildCreate` event auto-registers new guilds.
- **No-skip punishment**: ALL violators (bots and humans) are punished — only the server owner is immune (Discord API limit). First offense = kick + strip ALL roles + bot OAuth revocation. Second+ offense = permanent ban. Offense count persisted to DB (`antinuke_offenses`) so it survives restarts.
- **Snapshot ring buffer**: `guild_snapshot_history` keeps last 3 complete snapshots per guild. `loadSnapshot()` tries newest→oldest, falls back automatically if a snapshot is corrupt/empty. Legacy `guild_snapshots` table kept for backward compat.
- **Emergency restore**: `triggerEmergencyRestore()` fires immediately on `chDelete`/`roleDelete` violations — no cron dependency. Cleans up attacker-created channels/roles first (only within attack window), then restores from snapshot.
- **Idempotent restore**: matches by original ID → name+type+parent → name+type. Running restore twice makes zero changes on the second pass. Returns `RestoreStats` for reporting.
- **Manual restore confirmation**: `-antinuke restore` requires ✅ reaction within 30s before executing. Shows dry-run preview (what would be created vs already exists) before confirming.

## Product — Commands (`-antinuke`)

| Command | Description |
|---|---|
| `enable` / `disable` | Turn anti-nuke on/off |
| `status` | Show current config |
| `snapshot` | Save server layout (channels, roles, overwrites) |
| `restore` | Rebuild missing channels/roles from last snapshot |
| `lockdown` | Remove Send Messages from @everyone in all channels |
| `unlock` | Restore Send Messages permissions |
| `toggle <key> on\|off` | Enable/disable individual detection (17 keys) |
| `stats` | View last 25 incidents this session |
| `set punishment <ban\|kick\|strip>` | Set violation punishment |
| `set logchannel #ch` | Set alert log channel |
| `set threshold <action> <n>` | Override action threshold |
| `whitelist add/remove @user` | Whitelist trusted users |
| `reset` | Restore all defaults |

### Toggle keys
`ban` `kick` `unban` `chCreate` `chDelete` `chRename` `roleDelete` `roleCreate` `roleGrant` `webhook` `webhookDelete` `mention` `link` `emojiDelete` `raidJoin` `botAdd` `guildUpdate`

## Gotchas

- `pnpm run typecheck` fails with "Cannot find type definition file for 'node'" at the lib level — pre-existing, does not affect esbuild builds or runtime. The `api-server` typecheck has only pre-existing `implicit any` errors in `bot.ts`/`routes/`.
- New DB columns must be added both to `lib/db/src/schema/antinuke.ts` AND to the `ALTER TABLE` section of `migrate.ts`.
- `BotAdd` audit log target is the added bot's user object — must fetch the member after the event fires.
- GuildMemberAdd fires before `GuildAuditLogEntryCreate` for bot adds — raid detection uses the join event; bot-add punishment uses the audit log.

## User preferences

_Populate as you build — explicit user instructions worth remembering across sessions._
