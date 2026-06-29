import {
  Client,
  GatewayIntentBits,
  Events,
  AuditLogEvent,
  ActivityType,
  PermissionsBitField,
  EmbedBuilder,
  Colors,
  type Message,
  type GuildMember,
} from "discord.js";
import { db } from "@workspace/db";
import { roleAssignmentsTable, antinukeConfigTable } from "@workspace/db";
import { eq, and, desc, sql } from "drizzle-orm";
import { logger } from "./lib/logger";
import { isDbTableReady } from "./db-state";
import { runMigrations } from "./migrate";
import {
  registerAntiNukeListeners,
  handleAntiNukeCommand,
  handleAntiNukeMessage,
  showAntiNukeHelp,
  startSnapshotSchedule,
  scheduleGuildSnapshot,
  stopSnapshotSchedule,
  getAntinukeConfig,
} from "./antinuke";

// ── Hardcoded trusted owner — ONLY this user can use -role and is fully exempt ─
const TRUSTED_OWNER_ID = "1504639006443573272";

function isTrustedOwner(userId: string): boolean {
  if (userId === TRUSTED_OWNER_ID) return true;
  const envId = process.env.BOT_OWNER_ID;
  return envId !== null && envId !== undefined && userId === envId;
}

// ── Permission detection ───────────────────────────────────────────────────────

const ELEVATED_PERMISSIONS: bigint[] = [
  PermissionsBitField.Flags.Administrator,
  PermissionsBitField.Flags.BanMembers,
  PermissionsBitField.Flags.KickMembers,
  PermissionsBitField.Flags.ModerateMembers,  // Timeout
  PermissionsBitField.Flags.MuteMembers,       // Voice mute
  PermissionsBitField.Flags.ManageRoles,
  PermissionsBitField.Flags.ManageGuild,
  PermissionsBitField.Flags.ViewAuditLog,
  PermissionsBitField.Flags.ManageChannels,
  PermissionsBitField.Flags.ManageMessages,
  PermissionsBitField.Flags.ManageNicknames,
  PermissionsBitField.Flags.ManageWebhooks,
  PermissionsBitField.Flags.ManageThreads,
];

const ELEVATED_PERM_NAMES: Record<string, string> = {
  [String(PermissionsBitField.Flags.Administrator)]:   "Administrator",
  [String(PermissionsBitField.Flags.BanMembers)]:      "Ban Members",
  [String(PermissionsBitField.Flags.KickMembers)]:     "Kick Members",
  [String(PermissionsBitField.Flags.ModerateMembers)]: "Timeout Members",
  [String(PermissionsBitField.Flags.MuteMembers)]:     "Mute Members",
  [String(PermissionsBitField.Flags.ManageRoles)]:     "Manage Roles",
  [String(PermissionsBitField.Flags.ManageGuild)]:     "Manage Guild",
  [String(PermissionsBitField.Flags.ViewAuditLog)]:    "View Audit Log",
  [String(PermissionsBitField.Flags.ManageChannels)]:  "Manage Channels",
  [String(PermissionsBitField.Flags.ManageMessages)]:  "Manage Messages",
  [String(PermissionsBitField.Flags.ManageNicknames)]: "Manage Nicknames",
  [String(PermissionsBitField.Flags.ManageWebhooks)]:  "Manage Webhooks",
  [String(PermissionsBitField.Flags.ManageThreads)]:   "Manage Threads",
};

function hasElevatedPermission(permissions: PermissionsBitField): boolean {
  return ELEVATED_PERMISSIONS.some((perm) => permissions.has(perm));
}

function getElevatedPermNames(permissions: PermissionsBitField): string[] {
  return ELEVATED_PERMISSIONS
    .filter((perm) => permissions.has(perm))
    .map((perm) => ELEVATED_PERM_NAMES[String(perm)] ?? "Unknown");
}

// ── PostgreSQL error code map ──────────────────────────────────────────────────

const PG_CODES: Record<string, string> = {
  "42P01": 'Table "role_assignments" doesn\'t exist — migrations may not have run yet.',
  "42703": "Column not found — schema may be out of date. Re-run migrations.",
  "23505": "Duplicate entry — this record already exists.",
  "23503": "Foreign key violation.",
  "28P01": "Database authentication failed. Check the DATABASE_URL password.",
  "28000": "Database authentication failed. Check DATABASE_URL credentials.",
  "3D000": "Database does not exist. Check the DATABASE_URL database name.",
  "08000": "Database connection failed.",
  "08003": "Database connection lost. Will retry automatically.",
  "08006": "Database connection failure. Will retry automatically.",
  "08001": "Unable to connect to database. Check DATABASE_URL host/port.",
  "08004": "Database rejected the connection.",
  "57014": "Query cancelled (timeout). Try a more specific command.",
  "53300": "Database has too many connections.",
  "55P03": "Database table is locked. Try again in a moment.",
  "XX000": "Internal database error.",
};

// ── In-memory error log ────────────────────────────────────────────────────────

interface ErrorLogEntry {
  at: Date;
  command: string;
  message: string;
  code?: string;
  detail?: string;
}

const ERROR_LOG: ErrorLogEntry[] = [];
const MAX_LOG_SIZE = 25;

// ── Mention-guard state ────────────────────────────────────────────────────────
//
// Tracks users who have pinged @everyone or @here.
// Structure: Map<guildId, Map<userId, { at: Date; count: number }>>
// Lives in-memory — resets on bot restart. That's intentional: if the bot
// restarts it has no memory of past abuse, but existing role-strip already
// happened at the time of the offense.
//
const flaggedMentionUsers = new Map<string, Map<string, { at: Date; count: number }>>();

/** Mark userId as a mention-abuser for guildId. Increments count if already present. */
function flagMentionUser(guildId: string, userId: string): void {
  if (!flaggedMentionUsers.has(guildId)) flaggedMentionUsers.set(guildId, new Map());
  const guildMap = flaggedMentionUsers.get(guildId)!;
  const existing = guildMap.get(userId);
  guildMap.set(userId, { at: new Date(), count: (existing?.count ?? 0) + 1 });
}

/** Returns true if userId has been flagged for mention abuse in guildId. */
function isMentionFlagged(guildId: string, userId: string): boolean {
  return flaggedMentionUsers.get(guildId)?.has(userId) ?? false;
}

/** Remove a user's mention-guard flag (e.g. after a manual pardon). */
function clearMentionFlag(guildId: string, userId: string): void {
  flaggedMentionUsers.get(guildId)?.delete(userId);
}

/**
 * Dig through every layer of an error to find raw pg DatabaseError fields.
 * Drizzle-orm 0.45 wraps pg errors — the DatabaseError (with `.code`, `.detail`)
 * may be on `err.cause` or on `err` itself if Drizzle didn't wrap it.
 */
function digPgError(err: any): { message: string | null; code: string | null; detail: string | null } {
  for (const e of [err, err?.cause, err?.cause?.cause]) {
    if (!e) continue;
    const code: string | null = typeof e?.code === "string" ? e.code : null;
    const msg: string | null = typeof e?.message === "string" ? e.message : null;
    const detail: string | null = typeof e?.detail === "string" ? e.detail : null;
    // pg error codes are exactly 5 alphanumeric characters
    if (code && /^[0-9A-Z]{5}$/i.test(code)) {
      return { message: msg, code: code.toUpperCase(), detail };
    }
    // Non-Drizzle message — use it directly
    if (msg && !msg.startsWith("Failed query:") && !msg.startsWith("params:") && msg !== "[object Object]") {
      return { message: msg, code: null, detail };
    }
  }
  return { message: null, code: null, detail: null };
}

/**
 * User-facing message for Discord embeds.
 * NEVER shows raw JSON, stack traces, or Drizzle internals.
 */
function friendlyError(err: any): string {
  const { message, code } = digPgError(err);
  if (code && PG_CODES[code]) return PG_CODES[code];
  if (message) return message.split("\n")[0].slice(0, 300);
  return "A database error occurred. Please try again.";
}

/**
 * Full technical message for the error log (more detail than friendlyError).
 */
function extractFullMessage(err: any): string {
  const { message, code, detail } = digPgError(err);
  const parts: string[] = [];
  if (code) parts.push(`[${code}]`);
  if (message) parts.push(message.split("\n")[0]);
  if (detail) parts.push(`↳ ${detail}`);
  if (parts.length) return parts.join(" ");
  // Fallback: show the query snippet from DrizzleQueryError
  const query = (err as any)?.query;
  if (query) return `Failed query: ${String(query).slice(0, 150)}`;
  // Final fallback: first line of stack
  const stack = err?.stack ?? err?.message ?? String(err);
  return String(stack).split("\n")[0].slice(0, 200);
}

function pushErrorLog(command: string, err: any) {
  const { code, detail } = digPgError(err);
  ERROR_LOG.unshift({
    at: new Date(),
    command: command.slice(0, 60),
    message: extractFullMessage(err),
    code: code ?? undefined,
    detail: detail ?? undefined,
  });
  if (ERROR_LOG.length > MAX_LOG_SIZE) ERROR_LOG.length = MAX_LOG_SIZE;
}

// ── Helpers ────────────────────────────────────────────────────────────────────

function ts(date: Date): string {
  return `<t:${Math.floor(date.getTime() / 1000)}:f>`;
}

function resolveUserArg(arg: string): { id: string | null; raw: string } {
  const mentionMatch = arg.match(/^<@!?(\d+)>$/);
  if (mentionMatch) return { id: mentionMatch[1], raw: arg };
  if (/^\d+$/.test(arg)) return { id: arg, raw: arg };
  return { id: null, raw: arg };
}

function errorEmbed(msg: string): EmbedBuilder {
  return new EmbedBuilder()
    .setColor(Colors.Red)
    .setTitle("❌ Error")
    .setDescription(msg);
}

function noDataEmbed(action: "given" | "removed", filter?: string): EmbedBuilder {
  return new EmbedBuilder()
    .setColor(Colors.Yellow)
    .setTitle(`No roles ${action} recorded`)
    .setDescription(
      filter
        ? `No elevated roles have been **${action}** by **${filter}** since the bot joined.`
        : `No elevated roles have been **${action}** in this server since the bot joined.`
    )
    .setFooter({ text: "The bot only tracks events after it joined the server." });
}

// ── Command handlers ───────────────────────────────────────────────────────────

async function cmdPing(message: Message) {
  const latency = Date.now() - message.createdTimestamp;
  const embed = new EmbedBuilder()
    .setColor(Colors.Green)
    .setTitle("🏓 Pong!")
    .addFields(
      { name: "Bot latency", value: `${latency}ms`, inline: true },
    )
    .setTimestamp();
  await message.reply({ embeds: [embed] });
}

async function cmdStatus(message: Message, dbAvailable: boolean) {
  const latency = Date.now() - message.createdTimestamp;
  const guild = message.guild;

  let dbStatus: string;
  let color: number;
  if (!dbAvailable) {
    dbStatus = "❌  Not configured — set `DATABASE_URL` in your environment";
    color = Colors.Red;
  } else if (!isDbTableReady()) {
    dbStatus = "⚠️  Connected but table missing — migrations failed or still running";
    color = Colors.Yellow;
  } else {
    dbStatus = "✅  Connected and ready";
    color = Colors.Green;
  }

  const tableStatus = !dbAvailable
    ? "❌  N/A (no database)"
    : isDbTableReady()
    ? "✅  `role_assignments` exists"
    : "⚠️  `role_assignments` table not found — run `,migrate` or check Railway logs";

  const guildName = guild?.name ?? "Unknown";
  const guildMembers = guild?.memberCount ?? "?";

  const embed = new EmbedBuilder()
    .setColor(color)
    .setTitle("Bot Status")
    .addFields(
      { name: "Database", value: dbStatus, inline: false },
      { name: "Table", value: tableStatus, inline: false },
      { name: "Bot latency", value: `${latency}ms`, inline: true },
      { name: "WebSocket ping", value: `${message.client.ws.ping}ms`, inline: true },
      { name: "Server", value: guildName, inline: true },
      { name: "Members", value: String(guildMembers), inline: true },
      { name: "Uptime", value: `${Math.floor((message.client.uptime ?? 0) / 60000)}m`, inline: true },
    )
    .setFooter({
      text: !dbAvailable
        ? "Fix: add a PostgreSQL service in Railway and set DATABASE_URL."
        : !isDbTableReady()
        ? "Fix: check Railway logs for migration errors, or run ,migrate to retry."
        : "All systems operational.",
    })
    .setTimestamp();

  await message.reply({ embeds: [embed] });
}

async function cmdHelp(message: Message) {
  const line = "─────────────────────────────────────";

  const embed = new EmbedBuilder()
    .setColor(0x2B2D31)
    .setTitle("Role Audit  ·  Command Reference")
    .setDescription(
      "Tracks every elevated role assignment and removal.\n" +
      `All commands use the \`,\` prefix  ·  e.g. \`,recent 15\``
    )
    .addFields(
      {
        name: "MEMBER LOOKUP",
        value: [
          "`,roles given <user>`  —  Roles a moderator has given to others",
          "`,roles removed <user>`  —  Roles a moderator has stripped from others",
          "`,lookup <user>`  —  Who gave or removed roles **to** a specific member",
          "`,timeline <user>`  —  Full chronological role history for a member",
          "`,mod <user>`  —  Detailed moderator profile with stats and recent events",
          "`,between <user1> <user2>`  —  All role interactions between two users",
          "`,myactivity`  —  Your own give/remove counts and recent events",
        ].join("\n"),
      },
      { name: line, value: "\u200b" },
      {
        name: "SERVER LOGS",
        value: [
          "`,all roles given`  —  Most recent 25 role assignments",
          "`,all roles removed`  —  Most recent 25 role removals",
          "`,recent [n]`  —  Last N events across both actions  *(default 10, max 50)*",
          "`,history [days]`  —  All activity within the last N days  *(default 7)*",
          "`,active [days]`  —  Most active moderators in the last N days  *(default 7)*",
        ].join("\n"),
      },
      { name: line, value: "\u200b" },
      {
        name: "SEARCH  &  FILTER",
        value: [
          "`,search <role>`  —  Every event involving a specific role name",
          "`,find <name>`  —  Search all records by any username or tag fragment",
          "`,whohas <role>`  —  Who currently holds a role with elevated permissions",
          "`,undone [hours]`  —  Roles given then removed within N hours  *(default 24)*",
          "`,audit`  —  Flag moderators who assigned 5+ roles within any 10-minute window",
        ].join("\n"),
      },
      { name: line, value: "\u200b" },
      {
        name: "STATS  &  EXPORT",
        value: [
          "`,server stats`  —  Server-wide summary with top moderators and top roles",
          "`,top [n]`  —  All-time moderator leaderboard  *(default 10)*",
          "`,export`  —  Download the complete role log as a plain-text file",
        ].join("\n"),
      },
      { name: line, value: "\u200b" },
      {
        name: "UTILITIES",
        value: [
          "`,status`  —  Show database connection, table health, and bot latency",
          "`,migrate`  —  Retry database migrations if the table is missing",
          "`,logs`  —  Show all recent command errors (last 25, in-memory)",
          "`,ping`  —  Bot latency",
          "`,help`  —  This command reference",
        ].join("\n"),
      },
      { name: line, value: "\u200b" },
      {
        name: "TRACKED PERMISSIONS",
        value:
          "`Administrator`  `Ban Members`  `Kick Members`  `Timeout Members`\n" +
          "`Manage Roles`  `Manage Guild`  `Manage Channels`  `Manage Messages`\n" +
          "`Manage Nicknames`  `Manage Webhooks`  `Manage Threads`",
      },
    )
    .setFooter({ text: "Only events recorded after the bot joined are available.  Historical data cannot be retrieved." })
    .setTimestamp();

  await message.reply({ embeds: [embed] });
}

async function cmdRolesGiven(message: Message, args: string[]) {
  if (!message.guild) {
    await message.reply({ embeds: [errorEmbed("This command must be used in a server, not a DM.")] });
    return;
  }

  const userArg = args.join(" ").trim();
  if (!userArg) {
    await message.reply({ embeds: [errorEmbed("Usage: `,roles given @user` or `,roles given username`")] });
    return;
  }

  const { id: targetId } = resolveUserArg(userArg);

  let records;
  if (targetId) {
    records = await db!
      .select()
      .from(roleAssignmentsTable)
      .where(and(
        eq(roleAssignmentsTable.guildId, message.guild.id),
        eq(roleAssignmentsTable.executorId, targetId),
        eq(roleAssignmentsTable.action, "assigned"),
      ))
      .orderBy(desc(roleAssignmentsTable.assignedAt));
  } else {
    const nameSearch = userArg.toLowerCase();
    const all = await db!
      .select()
      .from(roleAssignmentsTable)
      .where(and(
        eq(roleAssignmentsTable.guildId, message.guild.id),
        eq(roleAssignmentsTable.action, "assigned"),
      ))
      .orderBy(desc(roleAssignmentsTable.assignedAt));
    records = all.filter((r) => r.executorTag.toLowerCase().includes(nameSearch));
  }

  if (!records.length) {
    await message.reply({ embeds: [noDataEmbed("given", userArg)] });
    return;
  }

  const executorTag = records[0].executorTag;
  const executorId = records[0].executorId;

  // Group by roleId so each unique role gets its own section
  const grouped = new Map<string, typeof records>();
  for (const r of records) {
    if (!grouped.has(r.roleId)) grouped.set(r.roleId, []);
    grouped.get(r.roleId)!.push(r);
  }

  // Fetch live role permissions from the guild cache
  const guild = message.guild;
  await guild.roles.fetch(); // ensure cache is populated

  const fields: { name: string; value: string; inline: boolean }[] = [];

  for (const [roleId, entries] of grouped) {
    const roleName = entries[0].roleName;

    // Look up live permissions for this role
    const liveRole = guild.roles.cache.get(roleId);
    let permsText: string;
    if (liveRole) {
      const elevatedPerms = getElevatedPermNames(liveRole.permissions);
      permsText = elevatedPerms.length
        ? elevatedPerms.map((p) => `\`${p}\``).join(", ")
        : "*No elevated permissions currently*";
    } else {
      permsText = "*Role no longer exists in server*";
    }

    // Build the recipient list
    const recipientLines = entries.slice(0, 8).map(
      (e) => `• **${e.targetTag}** — ${ts(new Date(e.assignedAt))}`
    );
    if (entries.length > 8) {
      recipientLines.push(`*…and ${entries.length - 8} more*`);
    }

    const fieldValue = [
      `**Permissions:** ${permsText}`,
      "",
      ...recipientLines,
    ].join("\n");

    fields.push({
      name: `🔐 @${roleName}  (given ${entries.length}×)`,
      value: fieldValue,
      inline: false,
    });
  }

  // Discord limits: max 10 fields per embed, max 1024 chars per field value
  // If there are many roles, split across multiple embeds
  const FIELDS_PER_EMBED = 5;
  const chunks: typeof fields[] = [];
  for (let i = 0; i < fields.length; i += FIELDS_PER_EMBED) {
    chunks.push(fields.slice(i, i + FIELDS_PER_EMBED));
  }

  for (let i = 0; i < chunks.length; i++) {
    const embed = new EmbedBuilder()
      .setColor(Colors.Orange)
      .setTitle(i === 0 ? `Roles given by ${executorTag}` : `Roles given by ${executorTag} (cont.)`)
      .setDescription(
        i === 0
          ? `**${records.length}** elevated role assignment(s) across **${grouped.size}** unique role(s)\n<@${executorId}>`
          : null
      )
      .addFields(chunks[i])
      .setFooter({ text: "Showing elevated roles only" })
      .setTimestamp();

    if (i === 0) {
      await message.reply({ embeds: [embed] });
    } else if ("send" in message.channel) {
      await (message.channel as import("discord.js").TextChannel).send({ embeds: [embed] });
    }
  }
}

async function cmdRolesRemoved(message: Message, args: string[]) {
  if (!message.guild) {
    await message.reply({ embeds: [errorEmbed("This command must be used in a server, not a DM.")] });
    return;
  }

  const userArg = args.join(" ").trim();
  if (!userArg) {
    await message.reply({ embeds: [errorEmbed("Usage: `,roles removed @user` or `,roles removed username`")] });
    return;
  }

  const { id: targetId } = resolveUserArg(userArg);

  let records;
  if (targetId) {
    records = await db!
      .select()
      .from(roleAssignmentsTable)
      .where(and(
        eq(roleAssignmentsTable.guildId, message.guild.id),
        eq(roleAssignmentsTable.executorId, targetId),
        eq(roleAssignmentsTable.action, "removed"),
      ))
      .orderBy(desc(roleAssignmentsTable.assignedAt));
  } else {
    const nameSearch = userArg.toLowerCase();
    const all = await db!
      .select()
      .from(roleAssignmentsTable)
      .where(and(
        eq(roleAssignmentsTable.guildId, message.guild.id),
        eq(roleAssignmentsTable.action, "removed"),
      ))
      .orderBy(desc(roleAssignmentsTable.assignedAt));
    records = all.filter((r) => r.executorTag.toLowerCase().includes(nameSearch));
  }

  if (!records.length) {
    await message.reply({ embeds: [noDataEmbed("removed", userArg)] });
    return;
  }

  const executorTag = records[0].executorTag;
  const grouped = new Map<string, typeof records>();
  for (const r of records) {
    if (!grouped.has(r.roleName)) grouped.set(r.roleName, []);
    grouped.get(r.roleName)!.push(r);
  }

  const fields: { name: string; value: string }[] = [];
  for (const [roleName, entries] of grouped) {
    const preview = entries.slice(0, 5)
      .map((e) => `• **${e.targetTag}** — ${ts(new Date(e.assignedAt))}`)
      .join("\n");
    const extra = entries.length > 5 ? `\n*…and ${entries.length - 5} more*` : "";
    fields.push({ name: `@${roleName} (${entries.length}×)`, value: preview + extra });
  }

  const embed = new EmbedBuilder()
    .setColor(Colors.Purple)
    .setTitle(`Roles removed by ${executorTag}`)
    .setDescription(`**${records.length}** total elevated role removal(s)`)
    .addFields(fields.slice(0, 10))
    .setFooter({ text: "Showing elevated roles only" })
    .setTimestamp();

  await message.reply({ embeds: [embed] });
}

async function cmdAllRolesGiven(message: Message) {
  if (!message.guild) {
    await message.reply({ embeds: [errorEmbed("This command must be used in a server.")] });
    return;
  }

  const records = await db!
    .select()
    .from(roleAssignmentsTable)
    .where(and(
      eq(roleAssignmentsTable.guildId, message.guild.id),
      eq(roleAssignmentsTable.action, "assigned"),
    ))
    .orderBy(desc(roleAssignmentsTable.assignedAt))
    .limit(25);

  const total = await db!
    .select({ count: sql<number>`count(*)` })
    .from(roleAssignmentsTable)
    .where(and(
      eq(roleAssignmentsTable.guildId, message.guild.id),
      eq(roleAssignmentsTable.action, "assigned"),
    ));

  const totalCount = Number(total[0]?.count ?? 0);

  if (!records.length) {
    await message.reply({ embeds: [noDataEmbed("given")] });
    return;
  }

  const lines = records.map(
    (r) => `${ts(new Date(r.assignedAt))} **${r.executorTag}** → **${r.roleName}** → **${r.targetTag}**`
  );

  const embed = new EmbedBuilder()
    .setColor(Colors.Orange)
    .setTitle(`Role Assignments in ${message.guild.name}`)
    .setDescription(lines.join("\n"))
    .setFooter({
      text: totalCount > 25
        ? `Showing 25 of ${totalCount} — use \`,roles given @user\` to filter by mod`
        : `${totalCount} total assignment(s)`,
    })
    .setTimestamp();

  await message.reply({ embeds: [embed] });
}

async function cmdAllRolesRemoved(message: Message) {
  if (!message.guild) {
    await message.reply({ embeds: [errorEmbed("This command must be used in a server.")] });
    return;
  }

  const records = await db!
    .select()
    .from(roleAssignmentsTable)
    .where(and(
      eq(roleAssignmentsTable.guildId, message.guild.id),
      eq(roleAssignmentsTable.action, "removed"),
    ))
    .orderBy(desc(roleAssignmentsTable.assignedAt))
    .limit(25);

  const total = await db!
    .select({ count: sql<number>`count(*)` })
    .from(roleAssignmentsTable)
    .where(and(
      eq(roleAssignmentsTable.guildId, message.guild.id),
      eq(roleAssignmentsTable.action, "removed"),
    ));

  const totalCount = Number(total[0]?.count ?? 0);

  if (!records.length) {
    await message.reply({ embeds: [noDataEmbed("removed")] });
    return;
  }

  const lines = records.map(
    (r) => `${ts(new Date(r.assignedAt))} **${r.executorTag}** → removed **${r.roleName}** from **${r.targetTag}**`
  );

  const embed = new EmbedBuilder()
    .setColor(Colors.Purple)
    .setTitle(`Role Removals in ${message.guild.name}`)
    .setDescription(lines.join("\n"))
    .setFooter({
      text: totalCount > 25
        ? `Showing 25 of ${totalCount} — use \`,roles removed @user\` to filter by mod`
        : `${totalCount} total removal(s)`,
    })
    .setTimestamp();

  await message.reply({ embeds: [embed] });
}

async function cmdRecent(message: Message, args: string[]) {
  if (!message.guild) {
    await message.reply({ embeds: [errorEmbed("This command must be used in a server.")] });
    return;
  }

  const rawN = parseInt(args[0] ?? "10", 10);
  const n = isNaN(rawN) || rawN < 1 ? 10 : Math.min(rawN, 50);

  const records = await db!
    .select()
    .from(roleAssignmentsTable)
    .where(eq(roleAssignmentsTable.guildId, message.guild.id))
    .orderBy(desc(roleAssignmentsTable.assignedAt))
    .limit(n);

  if (!records.length) {
    await message.reply({
      embeds: [
        new EmbedBuilder()
          .setColor(Colors.Yellow)
          .setTitle("No events recorded")
          .setDescription("No role events have been recorded in this server since the bot joined."),
      ],
    });
    return;
  }

  const lines = records.map((r) => {
    const icon = r.action === "assigned" ? "🟢" : "🔴";
    const verb = r.action === "assigned" ? "gave" : "removed";
    return `${icon} ${ts(new Date(r.assignedAt))} **${r.executorTag}** ${verb} **${r.roleName}** ${r.action === "assigned" ? "to" : "from"} **${r.targetTag}**`;
  });

  const embed = new EmbedBuilder()
    .setColor(0x5865f2)
    .setTitle(`Last ${records.length} role event(s)`)
    .setDescription(lines.join("\n"))
    .setFooter({ text: "🟢 = assigned  🔴 = removed" })
    .setTimestamp();

  await message.reply({ embeds: [embed] });
}

async function cmdServerStats(message: Message) {
  if (!message.guild) {
    await message.reply({ embeds: [errorEmbed("This command must be used in a server.")] });
    return;
  }

  const guildId = message.guild.id;

  const [totalAssigned, totalRemoved, topGivers, topRoles] = await Promise.all([
    db!.select({ count: sql<number>`count(*)` })
      .from(roleAssignmentsTable)
      .where(and(eq(roleAssignmentsTable.guildId, guildId), eq(roleAssignmentsTable.action, "assigned"))),

    db!.select({ count: sql<number>`count(*)` })
      .from(roleAssignmentsTable)
      .where(and(eq(roleAssignmentsTable.guildId, guildId), eq(roleAssignmentsTable.action, "removed"))),

    db!.select({
        executorTag: roleAssignmentsTable.executorTag,
        given: sql<number>`sum(case when action = 'assigned' then 1 else 0 end)`,
        removed: sql<number>`sum(case when action = 'removed' then 1 else 0 end)`,
        total: sql<number>`count(*)`,
      })
      .from(roleAssignmentsTable)
      .where(eq(roleAssignmentsTable.guildId, guildId))
      .groupBy(roleAssignmentsTable.executorTag)
      .orderBy(desc(sql`count(*)`))
      .limit(5),

    db!.select({
        roleName: roleAssignmentsTable.roleName,
        times: sql<number>`count(*)`,
      })
      .from(roleAssignmentsTable)
      .where(and(eq(roleAssignmentsTable.guildId, guildId), eq(roleAssignmentsTable.action, "assigned")))
      .groupBy(roleAssignmentsTable.roleName)
      .orderBy(desc(sql`count(*)`))
      .limit(5),
  ]);

  const assigned = Number(totalAssigned[0]?.count ?? 0);
  const removed = Number(totalRemoved[0]?.count ?? 0);

  const topGiversText = topGivers.length
    ? topGivers.map((g, i) => `${i + 1}. **${g.executorTag}** — ${g.given} given, ${g.removed} removed`).join("\n")
    : "No data yet.";

  const topRolesText = topRoles.length
    ? topRoles.map((r, i) => `${i + 1}. **${r.roleName}** — ${r.times}×`).join("\n")
    : "No data yet.";

  const embed = new EmbedBuilder()
    .setColor(0x5865f2)
    .setTitle(`📊 Server Stats — ${message.guild.name}`)
    .addFields(
      {
        name: "Overall",
        value: `🟢 **${assigned}** elevated roles given\n🔴 **${removed}** elevated roles removed\n📋 **${assigned + removed}** total events`,
        inline: false,
      },
      {
        name: "Top Moderators (by activity)",
        value: topGiversText,
        inline: false,
      },
      {
        name: "Most Assigned Roles",
        value: topRolesText,
        inline: false,
      },
    )
    .setFooter({ text: "Data collected since bot joined" })
    .setTimestamp();

  await message.reply({ embeds: [embed] });
}

// ── New command handlers ───────────────────────────────────────────────────────

async function cmdLookup(message: Message, args: string[]) {
  if (!message.guild) {
    await message.reply({ embeds: [errorEmbed("This command must be used in a server.")] });
    return;
  }
  const userArg = args.join(" ").trim();
  if (!userArg) {
    await message.reply({ embeds: [errorEmbed("Usage: `,lookup @user` — shows who gave or removed elevated roles **to** that user.")] });
    return;
  }
  const { id: targetId } = resolveUserArg(userArg);
  let records;
  if (targetId) {
    records = await db!.select().from(roleAssignmentsTable)
      .where(and(eq(roleAssignmentsTable.guildId, message.guild.id), eq(roleAssignmentsTable.targetId, targetId)))
      .orderBy(desc(roleAssignmentsTable.assignedAt));
  } else {
    const nameSearch = userArg.toLowerCase();
    const all = await db!.select().from(roleAssignmentsTable)
      .where(eq(roleAssignmentsTable.guildId, message.guild.id))
      .orderBy(desc(roleAssignmentsTable.assignedAt));
    records = all.filter((r) => r.targetTag.toLowerCase().includes(nameSearch));
  }
  if (!records.length) {
    await message.reply({ embeds: [new EmbedBuilder().setColor(Colors.Yellow).setTitle("No records found").setDescription(`No elevated role events found for **${userArg}**.`).setFooter({ text: "Only tracked after the bot joined." })] });
    return;
  }
  const targetTag = records[0].targetTag;
  const lines = records.slice(0, 20).map((r) => {
    const icon = r.action === "assigned" ? "🟢" : "🔴";
    const verb = r.action === "assigned" ? "gave" : "removed";
    return `${icon} ${ts(new Date(r.assignedAt))} **${r.executorTag}** ${verb} **${r.roleName}**`;
  });
  if (records.length > 20) lines.push(`*…and ${records.length - 20} more events*`);
  const given = records.filter((r) => r.action === "assigned").length;
  const removed = records.filter((r) => r.action === "removed").length;
  const embed = new EmbedBuilder()
    .setColor(0x5865f2)
    .setTitle(`Role history for ${targetTag}`)
    .setDescription(lines.join("\n"))
    .addFields({ name: "Summary", value: `🟢 ${given} role(s) given  •  🔴 ${removed} role(s) removed`, inline: false })
    .setFooter({ text: `${records.length} total event(s) — 🟢 given  🔴 removed` })
    .setTimestamp();
  await message.reply({ embeds: [embed] });
}

async function cmdTimeline(message: Message, args: string[]) {
  if (!message.guild) {
    await message.reply({ embeds: [errorEmbed("This command must be used in a server.")] });
    return;
  }
  const userArg = args.join(" ").trim();
  if (!userArg) {
    await message.reply({ embeds: [errorEmbed("Usage: `,timeline @user` — chronological role history for that user.")] });
    return;
  }
  const { id: targetId } = resolveUserArg(userArg);
  let records;
  if (targetId) {
    records = await db!.select().from(roleAssignmentsTable)
      .where(and(eq(roleAssignmentsTable.guildId, message.guild.id), eq(roleAssignmentsTable.targetId, targetId)))
      .orderBy(roleAssignmentsTable.assignedAt);
  } else {
    const nameSearch = userArg.toLowerCase();
    const all = await db!.select().from(roleAssignmentsTable)
      .where(eq(roleAssignmentsTable.guildId, message.guild.id))
      .orderBy(roleAssignmentsTable.assignedAt);
    records = all.filter((r) => r.targetTag.toLowerCase().includes(nameSearch));
  }
  if (!records.length) {
    await message.reply({ embeds: [new EmbedBuilder().setColor(Colors.Yellow).setTitle("No timeline data").setDescription(`No events found for **${userArg}**.`)] });
    return;
  }
  const targetTag = records[0].targetTag;
  const lines = records.slice(0, 25).map((r) => {
    const icon = r.action === "assigned" ? "🟢" : "🔴";
    return `${icon} ${ts(new Date(r.assignedAt))} **${r.roleName}** — by **${r.executorTag}**`;
  });
  if (records.length > 25) lines.push(`*…and ${records.length - 25} more*`);
  const embed = new EmbedBuilder()
    .setColor(0x5865f2)
    .setTitle(`📅 Timeline for ${targetTag}`)
    .setDescription(lines.join("\n"))
    .setFooter({ text: `${records.length} total event(s) — oldest first — 🟢 given  🔴 removed` })
    .setTimestamp();
  await message.reply({ embeds: [embed] });
}

async function cmdMod(message: Message, args: string[]) {
  if (!message.guild) {
    await message.reply({ embeds: [errorEmbed("This command must be used in a server.")] });
    return;
  }
  const userArg = args.join(" ").trim();
  if (!userArg) {
    await message.reply({ embeds: [errorEmbed("Usage: `,mod @user` — full moderator profile.")] });
    return;
  }
  const { id: executorId } = resolveUserArg(userArg);
  let records;
  if (executorId) {
    records = await db!.select().from(roleAssignmentsTable)
      .where(and(eq(roleAssignmentsTable.guildId, message.guild.id), eq(roleAssignmentsTable.executorId, executorId)))
      .orderBy(desc(roleAssignmentsTable.assignedAt));
  } else {
    const nameSearch = userArg.toLowerCase();
    const all = await db!.select().from(roleAssignmentsTable)
      .where(eq(roleAssignmentsTable.guildId, message.guild.id))
      .orderBy(desc(roleAssignmentsTable.assignedAt));
    records = all.filter((r) => r.executorTag.toLowerCase().includes(nameSearch));
  }
  if (!records.length) {
    await message.reply({ embeds: [new EmbedBuilder().setColor(Colors.Yellow).setTitle("No data for this mod").setDescription(`No role events found for **${userArg}**.`)] });
    return;
  }
  const executorTag = records[0].executorTag;
  const eId = records[0].executorId;
  const given = records.filter((r) => r.action === "assigned");
  const removed = records.filter((r) => r.action === "removed");
  const roleFreq = new Map<string, number>();
  for (const r of given) roleFreq.set(r.roleName, (roleFreq.get(r.roleName) ?? 0) + 1);
  const topRoles = [...roleFreq.entries()].sort((a, b) => b[1] - a[1]).slice(0, 3);
  const targetFreq = new Map<string, number>();
  for (const r of records) targetFreq.set(r.targetTag, (targetFreq.get(r.targetTag) ?? 0) + 1);
  const topTargets = [...targetFreq.entries()].sort((a, b) => b[1] - a[1]).slice(0, 3);
  const recentLines = records.slice(0, 5).map((r) => {
    const icon = r.action === "assigned" ? "🟢" : "🔴";
    return `${icon} ${ts(new Date(r.assignedAt))} **${r.roleName}** → **${r.targetTag}**`;
  });
  const embed = new EmbedBuilder()
    .setColor(Colors.Orange)
    .setTitle(`🛡️ Mod Profile — ${executorTag}`)
    .setDescription(`<@${eId}>`)
    .addFields(
      { name: "📊 Activity", value: `🟢 **${given.length}** roles given\n🔴 **${removed.length}** roles removed\n📋 **${records.length}** total events`, inline: true },
      { name: "🔝 Top Roles Given", value: topRoles.length ? topRoles.map(([n, c]) => `**${n}** (${c}×)`).join("\n") : "None", inline: true },
      { name: "👥 Top Recipients", value: topTargets.length ? topTargets.map(([n, c]) => `**${n}** (${c}×)`).join("\n") : "None", inline: true },
      { name: "🕐 Recent Activity", value: recentLines.join("\n") || "None", inline: false },
    )
    .setFooter({ text: `First event: ${new Date(records[records.length - 1].assignedAt).toLocaleDateString()}` })
    .setTimestamp();
  await message.reply({ embeds: [embed] });
}

async function cmdBetween(message: Message, args: string[]) {
  if (!message.guild) {
    await message.reply({ embeds: [errorEmbed("This command must be used in a server.")] });
    return;
  }
  if (args.length < 2) {
    await message.reply({ embeds: [errorEmbed("Usage: `,between @user1 @user2` — all role interactions between two users.")] });
    return;
  }
  const { id: id1 } = resolveUserArg(args[0]);
  const { id: id2 } = resolveUserArg(args[1]);
  if (!id1 || !id2) {
    await message.reply({ embeds: [errorEmbed("Please mention or provide IDs for both users.")] });
    return;
  }
  const all = await db!.select().from(roleAssignmentsTable)
    .where(eq(roleAssignmentsTable.guildId, message.guild.id))
    .orderBy(desc(roleAssignmentsTable.assignedAt));
  const records = all.filter((r) =>
    (r.executorId === id1 && r.targetId === id2) || (r.executorId === id2 && r.targetId === id1)
  );
  if (!records.length) {
    await message.reply({ embeds: [new EmbedBuilder().setColor(Colors.Yellow).setTitle("No interactions found").setDescription("No role events between those two users.")] });
    return;
  }
  const lines = records.slice(0, 20).map((r) => {
    const icon = r.action === "assigned" ? "🟢" : "🔴";
    const verb = r.action === "assigned" ? "gave" : "removed";
    return `${icon} ${ts(new Date(r.assignedAt))} **${r.executorTag}** ${verb} **${r.roleName}** ${r.action === "assigned" ? "to" : "from"} **${r.targetTag}**`;
  });
  if (records.length > 20) lines.push(`*…and ${records.length - 20} more*`);
  const tag1 = records.find((r) => r.executorId === id1)?.executorTag ?? records.find((r) => r.targetId === id1)?.targetTag ?? id1;
  const tag2 = records.find((r) => r.executorId === id2)?.executorTag ?? records.find((r) => r.targetId === id2)?.targetTag ?? id2;
  const embed = new EmbedBuilder()
    .setColor(0x5865f2)
    .setTitle(`⚔️ Interactions: ${tag1} ↔ ${tag2}`)
    .setDescription(lines.join("\n"))
    .setFooter({ text: `${records.length} total event(s)` })
    .setTimestamp();
  await message.reply({ embeds: [embed] });
}

async function cmdMyActivity(message: Message) {
  if (!message.guild) {
    await message.reply({ embeds: [errorEmbed("This command must be used in a server.")] });
    return;
  }
  const userId = message.author.id;
  const [asExecutor, asTarget] = await Promise.all([
    db!.select().from(roleAssignmentsTable)
      .where(and(eq(roleAssignmentsTable.guildId, message.guild.id), eq(roleAssignmentsTable.executorId, userId)))
      .orderBy(desc(roleAssignmentsTable.assignedAt)),
    db!.select().from(roleAssignmentsTable)
      .where(and(eq(roleAssignmentsTable.guildId, message.guild.id), eq(roleAssignmentsTable.targetId, userId)))
      .orderBy(desc(roleAssignmentsTable.assignedAt)),
  ]);
  const given = asExecutor.filter((r) => r.action === "assigned").length;
  const removed = asExecutor.filter((r) => r.action === "removed").length;
  const receivedGiven = asTarget.filter((r) => r.action === "assigned").length;
  const receivedRemoved = asTarget.filter((r) => r.action === "removed").length;
  const recentDone = asExecutor.slice(0, 3).map((r) => {
    const icon = r.action === "assigned" ? "🟢" : "🔴";
    const verb = r.action === "assigned" ? "gave" : "removed";
    return `${icon} ${ts(new Date(r.assignedAt))} ${verb} **${r.roleName}** → **${r.targetTag}**`;
  });
  const recentReceived = asTarget.slice(0, 3).map((r) => {
    const icon = r.action === "assigned" ? "🟢" : "🔴";
    return `${icon} ${ts(new Date(r.assignedAt))} **${r.roleName}** by **${r.executorTag}**`;
  });
  const embed = new EmbedBuilder()
    .setColor(0x5865f2)
    .setTitle(`📊 Your Activity — ${message.author.tag}`)
    .addFields(
      { name: "🛡️ As Moderator", value: `🟢 **${given}** given  •  🔴 **${removed}** removed\n${recentDone.join("\n") || "*No activity*"}`, inline: false },
      { name: "👤 Roles Received", value: `🟢 **${receivedGiven}** given to you  •  🔴 **${receivedRemoved}** removed from you\n${recentReceived.join("\n") || "*No activity*"}`, inline: false },
    )
    .setTimestamp();
  await message.reply({ embeds: [embed] });
}

async function cmdSearch(message: Message, args: string[]) {
  if (!message.guild) {
    await message.reply({ embeds: [errorEmbed("This command must be used in a server.")] });
    return;
  }
  const query = args.join(" ").trim().toLowerCase();
  if (!query) {
    await message.reply({ embeds: [errorEmbed("Usage: `,search <rolename>` — find all events for a role.")] });
    return;
  }
  const all = await db!.select().from(roleAssignmentsTable)
    .where(eq(roleAssignmentsTable.guildId, message.guild.id))
    .orderBy(desc(roleAssignmentsTable.assignedAt));
  const records = all.filter((r) => r.roleName.toLowerCase().includes(query));
  if (!records.length) {
    await message.reply({ embeds: [new EmbedBuilder().setColor(Colors.Yellow).setTitle("No results").setDescription(`No role events found matching **${query}**.`)] });
    return;
  }
  const given = records.filter((r) => r.action === "assigned").length;
  const removed = records.filter((r) => r.action === "removed").length;
  const lines = records.slice(0, 20).map((r) => {
    const icon = r.action === "assigned" ? "🟢" : "🔴";
    const verb = r.action === "assigned" ? "gave" : "removed";
    return `${icon} ${ts(new Date(r.assignedAt))} **${r.executorTag}** ${verb} **${r.roleName}** ${r.action === "assigned" ? "to" : "from"} **${r.targetTag}**`;
  });
  if (records.length > 20) lines.push(`*…and ${records.length - 20} more*`);
  const embed = new EmbedBuilder()
    .setColor(Colors.Blue)
    .setTitle(`🔍 Search: "${query}"`)
    .setDescription(lines.join("\n"))
    .setFooter({ text: `${records.length} result(s) — 🟢 ${given} given  🔴 ${removed} removed` })
    .setTimestamp();
  await message.reply({ embeds: [embed] });
}

async function cmdFind(message: Message, args: string[]) {
  if (!message.guild) {
    await message.reply({ embeds: [errorEmbed("This command must be used in a server.")] });
    return;
  }
  const query = args.join(" ").trim().toLowerCase();
  if (!query) {
    await message.reply({ embeds: [errorEmbed("Usage: `,find <name>` — search across all usernames.")] });
    return;
  }
  const all = await db!.select().from(roleAssignmentsTable)
    .where(eq(roleAssignmentsTable.guildId, message.guild.id))
    .orderBy(desc(roleAssignmentsTable.assignedAt));
  const records = all.filter((r) =>
    r.executorTag.toLowerCase().includes(query) || r.targetTag.toLowerCase().includes(query)
  );
  if (!records.length) {
    await message.reply({ embeds: [new EmbedBuilder().setColor(Colors.Yellow).setTitle("No results").setDescription(`No events matched **"${query}"** in any username.`)] });
    return;
  }
  const lines = records.slice(0, 20).map((r) => {
    const icon = r.action === "assigned" ? "🟢" : "🔴";
    const verb = r.action === "assigned" ? "gave" : "removed";
    return `${icon} ${ts(new Date(r.assignedAt))} **${r.executorTag}** ${verb} **${r.roleName}** → **${r.targetTag}**`;
  });
  if (records.length > 20) lines.push(`*…and ${records.length - 20} more*`);
  const embed = new EmbedBuilder()
    .setColor(Colors.Blue)
    .setTitle(`🔎 Find: "${query}"`)
    .setDescription(lines.join("\n"))
    .setFooter({ text: `${records.length} matching event(s)` })
    .setTimestamp();
  await message.reply({ embeds: [embed] });
}

async function cmdWhoHas(message: Message, args: string[]) {
  if (!message.guild) {
    await message.reply({ embeds: [errorEmbed("This command must be used in a server.")] });
    return;
  }
  const query = args.join(" ").trim().toLowerCase();
  if (!query) {
    await message.reply({ embeds: [errorEmbed("Usage: `,whohas <rolename>` — see who currently holds that role.")] });
    return;
  }
  await message.guild.members.fetch();
  await message.guild.roles.fetch();
  const matchingRoles = message.guild.roles.cache.filter((r) => r.name.toLowerCase().includes(query) && hasElevatedPermission(r.permissions));
  if (!matchingRoles.size) {
    await message.reply({ embeds: [new EmbedBuilder().setColor(Colors.Yellow).setTitle("No elevated roles found").setDescription(`No roles matching **"${query}"** with elevated permissions exist in this server.`)] });
    return;
  }
  const fields: { name: string; value: string; inline: boolean }[] = [];
  for (const [, role] of matchingRoles) {
    const members = role.members;
    const perms = getElevatedPermNames(role.permissions).map((p) => `\`${p}\``).join(", ");
    const memberList = members.size
      ? members.map((m) => `• **${m.user.tag}**`).slice(0, 10).join("\n") + (members.size > 10 ? `\n*…and ${members.size - 10} more*` : "")
      : "*No members*";
    fields.push({
      name: `@${role.name} (${members.size} member${members.size !== 1 ? "s" : ""})`,
      value: `**Perms:** ${perms}\n${memberList}`,
      inline: false,
    });
  }
  const embed = new EmbedBuilder()
    .setColor(Colors.Gold)
    .setTitle(`👥 Who has "${query}"?`)
    .addFields(fields.slice(0, 5))
    .setFooter({ text: "Live data from Discord" })
    .setTimestamp();
  await message.reply({ embeds: [embed] });
}

async function cmdHistory(message: Message, args: string[]) {
  if (!message.guild) {
    await message.reply({ embeds: [errorEmbed("This command must be used in a server.")] });
    return;
  }
  const rawDays = parseInt(args[0] ?? "7", 10);
  const days = isNaN(rawDays) || rawDays < 1 ? 7 : Math.min(rawDays, 90);
  const since = new Date(Date.now() - days * 24 * 60 * 60 * 1000);
  const all = await db!.select().from(roleAssignmentsTable)
    .where(eq(roleAssignmentsTable.guildId, message.guild.id))
    .orderBy(desc(roleAssignmentsTable.assignedAt));
  const records = all.filter((r) => new Date(r.assignedAt) >= since);
  if (!records.length) {
    await message.reply({ embeds: [new EmbedBuilder().setColor(Colors.Yellow).setTitle(`No activity in the last ${days} day(s)`).setDescription("No role events recorded in this time period.")] });
    return;
  }
  const given = records.filter((r) => r.action === "assigned").length;
  const removed = records.filter((r) => r.action === "removed").length;
  const lines = records.slice(0, 20).map((r) => {
    const icon = r.action === "assigned" ? "🟢" : "🔴";
    const verb = r.action === "assigned" ? "gave" : "removed";
    return `${icon} ${ts(new Date(r.assignedAt))} **${r.executorTag}** ${verb} **${r.roleName}** → **${r.targetTag}**`;
  });
  if (records.length > 20) lines.push(`*…and ${records.length - 20} more*`);
  const embed = new EmbedBuilder()
    .setColor(0x5865f2)
    .setTitle(`📅 Last ${days} day(s) — ${records.length} event(s)`)
    .setDescription(lines.join("\n"))
    .setFooter({ text: `🟢 ${given} given  •  🔴 ${removed} removed` })
    .setTimestamp();
  await message.reply({ embeds: [embed] });
}

async function cmdActive(message: Message, args: string[]) {
  if (!message.guild) {
    await message.reply({ embeds: [errorEmbed("This command must be used in a server.")] });
    return;
  }
  const rawDays = parseInt(args[0] ?? "7", 10);
  const days = isNaN(rawDays) || rawDays < 1 ? 7 : Math.min(rawDays, 90);
  const since = new Date(Date.now() - days * 24 * 60 * 60 * 1000);
  const all = await db!.select().from(roleAssignmentsTable)
    .where(eq(roleAssignmentsTable.guildId, message.guild.id))
    .orderBy(desc(roleAssignmentsTable.assignedAt));
  const recent = all.filter((r) => new Date(r.assignedAt) >= since);
  if (!recent.length) {
    await message.reply({ embeds: [new EmbedBuilder().setColor(Colors.Yellow).setTitle(`No activity in the last ${days} day(s)`).setDescription("No role events in this time window.")] });
    return;
  }
  const modMap = new Map<string, { tag: string; given: number; removed: number }>();
  for (const r of recent) {
    if (!modMap.has(r.executorId)) modMap.set(r.executorId, { tag: r.executorTag, given: 0, removed: 0 });
    const entry = modMap.get(r.executorId)!;
    if (r.action === "assigned") entry.given++;
    else entry.removed++;
  }
  const sorted = [...modMap.values()].sort((a, b) => (b.given + b.removed) - (a.given + a.removed));
  const lines = sorted.slice(0, 10).map((m, i) => `${i + 1}. **${m.tag}** — 🟢 ${m.given} given, 🔴 ${m.removed} removed`);
  const embed = new EmbedBuilder()
    .setColor(Colors.Orange)
    .setTitle(`⚡ Most Active Mods — Last ${days} day(s)`)
    .setDescription(lines.join("\n"))
    .setFooter({ text: `${recent.length} total events across ${modMap.size} moderator(s)` })
    .setTimestamp();
  await message.reply({ embeds: [embed] });
}

async function cmdTop(message: Message, args: string[]) {
  if (!message.guild) {
    await message.reply({ embeds: [errorEmbed("This command must be used in a server.")] });
    return;
  }
  const rawN = parseInt(args[0] ?? "10", 10);
  const n = isNaN(rawN) || rawN < 1 ? 10 : Math.min(rawN, 25);
  const all = await db!.select().from(roleAssignmentsTable)
    .where(eq(roleAssignmentsTable.guildId, message.guild.id));
  if (!all.length) {
    await message.reply({ embeds: [new EmbedBuilder().setColor(Colors.Yellow).setTitle("No data yet").setDescription("No role events have been recorded.")] });
    return;
  }
  const modMap = new Map<string, { tag: string; given: number; removed: number }>();
  for (const r of all) {
    if (!modMap.has(r.executorId)) modMap.set(r.executorId, { tag: r.executorTag, given: 0, removed: 0 });
    const entry = modMap.get(r.executorId)!;
    if (r.action === "assigned") entry.given++;
    else entry.removed++;
  }
  const sorted = [...modMap.values()].sort((a, b) => (b.given + b.removed) - (a.given + a.removed));
  const medals = ["🥇", "🥈", "🥉"];
  const lines = sorted.slice(0, n).map((m, i) => `${medals[i] ?? `${i + 1}.`} **${m.tag}** — ${m.given + m.removed} total (🟢 ${m.given} given, 🔴 ${m.removed} removed)`);
  const embed = new EmbedBuilder()
    .setColor(Colors.Gold)
    .setTitle(`🏆 Top ${Math.min(n, sorted.length)} Moderators`)
    .setDescription(lines.join("\n"))
    .setFooter({ text: `All-time • ${modMap.size} unique moderator(s) tracked` })
    .setTimestamp();
  await message.reply({ embeds: [embed] });
}

async function cmdAudit(message: Message) {
  if (!message.guild) {
    await message.reply({ embeds: [errorEmbed("This command must be used in a server.")] });
    return;
  }
  const all = await db!.select().from(roleAssignmentsTable)
    .where(and(eq(roleAssignmentsTable.guildId, message.guild.id), eq(roleAssignmentsTable.action, "assigned")))
    .orderBy(desc(roleAssignmentsTable.assignedAt));

  const WINDOW_MS = 10 * 60 * 1000;
  const THRESHOLD = 5;

  const flagged: string[] = [];
  const seenExecutors = new Set<string>();
  const modGroups = new Map<string, typeof all>();
  for (const r of all) {
    if (!modGroups.has(r.executorId)) modGroups.set(r.executorId, []);
    modGroups.get(r.executorId)!.push(r);
  }
  for (const [executorId, events] of modGroups) {
    if (seenExecutors.has(executorId)) continue;
    for (let i = 0; i < events.length; i++) {
      const windowEnd = new Date(events[i].assignedAt).getTime();
      const windowStart = windowEnd - WINDOW_MS;
      const inWindow = events.filter((e) => {
        const t = new Date(e.assignedAt).getTime();
        return t >= windowStart && t <= windowEnd;
      });
      if (inWindow.length >= THRESHOLD) {
        seenExecutors.add(executorId);
        const execTag = inWindow[0].executorTag;
        const targets = [...new Set(inWindow.map((e) => e.targetTag))];
        flagged.push(`⚠️ **${execTag}** assigned **${inWindow.length}** roles in 10 minutes (to: ${targets.slice(0, 3).map((t) => `**${t}**`).join(", ")}${targets.length > 3 ? ` and ${targets.length - 3} more` : ""}) — ${ts(new Date(inWindow[inWindow.length - 1].assignedAt))}`);
        break;
      }
    }
  }

  if (!flagged.length) {
    await message.reply({ embeds: [new EmbedBuilder().setColor(Colors.Green).setTitle("✅ Audit Clean").setDescription("No suspicious rapid role activity detected.\n\n*Threshold: 5+ roles assigned within 10 minutes by one mod.*")] });
    return;
  }
  const embed = new EmbedBuilder()
    .setColor(Colors.Red)
    .setTitle(`🚨 Suspicious Activity — ${flagged.length} flag(s)`)
    .setDescription(flagged.slice(0, 10).join("\n\n"))
    .setFooter({ text: "Threshold: 5+ assignments in 10 min by one moderator" })
    .setTimestamp();
  await message.reply({ embeds: [embed] });
}

async function cmdUndone(message: Message, args: string[]) {
  if (!message.guild) {
    await message.reply({ embeds: [errorEmbed("This command must be used in a server.")] });
    return;
  }
  const rawHours = parseInt(args[0] ?? "24", 10);
  const hours = isNaN(rawHours) || rawHours < 1 ? 24 : Math.min(rawHours, 720);
  const windowMs = hours * 60 * 60 * 1000;

  const all = await db!.select().from(roleAssignmentsTable)
    .where(eq(roleAssignmentsTable.guildId, message.guild.id))
    .orderBy(roleAssignmentsTable.assignedAt);

  const bounced: string[] = [];
  const usedReversalIds = new Set<number>();
  const assignments = all.filter((r) => r.action === "assigned");
  for (const assign of assignments) {
    const reversal = all.find((r) =>
      r.action === "removed" &&
      !usedReversalIds.has(r.id) &&
      r.targetId === assign.targetId &&
      r.roleId === assign.roleId &&
      new Date(r.assignedAt).getTime() > new Date(assign.assignedAt).getTime() &&
      new Date(r.assignedAt).getTime() - new Date(assign.assignedAt).getTime() <= windowMs
    );
    if (reversal) {
      usedReversalIds.add(reversal.id);
      const gapMs = new Date(reversal.assignedAt).getTime() - new Date(assign.assignedAt).getTime();
      const gapMins = Math.round(gapMs / 60000);
      bounced.push(`• **${assign.roleName}** → **${assign.targetTag}** — given by **${assign.executorTag}** ${ts(new Date(assign.assignedAt))}, removed by **${reversal.executorTag}** ${ts(new Date(reversal.assignedAt))} *(${gapMins} min later)*`);
    }
  }

  if (!bounced.length) {
    await message.reply({ embeds: [new EmbedBuilder().setColor(Colors.Green).setTitle(`✅ No Role Bouncing`).setDescription(`No roles were given then removed within **${hours}h**.`)] });
    return;
  }
  const embed = new EmbedBuilder()
    .setColor(Colors.Yellow)
    .setTitle(`🔄 Role Bouncing — ${bounced.length} case(s)`)
    .setDescription(bounced.slice(0, 15).join("\n"))
    .setFooter({ text: `Roles given then removed within ${hours}h` })
    .setTimestamp();
  await message.reply({ embeds: [embed] });
}

async function cmdExport(message: Message) {
  if (!message.guild) {
    await message.reply({ embeds: [errorEmbed("This command must be used in a server.")] });
    return;
  }
  const records = await db!.select().from(roleAssignmentsTable)
    .where(eq(roleAssignmentsTable.guildId, message.guild.id))
    .orderBy(desc(roleAssignmentsTable.assignedAt));
  if (!records.length) {
    await message.reply({ embeds: [new EmbedBuilder().setColor(Colors.Yellow).setTitle("Nothing to export").setDescription("No role events have been recorded yet.")] });
    return;
  }
  const header = `Role Audit Export — ${message.guild.name}\nGenerated: ${new Date().toUTCString()}\nTotal events: ${records.length}\n${"─".repeat(60)}\n\n`;
  const lines = records.map((r) => {
    const date = new Date(r.assignedAt).toUTCString();
    const verb = r.action === "assigned" ? "GAVE    " : "REMOVED ";
    return `[${date}] ${r.executorTag.padEnd(32)} ${verb} @${r.roleName.padEnd(30)} → ${r.targetTag}`;
  });
  const content = header + lines.join("\n");
  const buffer = Buffer.from(content, "utf-8");
  const filename = `role-audit-${message.guild.id}-${Date.now()}.txt`;
  await message.reply({
    content: `📄 Full export — **${records.length}** event(s)`,
    files: [{ attachment: buffer, name: filename }],
  });
}

async function cmdDeleteAllChannels(message: Message, confirmed: boolean) {
  if (!message.guild || !message.member) return;
  if (
    message.author.id !== message.guild.ownerId &&
    !message.member.permissions.has(PermissionsBitField.Flags.Administrator)
  ) {
    await message.reply({ embeds: [errorEmbed("This command requires **Administrator** permission or server ownership.")] });
    return;
  }

  if (!confirmed) {
    await message.reply({
      embeds: [
        new EmbedBuilder()
          .setColor(Colors.Red)
          .setTitle("⚠️ Confirm: Delete ALL Channels")
          .setDescription(
            `This will permanently delete **every channel** in **${message.guild.name}**.\n\n` +
            `Type \`,delete all channels confirm\` to proceed.\n\n` +
            `**This cannot be undone unless you have an anti-nuke snapshot.**`
          )
          .setFooter({ text: "Waiting for confirmation" })
          .setTimestamp(),
      ],
    });
    return;
  }

  const guild = message.guild;
  await guild.channels.fetch();
  const channels = [...guild.channels.cache.values()];

  const pending = await message.reply({
    embeds: [
      new EmbedBuilder()
        .setColor(Colors.Orange)
        .setTitle("Deleting All Channels…")
        .setDescription(`Deleting **${channels.length}** channel(s). This may take a moment.`)
        .setTimestamp(),
    ],
  }).catch(() => null);

  let deleted = 0;
  let failed = 0;
  for (const ch of channels) {
    try {
      await ch.delete("Admin command: delete all channels");
      deleted++;
    } catch {
      failed++;
    }
  }

  // Try to log in any channel that still exists after the wipe
  const remaining = [...guild.channels.cache.values()].find(c => "send" in c) as any;
  const resultEmbed = new EmbedBuilder()
    .setColor(failed > 0 ? Colors.Yellow : Colors.Green)
    .setTitle("Channel Deletion Complete")
    .setDescription(
      `✅ Deleted: **${deleted}** channel(s)\n` +
      (failed > 0 ? `⚠️ Failed: **${failed}** (missing permissions or already gone)\n` : "") +
      `\nUse \`-antinuke restore\` to rebuild from the last snapshot.`
    )
    .setTimestamp();

  if (remaining) {
    await remaining.send({ embeds: [resultEmbed] }).catch(() => null);
  } else if (pending) {
    await pending.edit({ embeds: [resultEmbed] }).catch(() => null);
  }
}

async function cmdLogs(message: Message) {
  if (!ERROR_LOG.length) {
    const embed = new EmbedBuilder()
      .setColor(Colors.Green)
      .setTitle("✅ No errors logged")
      .setDescription("No command errors have occurred since the bot started.")
      .setFooter({ text: `Stores up to ${MAX_LOG_SIZE} most recent errors in memory` })
      .setTimestamp();
    await message.reply({ embeds: [embed] });
    return;
  }

  const lines = ERROR_LOG.map((e, i) => {
    const discordTs = `<t:${Math.floor(e.at.getTime() / 1000)}:R>`;
    const code = e.code ? ` [${e.code}]` : "";
    const detail = e.detail ? `\n  ↳ ${e.detail}` : "";
    return `**${i + 1}.** ${discordTs} — \`${e.command}\`\n  ${e.message}${code}${detail}`;
  });

  const CHUNK = 8;
  const chunks: string[][] = [];
  for (let i = 0; i < lines.length; i += CHUNK) chunks.push(lines.slice(i, i + CHUNK));

  for (let i = 0; i < chunks.length; i++) {
    const embed = new EmbedBuilder()
      .setColor(Colors.Red)
      .setTitle(i === 0 ? `🪵 Error Log — ${ERROR_LOG.length} error(s)` : "🪵 Error Log (cont.)")
      .setDescription(chunks[i].join("\n\n"))
      .setFooter({ text: i === 0 ? `Last ${MAX_LOG_SIZE} errors since bot start — newest first` : "" })
      .setTimestamp();

    if (i === 0) {
      await message.reply({ embeds: [embed] });
    } else if ("send" in message.channel) {
      await (message.channel as import("discord.js").TextChannel).send({ embeds: [embed] });
    }
  }
}

async function cmdMigrate(message: Message) {
  if (!db) {
    await message.reply({ embeds: [errorEmbed("Database not configured — set `DATABASE_URL` first.")] });
    return;
  }
  if (isDbTableReady()) {
    await message.reply({
      embeds: [new EmbedBuilder()
        .setColor(Colors.Green)
        .setTitle("✅ Table already exists")
        .setDescription("The `role_assignments` table is confirmed ready. No action needed.")
        .setTimestamp()],
    });
    return;
  }
  const pending = await message.reply({
    embeds: [new EmbedBuilder()
      .setColor(Colors.Yellow)
      .setTitle("⏳ Running migrations…")
      .setDescription("Attempting to create the `role_assignments` table. This may take a few seconds.")
      .setTimestamp()],
  });
  try {
    await runMigrations();
    await pending.edit({
      embeds: [new EmbedBuilder()
        .setColor(Colors.Green)
        .setTitle("✅ Migration complete")
        .setDescription("The `role_assignments` table is now ready. All commands should work.")
        .setTimestamp()],
    });
  } catch (err: any) {
    const { code, message: pgMsg } = digPgError(err);
    const detail = [code && `Code: \`${code}\``, pgMsg].filter(Boolean).join("\n");
    await pending.edit({
      embeds: [new EmbedBuilder()
        .setColor(Colors.Red)
        .setTitle("❌ Migration failed")
        .setDescription(`Could not create the table:\n${detail || "Unknown error"}\n\nCheck Railway logs for more detail.`)
        .setTimestamp()],
    });
  }
}

// ── Role change tracking ───────────────────────────────────────────────────────

async function recordRoleEvent(
  guild: import("discord.js").Guild,
  executorId: string,
  executorTag: string,
  targetId: string,
  targetTag: string,
  roleId: string,
  roleName: string,
  action: "assigned" | "removed",
) {
  await db!.insert(roleAssignmentsTable).values({
    guildId: guild.id,
    executorId,
    executorTag,
    targetId,
    targetTag,
    roleId,
    roleName,
    action,
  });

  logger.info({ executor: executorTag, target: targetTag, role: roleName, action }, "Role event recorded");
}

// ── Mention-guard: core helpers ───────────────────────────────────────────────

/**
 * Strips EVERY non-managed, non-@everyone role from a GuildMember.
 *
 * Safety guarantees:
 *  - Skips integration-managed roles (bots can never remove those anyway).
 *  - Retries each individual role once after 600 ms if it fails (handles
 *    transient rate-limits without hammering the API).
 *  - Logs every success and every permanent failure so nothing is silent.
 *  - Never throws — always resolves with the list of successfully stripped names.
 */
async function stripAllRoles(member: GuildMember, reason: string): Promise<string[]> {
  const stripped: string[] = [];
  const failed:   string[] = [];
  const skipped:  string[] = [];

  // Bot's highest role — we can only remove roles strictly below this position
  const botMember  = member.guild.members.me;
  const botHighest = botMember?.roles.highest;

  // Collect roles to remove (exclude @everyone and bot-managed integration roles)
  const toStrip = [...member.roles.cache.values()].filter(
    (r) => !r.managed && r.id !== member.guild.id,
  );

  for (const role of toStrip) {
    // Skip roles at or above the bot's highest role — Discord would reject these anyway
    if (botHighest && role.comparePositionTo(botHighest) >= 0) {
      skipped.push(role.name);
      logger.warn(`[STRIP-ALL] Skipping "${role.name}" — at or above bot's highest role "${botHighest.name}"`);
      continue;
    }

    let success = false;
    for (let attempt = 1; attempt <= 2; attempt++) {
      try {
        await member.roles.remove(role, reason);
        success = true;
        break;
      } catch (err: any) {
        if (attempt === 1) {
          // Brief back-off on first failure (rate-limit or transient Discord error)
          await new Promise((r) => setTimeout(r, 600));
        } else {
          logger.warn(
            `[STRIP-ALL] Could not remove "${role.name}" from ${member.user.tag} ` +
            `(${member.id}) after 2 attempts — ${err?.message ?? "hierarchy or permission issue"}`,
          );
        }
      }
    }
    if (success) {
      stripped.push(role.name);
      logger.info(`[STRIP-ALL] Removed "${role.name}" from ${member.user.tag} (${member.id}) — ${reason}`);
    } else {
      failed.push(role.name);
    }
  }

  if (skipped.length > 0) {
    logger.warn(
      `[STRIP-ALL] ${member.user.tag} — skipped ${skipped.length} role(s) above bot hierarchy: [${skipped.join(", ")}]. ` +
      `Move the bot's role above these in Server Settings → Roles to enable full enforcement.`,
    );
  }
  if (failed.length > 0) {
    logger.warn(
      `[STRIP-ALL] ${member.user.tag} (${member.id}) — ` +
      `stripped ${stripped.length}, permanently failed ${failed.length}: [${failed.join(", ")}].`,
    );
  }

  return stripped;
}

/**
 * Strips roles that carry admin, mod, or staff-level permissions from a member.
 * Used when a mention-flagged user attempts to assign any role to someone else.
 * Returns the list of successfully removed role names.
 */
async function stripElevatedRolesFromMember(member: GuildMember, reason: string): Promise<string[]> {
  const stripped: string[] = [];

  // Bot's highest role — only remove roles strictly below this position
  const botHighest = member.guild.members.me?.roles.highest;

  for (const role of member.roles.cache.values()) {
    // Skip @everyone and integration-managed roles
    if (role.managed || role.id === member.guild.id) continue;
    // Only target roles with admin / mod / staff permissions
    if (!hasElevatedPermission(role.permissions)) continue;
    // Skip roles at or above the bot's highest role in the hierarchy
    if (botHighest && role.comparePositionTo(botHighest) >= 0) {
      logger.warn(`[STRIP-ELEVATED] Skipping "${role.name}" — at or above bot's highest role "${botHighest.name}"`);
      continue;
    }

    let success = false;
    for (let attempt = 1; attempt <= 2; attempt++) {
      try {
        await member.roles.remove(role, reason);
        success = true;
        break;
      } catch (err: any) {
        if (attempt === 1) {
          await new Promise((r) => setTimeout(r, 600));
        } else {
          logger.warn(
            `[STRIP-ELEVATED] Could not remove "${role.name}" from ${member.user.tag} — ` +
            `${err?.message ?? "hierarchy issue"}`,
          );
        }
      }
    }
    if (success) {
      stripped.push(role.name);
      logger.info(`[STRIP-ELEVATED] Removed "${role.name}" from ${member.user.tag} — ${reason}`);
    }
  }

  return stripped;
}

/**
 * Mention-guard handler — called on every non-bot MessageCreate event.
 *
 * Triggers when the message:
 *   a) Discord-pinged @everyone or @here  (message.mentions.everyone === true), OR
 *   b) Contains the literal text "@everyone" or "@here" (catches attempts with
 *      no-ping formatting tricks like zero-width chars may still slip through,
 *      but this catches the common cases).
 *
 * On trigger:
 *   1. Flags the user in flaggedMentionUsers for this guild.
 *   2. Strips ALL roles from the user immediately.
 *   3. Attempts to delete the offending message.
 *   4. Posts a visible alert embed in the channel.
 */
async function handleEveryoneMentionGuard(message: Message): Promise<void> {
  // Guard: only process messages in guilds
  if (!message.guild) return;
  // Guard: never act on bots (MessageCreate already checks, but be explicit)
  if (message.author.bot) return;
  // Guard: never act on the bot itself
  if (message.author.id === message.client.user?.id) return;

  const guild = message.guild;

  // Detect @everyone / @here
  //   message.mentions.everyone  — set by Discord for actual pings (works with or without content intent)
  //   regex fallback             — catches literal "@everyone"/"@here" text when content intent IS enabled
  const discordPing  = message.mentions.everyone;
  const literalMatch = message.content ? /@everyone|@here/i.test(message.content) : false;

  if (!discordPing && !literalMatch) return; // nothing to do

  // Trusted owner is permanently exempt from all enforcement
  if (isTrustedOwner(message.author.id)) {
    logger.info(`[MENTION-GUARD] @everyone/@here from trusted owner ${message.author.tag} — skipped`);
    return;
  }

  // Resolve the GuildMember — use cache first, fall back to a live fetch.
  // message.member can be null when the member isn't cached (common after bot restart).
  let member = message.member ?? await guild.members.fetch(message.author.id).catch(() => null);
  if (!member) {
    logger.warn(`[MENTION-GUARD] Could not resolve member for ${message.author.tag} (${message.author.id}) — skipping strip`);
    return;
  }
  const pingType  = discordPing ? "Discord ping" : "literal text";

  logger.warn(
    `[MENTION-GUARD] @everyone/@here detected (${pingType}) ` +
    `from ${message.author.tag} (${message.author.id}) ` +
    `in guild "${guild.name}" (${guild.id}) — initiating full role strip`,
  );

  // 1. Flag this user so future role assignments also trigger enforcement
  flagMentionUser(guild.id, message.author.id);
  const flagData = flaggedMentionUsers.get(guild.id)!.get(message.author.id)!;

  // 2. Strip every role (sequential with retry — see stripAllRoles above)
  const stripped = await stripAllRoles(
    member,
    `Mention-guard: sent @everyone/@here (offense #${flagData.count}) — all roles removed`,
  );

  logger.info(
    `[MENTION-GUARD] Role strip complete for ${message.author.tag} (${message.author.id}): ` +
    `${stripped.length > 0 ? stripped.join(", ") : "no roles to strip"}`,
  );

  // 3. Attempt to delete the offending message
  try {
    await message.delete();
    logger.info(`[MENTION-GUARD] Deleted @everyone/@here message from ${message.author.tag}`);
  } catch {
    // Missing Manage Messages permission — log and continue (non-fatal)
    logger.warn(
      `[MENTION-GUARD] Could not delete message from ${message.author.tag} ` +
      `— bot may lack Manage Messages permission in this channel`,
    );
  }

  // 4. Post a visible alert embed in the channel
  if ("send" in message.channel) {
    await (message.channel as import("discord.js").TextChannel)
      .send({
        embeds: [
          new EmbedBuilder()
            .setColor(Colors.Red)
            .setTitle("🚨 Mention Guard — @everyone/@here Blocked")
            .setDescription(
              `<@${message.author.id}> used \`@everyone\` or \`@here\` and has had **all roles stripped**.\n\n` +
              (stripped.length > 0
                ? `**Removed roles (${stripped.length}):** ${stripped.map((r) => `\`${r}\``).join(", ")}`
                : "*This user had no roles to strip.*"),
            )
            .addFields({
              name: "⚠️ User is now flagged",
              value:
                "Any future role assignments made by this user will also trigger " +
                "an immediate strip of their admin/mod/staff permissions.",
              inline: false,
            })
            .setFooter({ text: `Offense #${flagData.count} • ${message.author.tag}` })
            .setTimestamp(),
        ],
      })
      .catch(() => null); // Missing Send Messages permission — non-fatal
  }
}

// ── Bot startup ────────────────────────────────────────────────────────────────

export async function startBot() {
  // Trim whitespace — copy-paste from Railway/dashboards often adds trailing newlines or spaces
  const token = process.env.DISCORD_BOT_TOKEN?.trim();
  if (!token) {
    logger.warn("DISCORD_BOT_TOKEN not set — Discord bot will not start.");
    return;
  }
  logger.info(`DISCORD_BOT_TOKEN loaded — length: ${token.length}, starts: ${token.slice(0, 10)}...`);

  const client = new Client({
    intents: [
      GatewayIntentBits.Guilds,
      GatewayIntentBits.GuildMembers,    // Privileged — enable in Dev Portal
      GatewayIntentBits.GuildMessages,
      GatewayIntentBits.MessageContent,  // Privileged — enable in Dev Portal
      GatewayIntentBits.GuildModeration,
    ],
  });

  registerAntiNukeListeners(client);

  client.once(Events.ClientReady, (readyClient) => {
    logger.info({ tag: readyClient.user.tag }, "Discord bot logged in and ready");
    readyClient.user.setActivity("/florida", { type: ActivityType.Watching });

    if (!db) {
      logger.warn("Bot ready but DATABASE_URL is not set — all database commands will fail.");
    } else if (!isDbTableReady()) {
      logger.warn(
        "Bot ready but database table may not exist — migrations may have failed. " +
        "Check logs or use ,migrate to retry. Commands will error until the table exists."
      );
    } else {
      logger.info("Bot ready and database table verified — all systems operational.");
    }

    // ── Role hierarchy check ─────────────────────────────────────────────────
    // The bot MUST be positioned ABOVE every role it needs to remove.
    // If it is not, role-strip calls will fail silently. We warn here at startup.
    for (const [, guild] of readyClient.guilds.cache) {
      const botMember = guild.members.me;
      if (!botMember) continue;
      const botHighest = botMember.roles.highest;
      const problematic: string[] = [];
      for (const [, role] of guild.roles.cache) {
        if (role.managed || role.id === guild.id) continue;
        if (!hasElevatedPermission(role.permissions)) continue;
        if (role.comparePositionTo(botHighest) >= 0) {
          problematic.push(`"${role.name}" (pos ${role.rawPosition})`);
        }
      }
      if (problematic.length > 0) {
        logger.warn(
          `⚠️  ROLE HIERARCHY ISSUE in "${guild.name}" (${guild.id}): ` +
          `Bot's highest role "${botHighest.name}" (pos ${botHighest.rawPosition}) is BELOW or equal to ` +
          `these elevated roles — the bot cannot remove them:\n  ${problematic.join("\n  ")}\n` +
          `FIX: In Server Settings → Roles, drag the bot's role ABOVE all roles listed above.`
        );
      } else {
        logger.info({ guildId: guild.id, guildName: guild.name, botRole: botHighest.name }, "Role hierarchy OK — bot can manage all elevated roles");
      }
    }

    // Start periodic snapshots for every guild the bot is already in
    startSnapshotSchedule(readyClient);
  });

  // ── Auto-enable anti-nuke when the bot joins a new guild ──────────────────
  client.on(Events.GuildCreate, async (guild) => {
    logger.info({ guildId: guild.id, guildName: guild.name }, "Bot joined new guild — auto-enabling anti-nuke");

    if (db) {
      try {
        await db
          .insert(antinukeConfigTable)
          .values({ guildId: guild.id, enabled: true })
          .onConflictDoUpdate({
            target: antinukeConfigTable.guildId,
            set: { enabled: true },
          });
        logger.info({ guildId: guild.id }, "Anti-nuke auto-enabled for new guild");
      } catch (err: any) {
        logger.error(`Failed to auto-enable anti-nuke for guild ${guild.id}: ${err?.message}`);
      }
    }

    // Take an initial snapshot and schedule periodic ones
    scheduleGuildSnapshot(guild);
  });

  // ── Clean up snapshot schedule when the bot leaves a guild ────────────────
  client.on(Events.GuildDelete, (guild) => {
    stopSnapshotSchedule(guild.id);
  });

  // ── Track role assignments + strip dangerous roles from giver and receiver ────
  client.on(Events.GuildMemberUpdate, async (oldMember, newMember) => {
    try {
      const guild = newMember.guild;

      const addedRoles   = newMember.roles.cache.filter((r) => !oldMember.roles.cache.has(r.id));
      const removedRoles = oldMember.roles.cache.filter((r) => !newMember.roles.cache.has(r.id));

      const elevatedAdded   = addedRoles.filter((r) => hasElevatedPermission(r.permissions));
      const elevatedRemoved = removedRoles.filter((r) => hasElevatedPermission(r.permissions));

      // Skip if nothing relevant happened — only proceed for elevated changes or
      // any role change when mention-guard has flagged users in this guild.
      const anyRoleAdded      = addedRoles.size > 0;
      const anyFlaggedInGuild = (flaggedMentionUsers.get(guild.id)?.size ?? 0) > 0;
      if (elevatedAdded.size === 0 && elevatedRemoved.size === 0 && !(anyRoleAdded && anyFlaggedInGuild)) return;

      // ── Fetch audit log first — we need the executor before deciding any strip ──
      // We must know WHO assigned the role before stripping, because whitelist /
      // roleingExempt givers bypass ALL enforcement (receiver and giver both safe).
      let entry: import("discord.js").GuildAuditLogsEntry | undefined;
      for (const delay of [500, 1000]) {
        await new Promise((r) => setTimeout(r, delay));
        const logs = await guild.fetchAuditLogs({ limit: 5, type: AuditLogEvent.MemberRoleUpdate });
        entry = logs.entries.find((e) => (e.target as GuildMember | null)?.id === newMember.id);
        if (entry?.executor) break;
      }

      if (!entry?.executor) {
        logger.warn({ targetId: newMember.id }, "Role change: no audit log entry found — bot may lack View Audit Log permission");
        return;
      }

      const executor    = entry.executor;
      const executorId  = typeof executor.id === "string" ? executor.id : "unknown";
      const executorTag = executor.tag ?? executor.username ?? "unknown";
      const targetTag   = newMember.user.tag ?? newMember.user.username;

      // ── Exemption check ──────────────────────────────────────────────────────
      // Whitelist and roleingExempt givers bypass ALL strips — neither the giver
      // nor the receiver gets touched. Trusted owner and server owner are always exempt.
      const antinukeConfig = await getAntinukeConfig(guild.id).catch(() => null);
      const whitelist      = antinukeConfig?.whitelist     ?? [];
      const roleingExempt  = antinukeConfig?.roleingExempt ?? [];
      const isGiverExempt  =
        isTrustedOwner(executorId) ||
        executorId === guild.ownerId ||
        whitelist.includes(executorId) ||
        roleingExempt.includes(executorId);

      // Record every elevated change to the DB (always — even for exempt givers)
      for (const [, role] of elevatedAdded) {
        await recordRoleEvent(guild, executorId, executorTag, newMember.id, targetTag, role.id, role.name, "assigned");
      }
      for (const [, role] of elevatedRemoved) {
        await recordRoleEvent(guild, executorId, executorTag, newMember.id, targetTag, role.id, role.name, "removed");
      }

      if (isGiverExempt) {
        logger.info(`Auto-mod: giver ${executorTag} (${executorId}) is exempt — no strips applied`);
        return;
      }

      const botHighest = guild.members.me?.roles.highest;

      // ── STRIP RECEIVER — remove the elevated roles that were just added ───────
      const isReceiverExempt = isTrustedOwner(newMember.id);
      const receiverStripped: string[] = [];

      if (elevatedAdded.size > 0 && !isReceiverExempt) {
        for (const [, role] of elevatedAdded) {
          if (botHighest && role.comparePositionTo(botHighest) >= 0) {
            logger.warn(`Auto-mod: skipping "${role.name}" from receiver ${newMember.user.tag} — above bot's highest role`);
            continue;
          }
          try {
            await newMember.roles.remove(role, "Auto-mod: dangerous role assigned — stripped from receiver");
            receiverStripped.push(role.name);
            logger.warn(`Auto-mod: stripped "${role.name}" from receiver ${newMember.user.tag} (${newMember.id})`);
          } catch (err: any) {
            logger.warn(`Auto-mod: could not strip "${role.name}" from receiver ${newMember.id} — ${err?.message ?? "hierarchy issue"}`);
          }
        }
      }

      // ── STRIP GIVER — remove their own elevated roles as punishment ───────────
      const giverMember = await guild.members.fetch(executorId).catch(() => null);
      const giverStripped: string[] = [];

      if (giverMember && elevatedAdded.size > 0) {
        for (const [, role] of giverMember.roles.cache) {
          if (role.managed || role.id === guild.id) continue;
          if (!hasElevatedPermission(role.permissions)) continue;
          if (botHighest && role.comparePositionTo(botHighest) >= 0) {
            logger.warn(`Auto-mod: skipping "${role.name}" from giver ${executorTag} — above bot's highest role`);
            continue;
          }
          try {
            await giverMember.roles.remove(role, "Auto-mod: assigned dangerous role — giver stripped");
            giverStripped.push(role.name);
            logger.warn(`Auto-mod: stripped "${role.name}" from giver ${executorTag} (${executorId})`);
          } catch (err: any) {
            logger.warn(`Auto-mod: could not strip giver role "${role.name}" — ${err?.message ?? "hierarchy issue"}`);
          }
        }
      }

      if (receiverStripped.length > 0 || giverStripped.length > 0) {
        logger.info(
          { guildId: guild.id, giver: executorTag, receiver: targetTag, receiverStripped, giverStripped },
          "Auto-mod: elevated role grant — both giver and receiver stripped"
        );
      }

      // ── Mention-guard: extra punishment for @everyone/@here flagged users ─────
      // If the executor was previously flagged for @everyone/@here abuse, they also
      // get their admin/mod/staff roles stripped on ANY role assignment (even non-elevated).
      // roleingExempt already handled above — this block only runs for non-exempt users.
      if (anyRoleAdded && isMentionFlagged(guild.id, executorId)) {
        const flaggedGiver = giverMember ?? await guild.members.fetch(executorId).catch(() => null);
        if (flaggedGiver) {
          logger.warn(
            `[MENTION-GUARD] Flagged user ${executorTag} (${executorId}) attempted role assignment ` +
            `in guild "${guild.name}" — stripping their admin/mod/staff roles`,
          );
          const mgStripped = await stripElevatedRolesFromMember(
            flaggedGiver,
            "Mention-guard: flagged user (@everyone/@here abuse) attempted role assignment",
          );
          logger.info(`[MENTION-GUARD] Stripped ${mgStripped.length} elevated role(s) from flagged user ${executorTag}: ${mgStripped.join(", ") || "none"}`);

          const anyTextCh = [...guild.channels.cache.values()].find((c) => "send" in c) as any;
          if (anyTextCh) {
            await anyTextCh.send({
              embeds: [
                new EmbedBuilder()
                  .setColor(Colors.DarkRed)
                  .setTitle("🚨 Mention-Guard — Flagged User Blocked Role Assignment")
                  .setDescription(
                    `<@${executorId}> (previously flagged for @everyone/@here abuse) ` +
                    `attempted to assign a role and has had **${mgStripped.length}** ` +
                    `elevated role(s) stripped.\n\n` +
                    (mgStripped.length > 0
                      ? `**Removed:** ${mgStripped.map((r) => `\`${r}\``).join(", ")}`
                      : "*No elevated roles were present.*"),
                  )
                  .setFooter({ text: executorTag })
                  .setTimestamp(),
              ],
            }).catch(() => null);
          }
        }
      }
    } catch (err) {
      logger.error({ err }, "Error handling GuildMemberUpdate");
    }
  });

  // ── Command router ───────────────────────────────────────────────────────────
  client.on(Events.MessageCreate, async (message) => {
    if (message.author.bot) return;

    // Mention-guard runs FIRST — before any content check.
    // message.mentions.everyone is set by Discord regardless of Message Content Intent,
    // so the strip fires even when content intent is disabled.
    handleEveryoneMentionGuard(message).catch((err: any) => {
      logger.error(`[MENTION-GUARD] Unhandled error in mention guard: ${err?.message}`);
    });

    // Message Content Intent is not enabled in the Discord Developer Portal.
    // message.content will be empty for every message — commands cannot work.
    if (message.content === "") {
      logger.warn(
        "Message Content Intent is NOT enabled. " +
        "Go to discord.com/developers/applications → your app → Bot → " +
        "Privileged Gateway Intents → enable 'Message Content Intent' and save."
      );
      return;
    }

    // Anti-nuke: scan every non-bot message for link spam and mass mentions
    handleAntiNukeMessage(message).catch((err: any) => {
      logger.error(`Anti-nuke message scan error: ${err?.message}`);
    });

    // ── - prefix — Anti-nuke commands + -role ────────────────────────────────
    if (message.content.startsWith("-")) {
      const anRaw   = message.content.slice(1).trim();
      const anLower = anRaw.toLowerCase();

      // ── -role @user {rolename} — trusted owner only ──────────────────────
      if (anLower.startsWith("role ")) {
        if (!isTrustedOwner(message.author.id)) {
          await message.reply({ embeds: [errorEmbed("You do not have permission to use `-role`.")] });
          return;
        }

        if (!message.guild) {
          await message.reply({ embeds: [errorEmbed("This command can only be used in a server.")] });
          return;
        }

        // Parse: first mention is the target user, rest is role name
        const targetMember = message.mentions.members?.first();
        if (!targetMember) {
          await message.reply({ embeds: [errorEmbed("**Usage:** `-role @user role name`\nMention the user you want to give the role to.")] });
          return;
        }

        // Role name is everything after the mention
        const roleName = anRaw.slice("role ".length).replace(/<@!?\d+>/g, "").trim();
        if (!roleName) {
          await message.reply({ embeds: [errorEmbed("**Usage:** `-role @user role name`\nProvide the role name after the mention.")] });
          return;
        }

        const role = message.guild.roles.cache.find(
          (r) => r.name.toLowerCase() === roleName.toLowerCase()
        );
        if (!role) {
          const close = message.guild.roles.cache
            .filter((r) => r.name.toLowerCase().includes(roleName.toLowerCase()))
            .map((r) => `\`${r.name}\``)
            .slice(0, 5)
            .join(", ");
          const hint = close ? `\n\nDid you mean: ${close}` : "";
          await message.reply({ embeds: [errorEmbed(`No role found with name **${roleName}**.${hint}`)] });
          return;
        }

        try {
          await targetMember.roles.add(role, `Assigned by trusted owner ${message.author.tag} via -role command`);
          logger.info({ giver: message.author.id, receiver: targetMember.id, role: role.name }, "-role command used by trusted owner");
          await message.reply({
            embeds: [{
              color: 0x57f287,
              description: `✅ Gave **${role.name}** to ${targetMember}`,
              footer: { text: `Assigned by ${message.author.tag}` },
            }],
          });
        } catch (err: any) {
          await message.reply({ embeds: [errorEmbed(`Failed to add role: ${err?.message ?? "hierarchy issue — bot's role must be above the target role"}`)] });
        }
        return;
      }

      if (anLower === "help") {
        logger.info({ author: message.author.tag }, "Anti-nuke help requested");
        try {
          await showAntiNukeHelp(message);
        } catch (err: any) {
          logger.error(`Anti-nuke help error: ${err?.message}`);
        }
      } else if (anLower.startsWith("roleing ")) {
        const sub = anRaw.slice("roleing ".length).trim().toLowerCase();
        if (sub.startsWith("exempt")) {
          const subArgs = anRaw.slice("roleing ".length).trim().split(/\s+/).filter(Boolean).slice(1);
          logger.info({ author: message.author.tag, command: anLower.slice(0, 60) }, "-roleing exempt command received");
          try {
            await handleAntiNukeCommand(message, ["roleing-exempt", ...subArgs]);
          } catch (err: any) {
            logger.error(`-roleing exempt error: ${err?.message}`);
          }
        }
      } else if (anLower.startsWith("antinuke")) {
        const args = anRaw.slice("antinuke".length).trim().split(/\s+/).filter(Boolean);
        logger.info({ author: message.author.tag, command: anLower.slice(0, 50) }, "Anti-nuke command received");
        try {
          await handleAntiNukeCommand(message, args);
        } catch (err: any) {
          logger.error(`Anti-nuke command error: ${err?.message}`);
        }
      }
      return;
    }

    if (!message.content.startsWith(",")) return;

    const raw = message.content.slice(1).trim();
    const lower = raw.toLowerCase();

    logger.info({ author: message.author.tag, command: lower.slice(0, 40) }, "Command received");

    const RETRYABLE_CODES = new Set(["ETIMEDOUT", "ECONNRESET", "EPIPE", "ECONNREFUSED", "ENOTFOUND"]);

    for (let attempt = 1; attempt <= 2; attempt++) {
    try {
      if (lower === "ping") {
        await cmdPing(message);
      } else if (lower === "help") {
        await cmdHelp(message);
      } else if (lower === "status" || lower === "reload") {
        // ,reload gives the same status output + re-runs the hierarchy check
        await cmdStatus(message, !!db);
        if (lower === "reload" && message.guild) {
          // Re-run role hierarchy check for this guild so operators can verify
          const botMember = message.guild.members.me;
          if (botMember) {
            const botHighest = botMember.roles.highest;
            const bad: string[] = [];
            for (const [, role] of message.guild.roles.cache) {
              if (role.managed || role.id === message.guild.id) continue;
              if (!hasElevatedPermission(role.permissions)) continue;
              if (role.comparePositionTo(botHighest) >= 0) bad.push(`\`${role.name}\``);
            }
            const hierarchyOk = bad.length === 0;
            await message.channel.send({
              embeds: [
                new EmbedBuilder()
                  .setColor(hierarchyOk ? Colors.Green : Colors.Yellow)
                  .setTitle(hierarchyOk ? "✅ Role Hierarchy OK" : "⚠️ Role Hierarchy Issue")
                  .setDescription(
                    hierarchyOk
                      ? "Bot's role is above all elevated roles — role stripping will work correctly."
                      : `The bot cannot remove these roles (its role is below them):\n${bad.join(", ")}\n\n` +
                        `**Fix:** In Server Settings → Roles, drag the bot's role above the listed roles.`,
                  )
                  .addFields({
                    name: "Mention-Guard Flags",
                    value: (() => {
                      if (!message.guild) return "*no guild*";
                      const guildFlags = flaggedMentionUsers.get(message.guild.id);
                      if (!guildFlags || guildFlags.size === 0) return "*No users currently flagged*";
                      return [...guildFlags.entries()]
                        .map(([uid, d]) => `<@${uid}> — ${d.count} offense(s) since <t:${Math.floor(d.at.getTime() / 1000)}:R>`)
                        .join("\n");
                    })(),
                    inline: false,
                  })
                  .setFooter({ text: "Runtime reload — no restart required" })
                  .setTimestamp(),
              ],
            }).catch(() => null);
          }
        }
      } else if (lower === "logs") {
        await cmdLogs(message);
      } else if (lower === "migrate") {
        await cmdMigrate(message);

      // ── Mention-guard commands ───────────────────────────────────────────────
      } else if (lower === "mentionguard" || lower === "mg") {
        // ,mentionguard — show status: which users are flagged in this guild
        if (!message.guild) {
          await message.reply({ embeds: [errorEmbed("This command must be used in a server.")] });
        } else {
          const guildFlags = flaggedMentionUsers.get(message.guild.id);
          const embed = new EmbedBuilder()
            .setColor(Colors.Orange)
            .setTitle("🛡️ Mention-Guard Status")
            .setDescription(
              "Tracks users who have pinged `@everyone` or `@here`. " +
              "Flagged users have all roles stripped on detection and lose elevated roles " +
              "if they attempt to assign any role to others.",
            );
          if (!guildFlags || guildFlags.size === 0) {
            embed.addFields({ name: "Flagged Users", value: "*No users currently flagged*", inline: false });
          } else {
            const lines = [...guildFlags.entries()].map(
              ([uid, d]) =>
                `• <@${uid}> — **${d.count}** offense(s), first at <t:${Math.floor(d.at.getTime() / 1000)}:f>`,
            );
            embed.addFields({ name: `Flagged Users (${guildFlags.size})`, value: lines.join("\n"), inline: false });
          }
          embed
            .addFields({
              name: "Commands",
              value:
                "`,mentionguard` — this status\n" +
                "`,mentionguard clear @user` — remove a flag (pardon the user)\n" +
                "`,reload` — re-run hierarchy check + show guard state",
              inline: false,
            })
            .setFooter({ text: "Flags reset on bot restart. Role strips are permanent." })
            .setTimestamp();
          await message.reply({ embeds: [embed] });
        }
      } else if (lower.startsWith("mentionguard clear ") || lower.startsWith("mg clear ")) {
        // ,mentionguard clear @user — pardon a flagged user
        if (!message.guild || !message.member) {
          await message.reply({ embeds: [errorEmbed("This command must be used in a server.")] });
        } else if (!message.member.permissions.has(PermissionsBitField.Flags.Administrator) && !isTrustedOwner(message.author.id)) {
          await message.reply({ embeds: [errorEmbed("You need **Administrator** permission to pardon flagged users.")] });
        } else {
          const target = message.mentions.users.first();
          if (!target) {
            await message.reply({ embeds: [errorEmbed("Usage: `,mentionguard clear @user`")] });
          } else if (!isMentionFlagged(message.guild.id, target.id)) {
            await message.reply({
              embeds: [new EmbedBuilder().setColor(Colors.Yellow).setTitle("Not flagged").setDescription(`<@${target.id}> is not currently flagged by mention-guard.`).setTimestamp()],
            });
          } else {
            clearMentionFlag(message.guild.id, target.id);
            logger.info(`[MENTION-GUARD] Flag cleared for ${target.tag} (${target.id}) by ${message.author.tag}`);
            await message.reply({
              embeds: [
                new EmbedBuilder()
                  .setColor(Colors.Green)
                  .setTitle("✅ Flag Cleared")
                  .setDescription(`<@${target.id}> has been pardoned and is no longer flagged by mention-guard.`)
                  .setFooter({ text: `Cleared by ${message.author.tag}` })
                  .setTimestamp(),
              ],
            });
          }
        }

      // ── Database guard — all commands below require DATABASE_URL ────────────
      } else if (!db) {
        await message.reply({
          embeds: [
            errorEmbed(
              "**Database not configured.**\n\n" +
              "Set `DATABASE_URL` in your Railway environment variables and redeploy.\n" +
              "Run `,status` for more details."
            ),
          ],
        });

      // ── Lookup commands ─────────────────────────────────────────────────────
      } else if (lower.startsWith("roles given ")) {
        const args = raw.slice("roles given ".length).trim().split(/\s+/);
        await cmdRolesGiven(message, args);
      } else if (lower.startsWith("roles removed ")) {
        const args = raw.slice("roles removed ".length).trim().split(/\s+/);
        await cmdRolesRemoved(message, args);
      } else if (lower.startsWith("lookup ")) {
        const args = raw.slice("lookup ".length).trim().split(/\s+/);
        await cmdLookup(message, args);
      } else if (lower.startsWith("timeline ")) {
        const args = raw.slice("timeline ".length).trim().split(/\s+/);
        await cmdTimeline(message, args);
      } else if (lower.startsWith("mod ")) {
        const args = raw.slice("mod ".length).trim().split(/\s+/);
        await cmdMod(message, args);
      } else if (lower.startsWith("between ")) {
        const args = raw.slice("between ".length).trim().split(/\s+/);
        await cmdBetween(message, args);
      } else if (lower === "myactivity") {
        await cmdMyActivity(message);

      // ── Server log commands ─────────────────────────────────────────────────
      } else if (lower === "all roles given") {
        await cmdAllRolesGiven(message);
      } else if (lower === "all roles removed") {
        await cmdAllRolesRemoved(message);
      } else if (lower.startsWith("recent")) {
        const args = raw.slice("recent".length).trim().split(/\s+/);
        await cmdRecent(message, args);
      } else if (lower.startsWith("history")) {
        const args = raw.slice("history".length).trim().split(/\s+/);
        await cmdHistory(message, args);
      } else if (lower.startsWith("active")) {
        const args = raw.slice("active".length).trim().split(/\s+/);
        await cmdActive(message, args);

      // ── Search & filter commands ────────────────────────────────────────────
      } else if (lower.startsWith("search ")) {
        const args = raw.slice("search ".length).trim().split(/\s+/);
        await cmdSearch(message, args);
      } else if (lower.startsWith("find ")) {
        const args = raw.slice("find ".length).trim().split(/\s+/);
        await cmdFind(message, args);
      } else if (lower.startsWith("whohas ")) {
        const args = raw.slice("whohas ".length).trim().split(/\s+/);
        await cmdWhoHas(message, args);
      } else if (lower.startsWith("undone")) {
        const args = raw.slice("undone".length).trim().split(/\s+/);
        await cmdUndone(message, args);
      } else if (lower === "audit") {
        await cmdAudit(message);

      // ── Stats & export commands ─────────────────────────────────────────────
      } else if (lower === "server stats") {
        await cmdServerStats(message);
      } else if (lower.startsWith("top")) {
        const args = raw.slice("top".length).trim().split(/\s+/);
        await cmdTop(message, args);
      } else if (lower === "export") {
        await cmdExport(message);

      // ── Destructive utility commands ────────────────────────────────────────
      } else if (lower === "delete all channels" || lower === "delete all channels confirm") {
        await cmdDeleteAllChannels(message, lower.endsWith("confirm"));
      }
      // Unknown commands are silently ignored to avoid noise
      break; // success — exit retry loop
    } catch (err: any) {
      const code = err?.cause?.code ?? err?.code;
      if (RETRYABLE_CODES.has(code) && attempt === 1) {
        logger.warn({ code, command: lower.slice(0, 40) }, "DB connection error — retrying command once...");
        await new Promise((r) => setTimeout(r, 400));
        continue; // retry
      }
      logger.error({
        err: err?.message ?? String(err),
        cause: err?.cause?.message ?? err?.cause,
        code,
        stack: err?.stack,
      }, "Command error");
      pushErrorLog(lower, err);
      const clean = friendlyError(err);
      await message
        .reply({
          embeds: [
            errorEmbed(`${clean}\n\nIf this keeps happening, contact a server admin.`),
          ],
        })
        .catch((e: any) => logger.error({ e: e?.message }, "Failed to send error reply — missing Send Messages permission?"));
      break; // error handled — exit retry loop
    }
    } // end retry loop
  });

  // ── Login ────────────────────────────────────────────────────────────────────
  try {
    await client.login(token);
  } catch (err: any) {
    if (err?.message?.includes("disallowed intents")) {
      logger.error(
        "Bot failed to start: Privileged intents not enabled. " +
        "Go to discord.com/developers/applications → your bot → Bot tab → " +
        "Privileged Gateway Intents → enable 'Server Members Intent' and 'Message Content Intent'."
      );
    } else if (
      err?.message?.includes("TOKEN_INVALID") ||
      err?.message?.includes("invalid token") ||
      err?.message?.includes("An invalid token")
    ) {
      logger.error(
        `Bot failed to start: Discord rejected the token. ` +
        `Token length was ${token.length}. ` +
        `Make sure DISCORD_BOT_TOKEN is the bot token from the Bot tab — not the client secret. ` +
        `Full error: ${err?.message}`
      );
    } else {
      logger.error({ err: err?.message }, "Bot failed to start");
    }
  }
}
