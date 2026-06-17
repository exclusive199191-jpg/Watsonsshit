import {
  Client,
  GatewayIntentBits,
  Events,
  AuditLogEvent,
  PermissionsBitField,
  EmbedBuilder,
  Colors,
  type Message,
  type GuildMember,
} from "discord.js";
import { db, pool } from "@workspace/db";
import { roleAssignmentsTable } from "@workspace/db";
import { eq, and, desc, sql } from "drizzle-orm";
import { logger } from "./lib/logger";

// ── Permission detection ───────────────────────────────────────────────────────

const ELEVATED_PERMISSIONS: bigint[] = [
  PermissionsBitField.Flags.Administrator,
  PermissionsBitField.Flags.BanMembers,
  PermissionsBitField.Flags.KickMembers,
  PermissionsBitField.Flags.ModerateMembers,
  PermissionsBitField.Flags.ManageRoles,
  PermissionsBitField.Flags.ManageGuild,
  PermissionsBitField.Flags.ManageChannels,
  PermissionsBitField.Flags.ManageMessages,
  PermissionsBitField.Flags.ManageNicknames,
  PermissionsBitField.Flags.ManageWebhooks,
  PermissionsBitField.Flags.ManageThreads,
];

const ELEVATED_PERM_NAMES: Record<string, string> = {
  [String(PermissionsBitField.Flags.Administrator)]: "Administrator",
  [String(PermissionsBitField.Flags.BanMembers)]: "Ban Members",
  [String(PermissionsBitField.Flags.KickMembers)]: "Kick Members",
  [String(PermissionsBitField.Flags.ModerateMembers)]: "Timeout Members",
  [String(PermissionsBitField.Flags.ManageRoles)]: "Manage Roles",
  [String(PermissionsBitField.Flags.ManageGuild)]: "Manage Guild",
  [String(PermissionsBitField.Flags.ManageChannels)]: "Manage Channels",
  [String(PermissionsBitField.Flags.ManageMessages)]: "Manage Messages",
  [String(PermissionsBitField.Flags.ManageNicknames)]: "Manage Nicknames",
  [String(PermissionsBitField.Flags.ManageWebhooks)]: "Manage Webhooks",
  [String(PermissionsBitField.Flags.ManageThreads)]: "Manage Threads",
};

function hasElevatedPermission(permissions: PermissionsBitField): boolean {
  return ELEVATED_PERMISSIONS.some((perm) => permissions.has(perm));
}

function getElevatedPermNames(permissions: PermissionsBitField): string[] {
  return ELEVATED_PERMISSIONS
    .filter((perm) => permissions.has(perm))
    .map((perm) => ELEVATED_PERM_NAMES[String(perm)] ?? "Unknown");
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

/**
 * Convert a raw drizzle/pg error into a short, user-safe string.
 * Drizzle wraps errors as "Failed query: <SQL>\nparams: <…>\n<actual PG message>".
 * We strip the SQL noise and surface only the meaningful line.
 */
function friendlyError(err: any): string {
  const raw: string = err?.message ?? String(err);

  // drizzle-orm error: pull out everything after the last blank line (the PG message)
  if (raw.startsWith("Failed query:")) {
    // Lines after the params line contain the actual PG error
    const lines = raw.split("\n").map((l: string) => l.trim()).filter(Boolean);
    // Skip lines that are the SQL or the params line
    const pgLine = lines.find(
      (l: string) => !l.startsWith("Failed query:") && !l.startsWith("params:") && !l.startsWith("select") && !l.startsWith("insert") && !l.startsWith("update") && !l.startsWith("delete")
    );
    if (pgLine) return pgLine;
  }

  // Fallback: return first line only (avoids multi-line SQL dumps)
  return raw.split("\n")[0] ?? "An unexpected error occurred.";
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

async function cmdHelp(message: Message) {
  const embed = new EmbedBuilder()
    .setColor(0x5865f2)
    .setTitle("Role Audit Bot — Help")
    .setDescription("Tracks every time an elevated role is given or removed, so you always know who did what.")
    .addFields(
      {
        name: "📋 Commands",
        value: [
          "`,ping` — Check if bot is online",
          "`,help` — Show this menu",
          "`,roles given <@user>` — Roles a mod has **given** to others",
          "`,roles removed <@user>` — Roles a mod has **removed** from others",
          "`,all roles given` — Full server log of role assignments",
          "`,all roles removed` — Full server log of role removals",
          "`,recent [n]` — Last N events, both given and removed (default 10, max 25)",
          "`,server stats` — Server-wide role moderation summary",
        ].join("\n"),
      },
      {
        name: "🔍 What counts as elevated?",
        value:
          "`Administrator` • `Ban Members` • `Kick Members` • `Timeout Members`\n" +
          "`Manage Roles` • `Manage Guild` • `Manage Channels` • `Manage Messages`\n" +
          "`Manage Nicknames` • `Manage Webhooks` • `Manage Threads`",
      },
      {
        name: "⚠️ Note",
        value: "Only events that happen **after the bot joined** are tracked. Historical data is not available.",
      },
    )
    .setFooter({ text: "Prefix: , (comma)" })
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
    records = await db
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
    const all = await db
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
    } else {
      await message.channel.send({ embeds: [embed] });
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
    records = await db
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
    const all = await db
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

  const records = await db
    .select()
    .from(roleAssignmentsTable)
    .where(and(
      eq(roleAssignmentsTable.guildId, message.guild.id),
      eq(roleAssignmentsTable.action, "assigned"),
    ))
    .orderBy(desc(roleAssignmentsTable.assignedAt))
    .limit(25);

  const total = await db
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

  const records = await db
    .select()
    .from(roleAssignmentsTable)
    .where(and(
      eq(roleAssignmentsTable.guildId, message.guild.id),
      eq(roleAssignmentsTable.action, "removed"),
    ))
    .orderBy(desc(roleAssignmentsTable.assignedAt))
    .limit(25);

  const total = await db
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
  const n = isNaN(rawN) || rawN < 1 ? 10 : Math.min(rawN, 25);

  const records = await db
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
    db.select({ count: sql<number>`count(*)` })
      .from(roleAssignmentsTable)
      .where(and(eq(roleAssignmentsTable.guildId, guildId), eq(roleAssignmentsTable.action, "assigned"))),

    db.select({ count: sql<number>`count(*)` })
      .from(roleAssignmentsTable)
      .where(and(eq(roleAssignmentsTable.guildId, guildId), eq(roleAssignmentsTable.action, "removed"))),

    db.select({
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

    db.select({
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
  await db.insert(roleAssignmentsTable).values({
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

// ── Bot startup ────────────────────────────────────────────────────────────────

export async function startBot() {
  const token = process.env.DISCORD_BOT_TOKEN;
  if (!token) {
    logger.warn("DISCORD_BOT_TOKEN not set — Discord bot will not start.");
    return;
  }

  const client = new Client({
    intents: [
      GatewayIntentBits.Guilds,
      GatewayIntentBits.GuildMembers,    // Privileged — enable in Dev Portal
      GatewayIntentBits.GuildMessages,
      GatewayIntentBits.MessageContent,  // Privileged — enable in Dev Portal
      GatewayIntentBits.GuildModeration,
    ],
  });

  client.once(Events.ClientReady, () => {
    logger.info({ tag: client.user?.tag }, "Discord bot logged in and ready");
  });

  // ── Track role assignments and removals ──────────────────────────────────────
  client.on(Events.GuildMemberUpdate, async (oldMember, newMember) => {
    try {
      const guild = newMember.guild;

      const addedRoles = newMember.roles.cache.filter((r) => !oldMember.roles.cache.has(r.id));
      const removedRoles = oldMember.roles.cache.filter((r) => !newMember.roles.cache.has(r.id));

      const elevatedAdded = addedRoles.filter((r) => hasElevatedPermission(r.permissions));
      const elevatedRemoved = removedRoles.filter((r) => hasElevatedPermission(r.permissions));

      if (elevatedAdded.size === 0 && elevatedRemoved.size === 0) return;

      // Wait for Discord audit log to populate
      await new Promise((r) => setTimeout(r, 1500));

      const auditLogs = await guild.fetchAuditLogs({
        limit: 5,
        type: AuditLogEvent.MemberRoleUpdate,
      });

      const entry = auditLogs.entries.find(
        (e) => (e.target as GuildMember | null)?.id === newMember.id
      );

      if (!entry?.executor) {
        logger.warn({ targetId: newMember.id }, "Role change detected but no audit log entry — bot may lack View Audit Log permission");
        return;
      }

      const executor = entry.executor;
      const executorTag = executor.tag ?? executor.username;
      const targetTag = newMember.user.tag ?? newMember.user.username;

      for (const [, role] of elevatedAdded) {
        await recordRoleEvent(guild, executor.id, executorTag, newMember.id, targetTag, role.id, role.name, "assigned");
      }

      for (const [, role] of elevatedRemoved) {
        await recordRoleEvent(guild, executor.id, executorTag, newMember.id, targetTag, role.id, role.name, "removed");
      }
    } catch (err) {
      logger.error({ err }, "Error handling GuildMemberUpdate");
    }
  });

  // ── Command router ───────────────────────────────────────────────────────────
  client.on(Events.MessageCreate, async (message) => {
    if (message.author.bot) return;

    if (message.content === "") {
      logger.warn("Empty message content — ensure 'Message Content Intent' is enabled in the Discord Developer Portal.");
      return;
    }

    if (!message.content.startsWith(",")) return;

    const raw = message.content.slice(1).trim();
    const lower = raw.toLowerCase();

    logger.info({ author: message.author.tag, command: lower.slice(0, 40) }, "Command received");

    try {
      if (lower === "ping") {
        await cmdPing(message);
      } else if (lower === "help") {
        await cmdHelp(message);
      } else if (lower.startsWith("roles given ")) {
        const args = raw.slice("roles given ".length).trim().split(/\s+/);
        await cmdRolesGiven(message, args);
      } else if (lower.startsWith("roles removed ")) {
        const args = raw.slice("roles removed ".length).trim().split(/\s+/);
        await cmdRolesRemoved(message, args);
      } else if (lower === "all roles given") {
        await cmdAllRolesGiven(message);
      } else if (lower === "all roles removed") {
        await cmdAllRolesRemoved(message);
      } else if (lower.startsWith("recent")) {
        const args = raw.slice("recent".length).trim().split(/\s+/);
        await cmdRecent(message, args);
      } else if (lower === "server stats") {
        await cmdServerStats(message);
      }
      // Unknown commands are silently ignored to avoid noise
    } catch (err: any) {
      logger.error({ err: err?.message ?? String(err), stack: err?.stack }, "Command error");
      const clean = friendlyError(err);
      await message
        .reply({
          embeds: [
            errorEmbed(`${clean}\n\nIf this keeps happening, contact a server admin.`),
          ],
        })
        .catch((e: any) => logger.error({ e: e?.message }, "Failed to send error reply — missing Send Messages permission?"));
    }
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
    } else if (err?.message?.includes("TOKEN_INVALID")) {
      logger.error("Bot failed to start: Invalid token. Check DISCORD_BOT_TOKEN.");
    } else {
      logger.error({ err: err?.message }, "Bot failed to start");
    }
  }
}
