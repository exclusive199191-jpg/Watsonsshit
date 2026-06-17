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
    .setDescription("Tracks every elevated role assignment and removal. Prefix: `,` (comma)")
    .addFields(
      {
        name: "🔎 Lookup Commands",
        value: [
          "`,roles given <@user>` — Roles a mod **gave** to others",
          "`,roles removed <@user>` — Roles a mod **removed** from others",
          "`,lookup <@user>` — Who gave/removed elevated roles **to** a user",
          "`,timeline <@user>` — Chronological role history for a user",
          "`,mod <@user>` — Full moderator profile & stats",
          "`,between <@user1> <@user2>` — All role interactions between two users",
          "`,myactivity` — Your own role moderation stats",
        ].join("\n"),
      },
      {
        name: "📋 Server Log Commands",
        value: [
          "`,all roles given` — Latest 25 role assignments",
          "`,all roles removed` — Latest 25 role removals",
          "`,recent [n]` — Last N events, given + removed (default 10, max 50)",
          "`,history [days]` — Activity in the last N days (default 7)",
          "`,active [days]` — Most active mods in the last N days (default 7)",
        ].join("\n"),
      },
      {
        name: "🔍 Search & Filter",
        value: [
          "`,search <rolename>` — All events for a specific role",
          "`,find <name>` — Search across all usernames/tags",
          "`,whohas <rolename>` — Who currently holds a role with elevated perms",
          "`,undone [hours]` — Roles given then removed within N hours (default 24)",
          "`,audit` — Detect suspicious rapid role activity",
        ].join("\n"),
      },
      {
        name: "📊 Stats & Export",
        value: [
          "`,server stats` — Server-wide role moderation summary",
          "`,top [n]` — Top N most active moderators (default 10)",
          "`,export` — Download the full role log as a text file",
        ].join("\n"),
      },
      {
        name: "⚙️ Utility",
        value: [
          "`,ping` — Check if bot is online",
          "`,help` — Show this menu",
        ].join("\n"),
      },
      {
        name: "🔐 What counts as elevated?",
        value:
          "`Administrator` • `Ban Members` • `Kick Members` • `Timeout Members`\n" +
          "`Manage Roles` • `Manage Guild` • `Manage Channels` • `Manage Messages`\n" +
          "`Manage Nicknames` • `Manage Webhooks` • `Manage Threads`",
      },
      {
        name: "⚠️ Note",
        value: "Only events after the bot joined are tracked. Historical data is not available.",
      },
    )
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
    records = await db.select().from(roleAssignmentsTable)
      .where(and(eq(roleAssignmentsTable.guildId, message.guild.id), eq(roleAssignmentsTable.targetId, targetId)))
      .orderBy(desc(roleAssignmentsTable.assignedAt));
  } else {
    const nameSearch = userArg.toLowerCase();
    const all = await db.select().from(roleAssignmentsTable)
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
    records = await db.select().from(roleAssignmentsTable)
      .where(and(eq(roleAssignmentsTable.guildId, message.guild.id), eq(roleAssignmentsTable.targetId, targetId)))
      .orderBy(roleAssignmentsTable.assignedAt);
  } else {
    const nameSearch = userArg.toLowerCase();
    const all = await db.select().from(roleAssignmentsTable)
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
    records = await db.select().from(roleAssignmentsTable)
      .where(and(eq(roleAssignmentsTable.guildId, message.guild.id), eq(roleAssignmentsTable.executorId, executorId)))
      .orderBy(desc(roleAssignmentsTable.assignedAt));
  } else {
    const nameSearch = userArg.toLowerCase();
    const all = await db.select().from(roleAssignmentsTable)
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
  const all = await db.select().from(roleAssignmentsTable)
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
    db.select().from(roleAssignmentsTable)
      .where(and(eq(roleAssignmentsTable.guildId, message.guild.id), eq(roleAssignmentsTable.executorId, userId)))
      .orderBy(desc(roleAssignmentsTable.assignedAt)),
    db.select().from(roleAssignmentsTable)
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
  const all = await db.select().from(roleAssignmentsTable)
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
  const all = await db.select().from(roleAssignmentsTable)
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
  const all = await db.select().from(roleAssignmentsTable)
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
  const all = await db.select().from(roleAssignmentsTable)
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
  const all = await db.select().from(roleAssignmentsTable)
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
  const all = await db.select().from(roleAssignmentsTable)
    .where(and(eq(roleAssignmentsTable.guildId, message.guild.id), eq(roleAssignmentsTable.action, "assigned")))
    .orderBy(desc(roleAssignmentsTable.assignedAt));

  const WINDOW_MS = 10 * 60 * 1000;
  const THRESHOLD = 5;

  const flagged: string[] = [];
  const modGroups = new Map<string, typeof all>();
  for (const r of all) {
    if (!modGroups.has(r.executorId)) modGroups.set(r.executorId, []);
    modGroups.get(r.executorId)!.push(r);
  }
  for (const [, events] of modGroups) {
    for (let i = 0; i < events.length; i++) {
      const windowEnd = new Date(events[i].assignedAt).getTime();
      const windowStart = windowEnd - WINDOW_MS;
      const inWindow = events.filter((e) => {
        const t = new Date(e.assignedAt).getTime();
        return t >= windowStart && t <= windowEnd;
      });
      if (inWindow.length >= THRESHOLD) {
        const execTag = inWindow[0].executorTag;
        const targets = [...new Set(inWindow.map((e) => e.targetTag))];
        const entry = `⚠️ **${execTag}** assigned **${inWindow.length}** roles in 10 minutes (to: ${targets.slice(0, 3).map((t) => `**${t}**`).join(", ")}${targets.length > 3 ? ` and ${targets.length - 3} more` : ""}) — ${ts(new Date(inWindow[0].assignedAt))}`;
        if (!flagged.includes(entry)) flagged.push(entry);
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

  const all = await db.select().from(roleAssignmentsTable)
    .where(eq(roleAssignmentsTable.guildId, message.guild.id))
    .orderBy(roleAssignmentsTable.assignedAt);

  const bounced: string[] = [];
  const assignments = all.filter((r) => r.action === "assigned");
  for (const assign of assignments) {
    const reversal = all.find((r) =>
      r.action === "removed" &&
      r.targetId === assign.targetId &&
      r.roleId === assign.roleId &&
      new Date(r.assignedAt).getTime() > new Date(assign.assignedAt).getTime() &&
      new Date(r.assignedAt).getTime() - new Date(assign.assignedAt).getTime() <= windowMs
    );
    if (reversal) {
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
  const records = await db.select().from(roleAssignmentsTable)
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
