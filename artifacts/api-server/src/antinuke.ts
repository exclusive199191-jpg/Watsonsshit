import {
  Events,
  AuditLogEvent,
  EmbedBuilder,
  Colors,
  PermissionsBitField,
  type Client,
  type Guild,
  type User,
  type PartialUser,
  type Message,
  type TextChannel,
  type GuildAuditLogsEntry,
} from "discord.js";
import { db } from "@workspace/db";
import { antinukeConfigTable } from "@workspace/db";
import { eq } from "drizzle-orm";
import { logger } from "./lib/logger";

type AnyUser = User | PartialUser;

// ── Rate tracker ────────────────────────────────────────────────────────────────

interface RateWindow { count: number; windowStart: number; }
const tracker = new Map<string, Map<string, Map<string, RateWindow>>>();

function tick(guildId: string, userId: string, action: string, windowMs: number): number {
  let gMap = tracker.get(guildId);
  if (!gMap) { gMap = new Map(); tracker.set(guildId, gMap); }
  let uMap = gMap.get(userId);
  if (!uMap) { uMap = new Map(); gMap.set(userId, uMap); }
  const now = Date.now();
  const w = uMap.get(action);
  if (!w || now - w.windowStart > windowMs) {
    uMap.set(action, { count: 1, windowStart: now });
    return 1;
  }
  w.count++;
  return w.count;
}

function resetRate(guildId: string, userId: string, action: string): void {
  tracker.get(guildId)?.get(userId)?.delete(action);
}

// ── Config cache ────────────────────────────────────────────────────────────────

interface AntiNukeConfig {
  enabled: boolean;
  logChannelId: string | null;
  punishment: "ban" | "kick" | "strip";
  whitelist: string[];
  banThreshold: number;
  kickThreshold: number;
  channelCreateThreshold: number;
  channelDeleteThreshold: number;
  channelRenameThreshold: number;
  roleDeleteThreshold: number;
  roleCreateThreshold: number;
  mentionThreshold: number;
  linkThreshold: number;
  webhookThreshold: number;
  timeWindowMs: number;
}

const configCache = new Map<string, { config: AntiNukeConfig; fetchedAt: number }>();
const CONFIG_TTL_MS = 30_000;

function invalidateCache(guildId: string): void {
  configCache.delete(guildId);
}

async function getConfig(guildId: string): Promise<AntiNukeConfig | null> {
  if (!db) return null;
  const cached = configCache.get(guildId);
  if (cached && Date.now() - cached.fetchedAt < CONFIG_TTL_MS) return cached.config;

  const rows = await db.select().from(antinukeConfigTable).where(eq(antinukeConfigTable.guildId, guildId)).limit(1);
  if (rows.length === 0) return null;

  const r = rows[0];
  let whitelist: string[] = [];
  try { whitelist = JSON.parse(r.whitelist ?? "[]"); } catch { whitelist = []; }

  const config: AntiNukeConfig = {
    enabled: r.enabled,
    logChannelId: r.logChannelId ?? null,
    punishment: (r.punishment as "ban" | "kick" | "strip") ?? "ban",
    whitelist,
    banThreshold: r.banThreshold,
    kickThreshold: r.kickThreshold,
    channelCreateThreshold: r.channelCreateThreshold,
    channelDeleteThreshold: r.channelDeleteThreshold,
    channelRenameThreshold: r.channelRenameThreshold,
    roleDeleteThreshold: r.roleDeleteThreshold,
    roleCreateThreshold: r.roleCreateThreshold,
    mentionThreshold: r.mentionThreshold,
    linkThreshold: r.linkThreshold,
    webhookThreshold: r.webhookThreshold,
    timeWindowMs: r.timeWindowMs,
  };

  configCache.set(guildId, { config, fetchedAt: Date.now() });
  return config;
}

type ConfigPatch = Partial<Omit<typeof antinukeConfigTable.$inferInsert, "guildId">>;

async function upsertConfig(guildId: string, patch: ConfigPatch): Promise<void> {
  if (!db) throw new Error("Database not configured");
  await db
    .insert(antinukeConfigTable)
    .values({ guildId, ...patch })
    .onConflictDoUpdate({
      target: antinukeConfigTable.guildId,
      set: { ...patch, updatedAt: new Date() },
    });
  invalidateCache(guildId);
}

// ── Punishment engine ───────────────────────────────────────────────────────────

type PunishResult =
  | "banned"
  | "kicked"
  | "stripped"
  | "skipped_owner"
  | "skipped_bot"
  | "not_found"
  | "hierarchy_error";

const ELEVATED = [
  PermissionsBitField.Flags.Administrator,
  PermissionsBitField.Flags.BanMembers,
  PermissionsBitField.Flags.KickMembers,
  PermissionsBitField.Flags.ManageChannels,
  PermissionsBitField.Flags.ManageRoles,
  PermissionsBitField.Flags.ManageGuild,
];

async function executePunishment(
  guild: Guild,
  executorId: string,
  config: AntiNukeConfig,
  reason: string,
): Promise<PunishResult> {
  if (executorId === guild.ownerId) return "skipped_owner";

  const member = await guild.members.fetch(executorId).catch(() => null);

  if (!member) {
    if (config.punishment === "ban") {
      await guild.bans.create(executorId, { reason }).catch(() => null);
      return "banned";
    }
    return "not_found";
  }

  if (member.user.bot) return "skipped_bot";

  const botMember = guild.members.me;
  if (botMember && member.roles.highest.comparePositionTo(botMember.roles.highest) >= 0) {
    return "hierarchy_error";
  }

  switch (config.punishment) {
    case "ban":
      await guild.bans.create(executorId, { reason });
      return "banned";
    case "kick":
      await member.kick(reason);
      return "kicked";
    case "strip": {
      const adminRoles = member.roles.cache.filter(r => ELEVATED.some(p => r.permissions.has(p)));
      if (adminRoles.size > 0) await member.roles.remove(adminRoles, reason);
      return "stripped";
    }
    default:
      return "hierarchy_error";
  }
}

const PUNISH_LABEL: Record<PunishResult, string> = {
  banned:          "User banned from the server",
  kicked:          "User kicked from the server",
  stripped:        "Elevated roles removed",
  skipped_owner:   "No action — user is the server owner",
  skipped_bot:     "No action — user is a bot",
  not_found:       "User not in server — ban record created",
  hierarchy_error: "No action — bot role is below this user's highest role",
};

// ── Violation handler ───────────────────────────────────────────────────────────

let _client: Client | null = null;

async function handleViolation(
  guild: Guild,
  executor: AnyUser,
  config: AntiNukeConfig,
  actionKey: string,
  violationLabel: string,
  count: number,
  threshold: number,
): Promise<void> {
  resetRate(guild.id, executor.id, actionKey);

  const executorLabel = (executor as User).tag ?? (executor as PartialUser).username ?? executor.id;
  const reason = `Anti-Nuke: ${violationLabel} — ${count} actions in ${config.timeWindowMs / 1000}s (limit: ${threshold})`;
  let result: PunishResult = "hierarchy_error";
  try {
    result = await executePunishment(guild, executor.id, config, reason);
  } catch (err: any) {
    logger.error(`Anti-nuke punishment error: ${err?.message}`);
  }

  logger.warn(
    `Anti-nuke triggered | guild: ${guild.id} | executor: ${executorLabel} (${executor.id}) | ` +
    `violation: ${violationLabel} | count: ${count}/${threshold} | result: ${result}`
  );

  if (!config.logChannelId) return;
  const channel = guild.channels.cache.get(config.logChannelId);
  if (!channel || !("send" in channel)) return;

  const embed = new EmbedBuilder()
    .setColor(Colors.Red)
    .setTitle("SECURITY ALERT — Anti-Nuke Triggered")
    .setDescription(
      `A protection threshold was exceeded in **${guild.name}**.\n` +
      `The system has responded automatically.`
    )
    .addFields(
      { name: "Violation",       value: violationLabel,                                          inline: true },
      { name: "Server",          value: guild.name,                                              inline: true },
      { name: "\u200b",          value: "\u200b",                                                inline: true },
      { name: "Executor",        value: `${executorLabel}\n\`${executor.id}\``,                  inline: true },
      { name: "Count / Limit",   value: `${count} / ${threshold} in ${config.timeWindowMs / 1000}s`, inline: true },
      { name: "Response",        value: PUNISH_LABEL[result],                                    inline: true },
    )
    .setFooter({ text: "Anti-Nuke System" })
    .setTimestamp();

  await (channel as TextChannel).send({ embeds: [embed] }).catch(() => null);
}

// ── Audit log event handler ─────────────────────────────────────────────────────

async function onAuditLogEntry(entry: GuildAuditLogsEntry, guild: Guild): Promise<void> {
  if (!entry.executor) return;

  const config = await getConfig(guild.id);
  if (!config?.enabled) return;

  const executorId = entry.executor.id;
  if (config.whitelist.includes(executorId)) return;
  if (_client?.user && executorId === _client.user.id) return;

  const w = config.timeWindowMs;

  switch (entry.action) {
    case AuditLogEvent.MemberBanAdd: {
      const n = tick(guild.id, executorId, "ban", w);
      if (n >= config.banThreshold)
        await handleViolation(guild, entry.executor, config, "ban", "Mass Ban", n, config.banThreshold);
      break;
    }
    case AuditLogEvent.MemberKick: {
      const n = tick(guild.id, executorId, "kick", w);
      if (n >= config.kickThreshold)
        await handleViolation(guild, entry.executor, config, "kick", "Mass Kick", n, config.kickThreshold);
      break;
    }
    case AuditLogEvent.ChannelCreate: {
      const n = tick(guild.id, executorId, "chCreate", w);
      if (n >= config.channelCreateThreshold)
        await handleViolation(guild, entry.executor, config, "chCreate", "Mass Channel Create", n, config.channelCreateThreshold);
      break;
    }
    case AuditLogEvent.ChannelDelete: {
      const n = tick(guild.id, executorId, "chDelete", w);
      if (n >= config.channelDeleteThreshold)
        await handleViolation(guild, entry.executor, config, "chDelete", "Mass Channel Delete", n, config.channelDeleteThreshold);
      break;
    }
    case AuditLogEvent.ChannelUpdate: {
      const changes = entry.changes as ReadonlyArray<{ key: string }>;
      if (!changes.some(c => c.key === "name")) break;
      const n = tick(guild.id, executorId, "chRename", w);
      if (n >= config.channelRenameThreshold)
        await handleViolation(guild, entry.executor, config, "chRename", "Mass Channel Rename", n, config.channelRenameThreshold);
      break;
    }
    case AuditLogEvent.RoleDelete: {
      const n = tick(guild.id, executorId, "roleDelete", w);
      if (n >= config.roleDeleteThreshold)
        await handleViolation(guild, entry.executor, config, "roleDelete", "Mass Role Delete", n, config.roleDeleteThreshold);
      break;
    }
    case AuditLogEvent.RoleCreate: {
      const n = tick(guild.id, executorId, "roleCreate", w);
      if (n >= config.roleCreateThreshold)
        await handleViolation(guild, entry.executor, config, "roleCreate", "Mass Role Create", n, config.roleCreateThreshold);
      break;
    }
    case AuditLogEvent.WebhookCreate: {
      const n = tick(guild.id, executorId, "webhook", w);
      if (n >= config.webhookThreshold)
        await handleViolation(guild, entry.executor, config, "webhook", "Webhook Creation Spam", n, config.webhookThreshold);
      break;
    }
    case AuditLogEvent.MemberRoleUpdate: {
      const changes = entry.changes as ReadonlyArray<{ key: string; new?: unknown }>;
      const hasGrant = changes.some(c => c.key === "$add" && Array.isArray(c.new) && (c.new as unknown[]).length > 0);
      if (!hasGrant) break;
      const n = tick(guild.id, executorId, "roleGrant", w);
      if (n >= 5)
        await handleViolation(guild, entry.executor, config, "roleGrant", "Mass Role Grant", n, 5);
      break;
    }
  }
}

// ── Message handler (link spam + mass mention) ──────────────────────────────────

const URL_REGEX = /https?:\/\/[^\s<>]+/gi;

export async function handleAntiNukeMessage(message: Message): Promise<void> {
  if (!message.guild || message.author.bot) return;

  const config = await getConfig(message.guild.id);
  if (!config?.enabled) return;
  if (config.whitelist.includes(message.author.id)) return;

  const guild = message.guild;
  const executor = message.author;
  const w = config.timeWindowMs;

  // Mass mention / @everyone / @here
  const uniqueMentions = message.mentions.users.size + message.mentions.roles.size;
  if (message.mentions.everyone || uniqueMentions >= config.mentionThreshold) {
    const count = message.mentions.everyone ? config.mentionThreshold : uniqueMentions;
    await message.delete().catch(() => null);
    await handleViolation(guild, executor, config, "mention", "Mass Mention / @everyone", count, config.mentionThreshold);
    return;
  }

  // Link spam
  const links = message.content.match(URL_REGEX);
  if (links) {
    const n = tick(guild.id, executor.id, "link", w);
    if (n >= config.linkThreshold) {
      await message.delete().catch(() => null);
      await handleViolation(guild, executor, config, "link", "Link Spam", n, config.linkThreshold);
    }
  }
}

// ── Embed helpers ───────────────────────────────────────────────────────────────

function anEmbed(color: number, title: string, description: string): EmbedBuilder {
  return new EmbedBuilder()
    .setColor(color)
    .setTitle(title)
    .setDescription(description)
    .setFooter({ text: "Anti-Nuke System" })
    .setTimestamp();
}

const okEmbed  = (t: string, d: string) => anEmbed(Colors.Green,  t, d);
const infoEmbed = (t: string, d: string) => anEmbed(Colors.Blurple, t, d);
const errEmbed  = (d: string)            => anEmbed(Colors.Red, "Error", d);

function isAdmin(message: Message): boolean {
  if (!message.guild || !message.member) return false;
  return (
    message.author.id === message.guild.ownerId ||
    message.member.permissions.has(PermissionsBitField.Flags.Administrator)
  );
}

// ── Sub-commands ────────────────────────────────────────────────────────────────

async function cmdEnable(message: Message): Promise<void> {
  if (!message.guild) return;
  if (!db) { await message.reply({ embeds: [errEmbed("Database not configured.")] }); return; }
  await upsertConfig(message.guild.id, { enabled: true });
  await message.reply({ embeds: [okEmbed(
    "Anti-Nuke Enabled",
    "The anti-nuke system is now **active**. All protection thresholds are being monitored in real time.\n\n" +
    "Use `-antinuke set logchannel #channel` to receive alerts when violations are detected."
  )] });
}

async function cmdDisable(message: Message): Promise<void> {
  if (!message.guild) return;
  if (!db) { await message.reply({ embeds: [errEmbed("Database not configured.")] }); return; }
  await upsertConfig(message.guild.id, { enabled: false });
  await message.reply({ embeds: [infoEmbed(
    "Anti-Nuke Disabled",
    "The anti-nuke system has been **deactivated**. No automatic protections are running."
  )] });
}

async function cmdStatus(message: Message): Promise<void> {
  if (!message.guild) return;
  if (!db) { await message.reply({ embeds: [errEmbed("Database not configured.")] }); return; }

  const config = await getConfig(message.guild.id);
  if (!config) {
    await message.reply({ embeds: [infoEmbed(
      "Anti-Nuke — Not Configured",
      "No configuration found for this server.\nRun `-antinuke enable` to activate with default settings."
    )] });
    return;
  }

  const logChannel = config.logChannelId ? `<#${config.logChannelId}>` : "Not configured";
  const whitelist  = config.whitelist.length > 0
    ? config.whitelist.map(id => `<@${id}>`).join(", ")
    : "None";

  const embed = new EmbedBuilder()
    .setColor(config.enabled ? Colors.Green : 0x5c5c5c)
    .setTitle("Anti-Nuke — Configuration")
    .setDescription(`**Status:** ${config.enabled ? "Active" : "Inactive"}`)
    .addFields(
      { name: "Punishment",  value: config.punishment.charAt(0).toUpperCase() + config.punishment.slice(1), inline: true },
      { name: "Log Channel", value: logChannel,                                                             inline: true },
      { name: "Time Window", value: `${config.timeWindowMs / 1000}s`,                                      inline: true },
      { name: "Thresholds", value: [
          `Mass Ban          ${config.banThreshold}`,
          `Mass Kick         ${config.kickThreshold}`,
          `Channel Create    ${config.channelCreateThreshold}`,
          `Channel Delete    ${config.channelDeleteThreshold}`,
          `Channel Rename    ${config.channelRenameThreshold}`,
          `Role Delete       ${config.roleDeleteThreshold}`,
          `Role Create       ${config.roleCreateThreshold}`,
          `Mass Mention      ${config.mentionThreshold}`,
          `Link Spam         ${config.linkThreshold}`,
          `Webhook Create    ${config.webhookThreshold}`,
        ].map(l => `\`${l}\``).join("\n"),
        inline: false,
      },
      { name: "Whitelist", value: whitelist, inline: false },
    )
    .setFooter({ text: "Anti-Nuke System" })
    .setTimestamp();

  await message.reply({ embeds: [embed] });
}

const ACTION_FIELD_MAP: Record<string, keyof ConfigPatch & string> = {
  ban:           "banThreshold",
  kick:          "kickThreshold",
  channelcreate: "channelCreateThreshold",
  channeldelete: "channelDeleteThreshold",
  channelrename: "channelRenameThreshold",
  roledelete:    "roleDeleteThreshold",
  rolecreate:    "roleCreateThreshold",
  mention:       "mentionThreshold",
  link:          "linkThreshold",
  webhook:       "webhookThreshold",
};

async function cmdSet(message: Message, args: string[]): Promise<void> {
  if (!message.guild) return;
  if (!db) { await message.reply({ embeds: [errEmbed("Database not configured.")] }); return; }

  const sub = args[0]?.toLowerCase();

  if (sub === "punishment") {
    const p = args[1]?.toLowerCase();
    if (!["ban", "kick", "strip"].includes(p ?? "")) {
      await message.reply({ embeds: [errEmbed("Valid punishments: `ban`, `kick`, `strip`")] });
      return;
    }
    await upsertConfig(message.guild.id, { punishment: p as "ban" | "kick" | "strip" });
    await message.reply({ embeds: [okEmbed("Punishment Updated", `Punishment for violations set to **${p}**.`)] });
    return;
  }

  if (sub === "logchannel") {
    const channelId = message.mentions.channels.first()?.id ?? args[1];
    if (!channelId) {
      await message.reply({ embeds: [errEmbed("Usage: `-antinuke set logchannel #channel`")] });
      return;
    }
    await upsertConfig(message.guild.id, { logChannelId: channelId });
    await message.reply({ embeds: [okEmbed("Log Channel Set", `Security alerts will be sent to <#${channelId}>.`)] });
    return;
  }

  if (sub === "window") {
    const ms = parseInt(args[1] ?? "", 10);
    if (isNaN(ms) || ms < 3000 || ms > 60000) {
      await message.reply({ embeds: [errEmbed("Window must be between `3000` and `60000` milliseconds (3 – 60 seconds).")] });
      return;
    }
    await upsertConfig(message.guild.id, { timeWindowMs: ms });
    await message.reply({ embeds: [okEmbed("Time Window Updated", `Rate-tracking window set to **${ms / 1000}s**.`)] });
    return;
  }

  if (sub === "threshold") {
    const field = ACTION_FIELD_MAP[args[1]?.toLowerCase() ?? ""];
    const val   = parseInt(args[2] ?? "", 10);
    if (!field || isNaN(val) || val < 1 || val > 100) {
      await message.reply({ embeds: [errEmbed(
        `Valid actions: ${Object.keys(ACTION_FIELD_MAP).join(", ")}\n` +
        "Value must be between **1** and **100**."
      )] });
      return;
    }
    await upsertConfig(message.guild.id, { [field]: val } as ConfigPatch);
    await message.reply({ embeds: [okEmbed("Threshold Updated", `**${args[1]}** threshold set to **${val}**.`)] });
    return;
  }

  await message.reply({ embeds: [errEmbed(
    "**Usage:**\n" +
    "`-antinuke set punishment <ban|kick|strip>`\n" +
    "`-antinuke set logchannel #channel`\n" +
    "`-antinuke set window <milliseconds>`\n" +
    "`-antinuke set threshold <action> <number>`"
  )] });
}

async function cmdWhitelist(message: Message, args: string[]): Promise<void> {
  if (!message.guild) return;
  if (!db) { await message.reply({ embeds: [errEmbed("Database not configured.")] }); return; }

  const sub = args[0]?.toLowerCase();

  if (sub === "add") {
    const userId = message.mentions.users.first()?.id ?? args[1];
    if (!userId) { await message.reply({ embeds: [errEmbed("Usage: `-antinuke whitelist add @user`")] }); return; }
    const config  = await getConfig(message.guild.id);
    const current = config?.whitelist ?? [];
    if (current.includes(userId)) {
      await message.reply({ embeds: [infoEmbed("Already Whitelisted", `<@${userId}> is already exempt from anti-nuke detection.`)] });
      return;
    }
    await upsertConfig(message.guild.id, { whitelist: JSON.stringify([...current, userId]) });
    await message.reply({ embeds: [okEmbed("Whitelist Updated", `<@${userId}> is now exempt from anti-nuke detection.`)] });
    return;
  }

  if (sub === "remove") {
    const userId = message.mentions.users.first()?.id ?? args[1];
    if (!userId) { await message.reply({ embeds: [errEmbed("Usage: `-antinuke whitelist remove @user`")] }); return; }
    const config  = await getConfig(message.guild.id);
    const current = config?.whitelist ?? [];
    await upsertConfig(message.guild.id, { whitelist: JSON.stringify(current.filter(id => id !== userId)) });
    await message.reply({ embeds: [okEmbed("Whitelist Updated", `<@${userId}> has been removed from the whitelist.`)] });
    return;
  }

  if (sub === "list") {
    const config = await getConfig(message.guild.id);
    const list   = config?.whitelist ?? [];
    await message.reply({ embeds: [infoEmbed(
      "Whitelisted Users",
      list.length > 0
        ? list.map(id => `<@${id}>  \`${id}\``).join("\n")
        : "No users are currently whitelisted."
    )] });
    return;
  }

  await message.reply({ embeds: [errEmbed(
    "**Usage:**\n" +
    "`-antinuke whitelist add @user`\n" +
    "`-antinuke whitelist remove @user`\n" +
    "`-antinuke whitelist list`"
  )] });
}

async function cmdReset(message: Message): Promise<void> {
  if (!message.guild) return;
  if (!db) { await message.reply({ embeds: [errEmbed("Database not configured.")] }); return; }
  await upsertConfig(message.guild.id, {
    enabled: false, logChannelId: null, punishment: "ban", whitelist: "[]",
    banThreshold: 3, kickThreshold: 5, channelCreateThreshold: 5,
    channelDeleteThreshold: 3, channelRenameThreshold: 5, roleDeleteThreshold: 3,
    roleCreateThreshold: 5, mentionThreshold: 10, linkThreshold: 5,
    webhookThreshold: 2, timeWindowMs: 10_000,
  });
  await message.reply({ embeds: [okEmbed(
    "Anti-Nuke Reset",
    "All settings have been restored to defaults. Anti-nuke is now **disabled**."
  )] });
}

async function cmdHelp(message: Message): Promise<void> {
  await showAntiNukeHelp(message);
}

export async function showAntiNukeHelp(message: Message): Promise<void> {
  const SEP = "▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬";

  const embed = new EmbedBuilder()
    .setColor(0x2B2D31)
    .setAuthor({ name: "Anti-Nuke System  ·  Security Module" })
    .setTitle("Command Reference")
    .setDescription(
      "Protects your server against automated destruction attacks.\n" +
      "All `-antinuke` commands require **Administrator** or server ownership.\n\n" +
      "**Quick Setup**\n" +
      "`-antinuke enable`  →  `-antinuke set logchannel #channel`  →  done."
    )
    .addFields(
      {
        name: "SYSTEM CONTROL",
        value:
          "`-antinuke enable`  —  Activate all active protections\n" +
          "`-antinuke disable`  —  Deactivate the system (no actions taken)\n" +
          "`-antinuke status`  —  View full configuration and thresholds\n" +
          "`-antinuke reset`  —  Restore every setting to factory defaults",
      },
      { name: SEP, value: "\u200b" },
      {
        name: "CONFIGURATION",
        value:
          "`-antinuke set punishment <ban|kick|strip>`\n" +
          "  Determines what happens to the attacker when a threshold is hit.\n" +
          "  `ban` — permanently removes them  |  `kick` — removes from server\n" +
          "  `strip` — revokes all elevated roles\n\n" +
          "`-antinuke set logchannel #channel`\n" +
          "  Channel where security alert embeds are sent on each violation.\n\n" +
          "`-antinuke set window <ms>`\n" +
          "  Rate-tracking window in milliseconds. Default: `10000` (10 seconds).\n" +
          "  Range: 3000 – 60000.\n\n" +
          "`-antinuke set threshold <action> <number>`\n" +
          "  How many of a given action within the window triggers a response.",
      },
      { name: SEP, value: "\u200b" },
      {
        name: "THRESHOLD ACTIONS",
        value:
          "Use these with `-antinuke set threshold <action> <n>`:\n\n" +
          "`ban`            — mass bans  *(default: 3)*\n" +
          "`kick`           — mass kicks  *(default: 5)*\n" +
          "`channelcreate`  — channel creation spam  *(default: 5)*\n" +
          "`channeldelete`  — mass channel deletion  *(default: 3)*\n" +
          "`channelrename`  — mass channel renames  *(default: 5)*\n" +
          "`roledelete`     — mass role deletion  *(default: 3)*\n" +
          "`rolecreate`     — mass role creation  *(default: 5)*\n" +
          "`mention`        — mass mentions / @everyone  *(default: 10)*\n" +
          "`link`           — link spam  *(default: 5)*\n" +
          "`webhook`        — webhook creation spam  *(default: 2)*",
      },
      { name: SEP, value: "\u200b" },
      {
        name: "WHITELIST",
        value:
          "Whitelisted users are fully exempt from all detection.\n" +
          "Add your most trusted admins and bots here.\n\n" +
          "`-antinuke whitelist add @user`  —  Exempt a user\n" +
          "`-antinuke whitelist remove @user`  —  Revoke exemption\n" +
          "`-antinuke whitelist list`  —  View all exempted users",
      },
      { name: SEP, value: "\u200b" },
      {
        name: "PROTECTIONS OVERVIEW",
        value:
          "The following actions are monitored in real time:\n\n" +
          "Mass Ban  ·  Mass Kick  ·  Mass Channel Create\n" +
          "Mass Channel Delete  ·  Mass Channel Rename\n" +
          "Mass Role Create  ·  Mass Role Delete  ·  Mass Role Grant\n" +
          "Webhook Creation Spam  ·  Link Spam  ·  Mass Mention / @everyone\n\n" +
          "Server owner and bots are always skipped. Bot role hierarchy is respected.",
      },
    )
    .setFooter({ text: "-help  ·  Anti-Nuke System  ·  All times in UTC" })
    .setTimestamp();

  await message.reply({ embeds: [embed] });
}

// ── Public API ──────────────────────────────────────────────────────────────────

export function registerAntiNukeListeners(client: Client): void {
  _client = client;
  client.on(Events.GuildAuditLogEntryCreate, async (entry, guild) => {
    try {
      await onAuditLogEntry(entry as GuildAuditLogsEntry, guild);
    } catch (err: any) {
      logger.error(`Anti-nuke audit log error: ${err?.message}`);
    }
  });
}

export async function handleAntiNukeCommand(message: Message, args: string[]): Promise<void> {
  if (!isAdmin(message)) {
    await message.reply({ embeds: [errEmbed("This command requires **Administrator** permission or server ownership.")] });
    return;
  }

  const sub = args[0]?.toLowerCase() ?? "";
  switch (sub) {
    case "enable":    return cmdEnable(message);
    case "disable":   return cmdDisable(message);
    case "status":    return cmdStatus(message);
    case "set":       return cmdSet(message, args.slice(1));
    case "whitelist": return cmdWhitelist(message, args.slice(1));
    case "reset":     return cmdReset(message);
    default:          return cmdHelp(message);
  }
}
