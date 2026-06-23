import {
  Events,
  AuditLogEvent,
  EmbedBuilder,
  Colors,
  ChannelType,
  OverwriteType,
  PermissionsBitField,
  type Client,
  type Guild,
  type GuildMember,
  type User,
  type PartialUser,
  type Message,
  type TextChannel,
  type GuildAuditLogsEntry,
  type GuildChannel,
  type PermissionOverwrites,
} from "discord.js";
import { db } from "@workspace/db";
import { antinukeConfigTable, guildSnapshotTable } from "@workspace/db";
import { eq } from "drizzle-orm";
import { logger } from "./lib/logger";

type AnyUser = User | PartialUser;

// ── In-memory incident log (per guild, max 25, newest first) ─────────────────

interface Incident {
  at: Date;
  violation: string;
  executorId: string;
  executorTag: string;
  count: number;
  threshold: number;
  result: string;
}
const incidentLog = new Map<string, Incident[]>();
const MAX_INCIDENTS = 25;

function recordIncident(guildId: string, inc: Omit<Incident, "at">): void {
  const log = incidentLog.get(guildId) ?? [];
  log.unshift({ ...inc, at: new Date() });
  if (log.length > MAX_INCIDENTS) log.length = MAX_INCIDENTS;
  incidentLog.set(guildId, log);
}

// ── Join tracker for raid detection (per guild) ───────────────────────────────

const joinTracker = new Map<string, number[]>(); // guildId → join timestamps

// ── Sliding-window rate tracker ─────────────────────────────────────────────
// Uses per-action timestamp queues so async/delayed burst attacks are caught
// correctly regardless of whether the attacker spaces out requests.

const timestamps = new Map<string, number[]>();

function tick(guildId: string, userId: string, action: string, windowMs: number): number {
  const key = `${guildId}:${userId}:${action}`;
  const now = Date.now();
  const prev = timestamps.get(key) ?? [];
  const within = prev.filter(t => now - t <= windowMs);
  within.push(now);
  timestamps.set(key, within);
  return within.length;
}

function resetRate(guildId: string, userId: string, action: string): void {
  const key = `${guildId}:${userId}:${action}`;
  timestamps.delete(key);
}

// ── Config cache ────────────────────────────────────────────────────────────

// All toggleable action keys — used by cmdToggle and checkToggle
const TOGGLE_KEYS = [
  "ban", "kick", "chCreate", "chDelete", "chRename",
  "roleDelete", "roleCreate", "roleGrant",
  "webhook", "webhookDelete",
  "mention", "link",
  "unban", "emojiDelete",
  "raidJoin", "botAdd", "guildUpdate",
] as const;
type ToggleKey = typeof TOGGLE_KEYS[number];

interface AntiNukeConfig {
  enabled: boolean;
  logChannelId: string | null;
  punishment: "ban" | "kick" | "strip";
  whitelist: string[];
  toggles: Partial<Record<ToggleKey, boolean>>;
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
  unbanThreshold: number;
  emojiDeleteThreshold: number;
  raidJoinThreshold: number;
  raidJoinWindowMs: number;
  timeWindowMs: number;
  emergencyMode: boolean;
}

function checkToggle(config: AntiNukeConfig, key: ToggleKey): boolean {
  return config.toggles[key] !== false; // default true if not explicitly disabled
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
  let toggles: Partial<Record<ToggleKey, boolean>> = {};
  try { toggles = JSON.parse((r as any).toggles ?? "{}"); } catch { toggles = {}; }

  const config: AntiNukeConfig = {
    enabled: r.enabled,
    logChannelId: r.logChannelId ?? null,
    punishment: (r.punishment as "ban" | "kick" | "strip") ?? "ban",
    whitelist,
    toggles,
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
    unbanThreshold: (r as any).unbanThreshold ?? 3,
    emojiDeleteThreshold: (r as any).emojiDeleteThreshold ?? 5,
    raidJoinThreshold: (r as any).raidJoinThreshold ?? 10,
    raidJoinWindowMs: (r as any).raidJoinWindowMs ?? 30000,
    timeWindowMs: r.timeWindowMs,
    emergencyMode: (r as any).emergencyMode ?? false,
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

// ── Server snapshot ─────────────────────────────────────────────────────────

interface ChannelSnap {
  id: string;
  name: string;
  type: number;
  parentId: string | null;
  position: number;
  topic: string | null;
  nsfw: boolean;
  rateLimitPerUser: number;
  bitrate: number | null;
  userLimit: number | null;
  permissionOverwrites: Array<{
    id: string;
    type: number;
    allow: string;
    deny: string;
  }>;
}

interface RoleSnap {
  id: string;
  name: string;
  color: number;
  hoist: boolean;
  mentionable: boolean;
  permissions: string;
  position: number;
  managed: boolean;
}

const SNAPSHOT_INTERVAL_MS = 5 * 60 * 1000;
const snapshotTimers = new Map<string, ReturnType<typeof setInterval>>();

export async function takeSnapshot(guild: Guild): Promise<void> {
  if (!db) return;
  try {
    await guild.channels.fetch();
    await guild.roles.fetch();

    const channels: ChannelSnap[] = [];
    for (const [, ch] of guild.channels.cache) {
      if (!("permissionOverwrites" in ch)) continue;
      const gc = ch as GuildChannel;
      const overwrites: ChannelSnap["permissionOverwrites"] = [];
      (gc.permissionOverwrites.cache as Map<string, PermissionOverwrites>).forEach((ow) => {
        overwrites.push({
          id: ow.id,
          type: ow.type === OverwriteType.Role ? 0 : 1,
          allow: ow.allow.bitfield.toString(),
          deny: ow.deny.bitfield.toString(),
        });
      });

      channels.push({
        id: gc.id,
        name: gc.name,
        type: gc.type,
        parentId: gc.parentId ?? null,
        position: gc.rawPosition,
        topic: ("topic" in gc ? (gc as TextChannel).topic : null) ?? null,
        nsfw: ("nsfw" in gc ? (gc as TextChannel).nsfw : false) ?? false,
        rateLimitPerUser: ("rateLimitPerUser" in gc ? (gc as TextChannel).rateLimitPerUser : 0) ?? 0,
        bitrate: "bitrate" in gc ? (gc as any).bitrate : null,
        userLimit: "userLimit" in gc ? (gc as any).userLimit : null,
        permissionOverwrites: overwrites,
      });
    }

    const roles: RoleSnap[] = [];
    for (const [, role] of guild.roles.cache) {
      if (role.managed || role.id === guild.id) continue;
      roles.push({
        id: role.id,
        name: role.name,
        color: role.color,
        hoist: role.hoist,
        mentionable: role.mentionable,
        permissions: role.permissions.bitfield.toString(),
        position: role.rawPosition,
        managed: role.managed,
      });
    }

    await db
      .insert(guildSnapshotTable)
      .values({
        guildId: guild.id,
        guildName: guild.name,
        channelsJson: JSON.stringify(channels),
        rolesJson: JSON.stringify(roles),
        takenAt: new Date(),
      })
      .onConflictDoUpdate({
        target: guildSnapshotTable.guildId,
        set: {
          guildName: guild.name,
          channelsJson: JSON.stringify(channels),
          rolesJson: JSON.stringify(roles),
          takenAt: new Date(),
        },
      });

    logger.info({ guildId: guild.id, channels: channels.length, roles: roles.length }, "Guild snapshot saved");
  } catch (err: any) {
    logger.error(`Snapshot error for guild ${guild.id}: ${err?.message}`);
  }
}

async function loadSnapshot(guildId: string): Promise<{ channels: ChannelSnap[]; roles: RoleSnap[] } | null> {
  if (!db) return null;
  const rows = await db.select().from(guildSnapshotTable).where(eq(guildSnapshotTable.guildId, guildId)).limit(1);
  if (rows.length === 0) return null;
  try {
    return {
      channels: JSON.parse(rows[0].channelsJson),
      roles: JSON.parse(rows[0].rolesJson),
    };
  } catch {
    return null;
  }
}

function delay(ms: number): Promise<void> {
  return new Promise(r => setTimeout(r, ms));
}

// Permissions to lock on @everyone while a restore is in progress,
// so any remaining attacker cannot interfere mid-flight.
const LOCKDOWN_DENY = [
  PermissionsBitField.Flags.ManageChannels,
  PermissionsBitField.Flags.ManageRoles,
  PermissionsBitField.Flags.ManageGuild,
  PermissionsBitField.Flags.Administrator,
  PermissionsBitField.Flags.BanMembers,
  PermissionsBitField.Flags.KickMembers,
  PermissionsBitField.Flags.ManageWebhooks,
];

async function restoreFromSnapshot(guild: Guild, config: AntiNukeConfig): Promise<void> {
  const snap = await loadSnapshot(guild.id);
  if (!snap) {
    logger.warn(`No snapshot found for guild ${guild.id} — cannot restore`);
    return;
  }

  logger.info({ guildId: guild.id }, "Starting server restore from snapshot");

  await guild.roles.fetch();
  await guild.channels.fetch();

  // ── Lock @everyone during restore so no one can interfere ────────────────
  const everyoneRole = guild.roles.everyone;
  const originalEveryonePerms = everyoneRole.permissions.bitfield;
  const lockPerms = LOCKDOWN_DENY.reduce((acc, p) => acc | p, 0n);
  const lockedPerms = originalEveryonePerms & ~lockPerms;
  let lockApplied = false;
  try {
    await everyoneRole.setPermissions(lockedPerms, "Anti-nuke: locking server during restore");
    lockApplied = true;
    logger.info({ guildId: guild.id }, "Server locked during restore");
  } catch (err: any) {
    logger.warn(`Could not lock @everyone during restore: ${err?.message}`);
  }

  try {
    // ── Restore roles ──────────────────────────────────────────────────────
    // Map: old role ID → live role ID (needed to remap permission overwrites)
    const roleIdMap = new Map<string, string>();
    const sortedRoles = [...snap.roles].sort((a, b) => a.position - b.position);

    for (const roleSnap of sortedRoles) {
      if (roleSnap.managed) continue;
      // Match by original ID first, then by exact name — never create a duplicate
      const existing =
        guild.roles.cache.get(roleSnap.id) ??
        guild.roles.cache.find(r => r.name === roleSnap.name);
      if (existing) {
        roleIdMap.set(roleSnap.id, existing.id);
        continue;
      }
      try {
        await delay(600);
        const created = await guild.roles.create({
          name: roleSnap.name,
          color: roleSnap.color,
          hoist: roleSnap.hoist,
          mentionable: roleSnap.mentionable,
          permissions: BigInt(roleSnap.permissions),
          reason: "Anti-nuke: restoring deleted role",
        });
        roleIdMap.set(roleSnap.id, created.id);
        logger.info({ guildId: guild.id, role: roleSnap.name }, "Role restored");
      } catch (err: any) {
        logger.error(`Failed to restore role "${roleSnap.name}": ${err?.message}`);
      }
    }

    // ── Restore channels ───────────────────────────────────────────────────
    // Remap overwrite role IDs in case roles were recreated with new IDs
    function remapOverwrites(overwrites: ChannelSnap["permissionOverwrites"]) {
      return overwrites.map(ow => ({
        id: ow.type === 0 ? (roleIdMap.get(ow.id) ?? ow.id) : ow.id,
        type: ow.type as 0 | 1,
        allow: BigInt(ow.allow),
        deny: BigInt(ow.deny),
      }));
    }

    // Categories first (sorted by position), then everything else
    const categories = snap.channels
      .filter(c => c.type === ChannelType.GuildCategory)
      .sort((a, b) => a.position - b.position);
    const otherChannels = snap.channels
      .filter(c => c.type !== ChannelType.GuildCategory)
      .sort((a, b) => a.position - b.position);

    // Map: old category ID → live category ID
    const categoryIdMap = new Map<string, string>();

    for (const catSnap of categories) {
      // Skip if already present by ID or by name (never duplicate)
      const existing =
        guild.channels.cache.get(catSnap.id) ??
        guild.channels.cache.find(
          c => c.name.toLowerCase() === catSnap.name.toLowerCase() &&
               c.type === ChannelType.GuildCategory
        );
      if (existing) {
        categoryIdMap.set(catSnap.id, existing.id);
        continue;
      }
      try {
        await delay(600);
        const created = await guild.channels.create({
          name: catSnap.name,
          type: ChannelType.GuildCategory,
          position: catSnap.position,
          permissionOverwrites: remapOverwrites(catSnap.permissionOverwrites),
          reason: "Anti-nuke: restoring deleted category",
        });
        categoryIdMap.set(catSnap.id, created.id);
        logger.info({ guildId: guild.id, category: catSnap.name }, "Category restored");
      } catch (err: any) {
        logger.error(`Failed to restore category "${catSnap.name}": ${err?.message}`);
      }
    }

    for (const chSnap of otherChannels) {
      // Skip if already present by ID or by name+type in the same parent (never duplicate)
      const resolvedParentId = chSnap.parentId
        ? (categoryIdMap.get(chSnap.parentId) ?? chSnap.parentId)
        : null;

      const existing =
        guild.channels.cache.get(chSnap.id) ??
        guild.channels.cache.find(
          c =>
            c.name.toLowerCase() === chSnap.name.toLowerCase() &&
            c.type === chSnap.type &&
            (c as GuildChannel).parentId === resolvedParentId
        );
      if (existing) continue;

      try {
        await delay(600);
        if (chSnap.type === ChannelType.GuildText || chSnap.type === ChannelType.GuildAnnouncement) {
          await guild.channels.create({
            name: chSnap.name,
            type: chSnap.type as ChannelType.GuildText | ChannelType.GuildAnnouncement,
            parent: resolvedParentId ?? undefined,
            position: chSnap.position,
            topic: chSnap.topic ?? undefined,
            nsfw: chSnap.nsfw,
            rateLimitPerUser: chSnap.rateLimitPerUser,
            permissionOverwrites: remapOverwrites(chSnap.permissionOverwrites),
            reason: "Anti-nuke: restoring deleted channel",
          });
        } else if (chSnap.type === ChannelType.GuildVoice || chSnap.type === ChannelType.GuildStageVoice) {
          await guild.channels.create({
            name: chSnap.name,
            type: chSnap.type as ChannelType.GuildVoice | ChannelType.GuildStageVoice,
            parent: resolvedParentId ?? undefined,
            position: chSnap.position,
            bitrate: chSnap.bitrate ?? undefined,
            userLimit: chSnap.userLimit ?? undefined,
            permissionOverwrites: remapOverwrites(chSnap.permissionOverwrites),
            reason: "Anti-nuke: restoring deleted channel",
          });
        } else if (chSnap.type === ChannelType.GuildForum) {
          await guild.channels.create({
            name: chSnap.name,
            type: ChannelType.GuildForum,
            parent: resolvedParentId ?? undefined,
            position: chSnap.position,
            permissionOverwrites: remapOverwrites(chSnap.permissionOverwrites),
            reason: "Anti-nuke: restoring deleted channel",
          });
        }
        logger.info({ guildId: guild.id, channel: chSnap.name, parent: resolvedParentId }, "Channel restored");
      } catch (err: any) {
        logger.error(`Failed to restore channel "${chSnap.name}": ${err?.message}`);
      }
    }
  } finally {
    // ── Always unlock @everyone when done, even if restore partially failed ─
    if (lockApplied) {
      try {
        await everyoneRole.setPermissions(originalEveryonePerms, "Anti-nuke: unlocking server after restore");
        logger.info({ guildId: guild.id }, "Server unlocked after restore");
      } catch (err: any) {
        logger.warn(`Could not unlock @everyone after restore: ${err?.message}`);
      }
    }
  }

  logger.info({ guildId: guild.id }, "Server restore complete");

  if (config.logChannelId) {
    const ch = guild.channels.cache.get(config.logChannelId);
    if (ch && "send" in ch) {
      await (ch as TextChannel).send({
        embeds: [
          new EmbedBuilder()
            .setColor(Colors.Green)
            .setTitle("Server Restored")
            .setDescription("Channels and roles have been restored from the last snapshot.")
            .setFooter({ text: "Anti-Nuke System" })
            .setTimestamp(),
        ],
      }).catch(() => null);
    }
  }
}

// ── Punishment engine ────────────────────────────────────────────────────────

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

// ── Violation handler ────────────────────────────────────────────────────────

let _client: Client | null = null;

// Actions that indicate a server is being destroyed — trigger auto-restore
const RESTORE_TRIGGERS = new Set(["chDelete", "roleDelete"]);

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

  recordIncident(guild.id, {
    violation: violationLabel,
    executorId: executor.id,
    executorTag: executorLabel,
    count,
    threshold,
    result,
  });

  logger.warn(
    `Anti-nuke triggered | guild: ${guild.id} | executor: ${executorLabel} (${executor.id}) | ` +
    `violation: ${violationLabel} | count: ${count}/${threshold} | result: ${result}`
  );

  if (config.logChannelId) {
    const channel = guild.channels.cache.get(config.logChannelId);
    if (channel && "send" in channel) {
      const embed = new EmbedBuilder()
        .setColor(Colors.Red)
        .setTitle("SECURITY ALERT — Anti-Nuke Triggered")
        .setDescription(
          `A protection threshold was exceeded in **${guild.name}**.\n` +
          `The system has responded automatically.`
        )
        .addFields(
          { name: "Violation",       value: violationLabel,                                               inline: true },
          { name: "Server",          value: guild.name,                                                   inline: true },
          { name: "\u200b",          value: "\u200b",                                                     inline: true },
          { name: "Executor",        value: `${executorLabel}\n\`${executor.id}\``,                       inline: true },
          { name: "Count / Limit",   value: `${count} / ${threshold} in ${config.timeWindowMs / 1000}s`, inline: true },
          { name: "Response",        value: PUNISH_LABEL[result],                                         inline: true },
        )
        .setFooter({ text: "Anti-Nuke System" })
        .setTimestamp();

      await (channel as TextChannel).send({ embeds: [embed] }).catch(() => null);
    }
  }

  // Auto-restore channels/roles when a destructive nuke is detected
  if (RESTORE_TRIGGERS.has(actionKey)) {
    restoreFromSnapshot(guild, config).catch((err: any) => {
      logger.error(`Restore error for guild ${guild.id}: ${err?.message}`);
    });
  }
}

// ── Audit log event handler ──────────────────────────────────────────────────

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
      if (!checkToggle(config, "ban")) break;
      const n = tick(guild.id, executorId, "ban", w);
      if (n >= config.banThreshold)
        await handleViolation(guild, entry.executor, config, "ban", "Mass Ban", n, config.banThreshold);
      break;
    }
    case AuditLogEvent.MemberBanRemove: {
      if (!checkToggle(config, "unban")) break;
      const n = tick(guild.id, executorId, "unban", w);
      if (n >= config.unbanThreshold)
        await handleViolation(guild, entry.executor, config, "unban", "Mass Unban", n, config.unbanThreshold);
      break;
    }
    case AuditLogEvent.MemberKick: {
      if (!checkToggle(config, "kick")) break;
      const n = tick(guild.id, executorId, "kick", w);
      if (n >= config.kickThreshold)
        await handleViolation(guild, entry.executor, config, "kick", "Mass Kick", n, config.kickThreshold);
      break;
    }
    case AuditLogEvent.ChannelCreate: {
      if (!checkToggle(config, "chCreate")) break;
      const n = tick(guild.id, executorId, "chCreate", w);
      if (n >= config.channelCreateThreshold)
        await handleViolation(guild, entry.executor, config, "chCreate", "Mass Channel Create", n, config.channelCreateThreshold);
      break;
    }
    case AuditLogEvent.ChannelDelete: {
      if (!checkToggle(config, "chDelete")) break;
      const n = tick(guild.id, executorId, "chDelete", w);
      if (n >= config.channelDeleteThreshold)
        await handleViolation(guild, entry.executor, config, "chDelete", "Mass Channel Delete", n, config.channelDeleteThreshold);
      break;
    }
    case AuditLogEvent.ChannelUpdate: {
      if (!checkToggle(config, "chRename")) break;
      const changes = entry.changes as ReadonlyArray<{ key: string }>;
      if (!changes.some(c => c.key === "name")) break;
      const n = tick(guild.id, executorId, "chRename", w);
      if (n >= config.channelRenameThreshold)
        await handleViolation(guild, entry.executor, config, "chRename", "Mass Channel Rename", n, config.channelRenameThreshold);
      break;
    }
    case AuditLogEvent.RoleDelete: {
      if (!checkToggle(config, "roleDelete")) break;
      const n = tick(guild.id, executorId, "roleDelete", w);
      if (n >= config.roleDeleteThreshold)
        await handleViolation(guild, entry.executor, config, "roleDelete", "Mass Role Delete", n, config.roleDeleteThreshold);
      break;
    }
    case AuditLogEvent.RoleCreate: {
      if (!checkToggle(config, "roleCreate")) break;
      const n = tick(guild.id, executorId, "roleCreate", w);
      if (n >= config.roleCreateThreshold)
        await handleViolation(guild, entry.executor, config, "roleCreate", "Mass Role Create", n, config.roleCreateThreshold);
      break;
    }
    case AuditLogEvent.WebhookCreate: {
      if (!checkToggle(config, "webhook")) break;
      const n = tick(guild.id, executorId, "webhook", w);
      if (n >= config.webhookThreshold)
        await handleViolation(guild, entry.executor, config, "webhook", "Webhook Creation Spam", n, config.webhookThreshold);
      break;
    }
    case AuditLogEvent.WebhookDelete:
    case AuditLogEvent.WebhookUpdate: {
      if (!checkToggle(config, "webhookDelete")) break;
      const n = tick(guild.id, executorId, "webhookDelete", w);
      if (n >= config.webhookThreshold)
        await handleViolation(guild, entry.executor, config, "webhookDelete", "Webhook Deletion/Modification", n, config.webhookThreshold);
      break;
    }
    case AuditLogEvent.MemberRoleUpdate: {
      if (!checkToggle(config, "roleGrant")) break;
      const changes = entry.changes as ReadonlyArray<{ key: string; new?: unknown }>;
      const hasGrant = changes.some(c => c.key === "$add" && Array.isArray(c.new) && (c.new as unknown[]).length > 0);
      if (!hasGrant) break;
      const n = tick(guild.id, executorId, "roleGrant", w);
      if (n >= 5)
        await handleViolation(guild, entry.executor, config, "roleGrant", "Mass Role Grant", n, 5);
      break;
    }
    case AuditLogEvent.EmojiDelete:
    case AuditLogEvent.StickerDelete: {
      if (!checkToggle(config, "emojiDelete")) break;
      const n = tick(guild.id, executorId, "emojiDelete", w);
      if (n >= config.emojiDeleteThreshold)
        await handleViolation(guild, entry.executor, config, "emojiDelete", "Mass Emoji/Sticker Delete", n, config.emojiDeleteThreshold);
      break;
    }
    case AuditLogEvent.GuildUpdate: {
      if (!checkToggle(config, "guildUpdate")) break;
      const changes = entry.changes as ReadonlyArray<{ key: string; old?: unknown; new?: unknown }>;
      const sensitiveKeys = ["name", "vanity_url_code", "owner_id", "mfa_level", "verification_level"];
      const hit = changes.find(c => sensitiveKeys.includes(c.key));
      if (!hit) break;
      const label = hit.key === "name" ? "Server Name Changed"
                  : hit.key === "vanity_url_code" ? "Vanity URL Changed"
                  : hit.key === "owner_id" ? "Ownership Transferred"
                  : "Critical Server Setting Changed";
      // Attempt to revert server name changes
      if (hit.key === "name" && hit.old && typeof hit.old === "string") {
        guild.setName(hit.old as string, "Anti-nuke: reverting server name change").catch(() => null);
      }
      await handleViolation(guild, entry.executor, config, "guildUpdate", label, 1, 1);
      break;
    }
    case AuditLogEvent.BotAdd: {
      if (!checkToggle(config, "botAdd")) break;
      // The target is the bot that was added
      const botId = (entry.target as { id?: string } | null)?.id;
      if (botId && !config.whitelist.includes(botId)) {
        const bot = await guild.members.fetch(botId).catch(() => null);
        if (bot?.user.bot) {
          await bot.kick("Anti-nuke: unauthorized bot addition").catch(() => null);
        }
        await handleViolation(guild, entry.executor, config, "botAdd", "Unauthorized Bot Added", 1, 1);
      }
      break;
    }
  }
}

// ── Raid detection (join flood) ───────────────────────────────────────────────

export async function onGuildMemberAdd(member: GuildMember): Promise<void> {
  const guild = member.guild;
  const config = await getConfig(guild.id);
  if (!config?.enabled) return;

  // ── Raid join flood ──────────────────────────────────────────────────────
  if (checkToggle(config, "raidJoin")) {
    const now = Date.now();
    const prev = joinTracker.get(guild.id) ?? [];
    const within = prev.filter(t => now - t <= config.raidJoinWindowMs);
    within.push(now);
    joinTracker.set(guild.id, within);

    if (within.length >= config.raidJoinThreshold) {
      joinTracker.delete(guild.id);
      recordIncident(guild.id, {
        violation: "Raid Join Flood",
        executorId: "raid",
        executorTag: "Raid",
        count: within.length,
        threshold: config.raidJoinThreshold,
        result: "lockdown",
      });
      logger.warn(`Raid detected in guild ${guild.id} — ${within.length} joins in ${config.raidJoinWindowMs / 1000}s`);

      if (config.logChannelId) {
        const ch = guild.channels.cache.get(config.logChannelId);
        if (ch && "send" in ch) {
          await (ch as TextChannel).send({
            embeds: [
              new EmbedBuilder()
                .setColor(Colors.DarkRed)
                .setTitle("RAID DETECTED")
                .setDescription(
                  `**${within.length}** accounts joined **${guild.name}** within **${config.raidJoinWindowMs / 1000}s**.\n` +
                  `Threshold: ${config.raidJoinThreshold} joins in ${config.raidJoinWindowMs / 1000}s.\n\n` +
                  `Use \`-antinuke lockdown\` to lock the server immediately.`
                )
                .setFooter({ text: "Anti-Nuke System  ·  Raid Detection" })
                .setTimestamp(),
            ],
          }).catch(() => null);
        }
      }
    }
  }
}

// ── Message handler (link spam + mass mention) ───────────────────────────────

const URL_REGEX = /https?:\/\/[^\s<>]+/gi;

export async function handleAntiNukeMessage(message: Message): Promise<void> {
  if (!message.guild || message.author.bot) return;

  const config = await getConfig(message.guild.id);
  if (!config?.enabled) return;
  if (config.whitelist.includes(message.author.id)) return;

  const guild = message.guild;
  const executor = message.author;
  const w = config.timeWindowMs;

  const uniqueMentions = message.mentions.users.size + message.mentions.roles.size;
  if (message.mentions.everyone || uniqueMentions >= config.mentionThreshold) {
    const count = message.mentions.everyone ? config.mentionThreshold : uniqueMentions;
    await message.delete().catch(() => null);
    await handleViolation(guild, executor, config, "mention", "Mass Mention / @everyone", count, config.mentionThreshold);
    return;
  }

  const links = message.content.match(URL_REGEX);
  if (links) {
    const n = tick(guild.id, executor.id, "link", w);
    if (n >= config.linkThreshold) {
      await message.delete().catch(() => null);
      await handleViolation(guild, executor, config, "link", "Link Spam", n, config.linkThreshold);
    }
  }
}

// ── Embed helpers ─────────────────────────────────────────────────────────────

function anEmbed(color: number, title: string, description: string): EmbedBuilder {
  return new EmbedBuilder()
    .setColor(color)
    .setTitle(title)
    .setDescription(description)
    .setFooter({ text: "Anti-Nuke System" })
    .setTimestamp();
}

const okEmbed   = (t: string, d: string) => anEmbed(Colors.Green,  t, d);
const infoEmbed = (t: string, d: string) => anEmbed(Colors.Blurple, t, d);
const errEmbed  = (d: string)            => anEmbed(Colors.Red, "Error", d);

function isAdmin(message: Message): boolean {
  if (!message.guild || !message.member) return false;
  return (
    message.author.id === message.guild.ownerId ||
    message.member.permissions.has(PermissionsBitField.Flags.Administrator)
  );
}

// ── Sub-commands ──────────────────────────────────────────────────────────────

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

  let snapshotAge = "No snapshot taken";
  if (db) {
    const rows = await db.select().from(guildSnapshotTable).where(eq(guildSnapshotTable.guildId, message.guild.id)).limit(1);
    if (rows.length > 0) {
      const ageSec = Math.floor((Date.now() - new Date(rows[0].takenAt).getTime()) / 1000);
      snapshotAge = ageSec < 60 ? `${ageSec}s ago` : `${Math.floor(ageSec / 60)}m ago`;
    }
  }

  const embed = new EmbedBuilder()
    .setColor(config.enabled ? Colors.Green : 0x5c5c5c)
    .setTitle("Anti-Nuke — Configuration")
    .setDescription(`**Status:** ${config.enabled ? "Active" : "Inactive"}`)
    .addFields(
      { name: "Punishment",     value: config.punishment.charAt(0).toUpperCase() + config.punishment.slice(1), inline: true },
      { name: "Log Channel",    value: logChannel,                                                              inline: true },
      { name: "Time Window",    value: `${config.timeWindowMs / 1000}s`,                                       inline: true },
      { name: "Last Snapshot",  value: snapshotAge,                                                            inline: true },
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
  unban:         "unbanThreshold",
  emojidelete:   "emojiDeleteThreshold",
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
    unbanThreshold: 3, emojiDeleteThreshold: 5,
    raidJoinThreshold: 10, raidJoinWindowMs: 30_000,
    emergencyMode: false,
  } as any);
  await message.reply({ embeds: [okEmbed(
    "Anti-Nuke Reset",
    "All settings have been restored to defaults. Anti-nuke is now **disabled**."
  )] });
}

async function cmdSnapshot(message: Message): Promise<void> {
  if (!message.guild) return;
  if (!db) { await message.reply({ embeds: [errEmbed("Database not configured.")] }); return; }
  const pending = await message.reply({ embeds: [infoEmbed("Taking Snapshot…", "Capturing all channels and roles…")] });
  await takeSnapshot(message.guild);
  await pending.edit({ embeds: [okEmbed(
    "Snapshot Saved",
    "The current server state (channels, categories, roles, and all permission overwrites) has been saved.\n" +
    "The anti-nuke system will restore from this snapshot if a nuke is detected."
  )] });
}

async function cmdRestore(message: Message): Promise<void> {
  if (!message.guild) return;
  if (!db) { await message.reply({ embeds: [errEmbed("Database not configured.")] }); return; }
  const snap = await loadSnapshot(message.guild.id);
  if (!snap) {
    await message.reply({ embeds: [errEmbed("No snapshot found. Run `-antinuke snapshot` first.")] });
    return;
  }
  const config = await getConfig(message.guild.id);
  if (!config) {
    await message.reply({ embeds: [errEmbed("Anti-nuke is not configured. Run `-antinuke enable` first.")] });
    return;
  }
  await message.reply({ embeds: [infoEmbed(
    "Restore Started",
    `Restoring **${snap.channels.length}** channels and **${snap.roles.length}** roles from the last snapshot.\n` +
    "This may take a minute. Categories are restored first, then channels within them."
  )] });
  restoreFromSnapshot(message.guild, config).catch((err: any) => {
    logger.error(`Manual restore error: ${err?.message}`);
  });
}

// ── Toggle command ───────────────────────────────────────────────────────────

async function cmdToggle(message: Message, args: string[]): Promise<void> {
  if (!message.guild) return;
  if (!db) { await message.reply({ embeds: [errEmbed("Database not configured.")] }); return; }

  const key = args[0]?.toLowerCase();
  const val  = args[1]?.toLowerCase();

  if (!key || !val) {
    const keyList = TOGGLE_KEYS.join(" · ");
    await message.reply({ embeds: [errEmbed(
      "**Usage:** `-antinuke toggle <action> <on|off>`\n\n" +
      `**Actions:** ${keyList}`
    )] });
    return;
  }

  if (!TOGGLE_KEYS.includes(key as ToggleKey)) {
    await message.reply({ embeds: [errEmbed(`Unknown action key: \`${key}\`\nValid: ${TOGGLE_KEYS.join(", ")}`)] });
    return;
  }

  if (val !== "on" && val !== "off") {
    await message.reply({ embeds: [errEmbed("Value must be `on` or `off`.")] });
    return;
  }

  const config = await getConfig(message.guild.id);
  const toggles = config?.toggles ?? {};
  (toggles as Record<string, boolean>)[key] = val === "on";
  await upsertConfig(message.guild.id, { toggles: JSON.stringify(toggles) } as any);
  await message.reply({ embeds: [okEmbed("Toggle Updated", `Detection for **${key}** is now **${val}**.`)] });
}

// ── Stats command ────────────────────────────────────────────────────────────

async function cmdStats(message: Message): Promise<void> {
  if (!message.guild) return;

  const incidents = incidentLog.get(message.guild.id) ?? [];

  const embed = new EmbedBuilder()
    .setColor(0x2B2D31)
    .setTitle("Anti-Nuke — Incident Stats")
    .setDescription(
      incidents.length === 0
        ? "No incidents recorded in this session."
        : `Last **${incidents.length}** incident(s):`
    );

  if (incidents.length > 0) {
    const lines = incidents.slice(0, 10).map((inc, i) => {
      const ts = `<t:${Math.floor(inc.at.getTime() / 1000)}:R>`;
      return `\`${String(i + 1).padStart(2, "0")}\` ${ts} **${inc.violation}** — <@${inc.executorId}> (${inc.count}/${inc.threshold}) → ${inc.result}`;
    });
    embed.addFields({ name: "Recent Incidents", value: lines.join("\n"), inline: false });
  }

  embed.setFooter({ text: "Anti-Nuke System  ·  Resets on bot restart" }).setTimestamp();
  await message.reply({ embeds: [embed] });
}

// ── Lockdown command ─────────────────────────────────────────────────────────

async function cmdLockdown(message: Message): Promise<void> {
  if (!message.guild) return;

  const guild = message.guild;
  const pending = await message.reply({ embeds: [infoEmbed("Lockdown In Progress…", "Removing Send Messages from @everyone in all channels…")] });

  let count = 0;
  const errs: string[] = [];
  for (const channel of guild.channels.cache.values()) {
    if (!("permissionOverwrites" in channel)) continue;
    try {
      await (channel as GuildChannel).permissionOverwrites.edit(
        guild.roles.everyone,
        { SendMessages: false },
        { reason: "Anti-nuke manual lockdown" }
      );
      count++;
    } catch { errs.push(channel.id); }
  }

  await pending.edit({ embeds: [okEmbed(
    "Server Locked Down",
    `Locked **${count}** channel(s). ${errs.length > 0 ? `\nCould not lock ${errs.length} channel(s) (missing permissions).` : ""}\n\n` +
    "Use `-antinuke unlock` to restore normal access."
  )] });
}

// ── Unlock command ───────────────────────────────────────────────────────────

async function cmdUnlock(message: Message): Promise<void> {
  if (!message.guild) return;

  const guild = message.guild;
  const pending = await message.reply({ embeds: [infoEmbed("Unlocking Server…", "Restoring @everyone Send Messages permissions…")] });

  let count = 0;
  const errs: string[] = [];
  for (const channel of guild.channels.cache.values()) {
    if (!("permissionOverwrites" in channel)) continue;
    try {
      await (channel as GuildChannel).permissionOverwrites.edit(
        guild.roles.everyone,
        { SendMessages: null },
        { reason: "Anti-nuke manual unlock" }
      );
      count++;
    } catch { errs.push(channel.id); }
  }

  await pending.edit({ embeds: [okEmbed(
    "Server Unlocked",
    `Restored permissions in **${count}** channel(s).${errs.length > 0 ? `\nCould not unlock ${errs.length} channel(s) (missing permissions).` : ""}`
  )] });
}

async function cmdHelp(message: Message): Promise<void> {
  await showAntiNukeHelp(message);
}

export async function showAntiNukeHelp(message: Message): Promise<void> {
  const embed = new EmbedBuilder()
    .setColor(0x2B2D31)
    .setTitle("Anti-Nuke — Commands")
    .setDescription(
      "**Setup:** `-antinuke enable` → `-antinuke set logchannel #ch` → `-antinuke snapshot`\n" +
      "All commands require **Administrator** or server ownership."
    )
    .addFields(
      {
        name: "Control",
        value:
          "`enable` · `disable` · `status` · `reset`\n" +
          "`lockdown` — lock all channels immediately\n" +
          "`unlock` — restore channel access",
        inline: false,
      },
      {
        name: "Snapshot & Restore",
        value:
          "`snapshot` — save server layout (auto every 5 min)\n" +
          "`restore` — rebuild missing channels/roles from snapshot",
        inline: false,
      },
      {
        name: "Settings",
        value:
          "`set punishment <ban|kick|strip>`\n" +
          "`set logchannel #channel`\n" +
          "`set window <ms>` — default 10 000ms\n" +
          "`set threshold <action> <n>` — see Threshold actions below",
        inline: false,
      },
      {
        name: "Threshold actions",
        value:
          "`ban` · `kick` · `unban` · `channelcreate` · `channeldelete` · `channelrename`\n" +
          "`roledelete` · `rolecreate` · `mention` · `link` · `webhook` · `emojidelete`",
        inline: false,
      },
      {
        name: "Per-action toggles",
        value:
          "`toggle <key> on|off` — enable/disable individual detections\n" +
          "Keys: `ban` `kick` `unban` `chCreate` `chDelete` `chRename`\n" +
          "`roleDelete` `roleCreate` `roleGrant` `webhook` `webhookDelete`\n" +
          "`mention` `link` `emojiDelete` `raidJoin` `botAdd` `guildUpdate`",
        inline: false,
      },
      {
        name: "Whitelist & Stats",
        value:
          "`whitelist add/remove @user` · `whitelist list`\n" +
          "`stats` — view recent incident log",
        inline: false,
      },
    )
    .setFooter({ text: "Anti-Nuke System  ·  Prefix: -antinuke" })
    .setTimestamp();

  await message.reply({ embeds: [embed] });
}

// ── Public API ────────────────────────────────────────────────────────────────

export function registerAntiNukeListeners(client: Client): void {
  _client = client;

  client.on(Events.GuildAuditLogEntryCreate, async (entry, guild) => {
    try {
      await onAuditLogEntry(entry as GuildAuditLogsEntry, guild);
    } catch (err: any) {
      logger.error(`Anti-nuke audit log error: ${err?.message}`);
    }
  });

  client.on(Events.GuildMemberAdd, async (member) => {
    try {
      await onGuildMemberAdd(member as GuildMember);
    } catch (err: any) {
      logger.error(`Anti-nuke member add error: ${err?.message}`);
    }
  });
}

// Start periodic snapshots for a guild (called when the bot is ready or joins)
export function startSnapshotSchedule(client: Client): void {
  // On ready: snapshot all guilds the bot is in, then schedule periodic refresh
  client.guilds.cache.forEach(guild => {
    scheduleGuildSnapshot(guild);
  });
}

export function scheduleGuildSnapshot(guild: Guild): void {
  if (snapshotTimers.has(guild.id)) return;
  // Take an initial snapshot immediately
  takeSnapshot(guild).catch((err: any) => logger.error(`Initial snapshot error: ${err?.message}`));
  // Then refresh every 5 minutes
  const timer = setInterval(() => {
    takeSnapshot(guild).catch((err: any) => logger.error(`Periodic snapshot error: ${err?.message}`));
  }, SNAPSHOT_INTERVAL_MS);
  snapshotTimers.set(guild.id, timer);
}

export function stopSnapshotSchedule(guildId: string): void {
  const timer = snapshotTimers.get(guildId);
  if (timer) {
    clearInterval(timer);
    snapshotTimers.delete(guildId);
  }
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
    case "snapshot":  return cmdSnapshot(message);
    case "restore":   return cmdRestore(message);
    case "toggle":    return cmdToggle(message, args.slice(1));
    case "stats":     return cmdStats(message);
    case "lockdown":  return cmdLockdown(message);
    case "unlock":    return cmdUnlock(message);
    default:          return cmdHelp(message);
  }
}
