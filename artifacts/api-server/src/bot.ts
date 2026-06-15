import {
  Client,
  GatewayIntentBits,
  Events,
  AuditLogEvent,
  PermissionsBitField,
  type Message,
  type GuildMember,
} from "discord.js";
import { db } from "@workspace/db";
import { roleAssignmentsTable } from "@workspace/db";
import { eq, and } from "drizzle-orm";
import { logger } from "./lib/logger";

const ELEVATED_PERMISSIONS = [
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

function hasElevatedPermission(permissions: PermissionsBitField): boolean {
  return ELEVATED_PERMISSIONS.some((perm) => permissions.has(perm));
}

function formatTimestamp(date: Date): string {
  return `<t:${Math.floor(date.getTime() / 1000)}:f>`;
}

async function handleRolesGivenCommand(message: Message, args: string[]) {
  const guild = message.guild;
  if (!guild) return;

  const userArg = args.join(" ").trim();
  if (!userArg) {
    await message.reply(
      "Usage: `,roles given @user` or `,roles given username`"
    );
    return;
  }

  let targetId: string | null = null;

  const mentionMatch = userArg.match(/^<@!?(\d+)>$/);
  if (mentionMatch) {
    targetId = mentionMatch[1];
  } else if (/^\d+$/.test(userArg)) {
    targetId = userArg;
  }

  let records;
  if (targetId) {
    records = await db
      .select()
      .from(roleAssignmentsTable)
      .where(
        and(
          eq(roleAssignmentsTable.guildId, guild.id),
          eq(roleAssignmentsTable.executorId, targetId)
        )
      )
      .orderBy(roleAssignmentsTable.assignedAt);
  } else {
    const nameSearch = userArg.toLowerCase();
    const all = await db
      .select()
      .from(roleAssignmentsTable)
      .where(eq(roleAssignmentsTable.guildId, guild.id));
    records = all.filter((r) =>
      r.executorTag.toLowerCase().includes(nameSearch)
    );
  }

  if (!records || records.length === 0) {
    await message.reply(
      `No elevated role assignments found for **${userArg}**.\n*(Note: only assignments made after the bot joined are tracked.)*`
    );
    return;
  }

  const grouped = new Map<string, typeof records>();
  for (const r of records) {
    const key = `${r.roleId}|${r.roleName}`;
    if (!grouped.has(key)) grouped.set(key, []);
    grouped.get(key)!.push(r);
  }

  const executorTag = records[0].executorTag;
  const lines: string[] = [
    `**Elevated roles given by ${executorTag}:**`,
    "",
  ];

  for (const [, entries] of grouped) {
    const roleName = entries[0].roleName;
    lines.push(`**${roleName}** — given to ${entries.length} user(s):`);
    for (const e of entries.slice(0, 5)) {
      lines.push(
        `  • ${e.targetTag} — ${formatTimestamp(new Date(e.assignedAt))}`
      );
    }
    if (entries.length > 5) {
      lines.push(`  *(and ${entries.length - 5} more…)*`);
    }
    lines.push("");
  }

  const output = lines.join("\n");
  if (output.length > 1900) {
    const chunks = output.match(/.{1,1900}/gs) ?? [];
    for (const chunk of chunks) await message.channel.send(chunk);
  } else {
    await message.reply(output);
  }
}

async function handleAllRolesGivenCommand(message: Message) {
  const guild = message.guild;
  if (!guild) return;

  const records = await db
    .select()
    .from(roleAssignmentsTable)
    .where(eq(roleAssignmentsTable.guildId, guild.id))
    .orderBy(roleAssignmentsTable.assignedAt);

  if (records.length === 0) {
    await message.reply(
      "No elevated role assignments have been recorded yet.\n*(The bot tracks assignments made after it joined.)*"
    );
    return;
  }

  const lines: string[] = [
    `**All elevated role assignments in ${guild.name}:**`,
    `Total: ${records.length} assignment(s)`,
    "",
  ];

  for (const r of records.slice(0, 30)) {
    lines.push(
      `${formatTimestamp(new Date(r.assignedAt))} — **${r.executorTag}** gave **${r.roleName}** to **${r.targetTag}**`
    );
  }

  if (records.length > 30) {
    lines.push(
      `\n*(showing 30 of ${records.length} — use \`,roles given @user\` to filter by mod)*`
    );
  }

  const output = lines.join("\n");
  if (output.length > 1900) {
    const chunks = output.match(/.{1,1900}/gs) ?? [];
    for (const chunk of chunks) await message.channel.send(chunk);
  } else {
    await message.reply(output);
  }
}

async function handleHelpCommand(message: Message) {
  const help = [
    "**Role Audit Bot — Commands**",
    "",
    "`,roles given @user` — Shows all elevated roles this mod has given out, grouped by role.",
    "`,all roles given` — Full server log: who gave what role, to whom, and when.",
    "`,help` — Shows this help menu.",
    "",
    "**Tracked as elevated permissions:**",
    "`Administrator` • `Ban Members` • `Kick Members` • `Timeout Members`",
    "`Manage Roles` • `Manage Guild` • `Manage Channels` • `Manage Messages`",
    "`Manage Nicknames` • `Manage Webhooks` • `Manage Threads`",
    "",
    "**Note:** Only role assignments made after the bot joined are tracked.",
  ].join("\n");

  await message.reply(help);
}

export async function startBot() {
  const token = process.env.DISCORD_BOT_TOKEN;
  if (!token) {
    logger.warn("DISCORD_BOT_TOKEN not set — Discord bot will not start.");
    return;
  }

  const client = new Client({
    intents: [
      GatewayIntentBits.Guilds,
      GatewayIntentBits.GuildMembers,       // Privileged — must enable in Dev Portal
      GatewayIntentBits.GuildMessages,
      GatewayIntentBits.MessageContent,     // Privileged — must enable in Dev Portal
      GatewayIntentBits.GuildModeration,
    ],
  });

  client.on(Events.ClientReady, () => {
    logger.info({ tag: client.user?.tag }, "Discord bot logged in and ready");
  });

  client.on(Events.GuildMemberUpdate, async (oldMember, newMember) => {
    try {
      const guild = newMember.guild;
      const addedRoles = newMember.roles.cache.filter(
        (r) => !oldMember.roles.cache.has(r.id)
      );

      if (addedRoles.size === 0) return;

      const elevatedRoles = addedRoles.filter((role) =>
        hasElevatedPermission(role.permissions)
      );

      if (elevatedRoles.size === 0) return;

      // Small delay so audit log is populated
      await new Promise((r) => setTimeout(r, 1500));

      const auditLogs = await guild.fetchAuditLogs({
        limit: 5,
        type: AuditLogEvent.MemberRoleUpdate,
      });

      const entry = auditLogs.entries.find(
        (e) => (e.target as GuildMember | null)?.id === newMember.id
      );

      if (!entry || !entry.executor) {
        logger.warn(
          { targetId: newMember.id },
          "Role update detected but no audit log entry found — bot may lack View Audit Log permission"
        );
        return;
      }

      const executor = entry.executor;

      for (const [, role] of elevatedRoles) {
        await db.insert(roleAssignmentsTable).values({
          guildId: guild.id,
          executorId: executor.id,
          executorTag: executor.tag ?? executor.username,
          targetId: newMember.id,
          targetTag: newMember.user.tag ?? newMember.user.username,
          roleId: role.id,
          roleName: role.name,
        });

        logger.info(
          {
            executor: executor.tag ?? executor.username,
            target: newMember.user.tag ?? newMember.user.username,
            role: role.name,
          },
          "Elevated role assignment recorded"
        );
      }
    } catch (err) {
      logger.error({ err }, "Error handling GuildMemberUpdate");
    }
  });

  client.on(Events.MessageCreate, async (message) => {
    if (message.author.bot) return;
    if (!message.content.startsWith(",")) return;

    const content = message.content.slice(1).trim();
    const lower = content.toLowerCase();

    try {
      if (lower.startsWith("roles given ")) {
        const args = content.slice("roles given ".length).trim().split(/\s+/);
        await handleRolesGivenCommand(message, args);
      } else if (lower === "all roles given") {
        await handleAllRolesGivenCommand(message);
      } else if (lower === "help") {
        await handleHelpCommand(message);
      }
    } catch (err) {
      logger.error({ err }, "Error handling command");
      await message
        .reply("An error occurred while processing that command.")
        .catch(() => {});
    }
  });

  try {
    await client.login(token);
  } catch (err: any) {
    if (err?.message?.includes("disallowed intents")) {
      logger.error(
        "Discord bot failed: Privileged intents not enabled. " +
        "Go to discord.com/developers/applications → your bot → Bot tab → " +
        "Privileged Gateway Intents → enable 'Server Members Intent' and 'Message Content Intent'."
      );
    } else {
      throw err;
    }
  }
}
