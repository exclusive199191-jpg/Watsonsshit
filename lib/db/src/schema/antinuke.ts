import { pgTable, text, boolean, integer, timestamp, serial, primaryKey } from "drizzle-orm/pg-core";

export const antinukeConfigTable = pgTable("antinuke_config", {
  guildId:                 text("guild_id").primaryKey(),
  enabled:                 boolean("enabled").notNull().default(false),
  logChannelId:            text("log_channel_id"),
  punishment:              text("punishment").notNull().default("ban"),
  whitelist:               text("whitelist").notNull().default("[]"),
  roleingExempt:           text("roleing_exempt").notNull().default("[]"),
  toggles:                 text("toggles").notNull().default("{}"),
  banThreshold:            integer("ban_threshold").notNull().default(3),
  kickThreshold:           integer("kick_threshold").notNull().default(5),
  channelCreateThreshold:  integer("channel_create_threshold").notNull().default(5),
  channelDeleteThreshold:  integer("channel_delete_threshold").notNull().default(3),
  channelRenameThreshold:  integer("channel_rename_threshold").notNull().default(5),
  roleDeleteThreshold:     integer("role_delete_threshold").notNull().default(3),
  roleCreateThreshold:     integer("role_create_threshold").notNull().default(5),
  mentionThreshold:        integer("mention_threshold").notNull().default(10),
  linkThreshold:           integer("link_threshold").notNull().default(5),
  webhookThreshold:        integer("webhook_threshold").notNull().default(2),
  unbanThreshold:          integer("unban_threshold").notNull().default(3),
  emojiDeleteThreshold:    integer("emoji_delete_threshold").notNull().default(5),
  raidJoinThreshold:       integer("raid_join_threshold").notNull().default(10),
  raidJoinWindowMs:        integer("raid_join_window_ms").notNull().default(30000),
  timeWindowMs:            integer("time_window_ms").notNull().default(10000),
  emergencyMode:           boolean("emergency_mode").notNull().default(false),
  updatedAt:               timestamp("updated_at", { withTimezone: true }).notNull().defaultNow(),
});

export const guildSnapshotTable = pgTable("guild_snapshots", {
  guildId:      text("guild_id").primaryKey(),
  channelsJson: text("channels_json").notNull().default("[]"),
  rolesJson:    text("roles_json").notNull().default("[]"),
  guildName:    text("guild_name").notNull().default(""),
  takenAt:      timestamp("taken_at", { withTimezone: true }).notNull().defaultNow(),
});

// Multi-snapshot history: keeps last 3 snapshots per guild for fallback
export const guildSnapshotHistoryTable = pgTable("guild_snapshot_history", {
  id:           serial("id").primaryKey(),
  guildId:      text("guild_id").notNull(),
  guildName:    text("guild_name").notNull().default(""),
  channelsJson: text("channels_json").notNull().default("[]"),
  rolesJson:    text("roles_json").notNull().default("[]"),
  takenAt:      timestamp("taken_at", { withTimezone: true }).notNull().defaultNow(),
  isComplete:   boolean("is_complete").notNull().default(false),
});

// Persistent per-user offense counter — survives restarts, drives kick→ban escalation
export const antinukeOffensesTable = pgTable("antinuke_offenses", {
  guildId:      text("guild_id").notNull(),
  userId:       text("user_id").notNull(),
  offenseCount: integer("offense_count").notNull().default(1),
  lastOffenseAt: timestamp("last_offense_at", { withTimezone: true }).notNull().defaultNow(),
}, (table) => ({
  pk: primaryKey({ columns: [table.guildId, table.userId] }),
}));

export type AntiNukeConfigRow = typeof antinukeConfigTable.$inferSelect;
export type InsertAntiNukeConfig = typeof antinukeConfigTable.$inferInsert;
export type GuildSnapshotRow = typeof guildSnapshotTable.$inferSelect;
export type GuildSnapshotHistoryRow = typeof guildSnapshotHistoryTable.$inferSelect;
export type AntiNukeOffenseRow = typeof antinukeOffensesTable.$inferSelect;
