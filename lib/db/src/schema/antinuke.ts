import { pgTable, text, boolean, integer, timestamp } from "drizzle-orm/pg-core";

export const antinukeConfigTable = pgTable("antinuke_config", {
  guildId:                 text("guild_id").primaryKey(),
  enabled:                 boolean("enabled").notNull().default(false),
  logChannelId:            text("log_channel_id"),
  punishment:              text("punishment").notNull().default("ban"),    // "ban" | "kick" | "strip"
  whitelist:               text("whitelist").notNull().default("[]"),      // JSON array of user IDs
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
  timeWindowMs:            integer("time_window_ms").notNull().default(10000),
  updatedAt:               timestamp("updated_at", { withTimezone: true }).notNull().defaultNow(),
});

export type AntiNukeConfigRow = typeof antinukeConfigTable.$inferSelect;
export type InsertAntiNukeConfig = typeof antinukeConfigTable.$inferInsert;
