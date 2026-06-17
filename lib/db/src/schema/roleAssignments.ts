import { pgTable, text, timestamp, serial } from "drizzle-orm/pg-core";
import { createInsertSchema } from "drizzle-zod";
import { z } from "zod/v4";

export const roleAssignmentsTable = pgTable("role_assignments", {
  id: serial("id").primaryKey(),
  guildId: text("guild_id").notNull(),
  executorId: text("executor_id").notNull(),
  executorTag: text("executor_tag").notNull(),
  targetId: text("target_id").notNull(),
  targetTag: text("target_tag").notNull(),
  roleId: text("role_id").notNull(),
  roleName: text("role_name").notNull(),
  action: text("action").notNull().default("assigned"), // "assigned" | "removed"
  assignedAt: timestamp("assigned_at", { withTimezone: true }).notNull().defaultNow(),
});

export const insertRoleAssignmentSchema = createInsertSchema(roleAssignmentsTable).omit({ id: true });
export type InsertRoleAssignment = z.infer<typeof insertRoleAssignmentSchema>;
export type RoleAssignment = typeof roleAssignmentsTable.$inferSelect;
