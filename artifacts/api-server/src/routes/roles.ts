import { Router, type IRouter } from "express";
import { db } from "@workspace/db";
import { roleAssignmentsTable } from "@workspace/db";
import { eq, and, or, ilike, desc, sql, count } from "drizzle-orm";

const router: IRouter = Router();

// GET /api/roles
router.get("/", async (req, res) => {
  if (!db) {
    res.status(503).json({ error: "Database not configured" });
    return;
  }

  const page = Math.max(1, Number(req.query["page"]) || 1);
  const limit = Math.min(100, Math.max(1, Number(req.query["limit"]) || 50));
  const offset = (page - 1) * limit;
  const guildId = req.query["guildId"] as string | undefined;
  const action = req.query["action"] as "assigned" | "removed" | undefined;
  const search = req.query["search"] as string | undefined;

  const conditions = [];
  if (guildId) conditions.push(eq(roleAssignmentsTable.guildId, guildId));
  if (action) conditions.push(eq(roleAssignmentsTable.action, action));
  if (search) {
    conditions.push(
      or(
        ilike(roleAssignmentsTable.executorTag, `%${search}%`),
        ilike(roleAssignmentsTable.targetTag, `%${search}%`),
        ilike(roleAssignmentsTable.roleName, `%${search}%`),
      )!,
    );
  }

  const where = conditions.length > 0 ? and(...conditions) : undefined;

  const [rows, [{ total }]] = await Promise.all([
    db
      .select()
      .from(roleAssignmentsTable)
      .where(where)
      .orderBy(desc(roleAssignmentsTable.assignedAt))
      .limit(limit)
      .offset(offset),
    db
      .select({ total: count() })
      .from(roleAssignmentsTable)
      .where(where),
  ]);

  res.json({
    data: rows.map((r) => ({
      id: r.id,
      guildId: r.guildId,
      executorId: r.executorId,
      executorTag: r.executorTag,
      targetId: r.targetId,
      targetTag: r.targetTag,
      roleId: r.roleId,
      roleName: r.roleName,
      action: r.action,
      assignedAt: r.assignedAt,
    })),
    total: Number(total),
    page,
    limit,
  });
});

// GET /api/roles/stats
router.get("/stats", async (req, res) => {
  if (!db) {
    res.status(503).json({ error: "Database not configured" });
    return;
  }

  const guildId = req.query["guildId"] as string | undefined;
  const where = guildId
    ? eq(roleAssignmentsTable.guildId, guildId)
    : undefined;

  const [totalAssigned, totalRemoved, topMods, topRoles] = await Promise.all([
    db
      .select({ c: count() })
      .from(roleAssignmentsTable)
      .where(and(where, eq(roleAssignmentsTable.action, "assigned"))),
    db
      .select({ c: count() })
      .from(roleAssignmentsTable)
      .where(and(where, eq(roleAssignmentsTable.action, "removed"))),
    db
      .select({
        executorId: roleAssignmentsTable.executorId,
        executorTag: roleAssignmentsTable.executorTag,
        assigned: sql<number>`sum(case when action = 'assigned' then 1 else 0 end)::int`,
        removed: sql<number>`sum(case when action = 'removed' then 1 else 0 end)::int`,
        total: count(),
      })
      .from(roleAssignmentsTable)
      .where(where)
      .groupBy(
        roleAssignmentsTable.executorId,
        roleAssignmentsTable.executorTag,
      )
      .orderBy(desc(count()))
      .limit(10),
    db
      .select({
        roleName: roleAssignmentsTable.roleName,
        times: count(),
      })
      .from(roleAssignmentsTable)
      .where(and(where, eq(roleAssignmentsTable.action, "assigned")))
      .groupBy(roleAssignmentsTable.roleName)
      .orderBy(desc(count()))
      .limit(10),
  ]);

  const assigned = Number(totalAssigned[0]?.c ?? 0);
  const removed = Number(totalRemoved[0]?.c ?? 0);

  res.json({
    totalAssigned: assigned,
    totalRemoved: removed,
    totalEvents: assigned + removed,
    topMods: topMods.map((m) => ({
      executorId: m.executorId,
      executorTag: m.executorTag,
      assigned: Number(m.assigned),
      removed: Number(m.removed),
      total: Number(m.total),
    })),
    topRoles: topRoles.map((r) => ({
      roleName: r.roleName,
      times: Number(r.times),
    })),
  });
});

// GET /api/roles/guilds
router.get("/guilds", async (req, res) => {
  if (!db) {
    res.status(503).json({ error: "Database not configured" });
    return;
  }

  const guilds = await db
    .selectDistinct({ id: roleAssignmentsTable.guildId })
    .from(roleAssignmentsTable)
    .orderBy(roleAssignmentsTable.guildId);

  res.json({ guilds: guilds.map((g) => ({ id: g.id })) });
});

export default router;
