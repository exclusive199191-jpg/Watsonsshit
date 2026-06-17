import { pool } from "@workspace/db";
import { logger } from "./lib/logger";

export async function runMigrations() {
  if (!pool) {
    logger.warn("DATABASE_URL not set — skipping migrations. Database commands will not work.");
    return;
  }

  const client = await pool.connect();
  try {
    logger.info("Running database migrations...");

    await client.query(`
      CREATE TABLE IF NOT EXISTS role_assignments (
        id           SERIAL PRIMARY KEY,
        guild_id     TEXT        NOT NULL,
        executor_id  TEXT        NOT NULL,
        executor_tag TEXT        NOT NULL,
        target_id    TEXT        NOT NULL,
        target_tag   TEXT        NOT NULL,
        role_id      TEXT        NOT NULL,
        role_name    TEXT        NOT NULL,
        action       TEXT        NOT NULL DEFAULT 'assigned',
        assigned_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
      )
    `);

    await client.query(`
      ALTER TABLE role_assignments
        ADD COLUMN IF NOT EXISTS action TEXT NOT NULL DEFAULT 'assigned'
    `);

    await client.query(`
      CREATE INDEX IF NOT EXISTS idx_role_assignments_guild
        ON role_assignments (guild_id, assigned_at DESC)
    `);

    await client.query(`
      CREATE INDEX IF NOT EXISTS idx_role_assignments_executor
        ON role_assignments (guild_id, executor_id, assigned_at DESC)
    `);

    await client.query(`
      CREATE INDEX IF NOT EXISTS idx_role_assignments_target
        ON role_assignments (guild_id, target_id, assigned_at DESC)
    `);

    logger.info("Database migrations complete.");
  } finally {
    client.release();
  }
}
