import { pool } from "@workspace/db";
import { logger } from "./lib/logger";
import { setDbTableReady } from "./bot";

const MAX_RETRIES = 3;
const RETRY_DELAY_MS = 3000;

async function sleep(ms: number) {
  return new Promise((r) => setTimeout(r, ms));
}

export async function runMigrations() {
  if (!pool) {
    logger.warn("DATABASE_URL not set — skipping migrations. Database commands will not work.");
    return;
  }

  for (let attempt = 1; attempt <= MAX_RETRIES; attempt++) {
    let client;
    try {
      logger.info({ attempt }, "Running database migrations...");
      client = await pool.connect();

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

      logger.info("Database migrations complete — table is ready.");
      setDbTableReady(true);
      return;
    } catch (err: any) {
      logger.error({ err: err?.message, code: err?.code, attempt }, "Migration attempt failed");
      if (attempt < MAX_RETRIES) {
        logger.info({ retryIn: RETRY_DELAY_MS }, "Retrying migration...");
        await sleep(RETRY_DELAY_MS);
      } else {
        logger.error("All migration attempts failed. Database commands will error until the table exists.");
        throw err;
      }
    } finally {
      client?.release();
    }
  }
}
