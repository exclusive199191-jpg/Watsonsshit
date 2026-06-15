import { pool } from "@workspace/db";
import { logger } from "./lib/logger";

export async function runMigrations() {
  const client = await pool.connect();
  try {
    logger.info("Running database migrations...");

    await client.query(`
      CREATE TABLE IF NOT EXISTS role_assignments (
        id          SERIAL PRIMARY KEY,
        guild_id    TEXT        NOT NULL,
        executor_id TEXT        NOT NULL,
        executor_tag TEXT       NOT NULL,
        target_id   TEXT        NOT NULL,
        target_tag  TEXT        NOT NULL,
        role_id     TEXT        NOT NULL,
        role_name   TEXT        NOT NULL,
        assigned_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      )
    `);

    logger.info("Database migrations complete.");
  } finally {
    client.release();
  }
}
