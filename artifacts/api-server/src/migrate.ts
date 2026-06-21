import { pool, dbHostname } from "@workspace/db";
import { logger } from "./lib/logger";
import { setDbTableReady } from "./db-state";

const MAX_RETRIES = 3;
const RETRY_DELAY_MS = 3000;

async function sleep(ms: number) {
  return new Promise<void>((r) => setTimeout(r, ms));
}

export async function runMigrations() {
  if (!pool) {
    logger.warn("DATABASE_URL not set — skipping migrations. Database commands will not work.");
    return;
  }

  const host = dbHostname();
  logger.info(`Starting migrations — target host: ${host}`);

  for (let attempt = 1; attempt <= MAX_RETRIES; attempt++) {
    let client;
    try {
      logger.info(`Migration attempt ${attempt}/${MAX_RETRIES} — connecting to ${host}...`);
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

      logger.info(`Database migrations complete — table is ready. (host: ${host})`);
      setDbTableReady(true);
      return;
    } catch (err: any) {
      const code: string = err?.code ?? err?.cause?.code ?? "NO_CODE";
      const msg: string = err?.message ?? err?.cause?.message ?? String(err);
      logger.error(
        `Migration attempt ${attempt}/${MAX_RETRIES} FAILED — host: ${host} | [${code}] ${msg || "(no message)"}`
      );
      if (attempt < MAX_RETRIES) {
        logger.info(`Retrying migration in ${RETRY_DELAY_MS / 1000}s...`);
        await sleep(RETRY_DELAY_MS);
      } else {
        logger.error(
          `All ${MAX_RETRIES} migration attempts failed. ` +
          `Could not reach ${host}. ` +
          `Last error: [${code}] ${msg || "(no message)"}. ` +
          "Check that DATABASE_URL points to the correct host and that the Railway service has a reference to the PostgreSQL plugin. " +
          "Run ,migrate in Discord to retry after fixing the URL."
        );
        throw err;
      }
    } finally {
      client?.release();
    }
  }
}
