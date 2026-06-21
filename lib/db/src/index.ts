import { drizzle } from "drizzle-orm/node-postgres";
import pg from "pg";
import * as schema from "./schema";

const { Pool } = pg;

const url = process.env.DATABASE_URL;

if (!url) {
  console.warn(
    "[db] WARNING: DATABASE_URL is not set. " +
    "All database-backed commands will be unavailable until it is configured."
  );
}

export const pool = url
  ? new Pool({
      connectionString: url,
      // Railway PostgreSQL (and most cloud providers) require SSL.
      // rejectUnauthorized:false accepts self-signed certs (standard for Railway).
      ssl: { rejectUnauthorized: false },
      // Keep connections alive so Railway infra doesn't silently kill them
      keepAlive: true,
      keepAliveInitialDelayMillis: 10_000,
      // Drop idle connections after 5s to avoid ETIMEDOUT on Railway
      idleTimeoutMillis: 5_000,
      // Fail reasonably fast if the DB is unreachable
      connectionTimeoutMillis: 15_000,
      // Small pool — Discord bot has very low concurrency
      max: 5,
    })
  : null;

// Log pool-level errors so they appear in Railway structured logs
pool?.on("error", (err: Error) => {
  console.error(`[db] Pool connection error: ${err.message}`);
});

export const db = url ? drizzle(pool as pg.Pool, { schema }) : null;

export * from "./schema";
