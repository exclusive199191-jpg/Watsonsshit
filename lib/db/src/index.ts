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
      // Keep connections alive so Railway/cloud infra doesn't silently kill them
      keepAlive: true,
      keepAliveInitialDelayMillis: 10_000,
      // Drop idle connections after 1s — always use a fresh connection for the next query.
      // This is the most reliable way to avoid ETIMEDOUT on Railway, which kills idle
      // TCP connections at the infra level. A Discord bot has very low concurrency so
      // the reconnect overhead (~50ms) is not a problem.
      idleTimeoutMillis: 1_000,
      // Fail fast if the DB is unreachable rather than hanging forever
      connectionTimeoutMillis: 10_000,
      // Small pool — this is a Discord bot, not a web server
      max: 5,
    })
  : null;

// Silently replace dead connections instead of surfacing the error to callers
pool?.on("error", (err) => {
  console.error("[db] Pool error (connection will be replaced):", err.message);
});

export const db = url ? drizzle(pool as pg.Pool, { schema }) : null;

export * from "./schema";
