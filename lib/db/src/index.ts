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
      // Discard idle connections after 30s so the pool never hands out a dead one
      idleTimeoutMillis: 30_000,
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
